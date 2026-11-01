using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keyhole.App.Controls;
using Keyhole.Core;
using Keyhole.Core.Ipc;
using Keyhole.Native.Npcap;

namespace Keyhole.App.ViewModels;

/// <summary>
/// M2 shell: the live application list plus a drill-down into one app's connections.
/// The designed dashboard, graphs and blocking arrive in M3 and M4.
/// </summary>
public sealed partial class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly KeyholeServiceClient _client;
    private readonly DispatcherTimer _refreshTimer;

    public MainWindowViewModel(KeyholeServiceClient client)
    {
        _client = client;

        Apps = [];
        Flows = [];

        // Matches the service's own sampling interval; refreshing faster would show
        // the same data repeatedly.
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _refreshTimer.Tick += (_, _) => _ = RefreshAsync();
        _refreshTimer.Start();

        _ = RefreshAsync();
    }

    public ObservableCollection<AppRow> Apps { get; }

    public ObservableCollection<FlowRow> Flows { get; }

    [ObservableProperty]
    private ConnectionState _state = ConnectionState.Unknown;

    [ObservableProperty]
    private string _statusMessage = "Checking the Keyhole service…";

    [ObservableProperty]
    private string? _serviceVersion;

    [ObservableProperty]
    private bool _serviceIsElevated;

    [ObservableProperty]
    private int _activeConnections;

    /// <summary>Set when the service cannot count bytes, so the UI can say why totals are zero.</summary>
    [ObservableProperty]
    private string? _byteCountingWarning;

    /// <summary>Set when rules cannot be written, so Block is disabled with an explanation.</summary>
    [ObservableProperty]
    private string? _blockingWarning;

    /// <summary>
    /// Set when packet recording is unavailable.
    ///
    /// Kept out of <see cref="CapabilityWarning"/> on purpose. That strip is about
    /// elevation and sits above the application list, where it would be permanent noise
    /// for anyone who does not use captures. This belongs in the Capture tab, next to the
    /// feature it affects and next to the button that fixes it.
    /// </summary>
    [ObservableProperty]
    private string? _packetCaptureWarning;

    /// <summary>"ready", "missing", "stopped" or "unusable".</summary>
    [ObservableProperty]
    private string? _npcapState;

    /// <summary>
    /// Whether offering the download would help. Only for a genuinely absent install:
    /// downloading a second copy does not start a stopped driver.
    /// </summary>
    public bool CanInstallNpcap => NpcapState == "missing";

    public bool HasPacketCaptureWarning => PacketCaptureWarning is not null;

    partial void OnPacketCaptureWarningChanged(string? value) =>
        OnPropertyChanged(nameof(HasPacketCaptureWarning));

    partial void OnNpcapStateChanged(string? value) =>
        OnPropertyChanged(nameof(CanInstallNpcap));

    /// <summary>Result of the last block or unblock, shown next to the rules list.</summary>
    [ObservableProperty]
    private string? _lastActionMessage;

    public bool CanBlock => BlockingWarning is null;

    /// <summary>
    /// One line covering whatever is unavailable. Byte counting and blocking both fail
    /// for the same reason — no elevation — so two separate strips would say the same
    /// thing twice and cost a third of the list's vertical space.
    /// </summary>
    public string? CapabilityWarning
    {
        get
        {
            var missing = new List<string>(2);
            if (ByteCountingWarning is not null)
            {
                missing.Add("byte counting");
            }

            if (BlockingWarning is not null)
            {
                missing.Add("blocking");
            }

            if (missing.Count == 0)
            {
                return null;
            }

            // Both reasons currently say "needs administrator rights". If they ever
            // diverge, fall back to showing them in full rather than inventing a summary.
            var sameCause = ByteCountingWarning is null || BlockingWarning is null ||
                            (ByteCountingWarning.Contains("administrator", StringComparison.OrdinalIgnoreCase) &&
                             BlockingWarning.Contains("administrator", StringComparison.OrdinalIgnoreCase));

            return sameCause
                ? $"The service is not elevated, so {string.Join(" and ", missing)} are unavailable. " +
                  "Connection monitoring still works."
                : $"{ByteCountingWarning} {BlockingWarning}";
        }
    }

    partial void OnBlockingWarningChanged(string? value)
    {
        OnPropertyChanged(nameof(CanBlock));
        OnPropertyChanged(nameof(CapabilityWarning));
    }

    partial void OnByteCountingWarningChanged(string? value) =>
        OnPropertyChanged(nameof(CapabilityWarning));

    public ObservableCollection<RuleRow> Rules { get; } = [];

    /// <summary>
    /// Destinations ranked by volume, across every application.
    ///
    /// The app list answers "what is this program doing". This answers it from the other
    /// end, which is where an unexpected destination shows up: a host three unrelated
    /// programs are all talking to is interesting in a way none of the three looks on its
    /// own.
    /// </summary>
    public ObservableCollection<HostRow> Hosts { get; } = [];

    /// <summary>Free-text filter over the host list, matching host, app or address.</summary>
    [ObservableProperty]
    private string _hostSearchText = "";

    partial void OnHostSearchTextChanged(string value) => ApplyHostFilter();

    public ObservableCollection<HostRow> VisibleHosts { get; } = [];

    /// <summary>
    /// Syncs the visible host list in place, for the same reason the app list does: the
    /// grid drops its selection when a row leaves the collection, and this runs on every
    /// refresh.
    /// </summary>
    private void ApplyHostFilter()
    {
        var needle = HostSearchText.Trim();
        var desired = Hosts.Where(h => needle.Length == 0 || h.Matches(needle)).ToList();

        for (var i = VisibleHosts.Count - 1; i >= 0; i--)
        {
            if (!desired.Contains(VisibleHosts[i]))
            {
                VisibleHosts.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            var host = desired[i];
            var current = VisibleHosts.IndexOf(host);

            if (current < 0)
            {
                VisibleHosts.Insert(Math.Min(i, VisibleHosts.Count), host);
            }
            else if (current != i)
            {
                VisibleHosts.Move(current, i);
            }
        }
    }

    private async Task LoadHostsAsync(CancellationToken ct)
    {
        try
        {
            var hosts = await _client.ListHostsAsync(ct);

            // Replaced wholesale rather than merged: the list is ranked by volume, so
            // rows reorder constantly and there is no stable identity to preserve. The
            // filter below restores whatever the user was looking at.
            Hosts.Clear();
            foreach (var host in hosts)
            {
                Hosts.Add(new HostRow(host));
            }

            ApplyHostFilter();
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            Hosts.Clear();
            VisibleHosts.Clear();
        }
    }

    /// <summary>Points for the dashboard graph.</summary>
    [ObservableProperty]
    private IReadOnlyList<ChartPoint> _throughput = [];

    /// <summary>Points for the selected application's own graph.</summary>
    [ObservableProperty]
    private IReadOnlyList<ChartPoint> _appThroughput = [];

    [ObservableProperty]
    private string _totalRate = "—";

    /// <summary>
    /// Free-text filter over the app list. Applied in the view model rather than the
    /// service: the list is small and filtering locally keeps typing responsive.
    /// </summary>
    [ObservableProperty]
    private string _searchText = "";

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    /// <summary>The rows actually shown, after the search filter.</summary>
    public ObservableCollection<AppRow> VisibleApps { get; } = [];

    /// <summary>
    /// Syncs <see cref="VisibleApps"/> to the current filter in place.
    ///
    /// Clearing and refilling would be simpler, but the grid drops its selection when the
    /// selected row leaves the collection — and this runs on every two-second refresh, so
    /// a user who clicked an application would lose the drill-down a moment later.
    /// </summary>
    private void ApplyFilter()
    {
        var needle = SearchText.Trim();
        var desired = Apps.Where(a => needle.Length == 0 || a.Matches(needle)).ToList();

        for (var i = VisibleApps.Count - 1; i >= 0; i--)
        {
            if (!desired.Contains(VisibleApps[i]))
            {
                VisibleApps.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            var app = desired[i];
            var current = VisibleApps.IndexOf(app);

            if (current < 0)
            {
                VisibleApps.Insert(Math.Min(i, VisibleApps.Count), app);
            }
            else if (current != i)
            {
                VisibleApps.Move(current, i);
            }
        }
    }

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private AppRow? _selectedApp;

    public bool HasSelection => SelectedApp is not null;

    partial void OnSelectedAppChanged(AppRow? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        _ = LoadFlowsAsync(value);
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            var status = await _client.GetStatusAsync(cts.Token);
            ServiceVersion = status.Version;
            ServiceIsElevated = status.IsElevated;
            ActiveConnections = status.ActiveConnections ?? 0;
            ByteCountingWarning = status.ByteCountingUnavailableReason;
            BlockingWarning = status.BlockingUnavailableReason;
            PacketCaptureWarning = status.PacketCaptureUnavailableReason;
            NpcapState = status.NpcapState;

            var apps = await _client.ListAppsAsync(cts.Token);
            MergeApps(apps);
            ApplyFilter();
            await LoadRulesAsync(cts.Token);
            await LoadThroughputAsync(cts.Token);
            await LoadHostsAsync(cts.Token);
            await LoadCapturesAsync(cts.Token);

            State = ConnectionState.Connected;
            StatusMessage = $"{Apps.Count} apps, {ActiveConnections} active connections.";

            if (SelectedApp is not null)
            {
                await LoadFlowsAsync(SelectedApp, cts.Token);
            }
        }
        catch (ServiceUnavailableException ex)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = $"Service unreachable: {ex.Message}";
            Apps.Clear();
            Flows.Clear();
        }
        catch (ServiceCallException ex)
        {
            State = ConnectionState.Error;
            StatusMessage = $"Service error ({ex.Code}): {ex.Message}";
        }
        catch (OperationCanceledException)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = "Service did not answer within 5 seconds.";
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Updates the list in place. Replacing the collection wholesale would drop the
    /// user's selection and reset scroll position on every two-second refresh.
    /// </summary>
    private void MergeApps(IReadOnlyList<AppSummary> incoming)
    {
        var selectedKey = SelectedApp?.Key;

        var byKey = new Dictionary<string, AppRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in Apps)
        {
            byKey[row.Key] = row;
        }

        for (var i = 0; i < incoming.Count; i++)
        {
            var summary = incoming[i];
            var key = AppRow.KeyFor(summary);

            if (byKey.TryGetValue(key, out var existing))
            {
                existing.Update(summary);

                var currentIndex = Apps.IndexOf(existing);
                if (currentIndex != i && i < Apps.Count)
                {
                    Apps.Move(currentIndex, i);
                }

                byKey.Remove(key);
            }
            else
            {
                Apps.Insert(Math.Min(i, Apps.Count), new AppRow(summary));
            }
        }

        foreach (var stale in byKey.Values)
        {
            Apps.Remove(stale);
        }

        if (selectedKey is not null && SelectedApp is null)
        {
            foreach (var row in Apps)
            {
                if (string.Equals(row.Key, selectedKey, StringComparison.OrdinalIgnoreCase))
                {
                    SelectedApp = row;
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Blocks the selected application. Only reachable from a deliberate click; Keyhole
    /// never creates a rule on its own.
    /// </summary>
    /// <summary>
    /// Cycles the window between following the OS setting, light and dark. Defaults to
    /// following the OS so Keyhole matches the rest of the desktop out of the box.
    /// </summary>
    [RelayCommand]
    private void CycleTheme()
    {
        if (Application.Current is not { } app)
        {
            return;
        }

        (app.RequestedThemeVariant, ThemeLabel) = app.RequestedThemeVariant switch
        {
            var v when v == ThemeVariant.Dark => (ThemeVariant.Light, "Light"),
            var v when v == ThemeVariant.Light => (ThemeVariant.Default, "Auto"),
            _ => (ThemeVariant.Dark, "Dark"),
        };

        PersistSettings();
    }

    [ObservableProperty]
    private string _themeLabel = "Auto";

    private KeyholeSettings _settings = new();

    /// <summary>Set once at startup by the application, before the window is shown.</summary>
    public KeyholeSettings Settings
    {
        get => _settings;
        set
        {
            _settings = value;
            ThemeLabel = value.Theme switch
            {
                "light" => "Light",
                "dark" => "Dark",
                _ => "Auto",
            };

            MinimiseToTray = value.MinimiseToTray;
            ResolveHostnames = value.ResolveHostnames;
            RetentionDays = value.RetentionDays;
            MaxPcapMegabytes = value.MaxPcapMegabytes;
            StartWithWindows = StartupRegistration.IsEnabled();
        }
    }

    [ObservableProperty] private bool _minimiseToTray = true;
    [ObservableProperty] private bool _resolveHostnames = true;
    [ObservableProperty] private int _retentionDays = 30;
    [ObservableProperty] private bool _startWithWindows;
    [ObservableProperty] private int _maxPcapMegabytes = 512;

    [ObservableProperty] private string? _settingsMessage;

    partial void OnMinimiseToTrayChanged(bool value) => PersistSettings();

    partial void OnResolveHostnamesChanged(bool value) => PersistSettings();

    partial void OnRetentionDaysChanged(int value) => PersistSettings();

    partial void OnMaxPcapMegabytesChanged(int value) => PersistSettings();

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (!StartupRegistration.SetEnabled(value))
        {
            SettingsMessage = "Could not update the sign-in startup entry.";
            return;
        }

        PersistSettings();
    }

    private void PersistSettings()
    {
        _settings = _settings with
        {
            MinimiseToTray = MinimiseToTray,
            ResolveHostnames = ResolveHostnames,
            RetentionDays = RetentionDays,
            MaxPcapMegabytes = MaxPcapMegabytes,
            StartWithWindows = StartWithWindows,
            Theme = ThemeLabel.ToLowerInvariant(),
        };

        try
        {
            SettingsStore.Save(_settings);
            SettingsMessage = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Settings are a convenience; failing to save one must not break the session.
            SettingsMessage = $"Could not save settings: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task BlockSelectedAsync()
    {
        if (SelectedApp?.ExecutablePath is not { } path)
        {
            LastActionMessage = "This entry has no readable executable path, so it cannot be blocked.";
            return;
        }

        await BlockPathAsync(path);
    }

    /// <summary>Blocks an executable chosen through the file picker.</summary>
    [RelayCommand]
    private async Task BrowseAndBlockAsync()
    {
        if (PickExecutableAsync is null)
        {
            return;
        }

        var path = await PickExecutableAsync();
        if (!string.IsNullOrWhiteSpace(path))
        {
            await BlockPathAsync(path);
        }
    }

    /// <summary>
    /// Supplied by the view: Avalonia's file picker needs a window handle, which a view
    /// model has no business holding.
    /// </summary>
    public Func<Task<string?>>? PickExecutableAsync { get; set; }

    private async Task BlockPathAsync(string path)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var rule = await _client.BlockAppAsync(path, "outbound", null, cts.Token);

            LastActionMessage = $"Blocked {rule.DisplayName}.";
            await LoadRulesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            // Carries the real reason — not elevated, file missing — so show it verbatim.
            LastActionMessage = ex.Message;
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = "The service did not respond; the block was not applied.";
        }
    }

    [RelayCommand]
    private async Task UnblockAsync(RuleRow? rule)
    {
        if (rule is null)
        {
            return;
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _client.UnblockAppAsync(rule.Id, cts.Token);

            LastActionMessage = $"Unblocked {rule.DisplayName}.";
            await LoadRulesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            LastActionMessage = ex.Message;
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = "The service did not respond; the rule was not removed.";
        }
    }

    public ObservableCollection<CaptureRow> Captures { get; } = [];

    /// <summary>
    /// Launches an application with TLS key logging scoped to it. This is the whole point
    /// of the feature: no machine-wide SSLKEYLOGFILE, nothing to remember to unset.
    /// </summary>
    [RelayCommand]
    private async Task StartCaptureAsync()
    {
        if (PickExecutableAsync is null)
        {
            return;
        }

        var path = await PickExecutableAsync();
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var session = await _client.StartCaptureAsync(path, null, cts.Token);

            LastActionMessage = session.KeylogSupport switch
            {
                "likely" => $"Capturing {session.DisplayName}. TLS keys go to {session.KeylogFile}.",

                // Said up front rather than leaving the user watching a keylog that will
                // never grow. Windows' own curl.exe is the classic case.
                "unlikely" => $"Started {session.DisplayName}, but it uses Windows' TLS stack, " +
                              "which ignores SSLKEYLOGFILE. No keys will be written.",

                _ => $"Started {session.DisplayName}. If the keylog stays at zero bytes, " +
                     "this application uses Windows' TLS stack and cannot be captured this way.",
            };

            await LoadCapturesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            LastActionMessage = ex.Message;
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = "The service did not respond; nothing was started.";
        }
    }

    [RelayCommand]
    private async Task StopCaptureAsync(CaptureRow? capture)
    {
        if (capture is null)
        {
            return;
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _client.StopCaptureAsync(capture.Id, cts.Token);

            LastActionMessage = $"Stopped capturing {capture.DisplayName}. The application is still running.";
            await LoadCapturesAsync(cts.Token);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            LastActionMessage = "The service did not respond; the capture was not stopped.";
        }
    }

    /// <summary>The requests recovered from the selected capture.</summary>
    public ObservableCollection<ExchangeRow> Exchanges { get; } = [];

    /// <summary>What the last decode pass found, shown above the request list.</summary>
    [ObservableProperty]
    private string? _decodeSummary;

    [ObservableProperty]
    private bool _isDecoding;

    [ObservableProperty]
    private CaptureRow? _decodedCapture;

    public bool HasDecoded => DecodeSummary is not null;

    partial void OnDecodeSummaryChanged(string? value) => OnPropertyChanged(nameof(HasDecoded));

    /// <summary>
    /// Decodes a session's capture into the requests it holds.
    ///
    /// Explicitly invoked rather than part of the refresh cycle: it reads the whole capture
    /// file and decrypts every record, which for a browser session takes seconds, and no
    /// amount of that belongs on a two-second timer.
    /// </summary>
    [RelayCommand]
    private async Task DecodeCaptureAsync(CaptureRow? capture)
    {
        if (capture is null || IsDecoding)
        {
            return;
        }

        IsDecoding = true;
        DecodedCapture = capture;
        Exchanges.Clear();
        DecodeSummary = $"Decoding {capture.DisplayName}…";

        try
        {
            // Generous: decoding a long session is genuinely slow, and timing out on a
            // capture that would have worked is worse than making the user wait.
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

            var result = await _client.DecodeCaptureAsync(capture.Id, cts.Token);

            foreach (var exchange in result.Exchanges)
            {
                Exchanges.Add(new ExchangeRow(exchange));
            }

            DecodeSummary = result.Summary;
        }
        catch (ServiceCallException ex)
        {
            DecodeSummary = ex.Message;
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            DecodeSummary = "The service did not finish decoding this capture.";
        }
        finally
        {
            IsDecoding = false;
        }
    }

    /// <summary>
    /// Opens a session's capture in Wireshark.
    ///
    /// One file is enough: the capture carries its own TLS secrets in a Decryption Secrets
    /// Block, so Wireshark decrypts it with nothing configured. That is the whole point of
    /// writing pcapng rather than classic pcap — the old workflow was to open the pcap,
    /// then find the keylog, then paste its path into a preferences dialog.
    /// </summary>
    [RelayCommand]
    private void OpenInWireshark(CaptureRow? capture)
    {
        if (capture?.PcapFile is not { } pcap || !File.Exists(pcap))
        {
            LastActionMessage = "This session recorded no packets, so there is nothing to open.";
            return;
        }

        var wireshark = FindWireshark();

        try
        {
            if (wireshark is null)
            {
                // Not installed where we looked, or installed somewhere unusual. Handing
                // the file to the shell lets whatever is registered for .pcapng take it,
                // which is Wireshark on any machine that has it.
                Process.Start(new ProcessStartInfo { FileName = pcap, UseShellExecute = true });
                LastActionMessage = $"Opened {Path.GetFileName(pcap)} with its registered application.";
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = wireshark,
                Arguments = $"-r \"{pcap}\"",
                UseShellExecute = false,
            });

            LastActionMessage = capture.HasKeys
                ? "Opened in Wireshark. The TLS keys are inside the capture, so it decrypts itself."
                : "Opened in Wireshark. This session wrote no TLS keys, so the traffic stays encrypted.";
        }
        catch (Exception ex)
        {
            LastActionMessage = $"Could not open the capture: {ex.Message}";
        }
    }

    private static string? FindWireshark()
    {
        string[] candidates =
        [
            @"C:\Program Files\Wireshark\Wireshark.exe",
            @"C:\Program Files (x86)\Wireshark\Wireshark.exe",
        ];

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Offers to fetch Npcap so packet recording can work.
    ///
    /// Keyhole does not ship Npcap — its free licence forbids redistribution — so this
    /// downloads the vendor's own installer, checks that it really is signed by the Nmap
    /// Project, and then hands it to the user with the normal elevation prompt. A download
    /// that does not verify is deleted rather than run.
    /// </summary>
    [RelayCommand]
    private async Task InstallNpcapAsync()
    {
        if (!CanInstallNpcap || IsInstallingNpcap)
        {
            return;
        }

        IsInstallingNpcap = true;
        PacketCaptureWarning = $"Downloading Npcap {NpcapInstallerFetch.PinnedVersion} from npcap.com…";

        try
        {
            var result = await new NpcapInstallerFetch().DownloadAsync();

            if (!result.IsSuccess)
            {
                PacketCaptureWarning = result.Error;
                return;
            }

            if (!NpcapInstallerFetch.Launch(result.InstallerPath!))
            {
                PacketCaptureWarning =
                    "The Npcap installer was downloaded and verified but not started. " +
                    $"Run it yourself from {result.InstallerPath}, or install from " +
                    $"{NpcapInstallerFetch.HomepageUri}.";

                return;
            }

            PacketCaptureWarning =
                "Npcap's installer is running. Captures will record packets once it " +
                "finishes — no need to restart Keyhole.";
        }
        catch (Exception ex)
        {
            PacketCaptureWarning =
                $"Could not fetch Npcap ({ex.Message}). Install it from " +
                $"{NpcapInstallerFetch.HomepageUri}.";
        }
        finally
        {
            IsInstallingNpcap = false;
        }
    }

    [ObservableProperty]
    private bool _isInstallingNpcap;

    /// <summary>Opens a session's folder so the pcap and keylog can be picked up by hand.</summary>
    [RelayCommand]
    private void OpenCaptureFolder(CaptureRow? capture)
    {
        if (capture is null || !Directory.Exists(capture.Directory))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = capture.Directory,
                UseShellExecute = true,
            });
        }
        catch (Exception)
        {
            LastActionMessage = $"Could not open {capture.Directory}.";
        }
    }

    private async Task LoadCapturesAsync(CancellationToken ct)
    {
        try
        {
            var sessions = await _client.ListCapturesAsync(ct);

            Captures.Clear();
            foreach (var session in sessions)
            {
                Captures.Add(new CaptureRow(session));
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            Captures.Clear();
        }
    }

    private async Task LoadThroughputAsync(CancellationToken ct)
    {
        try
        {
            var samples = await _client.GetThroughputAsync(ct);

            Throughput = samples
                .Select(s => new ChartPoint(s.TimestampUtc, s.SentPerSecond, s.ReceivedPerSecond))
                .ToList();

            var latest = samples.Count > 0 ? samples[^1] : null;
            TotalRate = latest is null
                ? "—"
                : $"↑ {ThroughputChart.FormatRate(latest.SentPerSecond)}   " +
                  $"↓ {ThroughputChart.FormatRate(latest.ReceivedPerSecond)}";
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            Throughput = [];
            TotalRate = "—";
        }
    }

    private async Task LoadRulesAsync(CancellationToken ct)
    {
        try
        {
            var rules = await _client.ListRulesAsync(ct);

            Rules.Clear();
            foreach (var rule in rules)
            {
                Rules.Add(new RuleRow(rule));
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            Rules.Clear();
        }
    }

    private async Task LoadFlowsAsync(AppRow? app, CancellationToken ct = default)
    {
        if (app is null)
        {
            Flows.Clear();
            return;
        }

        try
        {
            var response = await _client.ListFlowsAsync(app.Key, includeClosed: true, ct);

            Flows.Clear();
            foreach (var flow in response.Flows)
            {
                Flows.Add(new FlowRow(flow));
            }

            AppThroughput = response.Throughput
                .Select(s => new ChartPoint(s.TimestampUtc, s.SentPerSecond, s.ReceivedPerSecond))
                .ToList();
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            // The outer refresh already reports connection problems; a failed drill-down
            // should not overwrite that with a second message.
            Flows.Clear();
            AppThroughput = [];
        }
    }

    public void Dispose() => _refreshTimer.Stop();
}

/// <summary>One application in the list. Mutable so refreshes update in place.</summary>
public sealed partial class AppRow : ObservableObject
{
    public AppRow(AppSummary summary)
    {
        Key = KeyFor(summary);
        Update(summary);
    }

    /// <summary>
    /// Matches how the service groups applications: executable path, or display name when
    /// the path could not be read. Used as the drill-down argument.
    /// </summary>
    public static string KeyFor(AppSummary summary) => summary.ExecutablePath ?? summary.DisplayName;

    public string Key { get; }

    /// <summary>
    /// Null when the path could not be read, which is why Block has to check: the
    /// firewall matches on path, so there is nothing to write a rule against.
    /// </summary>
    public string? ExecutablePath { get; private set; }

    [ObservableProperty] private string _displayName = "";
    [ObservableProperty] private string? _publisher;
    [ObservableProperty] private string _signature = "";
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private int _totalConnections;
    [ObservableProperty] private string _traffic = "";
    [ObservableProperty] private string _rate = "";
    [ObservableProperty] private string _remoteHosts = "";
    [ObservableProperty] private Bitmap? _icon;

    /// <summary>
    /// Shown as text, not only as a colour or icon, so the blocked state survives
    /// colour-vision deficiency and a monochrome screenshot.
    /// </summary>
    [ObservableProperty] private string _blockedLabel = "";

    [ObservableProperty] private bool _isBlocked;

    public long? BlockedByRuleId { get; private set; }

    public void Update(AppSummary summary)
    {
        ExecutablePath = summary.ExecutablePath;
        DisplayName = summary.DisplayName;
        Publisher = summary.Publisher;
        Signature = summary.Signature;
        ActiveConnections = summary.ActiveConnections;
        TotalConnections = summary.TotalConnections;
        Traffic = Format.Traffic(summary.BytesSent, summary.BytesReceived);
        RemoteHosts = string.Join(", ", summary.RecentRemoteHosts);

        Rate = summary.SentRate < 1 && summary.ReceivedRate < 1
            ? "—"
            : $"↑{ThroughputChart.FormatRate(summary.SentRate)} ↓{ThroughputChart.FormatRate(summary.ReceivedRate)}";

        BlockedByRuleId = summary.BlockedByRuleId;
        IsBlocked = summary.BlockedByRuleId is not null;
        BlockedLabel = IsBlocked ? "Blocked" : "";

        // Loaded once per row: the shell lookup is cached, but building an Avalonia
        // bitmap on every two-second refresh would still churn.
        Icon ??= IconLoader.Load(summary.ExecutablePath);
    }

    /// <summary>Matches the search box against the fields a user would type.</summary>
    public bool Matches(string needle) =>
        DisplayName.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        (Publisher?.Contains(needle, StringComparison.OrdinalIgnoreCase) ?? false) ||
        (ExecutablePath?.Contains(needle, StringComparison.OrdinalIgnoreCase) ?? false) ||
        RemoteHosts.Contains(needle, StringComparison.OrdinalIgnoreCase);
}

/// <summary>One block rule in the rules list.</summary>
public sealed class RuleRow(RuleSummary rule)
{
    public long Id { get; } = rule.Id;
    public string DisplayName { get; } = rule.DisplayName;
    public string ExecutablePath { get; } = rule.ExecutablePath;
    public string Direction { get; } = rule.Direction;
    public bool IsEnabled { get; } = rule.IsEnabled;
    public string Created { get; } = rule.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

    /// <summary>
    /// Only surfaced when the binary changed. "match" is the normal case and saying so
    /// on every row would bury the one line that matters.
    /// </summary>
    public string ExecutableWarning { get; } = rule.ExecutableState switch
    {
        "changed" => "⚠ executable changed since this rule was created",
        "unknown" => "",
        _ => "",
    };

    public bool HasWarning { get; } = rule.ExecutableState == "changed";
}

/// <summary>One capture session in the Capture tab.</summary>
public sealed class CaptureRow(CaptureSummary session)
{
    public long Id { get; } = session.Id;
    public string DisplayName { get; } = session.DisplayName;
    public string Directory { get; } = session.Directory;
    public bool IsRunning { get; } = session.IsRunning;
    public string Status { get; } = session.IsRunning ? "Capturing" : "Finished";
    public string Started { get; } = session.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string KeylogSize { get; } = Format.Bytes(session.KeylogBytes);

    public string? PcapFile { get; } = session.PcapFile;

    /// <summary>
    /// Em dash rather than "0 B" when nothing was recorded: a session with no capture at
    /// all is a different thing from one whose capture is empty, and the distinction is
    /// what tells the user whether Npcap is working.
    /// </summary>
    public string PcapSize { get; } =
        session.PcapFile is null ? "—" : Format.Bytes(session.PcapBytes);

    public bool HasPcap { get; } = session.PcapFile is not null;

    public bool HasKeys { get; } = session.KeylogBytes > 0;

    /// <summary>Whether there is anything to decode — packets and keys both.</summary>
    public bool CanDecode { get; } = session.PcapFile is not null;

    /// <summary>
    /// Surfaced only when something is actually wrong. A running capture with an empty
    /// keylog almost always means the application uses Schannel, which ignores the
    /// variable — far more useful to say than to leave the user waiting.
    ///
    /// The recording issue takes precedence: if packets are not being recorded, that
    /// explains more about what the user is looking at than the keylog does.
    /// </summary>
    public string Note { get; } = session switch
    {
        { RecordingIssue: { } issue } => issue,
        { KeylogSupport: "unlikely" } => "uses Windows TLS, which ignores SSLKEYLOGFILE",
        { IsRunning: true, KeylogBytes: 0, KeylogSupport: "unknown" } =>
            "no keys yet — may use Windows TLS",
        { IsRunning: false, KeylogBytes: 0 } => "no keys were written",
        _ => "",
    };
}

/// <summary>One destination in the Hosts tab.</summary>
public sealed class HostRow(HostSummary host)
{
    public string Host { get; } = host.Host;

    public string Traffic { get; } = Format.Traffic(host.BytesSent, host.BytesReceived);

    public string Total { get; } = Format.Bytes(host.BytesSent + host.BytesReceived);

    public string Connections { get; } = host.ActiveConnections == host.TotalConnections
        ? host.TotalConnections.ToString()
        : $"{host.ActiveConnections} / {host.TotalConnections}";

    /// <summary>
    /// The applications, with a count when there are several. A destination shared by
    /// unrelated programs is the thing this tab exists to surface, so the number comes
    /// first and the names follow.
    /// </summary>
    public string Applications { get; } = host.Applications.Count switch
    {
        0 => "",
        1 => host.Applications[0],
        _ => $"{host.Applications.Count}: {string.Join(", ", host.Applications)}",
    };

    public string Ports { get; } = string.Join(", ", host.Ports);

    /// <summary>
    /// The addresses, shown only when the host resolved to a name — otherwise the Host
    /// column already is the address and repeating it says nothing.
    /// </summary>
    public string Addresses { get; } =
        host.Addresses.Count == 1 && host.Addresses[0] == host.Host
            ? ""
            : string.Join(", ", host.Addresses);

    public string LastSeen { get; } = host.LastActiveUtc.ToLocalTime().ToString("HH:mm:ss");

    /// <summary>
    /// Matches the search box against everything the row shows. Address and application
    /// are included because "which app talks to this" and "who is at this IP" are both
    /// reasons to search here.
    /// </summary>
    public bool Matches(string needle) =>
        Host.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Applications.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Addresses.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Ports.Contains(needle, StringComparison.OrdinalIgnoreCase);
}

/// <summary>One recovered request and response in the Capture tab's request list.</summary>
public sealed class ExchangeRow(ExchangeSummary exchange)
{
    public string Method { get; } = exchange.Method;
    public string Url { get; } = exchange.Url;
    public string Protocol { get; } = exchange.Protocol;

    /// <summary>
    /// The status as text, so a request with no response reads as "—" rather than as a
    /// zero that looks like a real status code.
    /// </summary>
    public string Status { get; } = exchange.StatusCode?.ToString() ?? "—";

    public string ContentType { get; } = exchange.ContentType ?? "";

    public string Size { get; } = exchange.ResponseBytes == 0 && exchange.RequestBytes == 0
        ? "—"
        : Format.Traffic(exchange.RequestBytes, exchange.ResponseBytes);

    public string Duration { get; } = exchange.DurationMs switch
    {
        null => "—",
        < 1000 => $"{exchange.DurationMs:F0} ms",
        _ => $"{exchange.DurationMs.Value / 1000:F2} s",
    };

    public string Time { get; } = exchange.RequestedUtc.ToLocalTime().ToString("HH:mm:ss.fff");

    public string Note { get; } = exchange.Incomplete ?? "";

    /// <summary>
    /// Headers folded into one tooltip. The grid has no room for them as columns, and a
    /// request's headers are the thing a user drills into once rather than scans.
    /// </summary>
    public string Headers { get; } = BuildHeaders(exchange);

    private static string BuildHeaders(ExchangeSummary exchange)
    {
        var lines = new List<string> { $"{exchange.Method} {exchange.Url}" };
        lines.AddRange(exchange.RequestHeaders.Select(h => $"  {h.Name}: {h.Value}"));

        if (exchange.StatusCode is { } status)
        {
            lines.Add("");
            lines.Add($"{status}");
            lines.AddRange(exchange.ResponseHeaders.Select(h => $"  {h.Name}: {h.Value}"));
        }

        return string.Join('\n', lines);
    }
}

/// <summary>One connection in the drill-down table.</summary>
public sealed class FlowRow(FlowSummary flow)
{
    public string Protocol { get; } = flow.Protocol;
    public int ProcessId { get; } = flow.ProcessId;
    public string Local { get; } = $"{flow.LocalAddress}:{flow.LocalPort}";
    public string Remote { get; } = flow.RemoteHostname ?? flow.RemoteAddress;
    public int RemotePort { get; } = flow.RemotePort;
    public string State { get; } = flow.IsActive ? flow.State : $"{flow.State} (closed)";
    public string Traffic { get; } = Format.Traffic(flow.BytesSent, flow.BytesReceived);
    public bool IsActive { get; } = flow.IsActive;
}

internal static class Format
{
    public static string Traffic(long sent, long received) =>
        sent == 0 && received == 0 ? "—" : $"↑{Bytes(sent)} ↓{Bytes(received)}";

    public static string Bytes(long value) => value switch
    {
        < 1024 => $"{value} B",
        < 1024 * 1024 => $"{value / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{value / (1024.0 * 1024):F1} MB",
        _ => $"{value / (1024.0 * 1024 * 1024):F2} GB",
    };
}

public enum ConnectionState
{
    Unknown,
    Connecting,
    Connected,
    Unavailable,
    Error,
}
