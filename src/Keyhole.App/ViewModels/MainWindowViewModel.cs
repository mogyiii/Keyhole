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
using Keyhole.App.Localization;
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

    /// <summary>
    /// The connection state as a word, translated.
    ///
    /// Separate from <see cref="State"/> because the enum still drives the status dot's
    /// colour, and an enum that has been turned into a sentence can no longer be switched
    /// on. Same split as <see cref="Theme"/> and <see cref="ThemeLabel"/>.
    /// </summary>
    public string StateLabel => State switch
    {
        ConnectionState.Connecting => Strings["StateConnecting"],
        ConnectionState.Connected => Strings["StateConnected"],
        ConnectionState.Unavailable => Strings["StateUnavailable"],
        ConnectionState.Error => Strings["StateError"],
        _ => Strings["StateUnknown"],
    };

    partial void OnStateChanged(ConnectionState value) => OnPropertyChanged(nameof(StateLabel));

    [ObservableProperty]
    private string _statusMessage = Loc.Current["StatusChecking"];

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
    /// Set when country and operator lookups are unavailable.
    ///
    /// Shown on the Hosts tab, where the empty columns are, rather than in the strip above
    /// the app list: it affects two columns and nothing else, and a permanent banner for
    /// an optional extra would be noise.
    /// </summary>
    [ObservableProperty]
    private string? _geoIpWarning;

    public bool HasGeoIpWarning => GeoIpWarning is not null;

    partial void OnGeoIpWarningChanged(string? value) =>
        OnPropertyChanged(nameof(HasGeoIpWarning));

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
    public string? CapabilityWarning =>
        Reasons.DescribeCapabilities(ByteCountingWarning, BlockingWarning);

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
            // Codes, rendered here rather than sentences composed by the service: the
            // interface exists in two languages, and the explanatory text is exactly
            // where a user needs their own.
            ByteCountingWarning = status.ByteCountingUnavailable;
            BlockingWarning = status.BlockingUnavailable;
            NpcapState = status.NpcapState;
            PacketCaptureWarning = Reasons.DescribeNpcap(status.NpcapState);
            GeoIpWarning = Reasons.Describe(status.GeoIpUnavailable, status.GeoIpDirectory);

            var apps = await _client.ListAppsAsync(cts.Token);
            MergeApps(apps);
            ApplyFilter();
            await LoadRulesAsync(cts.Token);
            await LoadThroughputAsync(cts.Token);
            await LoadHostsAsync(cts.Token);
            await LoadCapturesAsync(cts.Token);

            State = ConnectionState.Connected;
            StatusMessage = string.Format(Strings["StatusApps"], Apps.Count, ActiveConnections);

            if (SelectedApp is not null)
            {
                await LoadFlowsAsync(SelectedApp, cts.Token);
            }
        }
        catch (ServiceUnavailableException ex)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = string.Format(Strings["StatusServiceUnreachable"], ex.Message);
            Apps.Clear();
            Flows.Clear();
        }
        catch (ServiceCallException ex)
        {
            State = ConnectionState.Error;
            StatusMessage = string.Format(Strings["StatusServiceError"], ex.Code, ex.Message);
        }
        catch (OperationCanceledException)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = Strings["StatusServiceSilent"];
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

        (app.RequestedThemeVariant, Theme) = app.RequestedThemeVariant switch
        {
            var v when v == ThemeVariant.Dark => (ThemeVariant.Light, "light"),
            var v when v == ThemeVariant.Light => (ThemeVariant.Default, "auto"),
            _ => (ThemeVariant.Dark, "dark"),
        };

        PersistSettings();
    }

    /// <summary>
    /// "auto", "light" or "dark" — the value that goes in settings.json.
    ///
    /// Kept apart from the button's caption, which is translated. The two used to be one
    /// property, and localising it would have written "Sötét" into the settings file and
    /// lost the user's theme on the next start.
    /// </summary>
    [ObservableProperty]
    private string _theme = "auto";

    /// <summary>The button's caption, in the current language.</summary>
    public string ThemeLabel => Theme switch
    {
        "light" => Strings["ThemeLight"],
        "dark" => Strings["ThemeDark"],
        _ => Strings["ThemeAuto"],
    };

    partial void OnThemeChanged(string value) => OnPropertyChanged(nameof(ThemeLabel));

    private KeyholeSettings _settings = new();

    /// <summary>Set once at startup by the application, before the window is shown.</summary>
    public KeyholeSettings Settings
    {
        get => _settings;
        set
        {
            _settings = value;
            Theme = value.Theme;

            // Set before anything else reads a string: the rest of this method and the
            // first refresh both compose text, and they should do it in the right
            // language rather than in English and then again.
            Language = value.Language;
            Loc.Current.SetCulture(AppLanguage.Resolve(value.Language));

            MinimiseToTray = value.MinimiseToTray;
            ResolveHostnames = value.ResolveHostnames;
            RetentionDays = value.RetentionDays;
            MaxPcapMegabytes = value.MaxPcapMegabytes;
            StartWithWindows = StartupRegistration.IsEnabled();
        }
    }

    /// <summary>
    /// The interface's strings, in the language currently in force.
    ///
    /// Exposed so the view model can compose sentences in the user's language. The markup
    /// does not go through here — it binds to the same singleton directly, because a
    /// DataGrid column header has no data context to reach a view model through.
    /// </summary>
    public Loc Strings => Loc.Current;

    /// <summary>"auto", "en" or "hu".</summary>
    [ObservableProperty]
    private string _language = AppLanguage.Automatic;

    /// <summary>The label on the language button, in the language it will switch to showing.</summary>
    public string LanguageLabel => AppLanguage.Label(Language);

    partial void OnLanguageChanged(string value)
    {
        Loc.Current.SetCulture(AppLanguage.Resolve(value));

        OnPropertyChanged(nameof(LanguageLabel));

        // The labels that are computed from a stored value rather than bound to a resource
        // directly. Nothing else recomputes them: the stored value did not change, only
        // the language it is rendered in.
        OnPropertyChanged(nameof(ThemeLabel));
        OnPropertyChanged(nameof(StateLabel));
        OnPropertyChanged(nameof(CapabilityWarning));

        // Every row's text was built in the old language, so the lists have to be rebuilt
        // rather than merged: a row object caches its formatted strings at construction.
        _ = RefreshCommand.ExecuteAsync(null);

        PersistSettings();
    }

    /// <summary>
    /// Cycles the interface language the same way the theme button cycles themes.
    ///
    /// A button rather than a dropdown because there are three states and the current one
    /// is always visible on the button itself, which a collapsed dropdown is not.
    /// </summary>
    [RelayCommand]
    private void CycleLanguage()
    {
        var index = Array.IndexOf(AppLanguage.All, Language);
        Language = AppLanguage.All[(index + 1) % AppLanguage.All.Length];
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
            SettingsMessage = Strings["ActionStartupFailed"];
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
            Theme = Theme,
            Language = Language,
        };

        try
        {
            SettingsStore.Save(_settings);
            SettingsMessage = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Settings are a convenience; failing to save one must not break the session.
            SettingsMessage = string.Format(Strings["ActionSettingsSaveFailed"], ex.Message);
        }
    }

    [RelayCommand]
    private async Task BlockSelectedAsync()
    {
        if (SelectedApp?.ExecutablePath is not { } path)
        {
            LastActionMessage = Strings["ActionNoPath"];
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

            LastActionMessage = string.Format(Strings["ActionBlocked"], rule.DisplayName);
            await LoadRulesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            // Carries the real reason as a code — not elevated, file missing — so it is
            // phrased here. An unrecognised code shows as itself, which is something the
            // user can search for rather than nothing.
            LastActionMessage = Reasons.Describe(ex.Message);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = Strings["ActionBlockFailed"];
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

            LastActionMessage = string.Format(Strings["ActionUnblocked"], rule.DisplayName);
            await LoadRulesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            LastActionMessage = Reasons.Describe(ex.Message);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = Strings["ActionUnblockFailed"];
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
                "likely" => string.Format(
                    Strings["ActionCaptureStarted"], session.DisplayName, session.KeylogFile),

                // Said up front rather than leaving the user watching a keylog that will
                // never grow. Windows' own curl.exe is the classic case.
                "unlikely" => string.Format(
                    Strings["ActionCaptureStartedSchannel"], session.DisplayName),

                _ => string.Format(
                    Strings["ActionCaptureStartedUnknown"], session.DisplayName),
            };

            await LoadCapturesAsync(cts.Token);
        }
        catch (ServiceCallException ex)
        {
            LastActionMessage = Reasons.Describe(ex.Message);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            LastActionMessage = Strings["ActionCaptureStartFailed"];
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

            LastActionMessage = string.Format(Strings["ActionCaptureStopped"], capture.DisplayName);
            await LoadCapturesAsync(cts.Token);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            LastActionMessage = Strings["ActionCaptureStopFailed"];
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
        DecodeSummary = string.Format(Strings["DecodeInProgress"], capture.DisplayName);

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

            DecodeSummary = SummariseDecode(result);
        }
        catch (ServiceCallException ex)
        {
            DecodeSummary = Reasons.Describe(ex.Message);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or OperationCanceledException)
        {
            DecodeSummary = Strings["DecodeNoAnswer"];
        }
        finally
        {
            IsDecoding = false;
        }
    }

    /// <summary>
    /// Builds the line above the request list, in the current language.
    ///
    /// Composed here rather than by the service, from the counts it sends. That is the
    /// whole reason every decode outcome has to land in one of those counts: the sentence
    /// is assembled from numbers, so a bucket nobody counts is a clause nobody can write.
    ///
    /// The failures matter as much as the results. A capture of a Schannel application
    /// yields nothing and that is expected; one full of QUIC yields nothing for an
    /// entirely different reason. "0 requests" for both would make the feature look broken
    /// in one case and working in the other, when the truth is the reverse.
    /// </summary>
    private string SummariseDecode(DecodeCaptureResponse result)
    {
        if (result.Failure is { } failure)
        {
            return Reasons.Describe(failure);
        }

        var parts = new List<string>
        {
            result.Exchanges.Count == 1
                ? Strings["DecodeOneRequest"]
                : string.Format(Strings["DecodeRequests"], result.Exchanges.Count),
        };

        if (result.Decrypted > 0)
        {
            parts.Add(string.Format(
                Strings["DecodeDecrypted"], result.Decrypted, result.Conversations));
        }
        else if (result.Conversations > 0)
        {
            parts.Add(string.Format(Strings["DecodeNoneDecrypted"], result.Conversations));
        }

        if (result.EncryptedWithoutKeys > 0)
        {
            parts.Add(string.Format(Strings["DecodeNoKeys"], result.EncryptedWithoutKeys));
        }

        if (result.HandshakeMissing > 0)
        {
            parts.Add(string.Format(Strings["DecodeNoHandshake"], result.HandshakeMissing));
        }

        if (result.DecryptionFailed > 0)
        {
            parts.Add(string.Format(Strings["DecodeFailedCount"], result.DecryptionFailed));
        }

        if (result.QuicBytes > 0)
        {
            parts.Add(string.Format(Strings["DecodeQuic"], result.QuicBytes / 1024));
        }

        if (result.Truncated > 0)
        {
            parts.Add(string.Format(Strings["DecodeTruncated"], result.Truncated));
        }

        return string.Join("; ", parts) + ".";
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
            LastActionMessage = Strings["ActionNoPcap"];
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
                LastActionMessage = string.Format(
                    Strings["ActionOpenedWithDefault"], Path.GetFileName(pcap));
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = wireshark,
                Arguments = $"-r \"{pcap}\"",
                UseShellExecute = false,
            });

            LastActionMessage = capture.HasKeys
                ? Strings["ActionOpenedInWireshark"]
                : Strings["ActionOpenedInWiresharkNoKeys"];
        }
        catch (Exception ex)
        {
            LastActionMessage = string.Format(Strings["ActionOpenFailed"], ex.Message);
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
        PacketCaptureWarning = string.Format(
            Strings["NpcapDownloading"], NpcapInstallerFetch.PinnedVersion);

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
                PacketCaptureWarning = string.Format(
                    Strings["NpcapInstallerNotStarted"],
                    result.InstallerPath,
                    NpcapInstallerFetch.HomepageUri);

                return;
            }

            PacketCaptureWarning = Strings["NpcapInstallerRunning"];
        }
        catch (Exception ex)
        {
            PacketCaptureWarning = string.Format(
                Strings["NpcapFetchFailed"], ex.Message, NpcapInstallerFetch.HomepageUri);
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
            LastActionMessage = string.Format(Strings["ActionFolderOpenFailed"], capture.Directory);
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
        BlockedLabel = IsBlocked ? Loc.Current["BlockedLabel"] : "";

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
        "changed" => Loc.Current["RuleExecutableChanged"],
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
    public string Status { get; } =
        Loc.Current[session.IsRunning ? "CaptureStatusRunning" : "CaptureStatusFinished"];
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
        // The size limit is the one issue that needs a number, so it is the one that gets
        // the extra value. Everything else is a code on its own.
        { RecordingIssue: ReasonCodes.RecordingSizeLimit } =>
            Reasons.Describe(ReasonCodes.RecordingSizeLimit, session.SizeLimitMegabytes),
        { RecordingIssue: { } issue } => Reasons.Describe(issue),
        { KeylogSupport: "unlikely" } => Loc.Current["KeylogUnlikely"],
        { IsRunning: true, KeylogBytes: 0, KeylogSupport: "unknown" } =>
            Loc.Current["KeylogNoneYet"],
        { IsRunning: false, KeylogBytes: 0 } => Loc.Current["KeylogNoneWritten"],
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

    public string Country { get; } = Format.Country(host.Location);

    public string Operator { get; } = Format.Operator(host.Location);

    public string LocationDetail { get; } = Format.LocationDetail(host.Location);

    /// <summary>
    /// Matches the search box against everything the row shows. Address and application
    /// are included because "which app talks to this" and "who is at this IP" are both
    /// reasons to search here.
    /// </summary>
    public bool Matches(string needle) =>
        Host.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Applications.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Addresses.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Ports.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        // "Which hosts are in CN" and "what else is on Cloudflare" are both reasons to
        // search here, so the location is searchable as well as visible.
        Country.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
        Operator.Contains(needle, StringComparison.OrdinalIgnoreCase);
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

    public string Note { get; } = Reasons.Describe(exchange.Incomplete);

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

    public string Country { get; } = Format.Country(flow.Location);

    public string Operator { get; } = Format.Operator(flow.Location);

    /// <summary>The full country name and AS number, for the tooltip.</summary>
    public string LocationDetail { get; } = Format.LocationDetail(flow.Location);
}

internal static class Format
{
    /// <summary>
    /// The two-letter country code, or blank.
    ///
    /// Blank rather than "unknown": every private address and every machine without a
    /// GeoIP database would otherwise carry a placeholder, which is noise in a column
    /// meant to be scanned.
    /// </summary>
    public static string Country(EndpointLocation? location) =>
        location?.CountryCode ?? "";

    /// <summary>
    /// Who operates the network. Usually more telling than the country — "which company's
    /// network is this" answers more questions than "which country".
    /// </summary>
    public static string Operator(EndpointLocation? location) =>
        location?.Organisation ?? "";

    /// <summary>The full name and AS number, for a tooltip rather than a column.</summary>
    public static string LocationDetail(EndpointLocation? location)
    {
        if (location is null)
        {
            return "";
        }

        var parts = new List<string>(3);

        if (location.CountryName is { Length: > 0 } name)
        {
            parts.Add(name);
        }

        if (location.Organisation is { Length: > 0 } organisation)
        {
            parts.Add(organisation);
        }

        if (location.AutonomousSystemNumber is { } asn)
        {
            parts.Add($"AS{asn}");
        }

        return string.Join(" — ", parts);
    }

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
