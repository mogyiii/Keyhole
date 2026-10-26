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

    /// <summary>Points for the dashboard graph.</summary>
    [ObservableProperty]
    private IReadOnlyList<ChartPoint> _throughput = [];

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

    private void ApplyFilter()
    {
        var needle = SearchText.Trim();

        VisibleApps.Clear();
        foreach (var app in Apps)
        {
            if (needle.Length == 0 || app.Matches(needle))
            {
                VisibleApps.Add(app);
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

            var apps = await _client.ListAppsAsync(cts.Token);
            MergeApps(apps);
            ApplyFilter();
            await LoadRulesAsync(cts.Token);
            await LoadThroughputAsync(cts.Token);
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
            StartWithWindows = StartupRegistration.IsEnabled();
        }
    }

    [ObservableProperty] private bool _minimiseToTray = true;
    [ObservableProperty] private bool _resolveHostnames = true;
    [ObservableProperty] private int _retentionDays = 30;
    [ObservableProperty] private bool _startWithWindows;

    [ObservableProperty] private string? _settingsMessage;

    partial void OnMinimiseToTrayChanged(bool value) => PersistSettings();

    partial void OnResolveHostnamesChanged(bool value) => PersistSettings();

    partial void OnRetentionDaysChanged(int value) => PersistSettings();

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
            var flows = await _client.ListFlowsAsync(app.Key, includeClosed: true, ct);

            Flows.Clear();
            foreach (var flow in flows)
            {
                Flows.Add(new FlowRow(flow));
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCallException
                                      or OperationCanceledException)
        {
            // The outer refresh already reports connection problems; a failed drill-down
            // should not overwrite that with a second message.
            Flows.Clear();
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

    /// <summary>
    /// Surfaced only when something is actually wrong. A running capture with an empty
    /// keylog almost always means the application uses Schannel, which ignores the
    /// variable — far more useful to say than to leave the user waiting.
    /// </summary>
    public string Note { get; } = session switch
    {
        { KeylogSupport: "unlikely" } => "uses Windows TLS, which ignores SSLKEYLOGFILE",
        { IsRunning: true, KeylogBytes: 0, KeylogSupport: "unknown" } =>
            "no keys yet — may use Windows TLS",
        { IsRunning: false, KeylogBytes: 0 } => "no keys were written",
        _ => "",
    };
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
