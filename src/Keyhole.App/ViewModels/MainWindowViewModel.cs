using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

            var apps = await _client.ListAppsAsync(cts.Token);
            MergeApps(apps);

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

    [ObservableProperty] private string _displayName = "";
    [ObservableProperty] private string? _publisher;
    [ObservableProperty] private string _signature = "";
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private int _totalConnections;
    [ObservableProperty] private string _traffic = "";
    [ObservableProperty] private string _remoteHosts = "";

    public void Update(AppSummary summary)
    {
        DisplayName = summary.DisplayName;
        Publisher = summary.Publisher;
        Signature = summary.Signature;
        ActiveConnections = summary.ActiveConnections;
        TotalConnections = summary.TotalConnections;
        Traffic = Format.Traffic(summary.BytesSent, summary.BytesReceived);
        RemoteHosts = string.Join(", ", summary.RecentRemoteHosts);
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
