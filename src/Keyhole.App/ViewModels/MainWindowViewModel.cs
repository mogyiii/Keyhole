using System;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keyhole.Core.Ipc;

namespace Keyhole.App.ViewModels;

/// <summary>
/// M1 shell: proves the UI can reach the privileged service and reports what it found.
/// The real dashboard replaces this in M3.
/// </summary>
public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly KeyholeServiceClient _client;

    public MainWindowViewModel(KeyholeServiceClient client)
    {
        _client = client;
        _ = RefreshAsync();
    }

    [ObservableProperty]
    private ConnectionState _state = ConnectionState.Unknown;

    [ObservableProperty]
    private string _statusMessage = "Checking the Keyhole service…";

    [ObservableProperty]
    private string? _serviceVersion;

    [ObservableProperty]
    private string? _serviceUptime;

    [ObservableProperty]
    private bool _serviceIsElevated;

    /// <summary>True while a refresh is in flight, so the button can disable itself.</summary>
    [ObservableProperty]
    private bool _isBusy;

    [RelayCommand]
    private async Task RefreshAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        State = ConnectionState.Connecting;
        StatusMessage = "Connecting to the Keyhole service…";

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var status = await _client.GetStatusAsync(cts.Token);

            ServiceVersion = status.Version;
            ServiceIsElevated = status.IsElevated;
            ServiceUptime = FormatUptime(DateTimeOffset.UtcNow - status.StartedAtUtc);

            State = ConnectionState.Connected;
            StatusMessage = status.IsElevated
                ? "Connected. Service is elevated and ready for monitoring."
                : "Connected, but the service is not elevated — monitoring and blocking will fail.";
        }
        catch (ServiceUnavailableException ex)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = $"Service unreachable: {ex.Message}";
            ClearServiceDetails();
        }
        catch (ServiceCallException ex)
        {
            State = ConnectionState.Error;
            StatusMessage = $"Service returned an error ({ex.Code}): {ex.Message}";
            ClearServiceDetails();
        }
        catch (OperationCanceledException)
        {
            State = ConnectionState.Unavailable;
            StatusMessage = "Service did not answer within 5 seconds.";
            ClearServiceDetails();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ClearServiceDetails()
    {
        ServiceVersion = null;
        ServiceUptime = null;
        ServiceIsElevated = false;
    }

    private static string FormatUptime(TimeSpan uptime) => uptime switch
    {
        { TotalSeconds: < 60 } => $"{uptime.TotalSeconds:F0}s",
        { TotalMinutes: < 60 } => $"{uptime.Minutes}m {uptime.Seconds}s",
        { TotalHours: < 24 } => $"{uptime.Hours}h {uptime.Minutes}m",
        _ => $"{uptime.Days}d {uptime.Hours}h",
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
