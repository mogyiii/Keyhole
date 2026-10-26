using Keyhole.Core.Capture;
using Keyhole.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace Keyhole.Tests;

public class CaptureServiceTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _databaseFile =
        Path.Combine(Path.GetTempPath(), $"keyhole-capture-{Guid.NewGuid():n}.sqlite");

    /// <summary>Scoped to the test so throwaway sessions never land in the real capture folder.</summary>
    private readonly string _captureRoot =
        Path.Combine(Path.GetTempPath(), $"keyhole-captures-{Guid.NewGuid():n}");

    private KeyholeDatabase? _database;
    private CaptureService? _service;

    private CaptureService Service
    {
        get
        {
            if (_service is null)
            {
                _database = new KeyholeDatabase(_databaseFile);
                new MigrationRunner(_database).Migrate();
                _service = new CaptureService(
                    new SessionRepository(_database), logger: null, captureRoot: _captureRoot);
            }

            return _service;
        }
    }

    /// <summary>
    /// cmd.exe echoing the variable: a stand-in for any program that reads its own
    /// environment, which is exactly what an NSS or OpenSSL build does with SSLKEYLOGFILE.
    /// </summary>
    private static string Cmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");

    [Fact]
    public void Starting_a_capture_records_a_session()
    {
        var session = Service.Start(Cmd, "/c exit");

        Assert.True(session.Id > 0);
        Assert.Equal(Cmd, session.ExecutablePath);
        Assert.NotNull(session.ProcessId);
        Assert.True(Directory.Exists(session.Directory));
        output.WriteLine($"session {session.Id} in {session.Directory}");
    }

    [Fact]
    public async Task Launched_process_receives_the_keylog_variable()
    {
        // The whole point of this milestone: the target must see SSLKEYLOGFILE pointing
        // at this session's file, without it ever being set machine-wide.
        var probe = Path.Combine(Path.GetTempPath(), $"keyhole-probe-{Guid.NewGuid():n}.txt");

        var session = Service.Start(Cmd, $"/c echo %SSLKEYLOGFILE% > \"{probe}\"");

        await WaitForFileAsync(probe, TimeSpan.FromSeconds(15));

        var seen = (await File.ReadAllTextAsync(probe)).Trim();
        output.WriteLine($"child saw: {seen}");

        try
        {
            Assert.Equal(session.KeylogFile, seen);
        }
        finally
        {
            File.Delete(probe);
        }
    }

    [Fact]
    public async Task The_variable_does_not_leak_into_this_process_or_the_machine()
    {
        var before = Environment.GetEnvironmentVariable(CaptureService.KeylogVariable);

        Service.Start(Cmd, "/c exit");
        await Task.Delay(500);

        // The failure this guards against is the one that motivated the whole feature:
        // a global SSLKEYLOGFILE that every program picks up and nobody remembers to
        // unset. Setting it per-process means these must all stay empty.
        Assert.Equal(before, Environment.GetEnvironmentVariable(CaptureService.KeylogVariable));

        Assert.Null(Environment.GetEnvironmentVariable(
            CaptureService.KeylogVariable, EnvironmentVariableTarget.User));
        Assert.Null(Environment.GetEnvironmentVariable(
            CaptureService.KeylogVariable, EnvironmentVariableTarget.Machine));
    }

    [Fact]
    public async Task A_process_started_outside_the_capture_does_not_see_the_variable()
    {
        Service.Start(Cmd, "/c exit");
        await Task.Delay(500);

        // A sibling process launched normally must be unaffected, otherwise the capture
        // is not actually scoped to the one application the user chose.
        var probe = Path.Combine(Path.GetTempPath(), $"keyhole-sibling-{Guid.NewGuid():n}.txt");

        using (var sibling = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = Cmd,
            Arguments = $"/c echo %SSLKEYLOGFILE% > \"{probe}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        })!)
        {
            await sibling.WaitForExitAsync();
        }

        var seen = (await File.ReadAllTextAsync(probe)).Trim();
        output.WriteLine($"sibling saw: '{seen}'");

        try
        {
            // cmd echoes the literal name back when the variable is not set.
            Assert.Equal("%SSLKEYLOGFILE%", seen);
        }
        finally
        {
            File.Delete(probe);
        }
    }

    [Fact]
    public void Each_capture_gets_its_own_folder()
    {
        var first = Service.Start(Cmd, "/c exit");
        var second = Service.Start(Cmd, "/c exit");

        // Sharing a keylog between sessions would mix two applications' secrets into
        // one file and make neither decodable on its own.
        Assert.NotEqual(first.Directory, second.Directory);
        Assert.NotEqual(first.KeylogFile, second.KeylogFile);
    }

    [Fact]
    public void Starting_a_missing_executable_is_refused()
    {
        var ex = Assert.Throws<CaptureException>(() =>
            Service.Start(Path.Combine(Path.GetTempPath(), "definitely-not-here.exe")));

        Assert.Contains("No executable", ex.Message);
    }

    [Fact]
    public async Task Session_is_marked_stopped_when_the_application_exits()
    {
        var session = Service.Start(Cmd, "/c exit");

        var deadline = DateTime.UtcNow.AddSeconds(20);
        CaptureSession? latest = null;
        while (DateTime.UtcNow < deadline)
        {
            latest = Service.ListSessions().FirstOrDefault(s => s.Id == session.Id);
            if (latest is { IsRunning: false })
            {
                break;
            }

            await Task.Delay(200);
        }

        // Without this the UI would show a capture as live long after the user quit.
        Assert.NotNull(latest);
        Assert.False(latest.IsRunning);
        Assert.NotNull(latest.StoppedUtc);
    }

    [Fact]
    public void Stopping_a_session_twice_is_harmless()
    {
        var session = Service.Start(Cmd, "/c pause");

        Assert.True(Service.Stop(session.Id));
        Assert.False(Service.Stop(session.Id));
    }

    [Fact]
    public void Stopping_an_unknown_session_reports_false()
    {
        Assert.False(Service.Stop(9999));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Google\Chrome\chrome.exe", KeylogSupport.Likely)]
    [InlineData(@"C:\Program Files\Mozilla Firefox\firefox.exe", KeylogSupport.Likely)]
    [InlineData(@"C:\Program Files\BraveSoftware\brave.exe", KeylogSupport.Likely)]
    [InlineData(@"C:\tools\node.exe", KeylogSupport.Likely)]
    [InlineData(@"C:\MyApp\MyApp.exe", KeylogSupport.Unknown)]
    public void Keylog_support_is_guessed_from_the_executable(string path, KeylogSupport expected)
    {
        // A heuristic, not a promise — it exists so the UI can warn before a user waits
        // on a capture that was never going to produce anything.
        Assert.Equal(expected, CaptureService.SupportsKeylog(path));
    }

    [Fact]
    public void Windows_system_binaries_are_reported_as_unlikely()
    {
        // Measured, not assumed: `curl --version` on Windows reports Schannel, and a real
        // capture of the bundled curl.exe produced a zero-byte keylog. The name alone
        // says "curl", so without the path check the UI would promise keys it cannot get.
        Assert.Equal(KeylogSupport.Unlikely, CaptureService.SupportsKeylog(Cmd));
        Assert.Equal(
            KeylogSupport.Unlikely,
            CaptureService.SupportsKeylog(Path.Combine(Environment.SystemDirectory, "curl.exe")));
    }

    [Fact]
    public void A_browser_outside_the_windows_folder_is_still_likely()
    {
        // The system-folder rule must not swallow ordinary installs.
        Assert.Equal(
            KeylogSupport.Likely,
            CaptureService.SupportsKeylog(@"C:\Program Files\Google\Chrome\Application\chrome.exe"));
    }

    private static async Task WaitForFileAsync(string path, TimeSpan limit)
    {
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path) && new FileInfo(path).Length > 0)
            {
                return;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"{path} never appeared.");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                File.Delete(_databaseFile + suffix);
            }
            catch (IOException)
            {
                // A leaked handle must not mask a real failure.
            }
        }

        try
        {
            if (Directory.Exists(_captureRoot))
            {
                Directory.Delete(_captureRoot, recursive: true);
            }
        }
        catch (IOException)
        {
            // Same.
        }
    }
}
