using System.Diagnostics;
using System.Text.Json;

namespace AuditGuardian.Desktop.Services;

/// <summary>
/// Runs native collector EXEs and parses their JSON output.
/// </summary>
public class CollectorRunner
{
    private readonly string _collectorsDir;

    public CollectorRunner()
    {
        // Look for collectors next to the app, or in a known build path
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _collectorsDir = Path.Combine(baseDir, "..", "..", "..", "..", "..", "client", "native");
        if (!Directory.Exists(_collectorsDir))
            _collectorsDir = baseDir; // fallback to app dir
    }

    public event Action<int, string>? Progress;

    public async Task<T> RunCollectorAsync<T>(string exeRelativePath, string arguments = "")
    {
        var exePath = FindCollectorExe(exeRelativePath);
        if (exePath == null)
            throw new FileNotFoundException($"Collector not found: {exeRelativePath}");

        var tcs = new TaskCompletionSource<(int exitCode, string stdout, string stderr)>();
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
            EnableRaisingEvents = true
        };

        var stdout = new List<string>();
        var stderr = new List<string>();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) stdout.Add(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                stderr.Add(e.Data);
                TryReportProgress(e.Data);
            }
        };
        process.Exited += (_, _) =>
        {
            tcs.TrySetResult((process.ExitCode, string.Join("\n", stdout), string.Join("\n", stderr)));
            process.Dispose();
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var timeout = TimeSpan.FromSeconds(60);
        var completed = Task.WhenAny(tcs.Task, Task.Delay(timeout));
        if (await completed != tcs.Task)
        {
            process.Kill();
            throw new TimeoutException($"Collector {exeRelativePath} timed out after 60s");
        }

        var result = await tcs.Task;
        if (result.exitCode != 0)
            throw new Exception($"Collector failed (exit {result.exitCode}): {result.stderr}");

        var json = result.stdout;
        if (string.IsNullOrWhiteSpace(json))
            throw new Exception("Collector returned empty output");

        return JsonSerializer.Deserialize<T>(json) ?? throw new Exception("Failed to parse collector output");
    }

    private string? FindCollectorExe(string relative)
    {
        string[] searchPaths =
        {
            Path.Combine(_collectorsDir, relative),
            Path.Combine(_collectorsDir, relative.Replace("/", "\\")),
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relative),
        };

        // Also search in common build output paths
        var projectRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", "..", ".."));
        searchPaths = searchPaths.Concat(new[]
        {
            Path.Combine(projectRoot, "client", "native", relative.Replace("\\", "/")),
            Path.Combine(projectRoot, "client", "native", relative),
        }).ToArray();

        // Try adding .exe
        foreach (var path in searchPaths)
        {
            var withExe = path.EndsWith(".exe") ? path : path + ".exe";
            if (File.Exists(withExe)) return withExe;
            if (File.Exists(path)) return path;
        }
        return null;
    }

    private void TryReportProgress(string line)
    {
        try
        {
            var json = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
            if (json != null && json.ContainsKey("progress"))
            {
                var progress = json["progress"].GetInt32();
                var status = json.ContainsKey("status") ? json["status"].GetString() ?? "" : "";
                Progress?.Invoke(progress, status);
            }
        }
        catch { /* not a progress JSON line */ }
    }
}
