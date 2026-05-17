using System.Net.Http;
using System.Text.Json;

namespace AuditGuardian.Desktop.Services;

public class ServerConnectionService
{
    private readonly HttpClient _http;
    private string _serverUrl = "";

    public ServerConnectionService()
    {
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    public string ServerUrl => _serverUrl;
    public bool IsConnected { get; private set; }
    public string LastMessage { get; private set; } = "";

    public void SetServerUrl(string url)
    {
        _serverUrl = url.TrimEnd('/');
        IsConnected = false;
        LastMessage = "";
    }

    public async Task<bool> TestConnectionAsync()
    {
        if (string.IsNullOrWhiteSpace(_serverUrl))
        {
            LastMessage = "未配置服务器地址";
            return false;
        }

        try
        {
            var response = await _http.GetAsync($"{_serverUrl}/api/health");
            IsConnected = response.IsSuccessStatusCode;
            LastMessage = IsConnected ? "连接成功" : $"服务器返回 {(int)response.StatusCode}";
            return IsConnected;
        }
        catch (TaskCanceledException)
        {
            LastMessage = "连接超时";
            IsConnected = false;
            return false;
        }
        catch (HttpRequestException ex)
        {
            LastMessage = $"无法连接: {ex.Message}";
            IsConnected = false;
            return false;
        }
    }

    /// <summary>
    /// Upload encrypted report to the audit server.
    /// </summary>
    public async Task<bool> UploadReportAsync(object report)
    {
        if (string.IsNullOrWhiteSpace(_serverUrl) || !IsConnected)
        {
            LastMessage = "服务器未连接";
            return false;
        }

        try
        {
            var json = JsonSerializer.Serialize(report);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{_serverUrl}/api/reports", content);
            LastMessage = response.IsSuccessStatusCode ? "上传成功" : $"上传失败: {response.StatusCode}";
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            LastMessage = $"上传错误: {ex.Message}";
            return false;
        }
    }
}
