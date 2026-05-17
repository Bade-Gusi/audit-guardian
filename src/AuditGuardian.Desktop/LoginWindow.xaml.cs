using System.Net.Http;
using System.Net.Http.Json;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace AuditGuardian.Desktop;

public partial class LoginWindow : Window
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    public LoginWindow()
    {
        InitializeComponent();
    }

    private async void TestConnection_Click(object sender, RoutedEventArgs e)
    {
        var url = ServerUrlBox.Text.Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(url) || (!url.StartsWith("https://") && !url.StartsWith("http://")))
        {
            ShowStatus("请输入有效的服务器地址（支持 HTTPS 和 IPv6）");
            return;
        }

        ShowLoading("正在测试连接...");
        try
        {
            var response = await _http.GetAsync($"{url}/api/health");
            HideLoading();
            if (response.IsSuccessStatusCode)
                ShowStatus("✅ 服务器连接成功", "#34D399");
            else
                ShowStatus($"❌ 服务器返回 {(int)response.StatusCode}");
        }
        catch (TaskCanceledException)
        {
            HideLoading();
            ShowStatus("⏱ 连接超时，请检查地址和网络");
        }
        catch (Exception ex)
        {
            HideLoading();
            ShowStatus($"❌ 无法连接: {ex.Message}");
        }
    }

    private async void Login_Click(object sender, RoutedEventArgs e)
    {
        var url = ServerUrlBox.Text.Trim().TrimEnd('/');
        var password = PasswordBox.Password;

        // Try server authentication if URL is provided
        if (!string.IsNullOrWhiteSpace(url) && (url.StartsWith("https://") || url.StartsWith("http://")))
        {
            if (string.IsNullOrEmpty(password))
            {
                ShowStatus("请输入密码");
                return;
            }

            ShowLoading("正在认证...");
            try
            {
                var response = await _http.PostAsJsonAsync($"{url}/api/auth/login",
                    new { username = "admin", password });

                if (response.IsSuccessStatusCode)
                {
                    HideLoading();
                    OpenMainWindow(url);
                    return;
                }
                else
                {
                    HideLoading();
                    ShowStatus("❌ 认证失败：用户名或密码错误");
                    return;
                }
            }
            catch (TaskCanceledException)
            {
                HideLoading();
                ShowStatus("⏱ 认证超时");
                return;
            }
            catch (Exception ex)
            {
                HideLoading();
                ShowStatus($"❌ 认证错误: {ex.Message}");
                return;
            }
        }

        // Local mode: any non-empty password
        if (string.IsNullOrEmpty(password))
        {
            ShowStatus("请输入密码或配置服务器");
            return;
        }

        OpenMainWindow("");
    }

    private void SkipLogin_Click(object sender, RoutedEventArgs e)
    {
        OpenMainWindow("");
    }

    private void Example_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Border b && b.Tag is string url)
            ServerUrlBox.Text = url;
    }

    private void OpenMainWindow(string serverUrl)
    {
        var main = new MainWindow(serverUrl);
        main.Show();
        Close();
    }

    private void ShowStatus(string msg, string color = "#F87171")
    {
        StatusText.Text = msg;
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        StatusText.Visibility = Visibility.Visible;
    }

    private void ShowLoading(string text)
    {
        LoadingPanel.Visibility = Visibility.Visible;
        LoadingText.Text = text;
        LoadingBar.Width = 0;
        // Animate the loading bar
        var timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        double progress = 0;
        timer.Tick += (s, _) =>
        {
            progress += 5;
            if (progress > 85) progress = 85;
            LoadingBar.Width = progress;
        };
        timer.Start();
    }

    private void HideLoading()
    {
        LoadingPanel.Visibility = Visibility.Collapsed;
    }
}
