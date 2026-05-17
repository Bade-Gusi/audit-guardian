using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using AuditGuardian.Desktop.Models;
using AuditGuardian.Desktop.Services;

namespace AuditGuardian.Desktop;

public partial class MainWindow : Window
{
    private readonly string _serverUrl;
    private readonly HardwareService _hardware;
    private readonly EventLogService _eventLog;
    private readonly ScanService _scan;

    private HardwareData? _hardwareData;
    private List<TimelineEvent> _allEvents = new();
    private List<ScanFinding> _allFindings = new();
    private int _totalScanChecks;

    public MainWindow(string serverUrl)
    {
        InitializeComponent();
        _serverUrl = serverUrl;
        var runner = new CollectorRunner();
        _hardware = new HardwareService(runner);
        _eventLog = new EventLogService(runner);
        _scan = new ScanService();

        // Server URL is passed from LoginWindow - available via _serverUrl
    }

    // ==================== NAVIGATION ====================

    private void Nav_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Border border && border.Tag is string tag)
            SwitchPanel(tag);
    }

    private void SwitchPanel(string panel)
    {
        var navs = new[] { NavDashboard, NavHardware, NavTimeline, NavScan, NavReport, NavSettings };
        foreach (var n in navs)
        {
            n.Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));
            if (n.Child is Grid g && g.Children.Count > 1 && g.Children[1] is TextBlock tb)
                tb.Foreground = (SolidColorBrush)FindResource("BrTextSecondary");
        }

        PanelDashboard.Visibility = Visibility.Collapsed;
        PanelHardware.Visibility = Visibility.Collapsed;
        PanelTimeline.Visibility = Visibility.Collapsed;
        PanelScan.Visibility = Visibility.Collapsed;
        PanelReport.Visibility = Visibility.Collapsed;
        PanelSettings.Visibility = Visibility.Collapsed;

        Border activeNav = panel switch
        {
            "Dashboard" => NavDashboard,
            "Hardware" => NavHardware,
            "Timeline" => NavTimeline,
            "Scan" => NavScan,
            "Report" => NavReport,
            "Settings" => NavSettings,
            _ => NavDashboard
        };

        activeNav.Background = new SolidColorBrush(Color.FromArgb(0x15, 0x4F, 0x8C, 0xFF));
        if (activeNav.Child is Grid g2 && g2.Children.Count > 1 && g2.Children[1] is TextBlock tb2)
            tb2.Foreground = (SolidColorBrush)FindResource("BrAccent");

        switch (panel)
        {
            case "Dashboard": PanelDashboard.Visibility = Visibility.Visible; break;
            case "Hardware": PanelHardware.Visibility = Visibility.Visible; if (_hardwareData != null) PopulateHardwarePanel(); break;
            case "Timeline": PanelTimeline.Visibility = Visibility.Visible; ShowTimelineData(); break;
            case "Scan": PanelScan.Visibility = Visibility.Visible; ShowScanResults(); break;
            case "Report": PanelReport.Visibility = Visibility.Visible; break;
            case "Settings": PanelSettings.Visibility = Visibility.Visible; break;
        }
    }

    // ==================== DASHBOARD ====================

    private async void LoadHardware_Click(object sender, RoutedEventArgs e)
    {
        DashHardwareVal.Text = "加载中...";
        DashHardwareDesc.Text = "";
        try
        {
            _hardwareData = await Task.Run(() => _hardware.CollectHardwareDirect());
            var total = _hardwareData.Categories.Sum(c => c.Properties.Count);
            var spoofed = _hardwareData.Categories.SelectMany(c => c.Properties).Count(p => p.IsSpoofed);
            DashHardwareVal.Text = $"{total}项";
            DashHardwareVal.Foreground = spoofed > 0
                ? (SolidColorBrush)FindResource("BrYellow")
                : (SolidColorBrush)FindResource("BrTextPrimary");
            DashHardwareDesc.Text = spoofed > 0 ? $"{spoofed}项异常" : "所有硬件正常";
            PopulateHardwarePanel();
        }
        catch (Exception ex)
        {
            DashHardwareVal.Text = "失败";
            DashHardwareDesc.Text = ex.Message;
        }
    }

    private async void LoadEvents_Click(object sender, RoutedEventArgs e)
    {
        DashEventVal.Text = "加载中...";
        DashEventDesc.Text = "";
        try
        {
            var data = await Task.Run(() => _eventLog.CollectEventLogsDirect(7));
            _allEvents = data.Events;
            DashEventVal.Text = data.TotalEvents.ToString("N0");
            DashEventDesc.Text = $"过去7天，{data.Events.Count}条事件";
            ShowTimelineData();
        }
        catch (Exception ex)
        {
            DashEventVal.Text = "错误";
            DashEventDesc.Text = ex.Message;
        }
    }

    private async void LoadScan_Click(object sender, RoutedEventArgs e)
    {
        DashRiskVal.Text = "扫描中...";
        DashRiskDesc.Text = "";

        ScanProgressPanel.Visibility = Visibility.Visible;

        _scan.Progress += (p, s) => Dispatcher.Invoke(() =>
        {
            ScanProgressText.Text = s;
            ScanProgressPercent.Text = $"{p}%";
            ScanProgressFill.Width = p;
        });

        try
        {
            var result = await Task.Run(() => _scan.RunFullScanAsync());
            _allFindings = result.Findings;
            _totalScanChecks = result.TotalChecks;

            ScanProgressPanel.Visibility = Visibility.Collapsed;
            ScanResultsPanel.Visibility = Visibility.Visible;
            ScanFindingsPanel.Visibility = Visibility.Visible;

            ScanTotalFindings.Text = result.Findings.Count.ToString();
            ScanCriticalCount.Text = result.Summary?.Critical.ToString() ?? "0";
            ScanHighCount.Text = result.Summary?.High.ToString() ?? "0";
            ScanMediumCount.Text = result.Summary?.Medium.ToString() ?? "0";
            ScanPassCount.Text = (result.TotalChecks - result.Findings.Count).ToString("N0");

            ShowScanResults();

            DashRiskVal.Text = result.Findings.Count.ToString();
            DashRiskVal.Foreground = (SolidColorBrush)FindResource("BrYellow");
            DashRiskDesc.Text = $"{result.Summary?.High}高危 {result.Summary?.Medium}可疑";

            // Dashboard: real risk items from scan
            PopulateDashboardRisks(result.Findings);
        }
        catch (Exception ex)
        {
            ScanProgressPanel.Visibility = Visibility.Collapsed;
            DashRiskVal.Text = "错误";
            DashRiskDesc.Text = ex.Message;
        }
    }

    // ==================== HARDWARE ====================

    private void HardwareSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        PopulateHardwarePanel();
    }

    private void PopulateHardwarePanel()
    {
        if (_hardwareData == null)
        {
            HardwareItemsContainer.ItemsSource = null;
            HardwareCountText.Text = "0项 - 请先采集";
            return;
        }

        var search = HardwareSearchBox?.Text?.ToLower() ?? "";

        var items = _hardwareData.Categories.Select(cat =>
        {
            var filteredProps = string.IsNullOrWhiteSpace(search)
                ? cat.Properties
                : cat.Properties.Where(p =>
                    p.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    p.Value.Contains(search, StringComparison.OrdinalIgnoreCase)).ToList();

            return new
            {
                cat.Label,
                Status = cat.Properties.Any(p => p.IsSpoofed) ? "异常" : "正常",
                StatusColor = cat.Properties.Any(p => p.IsSpoofed) ? "#FBBF24" : "#34D399",
                Properties = filteredProps
            };
        }).ToList();

        var totalProps = items.Sum(i => i.Properties.Count);
        HardwareCountText.Text = $"{totalProps}项属性 - {_hardwareData.Categories.Count}类硬件";

        HardwareItemsContainer.ItemsSource = items;
    }

    // ==================== TIMELINE ====================

    private void TimelineSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        ShowTimelineData();
    }

    private void ShowTimelineData()
    {
        if (_allEvents.Count == 0)
        {
            EventLogContainer.ItemsSource = null;
            TimelineTotalEvents.Text = "0";
            TimelineProcesses.Text = "0";
            TimelineFiles.Text = "0";
            TimelineUsb.Text = "0";
            TimelineSystem.Text = "0";
            return;
        }

        var search = TimelineSearchBox?.Text?.ToLower() ?? "";
        var filtered = string.IsNullOrWhiteSpace(search)
            ? _allEvents
            : _allEvents.Where(e =>
                (e.Description ?? "").ToLower().Contains(search) ||
                (e.Source ?? "").ToLower().Contains(search) ||
                (e.UserName ?? "").ToLower().Contains(search)).ToList();

        var maxTake = 200;
        var displayItems = filtered.Take(maxTake).Select(e => new TimelineItemData
        {
            Description = string.IsNullOrWhiteSpace(e.Description)
                ? $"[{e.LogName}] Event {e.EventId}"
                : Truncate(e.Description, 150),
            Detail = $"{FormatTimestamp(e.Timestamp)}  |  {e.LogName}  |  EID: {e.EventId}  |  {e.Source}",
            SeverityColor = e.Level switch
            {
                "Error" => new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71)),
                "Warning" => new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
                _ => new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA))
            }
        }).ToList();

        TimelineTotalEvents.Text = filtered.Count.ToString("N0");
        TimelineProcesses.Text = filtered.Count(e => e.Description.Contains("进程", StringComparison.OrdinalIgnoreCase) || e.Source?.Contains("Process", StringComparison.OrdinalIgnoreCase) == true).ToString();
        // Simplified counts for other categories
        TimelineFiles.Text = filtered.Count(e => e.Source?.Contains("File", StringComparison.OrdinalIgnoreCase) == true).ToString();
        TimelineUsb.Text = filtered.Count(e => e.Source?.Contains("USB", StringComparison.OrdinalIgnoreCase) == true || e.Description.Contains("USB")).ToString();
        TimelineSystem.Text = filtered.Count(e => e.LogName == "System").ToString();

        EventLogContainer.ItemsSource = displayItems;

        if (filtered.Count > maxTake)
            TimelineNote.Text = $"显示前 {maxTake} 条，共 {filtered.Count} 条匹配结果";
        else
            TimelineNote.Text = $"共 {filtered.Count} 条事件";
    }

    // ==================== SCAN ====================

    private void ScanSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        ShowScanResults();
    }

    private void ShowScanResults()
    {
        if (_allFindings.Count == 0)
        {
            ScanFindingsContainer.ItemsSource = null;
            return;
        }

        var search = ScanSearchBox?.Text?.ToLower() ?? "";
        var filtered = string.IsNullOrWhiteSpace(search)
            ? _allFindings
            : _allFindings.Where(f =>
                f.Description.ToLower().Contains(search) ||
                f.Type.ToLower().Contains(search) ||
                f.MatchedRule.ToLower().Contains(search)).ToList();

        var items = filtered.Select(f => new ScanFindingItemData
        {
            SeverityLabel = f.Severity switch
            {
                "critical" => "严重", "high" => "高危", "medium" => "可疑", _ => "注意"
            },
            Type = f.Type,
            Description = f.Description,
            Meta = $"规则: {f.MatchedRule}  |  时间: {FormatTimestamp(f.FoundAt)}  |  状态: {f.Status}",
            BadgeBg = f.Severity switch
            {
                "critical" or "high" => "#F8717120",
                "medium" => "#FBBF2420",
                _ => "#4A557820"
            },
            BadgeFg = f.Severity switch
            {
                "critical" or "high" => "#F87171",
                "medium" => "#FBBF24",
                _ => "#8892B0"
            },
            BorderColor = f.Severity switch
            {
                "critical" or "high" => "#F87171",
                "medium" => "#FBBF24",
                _ => "#1E2A45"
            }
        }).ToList();

        ScanFindingsContainer.ItemsSource = items;
        ScanNote.Text = $"共 {filtered.Count} 条结果";
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        ScanProgressPanel.Visibility = Visibility.Visible;
        ScanResultsPanel.Visibility = Visibility.Collapsed;
        ScanFindingsPanel.Visibility = Visibility.Collapsed;

        _scan.Progress += (p, s) => Dispatcher.Invoke(() =>
        {
            ScanProgressText.Text = s;
            ScanProgressPercent.Text = $"{p}%";
            ScanProgressFill.Width = p;
        });

        try
        {
            var result = await Task.Run(() => _scan.RunFullScanAsync());
            _allFindings = result.Findings;
            _totalScanChecks = result.TotalChecks;

            ScanProgressPanel.Visibility = Visibility.Collapsed;
            ScanResultsPanel.Visibility = Visibility.Visible;
            ScanFindingsPanel.Visibility = Visibility.Visible;

            ScanTotalFindings.Text = result.Findings.Count.ToString();
            ScanCriticalCount.Text = result.Summary?.Critical.ToString() ?? "0";
            ScanHighCount.Text = result.Summary?.High.ToString() ?? "0";
            ScanMediumCount.Text = result.Summary?.Medium.ToString() ?? "0";
            ScanPassCount.Text = (result.TotalChecks - result.Findings.Count).ToString("N0");

            ShowScanResults();

            DashRiskVal.Text = result.Findings.Count.ToString();
            DashRiskVal.Foreground = (SolidColorBrush)FindResource("BrYellow");
            DashRiskDesc.Text = $"{result.Summary?.High}高危 {result.Summary?.Medium}可疑";

            // Dashboard: real risk items from scan
            PopulateDashboardRisks(result.Findings);
        }
        catch (Exception ex)
        {
            ScanProgressPanel.Visibility = Visibility.Collapsed;
            ScanProgressText.Text = $"扫描失败: {ex.Message}";
        }
    }

    private void PopulateDashboardRisks(List<ScanFinding> findings)
    {
        var riskItems = findings
            .Where(f => f.Severity == "critical" || f.Severity == "high" || f.Severity == "medium")
            .Take(10)
            .Select(f => new DashboardRiskItem
            {
                Description = f.Description,
                SeverityColor = f.Severity switch
                {
                    "critical" or "high" => (SolidColorBrush)FindResource("BrRed"),
                    _ => (SolidColorBrush)FindResource("BrYellow")
                }
            }).ToList();

        if (riskItems.Count > 0)
        {
            DashboardRiskContainer.ItemsSource = riskItems;
            DashboardRiskPanel.Visibility = Visibility.Visible;
        }
    }

    public class DashboardRiskItem
    {
        public string Description { get; set; } = "";
        public SolidColorBrush SeverityColor { get; set; } = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24));
    }

    // ==================== REPORT ====================

    private async void GenerateReport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ReportMachineInfo.Text = $"{Environment.MachineName}  |  {DateTime.Now:yyyy-MM-dd HH:mm}";

            var hardware = _hardwareData ?? await Task.Run(() => _hardware.CollectHardwareDirect());
            var events = _allEvents.Count > 0 ? _allEvents : (await Task.Run(() => _eventLog.CollectEventLogsDirect(7))).Events;
            var findings = _allFindings.Count > 0 ? _allFindings : (await Task.Run(() => _scan.RunFullScanAsync())).Findings;

            ReportTotalEvents.Text = events.Count.ToString("N0");
            ReportSuspiciousCount.Text = findings.Count.ToString();
            ReportHighCount.Text = findings.Count(f => f.Severity == "high" || f.Severity == "critical").ToString();

            var riskScore = Math.Min(100,
                findings.Count * 5 +
                findings.Count(f => f.Severity == "high") * 10 +
                findings.Count(f => f.Severity == "critical") * 20);

            ReportScoreText.Text = $"风险评分: {riskScore}";
            ReportScoreText.Foreground = riskScore switch
            {
                > 50 => (SolidColorBrush)FindResource("BrRed"),
                > 20 => (SolidColorBrush)FindResource("BrYellow"),
                _ => (SolidColorBrush)FindResource("BrGreen")
            };
        }
        catch (Exception ex)
        {
            MessageBox.Show($"生成报告失败: {ex.Message}", "错误");
        }
    }

    // ==================== SETTINGS ====================

    private async void SaveServerUrl_Click(object sender, RoutedEventArgs e)
    {
        // TODO: persist
        ServerStatusDot.Fill = (SolidColorBrush)FindResource("BrTextMuted");
        ServerStatusText.Text = "已保存，点击测试连接验证";
    }

    private async void TestConnection_Click(object sender, RoutedEventArgs e)
    {
        ServerStatusText.Text = "正在连接...";
        ServerStatusDot.Fill = (SolidColorBrush)FindResource("BrYellow");

        try
        {
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            var url = ServerUrlInput.Text.Trim().TrimEnd('/');
            var response = await http.GetAsync($"{url}/api/health");
            ServerStatusDot.Fill = response.IsSuccessStatusCode
                ? (SolidColorBrush)FindResource("BrGreen")
                : (SolidColorBrush)FindResource("BrRed");
            ServerStatusText.Text = response.IsSuccessStatusCode ? "连接成功" : $"返回 {(int)response.StatusCode}";
        }
        catch (Exception ex)
        {
            ServerStatusDot.Fill = (SolidColorBrush)FindResource("BrRed");
            ServerStatusText.Text = $"错误: {ex.Message}";
        }
    }

    private void ExampleUrl_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Border b && b.Tag is string url)
            ServerUrlInput.Text = url;
    }

    // ==================== HELPERS ====================

    private static string Truncate(string text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[..max] + "...";
    }

    private static string FormatTimestamp(string ts)
    {
        if (DateTime.TryParse(ts, out var dt))
            return dt.ToString("yyyy-MM-dd HH:mm:ss");
        return ts;
    }

    public class TimelineItemData
    {
        public string Description { get; set; } = "";
        public string Detail { get; set; } = "";
        public SolidColorBrush SeverityColor { get; set; } = new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA));
    }

    public class ScanFindingItemData
    {
        public string SeverityLabel { get; set; } = "";
        public string Type { get; set; } = "";
        public string Description { get; set; } = "";
        public string Meta { get; set; } = "";
        public string BadgeBg { get; set; } = "transparent";
        public string BadgeFg { get; set; } = "#8892B0";
        public string BorderColor { get; set; } = "#1E2A45";
    }
}
