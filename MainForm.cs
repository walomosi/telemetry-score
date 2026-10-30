using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.ServiceProcess;
using System.Windows.Forms;
using TelemetryScore.Core;
using System.Web.Script.Serialization;

namespace TelemetryScore
{
    public class MainForm : Form
    {
        private ScoreBreakdown _score;
        private List<int> _history = new List<int>();
        private string _csvFolder = "";
        private Button _btnAutoScan;
        private Button _btnPick;
        private Button _btnImportWireshark;
        private Button _btnDisable;
        private Label _lblFolder;
        private Panel _canvas;

        public MainForm()
        {
            Text = "Telemetry Score - Windows telemetry activity meter";
            Width = 820;
            Height = 660;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);

            _btnAutoScan = new Button();
            _btnAutoScan.Text = "Auto scan system";
            _btnAutoScan.Width = 130; _btnAutoScan.Height = 32;
            _btnAutoScan.Top = 12; _btnAutoScan.Left = 12;
            _btnAutoScan.BackColor = Color.LightSkyBlue;
            _btnAutoScan.Click += OnAutoScan;
            Controls.Add(_btnAutoScan);

            _btnPick = new Button();
            _btnPick.Text = "Pick NetAudit CSV";
            _btnPick.Width = 130; _btnPick.Height = 32;
            _btnPick.Top = 12; _btnPick.Left = 150;
            _btnPick.Click += OnPick;
            Controls.Add(_btnPick);

            _btnImportWireshark = new Button();
            _btnImportWireshark.Text = "Import Wireshark CSV";
            _btnImportWireshark.Width = 140; _btnImportWireshark.Height = 32;
            _btnImportWireshark.Top = 12; _btnImportWireshark.Left = 290;
            _btnImportWireshark.Click += OnImportWireshark;
            Controls.Add(_btnImportWireshark);

            _btnDisable = new Button();
            _btnDisable.Text = "Disable all found";
            _btnDisable.Width = 130; _btnDisable.Height = 32;
            _btnDisable.Top = 12; _btnDisable.Left = 440;
            _btnDisable.BackColor = Color.LightCoral;
            _btnDisable.Click += OnDisableAll;
            Controls.Add(_btnDisable);

            _lblFolder = new Label();
            _lblFolder.Text = "(no CSV folder - switch score only)";
            _lblFolder.Top = 20; _lblFolder.Left = 580;
            _lblFolder.Width = 220;
            _lblFolder.ForeColor = Color.DimGray;
            Controls.Add(_lblFolder);

            _canvas = new Panel();
            _canvas.Top = 56; _canvas.Left = 12;
            _canvas.Width = 780; _canvas.Height = 580;
            _canvas.BackColor = Color.White;
            _canvas.Paint += OnPaint;
            Controls.Add(_canvas);

            if (DetectWarp())
            {
                MessageBox.Show(this,
                    "Cloudflare WARP detected.\n\n" +
                    "WARP routes your traffic through Cloudflare, which means:\n" +
                    "  - Telemetry traffic measurements will include WARP overhead\n" +
                    "  - Microsoft endpoints may be seen via Cloudflare IPs\n" +
                    "  - Traffic score may look lower than real (WARP masks some endpoints)\n\n" +
                    "For accurate telemetry audit, disconnect WARP when scanning.",
                    "WARP detected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            LoadHistory();
        }

        private bool DetectWarp()
        {
            try
            {
                using (ServiceController sc = new ServiceController("CloudflareWARP"))
                {
                    if (sc.Status == ServiceControllerStatus.Running) return true;
                }
            }
            catch { }
            try
            {
                foreach (Process p in Process.GetProcessesByName("warp-cli")) return true;
            }
            catch { }
            return false;
        }

        private void OnAutoScan(object sender, EventArgs e)
        {
            _score = Core.TelemetryScore.Evaluate(_csvFolder);
            _history.Add(_score.Total);
            if (_history.Count > 30) _history.RemoveAt(0);
            SaveHistory();
            _canvas.Invalidate();
        }

        private string HistoryPath()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TelemetryScore");
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            return Path.Combine(dir, "history.json");
        }

        private void LoadHistory()
        {
            try
            {
                string p = HistoryPath();
                if (!File.Exists(p)) return;
                string json = File.ReadAllText(p);
                var ser = new JavaScriptSerializer();
                _history = ser.Deserialize<List<int>>(json);
            }
            catch { }
        }

        private void SaveHistory()
        {
            try
            {
                var ser = new JavaScriptSerializer();
                File.WriteAllText(HistoryPath(), ser.Serialize(_history));
            }
            catch { }
        }

        private void OnPick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    _csvFolder = fbd.SelectedPath;
                    _lblFolder.Text = _csvFolder;
                }
            }
        }

        private void OnImportWireshark(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "CSV files|*.csv";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    long msBytes = CountMicrosoftBytesFromWireshark(ofd.FileName);
                    MessageBox.Show(this, "Wireshark CSV imported.\nMicrosoft-related bytes: " + (msBytes / 1024) + " KB\nRe-run Auto scan to include this.");
                }
            }
        }

        private long CountMicrosoftBytesFromWireshark(string path)
        {
            long total = 0;
            try
            {
                foreach (string line in File.ReadAllLines(path))
                {
                    string lower = line.ToLower();
                    if (lower.Contains("microsoft") || lower.Contains("msft") ||
                        lower.Contains("telemetry") || lower.Contains("diag") ||
                        lower.Contains("windows.com") || lower.Contains("live.com"))
                    {
                        string[] cols = line.Split(',');
                        foreach (string c in cols)
                        {
                            long n;
                            if (long.TryParse(c.Trim(), out n) && n > 100 && n < 10000000)
                            {
                                total += n;
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
            return total;
        }

        private void OnDisableAll(object sender, EventArgs e)
        {
            if (MessageBox.Show(this, "This will apply all the disable commands (registry, services, scheduled tasks). Continue?",
                "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            string[] cmds = {
                @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"" /v AllowTelemetry /t REG_DWORD /d 0 /f",
                @"reg add ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"" /v Enabled /t REG_DWORD /d 0 /f",
                @"sc config DiagTrack start= disabled",
                @"sc stop DiagTrack",
                @"sc config dmwappushservice start= disabled",
                @"schtasks /change /tn ""\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"" /disable",
                @"schtasks /change /tn ""\Microsoft\Windows\Application Experience\ProgramDataUpdater"" /disable",
                @"schtasks /change /tn ""\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"" /disable",
                @"schtasks /change /tn ""\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"" /disable"
            };
            int ok = 0;
            foreach (string cmd in cmds)
            {
                try
                {
                    string[] parts = cmd.Split(new[] { ' ' }, 2);
                    ProcessStartInfo psi = new ProcessStartInfo(parts[0], parts[1]);
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.RedirectStandardOutput = true;
                    using (Process p = Process.Start(psi))
                    {
                        p.WaitForExit(8000);
                        if (p.ExitCode == 0) ok++;
                    }
                }
                catch { }
            }
            MessageBox.Show(this, "Applied " + ok + "/" + cmds.Length + " disable commands. Re-run Auto scan to see new score.");
            _score = Core.TelemetryScore.Evaluate(_csvFolder);
            _canvas.Invalidate();
        }

        private void OnPaint(object sender, PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            if (_score == null)
            {
                g.DrawString("Click 'Auto scan system' to evaluate.", new Font("Segoe UI", 12), Brushes.Gray, 220, 280);
                return;
            }

            int cx = 180, cy = 180, r = 120;
            Color scoreColor;
            if (_score.Total >= 70) scoreColor = Color.Firebrick;
            else if (_score.Total >= 40) scoreColor = Color.DarkOrange;
            else scoreColor = Color.ForestGreen;

            using (Pen p = new Pen(scoreColor, 12))
            {
                g.DrawEllipse(p, cx - r, cy - r, r * 2, r * 2);
            }
            string s = _score.Total.ToString();
            using (Font f = new Font("Segoe UI", 48f, FontStyle.Bold))
            {
                SizeF sz = g.MeasureString(s, f);
                g.DrawString(s, f, new SolidBrush(scoreColor), cx - sz.Width / 2, cy - sz.Height / 2 - 10);
            }
            g.DrawString("/ 100", new Font("Segoe UI", 10), Brushes.Gray, cx - 20, cy + 40);
            g.DrawString(_score.Summary, new Font("Segoe UI", 11), Brushes.Black, 60, 320);

            int bx = 380, by = 80;
            DrawBar(g, bx, by, "Switches (max 30)", _score.SwitchScore, 30);
            DrawBar(g, bx, by + 60, "Traffic (max 40)", _score.TrafficScore, 40);
            DrawBar(g, bx, by + 120, "Behavior (max 30)", _score.BehaviorScore, 30);

            g.DrawString("Suggestions:", new Font("Segoe UI", 10f, FontStyle.Bold), Brushes.Black, bx, 260);
            int yy = 290;
            foreach (string sug in _score.Suggestions)
            {
                g.DrawString("- " + sug, new Font("Segoe UI", 9.5f), Brushes.DimGray, bx, yy);
                yy += 24;
            }

            // History trend mini-chart at bottom
            if (_history.Count >= 2)
            {
                int hx = 60, hy = 480, hw = 680, hh = 60;
                g.DrawRectangle(Pens.LightGray, hx, hy, hw, hh);
                g.DrawString("Score history (last " + _history.Count + " scans):", new Font("Segoe UI", 8.5f), Brushes.Gray, hx, hy - 16);
                for (int i = 1; i < _history.Count; i++)
                {
                    int x1 = hx + (int)(hw * (i - 1) / (double)(_history.Count - 1));
                    int x2 = hx + (int)(hw * i / (double)(_history.Count - 1));
                    int y1 = hy + hh - (int)(hh * _history[i - 1] / 100.0);
                    int y2 = hy + hh - (int)(hh * _history[i] / 100.0);
                    g.DrawLine(Pens.SteelBlue, x1, y1, x2, y2);
                }
            }
        }

        private void DrawBar(Graphics g, int x, int y, string label, int val, int max)
        {
            g.DrawString(label, new Font("Segoe UI", 9.5f), Brushes.Black, x, y - 18);
            g.FillRectangle(Brushes.LightGray, x, y, 300, 18);
            int w = (int)(300.0 * val / max);
            Color c;
            if (val >= max * 0.7) c = Color.Firebrick;
            else if (val >= max * 0.4) c = Color.DarkOrange;
            else c = Color.ForestGreen;
            g.FillRectangle(new SolidBrush(c), x, y, w, 18);
            g.DrawString(val + " / " + max, new Font("Segoe UI", 9), Brushes.Black, x + 310, y);
        }
    }
}
