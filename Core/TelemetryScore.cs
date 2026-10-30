using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;

namespace TelemetryScore.Core
{
    public class ScoreBreakdown
    {
        public int SwitchScore;    // 0-30
        public int TrafficScore;   // 0-40
        public int BehaviorScore;  // 0-30
        public int Total { get { return SwitchScore + TrafficScore + BehaviorScore; } }
        public string Summary;
        public List<string> Suggestions = new List<string>();
    }

    internal static class TelemetryScore
    {
        // Three sub-scores are independent: a user can flip switches (30) while traffic (40)
        // still leaks because hosts are blocked only at DNS, and behavior (30) can still fire.
        // Separating them makes the score actionable: the lowest sub-score tells you what to fix.
        public static ScoreBreakdown Evaluate(string netAuditCsvFolder)
        {
            var b = new ScoreBreakdown();

            // --- Switch score (0-30) ---
            b.SwitchScore += EvalAllowTelemetry();
            b.SwitchScore += EvalAdvertisingId();
            b.SwitchScore += EvalDiagTrack();
            b.SwitchScore += EvalScheduledTasks();

            // --- Traffic score (0-40) ---
            long microsoftBytes = ReadMicrosoftTraffic(netAuditCsvFolder);
            b.TrafficScore = BucketTraffic(microsoftBytes);

            // --- Behavior score (0-30) ---
            int telemetryHits = CountTelemetryHits(netAuditCsvFolder);
            b.BehaviorScore = BucketBehavior(telemetryHits);

            // --- Summary ---
            if (b.Total >= 70) b.Summary = "Noisy - this box phones home a lot.";
            else if (b.Total >= 40) b.Summary = "Moderate - some telemetry still active.";
            else b.Summary = "Quiet - telemetry appears well contained.";

            BuildSuggestions(b);
            return b;
        }

        private static int EvalAllowTelemetry()
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection"))
                {
                    object v = k == null ? null : k.GetValue("AllowTelemetry");
                    if (v == null) return 10; // default is Full
                    int level = Convert.ToInt32(v);
                    if (level == 3) return 10;
                    if (level == 1) return 5;
                    return 0;
                }
            }
            // Registry read can fail on locked-down machines; fall back to "default Full" which is the worst case
            catch { return 5; }
        }

        private static int EvalAdvertisingId()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"))
                {
                    object v = k == null ? null : k.GetValue("Enabled");
                    return (v != null && Convert.ToInt32(v) == 1) ? 5 : 0;
                }
            }
            // HKCU key may not exist on fresh installs; treat as disabled
            catch { return 0; }
        }

        private static int EvalDiagTrack()
        {
            try
            {
                using (ServiceController sc = new ServiceController("DiagTrack"))
                {
                    return sc.Status == ServiceControllerStatus.Running ? 8 : 0;
                }
            }
            // HKCU key may not exist on fresh installs; treat as disabled
            catch { return 0; }
        }

        private static int EvalScheduledTasks()
        {
            string[][] tasks = {
                new[] { @"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" },
                new[] { @"Microsoft\Windows\Application Experience\ProgramDataUpdater" },
                new[] { @"Microsoft\Windows\Customer Experience Improvement Program\Consolidator" },
                new[] { @"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" }
            };
            int enabled = 0;
            foreach (string[] t in tasks)
            {
                if (TaskExists(t[0])) enabled++;
            }
            return Math.Min(7, enabled * 2);
        }

        private static bool TaskExists(string path)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("schtasks", "/query /tn \"" + path + "\"");
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.CreateNoWindow = true;
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
                {
                    p.WaitForExit(5000);
                    return p.ExitCode == 0;
                }
            }
            // schtasks query failed (permissions/timeouts); assume task does not exist
            catch { return false; }
        }

        private static long ReadMicrosoftTraffic(string folder)
        {
            // Look for CSV files from NetAudit; sum bytes to microsoft-owned IPs/domains.
            // Heuristic: any row whose remote host contains known MS telemetry keywords.
            long total = 0;
            if (!Directory.Exists(folder)) return 0;
            string[] files = Directory.GetFiles(folder, "*.csv");
            foreach (string f in files)
            {
                try
                {
                    foreach (string line in File.ReadAllLines(f))
                    {
                        string lower = line.ToLower();
                        if (lower.Contains("telemetry") || lower.Contains("telemetry") ||
                            lower.Contains("microsoft") || lower.Contains("msft") ||
                            lower.Contains("diag") || lower.Contains("office") ||
                            lower.Contains("windows.com") || lower.Contains("live.com"))
                        {
                            // try to extract a number (bytes) at end of line
                            string[] cols = line.Split(',');
                            long n;
                            for (int i = cols.Length - 1; i >= 0; i--)
                            {
                                if (long.TryParse(cols[i].Trim(), out n) && n > 100)
                                {
                                    total += n;
                                    break;
                                }
                            }
                        }
                    }
                }
                // Skip malformed CSV rows; we only need byte totals, not per-row parsing
                catch { }
            }
            return total;
        }

        private static int BucketTraffic(long bytes)
        {
            if (bytes < 1L * 1024 * 1024) return 0;        // <1MB
            if (bytes < 10L * 1024 * 1024) return 10;       // 1-10MB
            if (bytes < 50L * 1024 * 1024) return 20;      // 10-50MB
            if (bytes < 200L * 1024 * 1024) return 30;     // 50-200MB
            return 40;
        }

        private static int CountTelemetryHits(string folder)
        {
            int hits = 0;
            if (!Directory.Exists(folder)) return 0;
            string[] files = Directory.GetFiles(folder, "*.csv");
            foreach (string f in files)
            {
                try
                {
                    foreach (string line in File.ReadAllLines(f))
                    {
                        string lower = line.ToLower();
                        if (lower.Contains("telemetry") || lower.Contains("diag") ||
                            lower.Contains("compatibility appraiser") || lower.Contains("ceip"))
                        {
                            hits++;
                        }
                    }
                }
                // Skip malformed CSV rows; we only need byte totals, not per-row parsing
                catch { }
            }
            return hits;
        }

        private static int BucketBehavior(int hits)
        {
            if (hits == 0) return 0;
            if (hits <= 5) return 10;
            if (hits <= 20) return 20;
            return 30;
        }

        private static void BuildSuggestions(ScoreBreakdown b)
        {
            if (b.SwitchScore > 15)
            {
                b.Suggestions.Add("Run Telemetry Audit and disable the enabled switches.");
            }
            if (b.TrafficScore >= 20)
            {
                b.Suggestions.Add("NetAudit is seeing steady traffic to Microsoft endpoints. Block known telemetry IPs via firewall.");
            }
            if (b.BehaviorScore >= 20)
            {
                b.Suggestions.Add("Scheduled telemetry tasks are firing often. Disable them in Task Scheduler.");
            }
            if (b.Suggestions.Count == 0)
            {
                b.Suggestions.Add("No action needed. Keep monitoring.");
            }
        }
    }
}
