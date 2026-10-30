# Telemetry Score

**Stop guessing whether Windows is still phoning home. Get a 0-100 score for how noisy your machine actually is.**

Most telemetry guides tell you to flip a few switches and call it a day. Telemetry Score measures what actually happens after: it combines registry switches, service states, scheduled tasks, and real traffic data into one number — so you can see if flipping switches actually changed anything.

No installer, no cloud, no telemetry of its own. One WinForms exe, .NET Framework 4.8.

---

## Why

"Disabled telemetry" is a claim, not a measurement. You can:

- set `AllowTelemetry = 0` and still see svchost talking to Microsoft endpoints
- stop DiagTrack and still have scheduled tasks fire every few hours
- block hosts entries and still have telemetry over UDP

Telemetry Score turns this into a score: 0 = quiet, 100 = noisy. Re-run it after changes and watch the number drop.

## Features

| | |
|---|---|
| **One-click score** | Scans registry, services, and scheduled tasks, then combines them with NetAudit CSV traffic data into a 0-100 score. |
| **Three sub-scores** | Switches (30) + Traffic (40) + Behavior (30) — see exactly which layer is still leaking. |
| **One-click disable** | Applies all 9 standard disable commands (registry, services, scheduled tasks) and re-scores to show the effect. |
| **WARP detection** | Warns you if Cloudflare WARP is running — it masks real traffic and skews the score. |
| **History trend** | Saves every scan locally and draws a mini trend chart so you can see if telemetry is going up or down over time. |
| **Third-party CSV import** | Reads Wireshark-exported CSV files as an extra traffic data source. |

## Quick start

```bash
# build (uses the in-box C# compiler)
build.cmd

# run (admin recommended for the disable button)
bin\TelemetryScore.exe
```

Click **Auto scan system** to get a score. Click **Disable all found** to apply the standard privacy commands. Click again to watch the score drop.

## Scoring model

- **Switches (0-30)**: `AllowTelemetry` value, Advertising ID, DiagTrack service state, enabled telemetry scheduled tasks.
- **Traffic (0-40)**: bytes seen going to Microsoft endpoints, from NetAudit CSV or Wireshark CSV.
- **Behavior (0-30)**: how often telemetry tasks fire, from CSV event counts.

## Positioning

Telemetry Score is a **privacy measurement tool** for your own machine. It tells you how noisy Windows is; it does not itself block traffic. Pair it with NetAudit for network-level blocking.

Not for: tampering with managed devices at work, or anything your sysadmin would not want changed.

## License

[MIT](LICENSE).

---

If this helps you actually quiet Windows down, a ⭐ is appreciated.
