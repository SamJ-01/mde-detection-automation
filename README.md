# MDE Custom Detections with Automated Response

> **Lab scope:** a lab exercise using synthetic data on a single scoped lab VM. No
> real organisation, device or credential appears anywhere in this repository.

Custom detection rules in Microsoft Defender for Endpoint, engineered with
automated response actions — device isolation and forensic investigation
package collection — and validated by live-triggering the target behaviour.

## Case Study: RCE Detection → Auto-Isolation

**Behaviour detected:** PowerShell downloading and silently executing a payload
(Invoke-WebRequest → Start-Process pattern in DeviceProcessEvents).
**Response on trigger:** device network isolation + investigation package collection.
**Validation:** executed the target behaviour on a scoped lab VM; device was
isolated before manual triage began; investigation package (process trees,
registry deltas, network connections, event logs) collected automatically.

## Engineering Notes

- **Scoping:** rule restricted to a named device — auto-isolation without careful
  scoping is a self-inflicted outage in production.
- **Detection vs response latency:** manual triage = minutes-to-hours; automated
  isolation = seconds. This changes what containment means.
- Also covered: VM onboarding to MDE, manual isolation/release workflow,
  investigation package analysis.

## Detections

| Detection | ATT&CK | Table | Severity | Automated action |
|---|---|---|---|---|
| [PowerShell download-and-execute](detections/powershell-download-execute.kql) | T1059.001, T1105 | DeviceProcessEvents | High | Isolate + investigation package |
| [LSASS credential dumping](detections/lsass-credential-dumping.kql) | T1003.001 | DeviceProcessEvents | High | Isolate + investigation package |
| [LOLBin proxy execution](detections/lolbin-proxy-execution.kql) | T1218 | DeviceProcessEvents | Medium | Investigation package only |
| [Rare outbound from a built-in tool](detections/rare-outbound-from-lolbin.kql) | T1105, T1071.001 | DeviceNetworkEvents | Medium | None (triage) |

Validation: the PowerShell download-and-execute rule is the one live-triggered in
the case study above. The other three are not yet validated against live telemetry.

Each rule returns `Timestamp`, `DeviceId` and `ReportId`, which Defender requires
before a custom detection can act on a device.

## Pipeline

Telemetry → custom detection → severity gate → isolation → investigation. The full
walk-through is in [docs/pipeline.md](docs/pipeline.md).

**Isolation is destructive**, so it is gated: only High-severity, low-noise rules
isolate automatically; Medium rules collect evidence and wait for an analyst.

## Automation script

[`automation/isolate_device.py`](automation/isolate_device.py) shows the same
response triggered from outside Defender (e.g. a Sentinel incident) through the
Defender for Endpoint API. It is **illustrative only**: authentication is a stub,
it defaults to a dry run, and it refuses to isolate unless the alert is High and a
named analyst approves.

```bash
cd automation
python isolate_device.py --alert sample_alert.json --approved-by "analyst.name"
# DRY RUN: would isolate device ...
```

Tests for the safety gates (no network calls): `pytest tests/`.

## Licence

[MIT](LICENSE)
