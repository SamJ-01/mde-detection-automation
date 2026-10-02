# Detection-to-isolation pipeline

> **Lab scope:** synthetic data and a single lab device. Nothing here is connected
> to a live tenant.

This page follows one alert from the attacker's command to an isolated device.

## 1. Telemetry

The Defender for Endpoint sensor on the device records every process start in
`DeviceProcessEvents` (command line, parent process, account, file hashes) and
every network connection in `DeviceNetworkEvents`.

## 2. Detection

A **custom detection rule** is a saved advanced-hunting query that Defender runs on
a schedule (here, every hour). When it returns rows, each row becomes an alert. The
query must return `Timestamp`, `DeviceId` and `ReportId` so the alert can be tied to
the device and the exact event. The rules are in [`../detections/`](../detections/).

## 3. Decision: should this isolate automatically?

Isolation is destructive: the device loses all network access except to Defender.
It is therefore gated:

| Rule | Severity | Automated action |
|---|---|---|
| PowerShell download-and-execute | High | Isolate + collect investigation package |
| LSASS credential dumping | High | Isolate + collect investigation package |
| LOLBin proxy execution | Medium | Collect investigation package only |
| Rare outbound from a built-in tool | Medium | None (triage) |

Only High-severity rules with a low false-positive rate isolate. Everything else
gathers evidence and waits for a person.

## 4. Response

There are two ways to carry out the response:

1. **Built into the rule (used in the lab case study).** The custom detection's
   *Automated actions* setting isolates the device and collects the investigation
   package as soon as the rule fires: no code needed.
2. **From another pipeline.** When the trigger comes from somewhere else (a
   Sentinel incident, a SOAR playbook), [`../automation/isolate_device.py`](../automation/isolate_device.py)
   calls the Defender API (`POST /api/machines/{id}/isolate`). It runs as a dry
   run by default and refuses to act unless the alert is High severity and a named
   analyst has approved it.

## 5. After isolation

1. Review the investigation package (process tree, autoruns, network connections,
   event logs).
2. Decide: false positive → release from isolation and tune the rule; true
   positive → contain, eradicate and recover.
3. Release the device only once the cause is understood and removed.

## Why scoping matters

The lab rule was limited to one named device. An untuned auto-isolation rule run
across a whole estate can take down many machines at once on a single false
positive: a self-inflicted outage.
