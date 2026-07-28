# MDE Custom Detections with Automated Response

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
