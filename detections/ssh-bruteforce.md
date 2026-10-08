# Detection: SSH Brute-Force (Repeated Authentication Failures)

## Overview

This detection identifies SSH brute-force / password-guessing activity against a monitored Linux endpoint. It relies entirely on Wazuh's **default, out-of-the-box ruleset** — no custom rule authoring was required to catch this technique.

This document describes the detection logic itself: what triggers it, how it works under the hood, and its strengths and limitations. For a specific real-world example of this detection firing, see [`investigations/incident-001.md`](../investigations/incident-001.md).

---

## What This Detects

Repeated failed SSH authentication attempts against a single account, followed by (optionally) a successful login. This maps to adversaries attempting to gain initial access or compromise credentials through password guessing, dictionary attacks, or automated brute-force tooling (e.g., Hydra, Medusa, ncrack).

**MITRE ATT&CK Mapping:**

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Valid Accounts (on successful login) | T1078 | Defense Evasion / Initial Access / Persistence |

---

## Log Source & Pipeline

```
SSH authentication attempt
        │
        ▼
sshd / PAM (Linux authentication subsystem)
        │
        ▼
systemd-journald
        │
        ▼
Wazuh Agent  (<localfile><log_format>journald</log_format></localfile>)
        │
        ▼
Wazuh Manager — Analysis Engine (wazuh-analysisd)
        │
        ▼
Rule Match → Alert
        │
        ▼
Wazuh Dashboard
```

The monitored endpoint's Wazuh agent is configured to ingest `journald` directly (rather than relying solely on the legacy `/var/log/auth.log` text file), which is the modern logging subsystem on current Linux distributions. `auth.log` itself is maintained by `rsyslog` as a secondary text mirror of a subset of journal data.

---

## Detection Rules Involved

### Rule 5716 (or equivalent base rule) — Individual Failed Authentication

A single failed SSH login attempt. Low severity on its own — one failed login is not inherently suspicious (users mistype passwords regularly).

| Field | Value |
|---|---|
| Rule Level | 5 |
| Rule Groups | `syslog`, `sshd`, `authentication_failed` |
| Description | `sshd: authentication failed.` |

### Rule 2502 — Repeated Authentication Failures (Correlated / Escalated)

```xml
<rule id="2502" level="10">
  <match>more authentication failures|REPEATED login failures</match>
  <description>syslog: User missed the password more than one time</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Source: `/var/ossec/ruleset/rules/0020-syslog_rules.xml`

**How it actually works:** This rule does not independently count discrete failed-login events over a time window the way a typical correlation rule might. Instead, it performs a **text pattern match** against the content of a single log line. Linux's own PAM/sshd authentication stack internally tracks repeated failures on a connection and, once a threshold is reached, writes a log entry containing wording such as *"more authentication failures"*. Wazuh's rule 2502 recognizes that specific phrase and escalates the event to severity level 10, with an explicit MITRE T1110 mapping.

**Practical implication:** The "correlation" here is effectively performed upstream by the OS authentication subsystem itself, not by Wazuh's own statistical/frequency engine. This is an important distinction when explaining *why* this alert fired — it's a log-content match, not a Wazuh-side sliding-window count.

### Successful Login Alerts (PAM / sshd)

| Field | Value |
|---|---|
| Description | `PAM: Login session opened.` / `sshd: authentication success.` |
| Rule Level | 3 |
| Rule Groups | `pam`, `syslog`, `authentication_success` |
| MITRE Technique | T1078 — Valid Accounts |

Note the relatively low default severity (level 3) compared to the failed-attempt correlation alert (level 10). A successful login following a burst of failures is the more consequential event from an investigative standpoint, even though it scores lower by default — analysts should not rely on severity level alone when this pattern (failures → success, same source) is present.

---

## Detection Strengths

- Works immediately with Wazuh's default ruleset — no tuning needed to catch basic brute-force attempts
- Captures both the attack attempt (failures) and the outcome (success/failure) as separate, correlatable events
- Native MITRE ATT&CK mapping built into the rule definitions
- Source IP, destination user, and timestamps are all captured per event, enabling fast triage

## Detection Limitations / Considerations

- Rule 2502 depends on the OS authentication layer (PAM/sshd) generating a specific log phrase — it is reactive to what the OS already decided to log, not an independently tunable frequency/threshold rule within Wazuh itself.
- A sufficiently slow/low-and-slow brute-force (long delays between attempts) may not trigger the same "repeated failures" phrasing from PAM, potentially evading this specific rule even though the activity is still malicious.
- This detection identifies the attempt and outcome, but does not by itself block the activity. Pairing with Wazuh Active Response (or an external control such as `fail2ban`) would be required for automated containment.

## Recommended Hardening / Follow-up Detections

- Enable Wazuh Active Response to automatically block source IPs that trigger rule 2502
- Pair with a network-layer control (firewall / security group restrictions on SSH source IPs)
- Consider disabling SSH password authentication entirely in favor of key-based auth, which would prevent this technique from succeeding regardless of detection
- Extend monitoring to detect low-and-slow brute-force patterns (e.g., custom frequency-based rule counting failures per source IP over a longer window, independent of the PAM log phrasing)
