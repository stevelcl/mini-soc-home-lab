# Incident Report 001: SSH Brute-Force Authentication Attack

## Summary

A controlled SSH brute-force attack was simulated from an attacker-controlled Kali Linux machine against an Ubuntu Linux endpoint within an isolated home lab environment. Using the password-cracking tool Hydra, 11 authentication attempts were made against a known username over a 10-password custom wordlist. The 11th attempt succeeded, granting the attacker a valid interactive SSH session. Wazuh, deployed as the lab's SIEM, detected and alerted on both the repeated authentication failures and the subsequent successful login, correctly correlating the failures into a single higher-severity brute-force detection and mapping the activity to MITRE ATT&CK technique T1110 (Brute Force).

This exercise validated the full detection pipeline — from endpoint log generation through SIEM correlation to analyst-visible alerting — and produced a realistic, evidence-backed incident for investigation practice.

---

## Environment

| Role | System | IP Address |
|---|---|---|
| Attacker | Kali Linux | 192.168.0.26 |
| Victim / Monitored Endpoint | Ubuntu Linux (hostname: `steve`) | 192.168.0.24 |
| SIEM / Wazuh Manager + Dashboard | Wazuh Server | 192.168.0.25 |

All systems reside on an isolated VirtualBox host-only/NAT network. No activity targeted any system outside this lab.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 00:11:25 | Hydra brute-force attack initiated from Kali against Ubuntu SSH service |
| 00:11:30.734 | First failed SSH authentication alert recorded in Wazuh |
| 00:11:30 – 00:11:34 | 11 total failed authentication attempts recorded |
| 00:11:34.774 | Successful SSH authentication — correct password found |
| 00:11:35 | Hydra reports attack complete, 1 valid credential found |

**Total time to compromise: ~4 seconds** from first failed attempt to successful login (10-second total tool runtime).

---

## Attack Details

- **Technique:** Dictionary-based brute-force attack against SSH (password guessing)
- **Tool used:** Hydra v9.7
- **Target service:** OpenSSH server (port 22)
- **Target username:** `vboxuser`
- **Wordlist:** Custom 10-entry password list (mix of common weak passwords, including the correct credential)
- **Command used:**
  ```
  hydra -l vboxuser -P custom-list.txt -t 4 ssh://192.168.0.24
  ```
- **Result:** 11 attempts recorded, 1 successful authentication

---

## Detection & Evidence

### Alert 1 — Repeated Authentication Failures (Correlated Brute-Force Detection)

| Field | Value |
|---|---|
| Rule ID | 2502 |
| Rule Level | 10 |
| Rule Description | `syslog: User missed the password more than one time` |
| Rule Groups | `authentication_failed`, `syslog`, `access_control` |
| MITRE ATT&CK Technique | T1110 — Brute Force |
| Source IP | 192.168.0.26 |
| Destination User | vboxuser |

**How this rule works:** Rule 2502 does not independently count failed attempts over time. It pattern-matches on the phrase `"more authentication failures"` / `"REPEATED login failures"`, which Linux's own PAM/sshd authentication subsystem writes into the log once it internally observes repeated failures on the same connection. Wazuh recognizes this specific phrasing and escalates the event to severity level 10, mapping it to MITRE T1110.

### Alert 2 — Individual Failed Authentication Events

| Field | Value |
|---|---|
| Rule Description | `sshd: authentication failed.` |
| Rule Level | 5 |
| Rule Groups | `syslog`, `sshd`, `authentication_failed` |
| MITRE ATT&CK Technique | Password Guessing, SSH |
| Count (this incident) | 11 |

### Alert 3 — Successful Authentication

| Field | Value |
|---|---|
| Rule Description | `PAM: Login session opened.` / `sshd: authentication success.` |
| Rule Level | 3 |
| Rule Groups | `pam`, `syslog`, `authentication_success` |
| MITRE ATT&CK Technique | T1078 — Valid Accounts |
| Source IP | 192.168.0.26 |
| Destination User | vboxuser |

**Analyst note:** Despite the ultimately successful login appearing at a lower default severity (level 3) than the failed-attempt correlation alert (level 10), it is the more consequential event — the attacker now holds a valid, legitimately-authenticated session that will blend in with normal account activity. MITRE classifies T1078 (Valid Accounts) under the **Defense Evasion** and **Initial Access/Persistence** tactics specifically because authenticated access using real credentials is harder to distinguish from legitimate use than noisy failed attempts. Severity scoring alone should not be the sole driver of investigative priority.

---

## Analysis — Is This Malicious?

Yes. The following indicators, taken together, are consistent with malicious brute-force activity rather than legitimate user error:

1. **Volume and speed:** 11 authentication attempts against a single account within approximately 4 seconds — far exceeds any plausible human typing/retry pace.
2. **Tooling signature:** Activity matches the known behavioral pattern of an automated credential-testing tool (Hydra), corroborated by the source host (Kali Linux) and the rapid, evenly-paced request timing.
3. **No other SSH activity in the environment:** Review of the surrounding 24-hour window showed no other SSH authentication traffic outside the two deliberate test windows, ruling out coincidental overlap with legitimate traffic.
4. **Outcome:** Attack culminated in a successful authentication, indicating the targeted account was using a weak, guessable password.

*(Note: this incident was a deliberate, authorized simulation within the author's own lab. In a real environment, this evidence pattern would be treated as a confirmed brute-force compromise.)*

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Defense Evasion / Initial Access | Valid Accounts | T1078 |

---

## Recommended Response & Containment

1. **Immediate:** Force a password reset on the `vboxuser` account; enforce a strong password policy (minimum length, complexity, no dictionary words).
2. **Short-term:** Implement `fail2ban` or equivalent on the Ubuntu endpoint to automatically block source IPs after a defined number of failed SSH attempts within a time window.
3. **Short-term:** Disable SSH password authentication in favor of SSH key-based authentication (`PasswordAuthentication no` in `sshd_config`).
4. **Medium-term:** Restrict SSH access at the network layer (firewall rules / security groups) to only known, trusted source IP ranges.
5. **Medium-term:** Enable Wazuh's Active Response module to automatically block an offending source IP in real time when rule 2502 (or similar high-severity auth-failure rules) fires.
6. **Ongoing:** Review Wazuh alerts for rule 2502 and related SSH authentication rules on a recurring basis as part of routine SOC monitoring.

---

## Evidence Collected

- Wazuh Discover query results (`wazuh-alerts-*`, filtered on `sshd` and source IP `192.168.0.26`)
- Rule definition source: `/var/ossec/ruleset/rules/0020-syslog_rules.xml`, rule ID 2502
- Hydra tool output confirming attack execution and successful credential discovery
- Screenshots of Wazuh Dashboard alert views (see `/screenshots`)

---

## Lessons Learned / Notes for Detection Engineering

- Wazuh's default ruleset detected this attack out-of-the-box, with no custom rule authoring required — demonstrating the value of a well-maintained default detection baseline.
- Rule 2502's correlation logic relies on upstream log content generated by PAM/sshd itself rather than independent event counting by Wazuh — understanding this distinction is important for accurately explaining *why* an alert fired.
- A single successful login alert, while lower severity by default, represented the more significant outcome of this incident. Future dashboards/triage workflows for this lab should avoid relying on severity level alone to prioritize investigation.
