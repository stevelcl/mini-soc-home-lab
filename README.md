# Mini SOC Home Lab

A hands-on home lab built to practice real-world SOC (Security Operations Center) analyst skills — SIEM deployment, endpoint log collection, detection engineering, alert triage, and incident investigation — using Wazuh as the SIEM platform.

This is not a "I installed a SIEM" project. It walks through the full detection lifecycle: generating real attacker activity, collecting the resulting logs, detecting it with correlation rules, investigating the alert like an analyst, and mapping the activity to MITRE ATT&CK.

---

## Project Goals

- Deploy and operate a SIEM (Wazuh) in a realistic, isolated lab environment
- Collect and forward endpoint security logs from a monitored host
- Simulate a real attack technique (SSH brute-force) against a target in the lab
- Detect that activity using the SIEM's correlation rules
- Investigate the resulting alert using an evidence-based, analyst-style process
- Map observed activity to MITRE ATT&CK techniques
- Document findings the way a SOC analyst would in a real incident report

---

## Lab Architecture

```
Attacker VM (Kali Linux)
        │
        │  Simulated SSH brute-force attack
        ▼
Victim VM (Ubuntu Linux)
        │
        │  Authentication logs (journald / auth.log)
        ▼
Wazuh Agent  (installed on victim)
        │
        │  Forwarded log events
        ▼
Wazuh Manager / SIEM Server
        │
        │  Rule correlation + MITRE mapping
        ▼
Wazuh Dashboard
        │
        ▼
SOC Analyst — Investigation & Response
```

| Role | System |
|---|---|
| Attacker | Kali Linux |
| Victim / Monitored Endpoint | Ubuntu Linux |
| SIEM Manager + Dashboard | Wazuh Server (v4.14.7) |

All systems run as isolated VirtualBox VMs on a private lab network. All simulated attacks targeted only the author's own VMs.

See [`architecture/soc-architecture.png`](./architecture/soc-architecture.png) for a visual diagram.

---

## What Was Built

- **SIEM deployment:** Installed and configured the Wazuh Manager and Dashboard, and deployed a Wazuh Agent to a monitored Ubuntu endpoint.
- **Log collection:** Verified the agent was correctly forwarding authentication events via `systemd-journald`, and troubleshot real connectivity and configuration issues along the way (IPv6 resolution failures, agent-to-manager misconfiguration after a network/IP change, package manager lock conflicts).
- **Attack simulation:** Performed a controlled SSH brute-force attack from Kali against Ubuntu using Hydra and a small custom password list, confined entirely to the lab network.
- **Detection:** Confirmed Wazuh's default ruleset detected both the repeated failed login attempts and the resulting successful login, correlating the failures into a single higher-severity brute-force alert mapped to MITRE ATT&CK T1110.
- **Investigation:** Produced a full incident report establishing a timeline, source/destination identification, exact attempt counts, Wazuh rule IDs, and a recommended response and containment plan.

See [`detections/ssh-bruteforce.md`](./detections/ssh-bruteforce.md) for the detection logic and rule breakdown, and [`investigations/incident-001.md`](./investigations/incident-001.md) for the full investigation writeup.

---

## Key Skills Demonstrated

- SIEM deployment and configuration (Wazuh)
- Endpoint agent deployment and log forwarding
- Linux log sources (`journald`, `auth.log`, PAM/sshd logging)
- Real-world infrastructure troubleshooting (networking, DNS/IPv6, package management, service configuration)
- Detection rule analysis (reading and interpreting raw Wazuh rule definitions)
- Alert triage and correlation concepts
- MITRE ATT&CK mapping
- Incident investigation and evidence-based reporting
- Basic incident response / containment recommendations

---

## Repository Structure

```
mini-soc-home-lab/
│
├── README.md
│
├── architecture/
│   └── soc-architecture.png
│
├── detections/
│   └── ssh-bruteforce.md
│
├── investigations/
│   └── incident-001.md
│
└── screenshots/
    ├── wazuh-dashboard.png
    ├── alert.png
    └── investigation.png
```

---

## Notes

This lab is intentionally minimal and reproducible rather than exhaustive — it's meant to demonstrate the full SOC detection lifecycle end-to-end rather than a long checklist of disconnected tools. All IP addresses and hostnames in this documentation have been generalized for a public repository.
