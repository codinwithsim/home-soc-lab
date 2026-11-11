# Incident Reports — Home SOC Lab

Analyst: Simeon Todd
Environment: Wazuh SIEM (Ubuntu 24.04 server) monitoring a macOS endpoint,
isolated lab on a private network (UTM, Apple Silicon).

> Note: All activity below was self-generated in an isolated lab for training
> and detection-testing purposes. No production systems were involved.

---

## Incident Report #1 — SSH Brute-Force Attack

**Date:** 2026-11-09
**Analyst:** Simeon Todd
**Severity:** High (Wazuh rule level 10)
**Status:** Resolved (simulated / contained)

### Summary
A burst of failed SSH authentication attempts targeted a user account on the
Wazuh server. The volume and speed of the failures matched a brute-force
pattern, and the SIEM correlated the individual failures into a single
high-severity alert.

### Timeline (UTC)
| Time | Event |
|---|---|
| 2026-11-09 20:52 | First round of failed SSH logins from 192.168.64.1 (manual attempts) |
| 2026-11-09 21:13 | Rapid burst of failed logins from 127.0.0.1 (automated via Hydra) |
| 2026-11-09 21:13 | Wazuh correlated the failures and raised a level 10 brute-force alert |

### Indicators (IOCs)
- **Target account:** `testvictim` (test account)
- **Source IPs:** 192.168.64.1 (endpoint), 127.0.0.1 (local)
- **Failed attempts:** 40+ "Failed password" events in auth.log
- **Attack tool:** Hydra (automated password guessing)
- **Triggered rules:**
  - 5760 — sshd: authentication failed (level 5)
  - 5503 — PAM: user login failed (level 5)
  - 2501 — syslog: user authentication failure (level 5)
  - **2502 — multiple authentication failures / brute force (level 10)**

### MITRE ATT&CK
- **T1110 — Brute Force** (Tactic: Credential Access)

### Analysis
Individual failed logins are routine and logged at level 5. The SIEM escalated
to level 10 only once enough failures occurred inside a short time window,
correlating the noise into a recognizable attack pattern. The initial slow,
manual attempts did NOT trigger the brute-force alert because they were too
spread out to cross the correlation threshold — demonstrating that detection
depends on both volume and timing. No login succeeded; there is no evidence of
compromise.

### Recommended Response (if this were a real system)
- Confirm no successful login followed the failures (check for "Accepted password").
- Block or rate-limit the source IP at the firewall.
- Enforce key-based SSH authentication and disable password auth.
- Deploy fail2ban to auto-ban repeat offenders.
- Consider moving SSH off the default port to reduce automated scanning.

### Lessons Learned
A single detection rule can be evaded by a "low and slow" attack. Layered
detections and tuned thresholds matter. Overlapping rules (sshd, PAM, syslog)
provide defense in depth.

**Evidence:** `day4-individual-failures-level5.png`, `day4-failed-passwords-raw.png`, `day4-bruteforce-detected.png`

---

## Incident Report #2 — Unauthorized Local Account Creation

**Date:** 2026-11-10
**Analyst:** Simeon Todd
**Severity:** High (custom rule, level 10)
**Status:** Resolved (simulated / contained)

### Summary
A new local user account was created on the server. A custom detection rule
(ID 100100), authored specifically for this lab, flagged the event at level 10
as possible persistence activity.

### Timeline (UTC)
| Time | Event |
|---|---|
| 2026-11-10 07:43 | `useradd` executed via sudo on the server |
| 2026-11-10 07:43 | Built-in rule 5901 (new group) and 5402 (sudo to root) logged |
| 2026-11-10 07:43 | **Custom rule 100100 fired at level 10 — new account created** |

### Indicators (IOCs)
- **New account:** `ruletest` (test account)
- **Method:** `useradd` run with sudo privileges
- **Host:** wazuh-server
- **Triggered rules:**
  - 5901 — new group added to the system (level 8)
  - 5402 — successful sudo to ROOT (level 3)
  - **100100 — custom rule: new user account created, possible persistence (level 10)**

### MITRE ATT&CK
- **T1136.001 — Create Account: Local Account** (Tactic: Persistence)

### Detection Engineering Note
The built-in Wazuh rule for account creation fires at a lower severity. I
authored a custom rule (ID 100100) in `local_rules.xml` that builds on the base
event (`if_sid 5902`), raises the severity to level 10, and adds an explicit
MITRE T1136.001 mapping. This ensures unexpected account creation surfaces above
routine events for immediate analyst review.

```xml
<group name="local,syslog,">
  <rule id="100100" level="10">
    <if_sid>5902</if_sid>
    <description>New user account created - possible persistence</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
  </rule>
</group>
```

### Recommended Response (if this were a real system)
- Verify the account against change-management records — was it authorized?
- If unauthorized, disable the account and investigate how it was created.
- Review what the parent process / user was doing before and after.
- Check for other persistence mechanisms (cron jobs, SSH keys, services).

### Lessons Learned
Writing a custom rule shows detection engineering: deciding what matters,
setting severity deliberately, and mapping to a shared framework (MITRE) so the
alert is immediately understandable to any analyst.

**Evidence:** `day5-custom-rule.png`
