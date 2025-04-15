# 🛡️ LetsDefend Case #1: CVE-2024-49138 - Sticky Keys Abuse via LOLBins

## 🔍 Summary

This case involves detecting an attacker leveraging a Windows LOLBin (`Sethc.exe`) to establish persistence through Sticky Keys backdoor abuse. It ties into CVE-2024-49138 and involves Remote Desktop Protocol (RDP) access, privilege escalation, and potential lateral movement.

---

## 🚨 Initial Alert Details

- **Alert:** PowerShell - Suspicious CommandLine
- **Source IP:** 10.10.20.11
- **Detected Command:**
  ```powershell
  C:\Windows\System32\Sethc.exe /AccessibilitySoundAgent
  ```
- **Tool:** LetsDefend SOC Simulation (SOC335)
- **Time:** [Exact time not listed; assumed during case engagement]

---

## 🧪 Investigation Timeline

1. **RDP Logon Activity:**
   - Login from 10.10.20.11 observed on target host.
   - Indicates successful remote access and credential use.

2. **Suspicious Command Execution:**
   - Execution of `Sethc.exe` with unusual parameters.
   - Suggests hijack of the Sticky Keys feature for persistence.

3. **Malicious Registry Modification (Likely):**
   - Although not shown in raw logs, this behavior commonly involves:
     ```
     HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe
     ```
     to redirect execution or run a custom command.

4. **TTPs Mapped:**
   - `T1546.008` — Accessibility Features (Persistence)
   - `T1218` — Signed Binary Proxy Execution (LOLBins)
   - `T1021.001` — Remote Services: RDP
   - `T1053.005` — Scheduled Task/Job: Scheduled Task (if used)
   - `T1036` — Masquerading

---

## 🧠 Analysis Notes

- Sticky Keys (`sethc.exe`) is a known LOLBin.
- Modifying its behavior allows attackers to launch commands from the login screen.
- This attack may not be malware-based, but rather abuses built-in binaries.
- Endpoint logging with Sysmon or EDR is critical to detecting such actions.

---

## 🧰 Artifacts Included

- `sysmon_logs.txt`: (placeholder) Command execution events
- `scheduled_task.xml`: (placeholder) Possible scheduled task creation
- Screenshots can be added here to enhance investigation transparency.

---

## 🛡️ Recommendations

- Monitor usage of `sethc.exe` or similar accessibility tools from unexpected contexts.
- Audit registry keys under Image File Execution Options regularly.
- Restrict unnecessary RDP access; enforce MFA and lockout policies.
- Disable accessibility features if not in use on endpoints.

---

## 📚 References

- [CVE-2024-49138](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-49138)
- [MITRE ATT&CK T1546.008 - Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)
- [LetsDefend Blog Post (Author)](https://myitjourney12.wordpress.com/2025/04/15/letsdefend-case-1-soc335-cve-2024-49138-exploitation-detected-lolbin-and-rce/)
