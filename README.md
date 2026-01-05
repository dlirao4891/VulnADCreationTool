# VulnADCTool - Active Directory Automation Suite

**⚠️ SECURITY WARNING: INTENTIONALLY VULNERABLE ENVIRONMENT ⚠️**

This project is designed to deploy a **Compromised-by-Design** Active Directory environment for cyber security training and red teaming practice.

**DO NOT** run these scripts in a production environment or on a network connected to production systems. The resulting domain contains intentional misconfigurations, weak passwords, and well-known vulnerabilities.

---

## Overview

The suite automates the entire lifecycle of a Domain Controller deployment. It starts from a fresh Windows Server installation and results in a fully populated domain containing:
*   **Users & Groups**: Randomly generated identities with realistic metadata.
*   **Organizational Units**: A logical hierarchy (Users, Computers, Groups, Admins).
*   **Group Policies**: A mix of standard corporate policies and insecure configurations.
*   **Vulnerabilities**: Pre-baked attack paths including Kerberoasting, AS-REP Roasting, PrintNightmare, SMBv1, and more.
*   **Adversary Emulation**: Simulates a post-compromise state with a backdoor account and a persistent C2 beaconing task.

## Prerequisites

*   **OS**: Windows Server 2016, Windows Server 2019 or Windows Server 2022 (Standard or Datacenter).
*   **Network**: A **Static IP Address** is highly recommended before starting.
*   **Privileges**: Local Administrator rights.
*   **Internet (Optional)**: Required if you want the script to configure a specific DNS forwarder (1.1.1.1), but the script works fully offline.

## Installation Guide

### 1. Prepare the Server
1.  Install a fresh copy of Windows Server on a virtual environment.
2.  **Rename the computer** to your desired DC name (e.g., `DC01`).
3.  **Set a Static IP address**.
4.  **Turn OFF** updates using `sconfig`.
5.  Restart the server.

### 2. Deployment
1.  Copy the entire `VulnADCreationTool` folder to the server (e.g., `C:\VulnADCreationTool`).
2.  Open **PowerShell as Administrator**.
3.  Navigate to the `Scripts` directory:
    ```powershell
    cd C:\VulnADCreationTool\Scripts
    ```
4.  Run the installer:
    ```powershell
    .\installAD.ps1
    ```
5.  **Follow the Prompts**:
    *   Enter the desired **Domain Name** (e.g., `vuln.local`).
    *   Enter a **Safe Mode Administrator Password**.

### 3. The Process
1.  **Stage 1**: The script installs AD DS and promotes the server. **The server will reboot automatically.**
2.  **Stage 2**: Log back in as `DOMAIN\Administrator`. The script will automatically resume.
3.  **Completion**:
    *   DNS, Users, OUs, and GPOs are configured.
    *   Vulnerabilities are injected.
    *   **Cleanup**: The installation files will **try** to automatically delete the directory and the files to leave no trace. Depending on where the folder is located, the deletion will fail.
    *   **Final Reboot**: The server performs one last reboot to finalize all changes.

## Project Structure

```text
VulnADCreationTool/
├── Scripts/
│   ├── installAD.ps1              # Main script
│   ├── GenerateIdentities.ps1     # User/Group generation logic
│   ├── CreateOU.ps1               # OU structure & object moving
│   ├── GPOCreation.ps1            # GPO deployment (Good & Bad)
│   ├── Malicious.ps1              # Backdoors & C2 tasks
│   ├── Vulnerabilities.ps1        # AD-specific flaws (Roasting, etc.)
│   └── Data/                      # Source text files for generation
├── FLAWS.md                       # Documentation of intentional vulnerabilities
└── README.md                      # This file
```

## Intentional Flaws

For a detailed list of vulnerabilities and how to exploit them, see [FLAWS.md](FLAWS.md).

Key flaws include:
*   **Weak Passwords**: Domain-wide complexity disabled.
*   **Kerberoasting**: Service accounts with SPNs.
*   **AS-REP Roasting**: Users with pre-auth disabled.
*   **PrintNightmare**: Insecure "Point and Print" restrictions.
*   **Local Admin Abuse**: Domain Users added to Local Admins via GPO.
*   **Legacy Protocols**: SMBv1 and WDigest enabled.

## Troubleshooting

*   **Execution Policy**: If scripts fail to run, ensure you can execute scripts: `Set-ExecutionPolicy Bypass -Scope Process`.
*   **Progress Bar Overlap**: If the console looks messy during DNS setup, this is visual only and does not affect the installation.
*   **"Files Missing"**: The script self-destructs upon success. This is intentional.

---
**Author**: dlirao

> Note: This script idea was based on [this video](https://www.youtube.com/watch?v=yIXTPpluHVo) from **John Hammond**.