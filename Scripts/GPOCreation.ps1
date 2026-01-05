<#
.SYNOPSIS
    Deploys both standard and intentionally flawed Group Policy Objects (GPOs).

.DESCRIPTION
    This script automates the creation and linking of several GPOs to demonstrate 
    common misconfigurations and security flaws in an Active Directory environment.
    
    Standard GPOs: Wallpaper, Power Management, Task Manager restriction, Drive Mapping.
    Flawed GPOs: SMBv1/WDigest enablement, weak encryption, LLMNR enablement, RDP exposure, 
                and Local Admin rights abuse (via Restricted Groups).
#>

$domain = (Get-ADDomain).Name
$DomainDN = (Get-ADDomain).DistinguishedName
$DomainFQDN = (Get-ADDomain).DNSRoot
$rootOUPath = "OU=$domain,$DomainDN"
$DCOUPath = "OU=Domain Controllers,$DomainDN"
$CompOUPath = "OU=Computers,OU=$domain,$DomainDN"
$UsersOUPath = "OU=Users,OU=$domain,$DomainDN"

#---------------------------------------- Create basic GPOs for the domain

$DeskWallPaper = "Default Desktop WallPaper"
$Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
New-GPO -Name $DeskWallPaper -Comment "Sets the standard corporate wallpaper" | Out-Null
Set-GPRegistryValue -Name $DeskWallPaper -Key $Path -ValueName "Wallpaper" -Type String -Value "C:\Windows\Web\Wallpaper\Corporate_Wall.jpg" | Out-Null
Set-GPRegistryValue -Name $DeskWallPaper -Key $Path -ValueName "WallpaperStyle" -Type String -Value "4" | Out-Null
New-GPLink -Name $DeskWallPaper -Target $CompOUPath | Out-Null
Write-Host " [+] Created GPO: $DeskWallPaper" -ForegroundColor Green

$Power = "Power Management"
New-GPO -Name $Power -Comment "Sets High Performance Power Plan and disable sleep, like our workers" | Out-Null
Set-GPPrefRegistryValue -Name $Power -Context Computer -Action Create `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ControlPanel\NameSpace\{021E2840-7712-11D3-9399-4400F7F36F28}" `
    -ValueName "PreferredPlan" -Value "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Type String | Out-Null
Set-GPPrefRegistryValue -Name $Power -Context Computer -Action Create `
    -Key "HKLM\System\CurrentControlSet\Control\Power\User\PowerSchemes\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\238c9fe8-0427-4147-bc3e-4f08bfd173f2\29f72528-3395-4a21-8813-22295933c856" `
    -ValueName "ACSettingIndex" -Value 0 -Type DWord | Out-Null
New-GPLink -Name $Power -Target $CompOUPath | Out-Null
Write-Host " [+] Created GPO: $Power" -ForegroundColor Green

$TaskManager = "Restrict TaskManager"
$Path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
New-GPO -Name $TaskManager -Comment "Disables Task Manager for users" | Out-Null
Set-GPRegistryValue -Name $TaskManager -Key $Path -ValueName "DisableTaskMgr" -Type DWord -Value 1 | Out-Null
New-GPLink -Name $TaskManager -Target $UsersOUPath | Out-Null
Write-Host " [+] Created GPO: $TaskManager" -ForegroundColor Green

$Drive = "Drive Mapping"
New-GPO -Name $Drive -Comment "Maps P: drive to Shared Folder" | Out-Null
Set-GPPrefRegistryValue -Name $Drive -Context User -Action Create -Key "HKCU\Network\P" -ValueName "RemotePath" -Type String -Value "\\FS01\Public" | Out-Null
New-GPLink -Name $Drive -Target $UsersOUPath | Out-Null
Write-Host " [+] Created GPO: $Drive" -ForegroundColor Green

$HomePage = "Browser Settings"
$Path = "HKCU\Software\Policies\Microsoft\Internet Explorer\Main"
New-GPO -Name $HomePage -Comment "Sets corporate home page" | Out-Null
Set-GPRegistryValue -Name $HomePage -Key $Path -ValueName "Start Page" -Type String -Value "https://intranet.vuln.local" | Out-Null
New-GPLink -Name $HomePage -Target $UsersOUPath | Out-Null
Write-Host " [+] Created GPO: $HomePage" -ForegroundColor Green


#---------------------------------------- Create flawed GPOs

$Legacy = "Backwards Compatibility"
New-GPO -Name $Legacy -Comment "Enables Legacy Protocols to work with old computers from our network" | Out-Null
Set-GPRegistryValue -Name $Legacy -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $Legacy -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $Legacy -Key "HKLM\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $Legacy -Key "HKCU\Software\Policies\Microsoft\Windows\Installer" -ValueName "AlwaysInstallElevated" -Type DWord -Value 1 | Out-Null
New-GPLink -Name $Legacy -Target $rootOUPath | Out-Null
New-GPLink -Name $Legacy -Target $DCOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $Legacy" -ForegroundColor Red

$Crypto = "Encryption"
$GPO_Crypto = New-GPO -Name $Crypto -Comment "Allows Kerberos to work with legacy devices"
$GPOID_Crypto = $GPO_Crypto.Id
$SysVolPath_Crypto = "\\$DomainFQDN\SysVol\$DomainFQDN\Policies\{$GPOID_Crypto}\Machine\Microsoft\Windows NT\SecEdit"

New-Item -Path $SysVolPath_Crypto -ItemType Directory -Force | Out-Null

$Content_Crypto = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483647
"@
$Content_Crypto | Out-File "$SysVolPath_Crypto\GptTmpl.inf" -Encoding Unicode

# Register the Client Side Extension (CSE) - This is to make it work on the GPO GUI
$AdPath_Crypto = "CN={$GPOID_Crypto},CN=Policies,CN=System,$DomainDN"
Set-ADObject -Identity $AdPath_Crypto -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-D4D1-11D1-2244-00C04F79F83A}]"}

New-GPLink -Name $Crypto -Target $rootOUPath | Out-Null
New-GPLink -Name $Crypto -Target $DCOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $Crypto" -ForegroundColor Red

$LLMNR = "Disable LLMNR and NBNS"
New-GPO -Name $LLMNR -Comment "Ensures that LLMNR and NBNS are disabled" | Out-Null
Set-GPRegistryValue -Name $LLMNR -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 1 | Out-Null
New-GPLink -Name $LLMNR -Target $rootOUPath | Out-Null
New-GPLink -Name $LLMNR -Target $DCOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $LLMNR" -ForegroundColor Red

$RDP = "Remote Access"
New-GPO -Name $RDP -Comment "Enable Remote Desktop access" | Out-Null
Set-GPRegistryValue -Name $RDP -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Type DWord -Value 0 | Out-Null
Set-GPRegistryValue -Name $RDP -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "UserAuthentication" -Type DWord -Value 0 | Out-Null
Set-GPRegistryValue -Name $RDP -Key "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "SecurityLayer" -Type DWord -Value 0 | Out-Null
New-GPLink -Name $RDP -Target $rootOUPath | Out-Null
New-GPLink -Name $RDP -Target $DCOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $RDP" -ForegroundColor Red

$ITAdmin = "Local Admins"
$TargetGroupSID = "S-1-5-32-544" #SID for built-in Administrators
$MemberToAdd = "Domain Users"

$GPO = New-GPO -Name $ITAdmin -Comment "Adds IT Admins to Local Administrators group"
$GPOID = $GPO.Id
$SysVolPath = "\\$DomainFQDN\SysVol\$DomainFQDN\Policies\{$GPOID}\Machine\Microsoft\Windows NT\SecEdit"

New-Item -Path $SysVolPath -ItemType Directory -Force | Out-Null

$Content = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Group Membership]
*$TargetGroupSID`__Memberof =
*$TargetGroupSID`__Members = $MemberToAdd
"@
# Write file with Unicode encoding, so it doesn't break
$Content | Out-File "$SysVolPath\GptTmpl.inf" -Encoding Unicode

# Register the Client Side Extension (CSE) - This is to make it work on the GPO GUI
$AdPath = "CN={$GPOID},CN=Policies,CN=System,$DomainDN"
Set-ADObject -Identity $AdPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-D4D1-11D1-2244-00C04F79F83A}]"}

New-GPLink -Name $ITAdmin -Target $CompOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $ITAdmin" -ForegroundColor Red

$Printers = "Printer Drivers"
New-GPO -Name $Printers -Comment "Allows users to install printer drivers without admin rights" | Out-Null
Set-GPRegistryValue -Name $Printers -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "Restricted" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $Printers -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "NoWarningNoElevationOnInstall" -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $Printers -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ValueName "UpdatePromptSettings" -Type DWord -Value 2 | Out-Null
New-GPLink -Name $Printers -Target $RootOUPath | Out-Null
New-GPLink -Name $Printers -Target $DCOUPath | Out-Null
Write-Host " [!] Created Flawed GPO: $Printers" -ForegroundColor Red

Write-Host ""