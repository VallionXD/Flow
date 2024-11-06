# Check if the script is running with administrative privileges.
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -and (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }))) {
    Write-Host "This script requires administrative privileges. Please run as administrator."
    exit
}

# User information
$Username = "Flow"
$SystemDrive = $env:SystemDrive
$SystemRoot = $env:SystemRoot

# Remove the created user
Remove-LocalUser -Name $Username -Force

# Remove the user from the Administrators group
Remove-LocalGroupMember -Group "Administrators" -Member $Username

# Remove user rights from the user account
secpol.msc /remove-user-rights $Username SeBatchLogonRight
secpol.msc /remove-user-rights $Username SeInteractiveLogonRight
secpol.msc /remove-user-rights $Username SeNetworkLogonRight
secpol.msc /remove-user-rights $Username SeRemoteInteractiveLogonRight

# Revoke specific permissions from the user
$PermissionsList = @(
    "SeDebugPrivilege", 
    "SeBackupPrivilege", 
    "SeRestorePrivilege", 
    "SeTakeOwnershipPrivilege", 
    "SeIncreaseQuotaPrivilege", 
    "SeLoadDriverPrivilege", 
    "SeSystemTimePrivilege", 
    "SeRemoteShutdownPrivilege", 
    "SeManageVolumePrivilege", 
    "SeShutdownPrivilege", 
    "SeUndockPrivilege", 
    "SeIncreaseBasePriorityPrivilege", 
    "SeAssignPrimaryTokenPrivilege", 
    "SeCreatePagefilePrivilege", 
    "SeSecurityPrivilege", 
    "SeRelabelPrivilege", 
    "SeImpersonatePrivilege", 
    "SeTcbPrivilege", 
    "SeAuditPrivilege", 
    "SeChangeNotifyPrivilege", 
    "SeCreateTokenPrivilege", 
    "SeBatchLogonRight", 
    "SeInteractiveLogonRight", 
    "SeNetworkLogonRight", 
    "SeRemoteInteractiveLogonRight"
)

# For each permission in the list, remove from the user
foreach ($Permission in $PermissionsList) {
    ntrights -u $Username -r $Permission
}

# Remove the full control permissions granted to the user on the system drive
icacls "$SystemDrive\" /remove "${Username}" /T /C

# Remove the full control permissions granted to the user on important system folders
icacls "$SystemRoot\System32" /remove "${Username}" /T /C /Q
icacls "$SystemRoot\Flow" /remove "${Username}" /T /C /Q

# Remove full control permissions over the registry
icacls "HKCU" /remove "${Username}"
icacls "HKLM" /remove "${Username}"

# Remove specific registry key permissions
icacls "HKLM:\SYSTEM\CurrentControlSet\Control" /remove "${Username}"
icacls "HKLM:\SOFTWARE\Microsoft\Windows" /remove "${Username}"
icacls "HKLM:\SAM" /remove "${Username}"
