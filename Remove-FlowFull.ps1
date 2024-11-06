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

# ================================================================================================= #
#     Remove the scheduled tasks that were created to run high permission processes.                #
# ================================================================================================= #

# List of tasks to remove based on the program paths
$ProgramPaths = @(
    "${SystemRoot}\System32\WindowsFirewallWithAdvancedSecurity.msc",
    "${SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe",
    "${SystemRoot}\System32\SystemPropertiesComputerName.exe",
    "${SystemRoot}\System32\SystemPropertiesPerformance.exe",
    "${SystemRoot}\System32\UserAccountControlSettings.exe",
    "${SystemRoot}\System32\SystemPropertiesProtection.exe",
    "${SystemRoot}\System32\SystemPropertiesAdvanced.exe",
    "${SystemRoot}\System32\SystemPropertiesHardware.exe",
    "${SystemRoot}\System32\SystemSettingsAdminFlows.exe",
    "${SystemRoot}\System32\SystemPropertiesComputer.exe",
    "${SystemRoot}\System32\SystemPropertiesRemote.exe",
    "${SystemRoot}\System32\DeviceManagerLauncher.exe",
    "${SystemRoot}\System32\SystemSettingsBroker.exe",
    "${SystemRoot}\System32\TaskSchedulerConsole.exe",
    "${SystemRoot}\System32\SystemConfiguration.exe",
    "${SystemRoot}\System32\SystemInformation.exe",
    "${SystemRoot}\System32\SystemProperties.exe",
    "${SystemRoot}\System32\DeviceManager.exe",
    "${SystemRoot}\System32\SystemReset.exe",
    "${SystemRoot}\System32\SecConfig.exe",
    "${SystemRoot}\System32\diskmgmt.msc",
    "${SystemRoot}\System32\msconfig.exe",
    "${SystemRoot}\System32\services.msc",
    "${SystemRoot}\System32\eventvwr.msc",
    "${SystemRoot}\System32\compmgmt.msc",
    "${SystemRoot}\System32\perfmon.exe",
    "${SystemRoot}\System32\devmgmt.msc",
    "${SystemRoot}\System32\MdSched.exe",
    "${SystemRoot}\System32\gpedit.msc",
    "${SystemRoot}\System32\cmd.exe"
)

# Remove all scheduled tasks created by the script
foreach ($Program in $ProgramPaths) {
    $TaskName = "Elevated Task for $([System.IO.Path]::GetFileNameWithoutExtension($Program))"
    
    # Remove the task if it exists
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# ================================================================================================= #
#     Remove the Flow directory and any traces left by the script.                                   #
# ================================================================================================= #

# Remove the Flow directory
Remove-Item -Path "${SystemRoot}\Flow" -Recurse -Force
