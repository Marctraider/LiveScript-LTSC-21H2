<#
Global Variables
#>
$ErrorActionPreference = 'SilentlyContinue'

# AppX Packages
Write-Host "Installing UWP AppX and Libraries" -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name AllowAllTrustedApps -PropertyType Dword -Value 1 -Force
cd ".\Runtime Libraries\UWP"

$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.VCLibs.140.00*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe.appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.AV1VideoExtension*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.AV1VideoExtension_1.1.41601.0_x64__8wekyb3d8bbwe.appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.VP9VideoExtensions*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.VP9VideoExtensions_1.0.42791.0_x64__8wekyb3d8bbwe.appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.HEIFImageExtension*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.HEIFImageExtension_1.0.43012.0_x64__8wekyb3d8bbwe.appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.MPEG2VideoExtension*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.MPEG2VideoExtension_1.0.42152.0_x64__8wekyb3d8bbwe.appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.WebpImageExtension*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.WebpImageExtension_1.0.42351.0_x64__8wekyb3d8bbwe.Appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.HEVCVideoExtensions*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.HEVCVideoExtensions_1.0.42702.0_x64__8wekyb3d8bbwe.Appx -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.RawImageExtension*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.RawImageExtension_2.0.23022.0_neutral_~_8wekyb3d8bbwe.appxbundle -SkipLicense
    }
$Installed = Get-AppxPackage -AllUsers | where-object {$_.PackageFullName -like "Microsoft.WebMediaExtensions*"}; if(-not $Installed) {
    Add-AppxProvisionedPackage -Online -PackagePath .\Microsoft.WebMediaExtensions_1.0.42192.0_neutral_~_8wekyb3d8bbwe.AppxBundle -SkipLicense
    }
cd ..\..




# Custom Tasks
Write-Host "Generating Custom Tasks" -ForegroundColor Green

Unregister-ScheduledTask -TaskName "State" -Confirm:$false -erroraction 'silentlycontinue'
$Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit -WindowStyle Hidden -File C:\Windows\Scripts\State.ps1"
$Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
$Sttrig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask "State" -Action $Sta -Settings $Stset -Trigger $Sttrig

Unregister-ScheduledTask -TaskName ".NET Assembly Compiler" -Confirm:$false -erroraction 'silentlycontinue'
$Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NonInteractive -WindowStyle Hidden "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe ExecuteQueuedItems; C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe ExecuteQueuedItems"'
$Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -ExecutionTimeLimit '00:00:00'
$Sttrig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask ".NET Assembly Compiler" -Action $Sta -Settings $Stset -Trigger $Sttrig

Unregister-ScheduledTask -TaskName "Registry Backup" -Confirm:$false -erroraction 'silentlycontinue'
$Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NonInteractive -WindowStyle Hidden -Command "REG SAVE HKLM\SOFTWARE C:\Windows\System32\config\RegBack\SOFTWARE /Y; REG SAVE HKLM\SYSTEM C:\Windows\System32\config\RegBack\SYSTEM /Y; REG SAVE HKLM\SECURITY C:\Windows\System32\config\RegBack\SECURITY /Y; REG SAVE HKLM\SAM C:\Windows\System32\config\RegBack\SAM /Y; REG SAVE HKU\.DEFAULT C:\Windows\System32\config\RegBack\DEFAULT /Y; REG SAVE HKCU C:\Windows\System32\config\RegBack\NTUSER.DAT /Y; REG SAVE HKCU\Software\Classes C:\Windows\System32\config\RegBack\USRCLASS.DAT /Y; REG SAVE HKLM\BCD00000000 C:\Windows\System32\config\RegBack\BCD /Y" -WorkingDirectory "C:\Windows\System32\config"'
$Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
$Sttrig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask "Registry Backup" -Action $Sta -Settings $Stset -Trigger $Sttrig

Unregister-ScheduledTask -TaskName "Run" -Confirm:$false -erroraction 'silentlycontinue'
$Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NonInteractive -WindowStyle Hidden -File C:\Windows\Scripts\Run.ps1'
$Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
$Sttrig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask "Run" -Action $Sta -Settings $Stset -Trigger $Sttrig

Unregister-ScheduledTask -TaskName "Update" -Confirm:$false -erroraction 'silentlycontinue'
$Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NonInteractive -WindowStyle Hidden -File C:\Windows\Scripts\Update.ps1' -WorkingDirectory 'C:\Windows\System32'
$Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
$Sttrig = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask "Update" -Action $Sta -Settings $Stset -Trigger $Sttrig 

$model = (gwmi Win32_ComputerSystem).Model; if ( $model -like 'MS-7B12' -or $model -like 'Blade Stealth 13 (Early 2020) - RZ09-0310') {
    Unregister-ScheduledTask -TaskName MTHaxTool -Confirm:$false -erroraction 'silentlycontinue'
    $Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument 'Start-Process -NoNewWindow -LoadUserProfile -FilePath \"C:\Program Files\AutoHotkey\AutoHotkey.exe\" -ArgumentList "C:\Users\Administrator\Desktop\MTHaxTool\mthaxtool-systemwide_module.ahk" -WorkingDirectory "C:\Users\Administrator\Desktop\MTHaxTool"'
    $Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -ExecutionTimeLimit '00:00:00'
    $Stset.Priority = 4 # Default priority for tasks is 'Below Normal' which is troublesome as all the child processes AHK spawns consequently start at the same priority level rather than 'Normal'.
    $Sttrig = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask MTHaxTool -Action $Sta -Settings $Stset -Trigger $Sttrig
    }

$model = (gwmi Win32_ComputerSystem).Model; if ( $model -like 'MS-7B12') {
    Unregister-ScheduledTask -TaskName "Share" -Confirm:$false -erroraction 'silentlycontinue'
    $Sta = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit -WindowStyle Hidden -File C:\Windows\Scripts\Share.ps1"
    $Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
    $Sttrig = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask "Share" -Action $Sta -Settings $Stset -Trigger $Sttrig
    }
$model = (gwmi Win32_ComputerSystem).Model; if ( $model -like 'Blade Stealth 13 (Early 2020) - RZ09-0310') 
    {
    Unregister-ScheduledTask -TaskName HighDPIAware -Confirm:$false -erroraction 'silentlycontinue'
    $Sta = New-ScheduledTaskAction -Execute "cmd" -Argument '/c for /R "C:\Users\Administrator" %f in (*.exe) do reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "%f" /f /t REG_SZ /d "~ HIGHDPIAWARE"'
    $Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -ExecutionTimeLimit '00:00:00'
    $Sttrig = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask HighDPIAware -Action $Sta -Settings $Stset -Trigger $Sttrig
    }

# Install user-space applications
Write-Host "Install Userspace Applications" -ForegroundColor Green
Resources\AutoHotkey_1.1.33.10_setup\AutoHotkey_1.1.33.10_setup.exe /S
Resources\7z2104-x64\7z2104-x64.exe /S /D="C:\Program Files\7-Zip"


# Inject Registry Keys
Write-Host "Import Registry Keys from Files" -ForegroundColor Green
reg import ".\Registry\Context Add Menu Full Screen Optimizations.reg"
reg import ".\Registry\Context Add Menu Bypass Tunnel (DSCP).reg"
reg import ".\Registry\Context Add Run As Different User.reg"
reg import ".\Registry\Context Add Menu GPU Preference.reg"
reg import ".\Registry\Context Add Menu Advanced System Settings.reg"
reg import ".\Registry\Restore Windows Photo Viewer.reg"
reg import ".\Registry\Sysinternals Eula Prompts.reg"
reg import ".\Registry\Context Add Block Executable.reg"
reg import ".\Registry\Context Add Menu Classic Customize.reg"
reg import ".\Registry\Context Add Menu Command Prompt.reg"
reg import ".\Registry\Context Add Menu Powershell.reg"
reg import ".\Registry\Context Add Menu DPI Scaling.reg"
reg import ".\Registry\Context Add Menu Firewall.reg"
reg import ".\Registry\Context Add Menu Ownership.reg"

$model = (gwmi Win32_ComputerSystem).Model; if ( $model -notmatch 'VMware*') {
    reg import ".\Registry\Context Add Security Performance Mode.reg"
    }

$model = (gwmi Win32_ComputerSystem).Model; if ( $model -like 'MS-7B12') {
    reg import ".\Registry\XonarSwitch Profiles.reg"
    }

#>


# One-shot verification of Windows integrity
$Path = 'HKLM:\SOFTWARE\LiveScript'; if(-not (Test-Path -Path $Path)){ New-Item -ItemType String -Path $Path }
if( -not [String]::IsNullOrEmpty((Get-ItemProperty "HKLM:\SOFTWARE\LiveScript" -Name "IntegrityVerified" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IntegrityVerified))){
} else {
    New-ItemProperty -Path "HKLM:\SOFTWARE\LiveScript" -Name "IntegrityVerified" -Value "0" -PropertyType "DWORD" -Force | Out-Null
}

$integrity = Get-ItemProperty -Path 'HKLM:\SOFTWARE\LiveScript' -Name 'IntegrityVerified'
if($integrity.IntegrityVerified -ne 1)
{
    Write-Host "Verifying Windows integrity" -ForegroundColor Green

    Unregister-ScheduledTask -TaskName "Verify Integrity" -Confirm:$false -erroraction 'silentlycontinue'
    $Sta = New-ScheduledTaskAction -Execute "cmd" -Argument '/c sfc /scannow && schtasks /delete /tn "Verify Integrity" /f'
    $Stset = New-ScheduledTaskSettingsSet -Compatibility Win8 -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit '00:00:00'
    $Sttrig = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask "Verify Integrity" -Action $Sta -Settings $Stset -Trigger $Sttrig

    New-ItemProperty -Path "HKLM:\SOFTWARE\LiveScript" -Name 'IntegrityVerified' -PropertyType DWord -Value 1 -Force
}


<#
End of script
#>