# Monitor WMI events and take action on trigger

# Initial starting state of elements controlled by this script
Start-Sleep -Seconds 1
Disable-NetAdapter -Name '*VMNet*' -Confirm:$False # Fixes NCSI issues at startup
# Check whether we logged in from a logged out system remotely.
$Test = Get-EventLog -List | %{Get-EventLog -LogName Microsoft-Windows-TerminalServices-LocalSessionManager/Operational -InstanceId 21 -Message '*192.168.*'-After (Get-Date).AddSeconds(-15) -ErrorAction Ignore} | Sort-Object TimeGenerated | Format-Table -AutoSize -Wrap
if ($Test -eq $Null) {
    Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
    }



Get-EventSubscriber | Unregister-Event

$model = (gwmi Win32_ComputerSystem).Model

$objUser = New-Object System.Security.Principal.NTAccount("Administrator")
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
$strSID.Value

Function Test-IsOnBattery
{
Param(
[string]$computer
)
[BOOL](Get-WmiObject -Class BatteryStatus -Namespace root\wmi ` -ComputerName localhost).PowerOnLine
} #end function test-IsOnBattery


if(test-isOnBattery -computer $computer){
Start-Service -Name "STR"
}

# Monitor Power State Changes (Razer Laptop) and stop/start AHK and STR service.
if ( $model -like 'Blade Stealth 13 (Early 2020) - RZ09-0310') {
    Register-WmiEvent -Query 'Select * From Win32_PowerManagementEvent within 5' -SourceIdentifier 'Power' -Action {
        If ([bool](Get-WmiObject -Class BatteryStatus -Namespace root\wmi).PowerOnLine) {
        Start-Service -Name "STR"
    
    	if (Get-Process "AutoHotkey" -ErrorAction silentlycontinue) {
    	   	"Do Nothing"
    	   	}
    	else
    	   	{
    	   	Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Program Files\AutoHotkey\AutoHotKey.exe" -ArgumentList "C:\Users\Administrator\Desktop\MTHaxTool\mthaxtool-systemwide_module.ahk" -WorkingDirectory "C:\Users\Administrator\Desktop\MTHaxTool"
    	   	}
    
    
        } else {
            Stop-Service -Name "STR"
            Stop-Process -processname 'AutoHotkey' -Force
        }
    }
}


# Monitor Registry Changes
$wmiEvent = "SELECT * FROM RegistryTreeChangeEvent within 5 WHERE " + " Hive = 'HKEY_USERS' " +
                 "AND RootPath = '$($strSID.Value)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'"

Register-WmiEvent -Query $wmiEvent -SourceIdentifier myKeyListener -Action { 
    write-host "yes"; Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "*" -Confirm:$False
    }

# Monitor Firewall Changes
$query = "SELECT * FROM __instanceCreationEvent within 2 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode=2004"
Register-WMIEvent -Query $query -SourceIdentifier Firewall -Action { 
    Get-NetFirewallRule | Where { $_.DisplayName -notmatch 'Script Generated' -and $_.DisplayName -notmatch 'Allow' } | Remove-NetFirewallRule
    }

# Monitor Resume from Hibernation
if ( $model -like 'MS-7B12') {
    $query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode=107"
    Register-WMIEvent -Query $query -Action { 
        Start-Sleep -Seconds 10
        Start-Service -Name "audiosrv"
        Start-Sleep -Seconds 10
        Enable-PnpDevice -InstanceId 'PCI\VEN_13F6&DEV_8788&SUBSYS_85F41043&REV_00\5&19D6E015&0&200009' -Confirm:$False
        Start-Sleep -Seconds 10
        Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
        }
}

# Monitor VMWare
if ( $model -like 'MS-7B12') {
    Register-WmiEvent -Query 'Select * From __InstanceCreationEvent Within 2 Where TargetInstance Isa "Win32_Process" And TargetInstance.Name = "vmware-vmx.exe"' -SourceIdentifier 'VMWareInstanceStarted' -Action {
    Write-Host 'VMWare Virtual Machine Instance Started'
    
    $Interfaces = Get-NetAdapter -Name '*VMNet*'
    if ($Interfaces.InterfaceOperationalStatus -eq 2 -or $Interfaces.InterfaceOperationalStatus -eq 6)
        {
        Enable-NetAdapter -Name '*VMNet*' -Confirm:$False
        Write-Host "Enabling adapters"
        }
    }
    
    Register-WMIEvent -Query 'SELECT * From Win32_ProcessStopTrace WHERE ProcessName="vmware-vmx.exe"' -SourceIdentifier 'VMWareInstanceStopped' -Action {
    Write-Host 'VMWare Virtual Machine Instance Stopped'
    
    # Make sure adapters don't get disabled as long as at least one virtual machine is still running.
    if (!(Get-Process "vmware-vmx" -ErrorAction silentlycontinue)) {
        $Interfaces = Get-NetAdapter -Name '*VMNet*'
        if ($Interfaces.InterfaceOperationalStatus -eq 1)
            {
            Disable-NetAdapter -Name '*VMNet*' -Confirm:$False
            Write-Host "Disabling adapters"
            }
        }
    }
}

# Monitor RDP session events
if ( $model -like 'MS-7B12') {
    Register-WmiEvent -Query 'SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA "Win32_NTLogEvent" AND (TargetInstance.EventCode=25 OR TargetInstance.EventCode=21) AND TargetInstance.Message LIKE "%192.168.%"' -SourceIdentifier 'RemoteSessionLoggedOnOrReconnected' -Action {
    Write-Host "RDP Logged On or reconnected"
    if (Get-Process "XonarSwitch" -ErrorAction silentlycontinue) {
        Stop-Process -processname 'XonarSwitch' -Force
        }
    }
    
    Register-WmiEvent -Query 'SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA "Win32_NTLogEvent" AND TargetInstance.EventCode=24 AND TargetInstance.Message LIKE "%192.168.%"' -SourceIdentifier 'RemoteSessionLoggedff' -Action {
    Write-Host "RDP Logged off"
    if (!(Get-Process "XonarSwitch" -ErrorAction silentlycontinue)) {
        Start-Sleep -Seconds 5
        Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
        }
    }
}