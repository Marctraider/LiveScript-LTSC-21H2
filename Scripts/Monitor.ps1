# Monitor WMI events and take action on trigger.

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

# Monitor RDP Session
if ( $model -like 'MS-7B12') {
Register-WmiEvent -Query 'SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA "Win32_NTLogEvent" AND TargetInstance.EventCode=25 AND TargetInstance.Message LIKE "%192.168.%"' -SourceIdentifier 'RDPLogOn' -Action {
    if((get-process "XonarSwitch" -ea SilentlyContinue) -eq $Null){ 
    Write-Host "Do Nothing"
    }
    else {
        Start-Sleep -Seconds 1
        Stop-Process -Name XonarSwitch -Force
        Write-Host "Stop XonarSwitch"
        }
    
    }

Register-WmiEvent -Query 'SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA "Win32_NTLogEvent" AND TargetInstance.EventCode=24 AND TargetInstance.Message LIKE "%192.168.%"' -SourceIdentifier 'RDPLogOff' -Action {
 if((get-process "XonarSwitch" -ea SilentlyContinue) -ne $Null){ 
    Write-Host "Do Nothing"
    }
    else {
        Start-Sleep -Seconds 5
        Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
        Write-Host "Start XonarSwitch"
        }
    }
}