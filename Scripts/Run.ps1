$model = (gwmi Win32_ComputerSystem).Model

# Commands to execute once after login
stop-dtc -Confirm:$False
Remove-NetFirewallRule -DisplayName '*(Temporary)*'
Remove-NetQosPolicy -Name "Bypass" -Force
Disable-NetAdapter -Name '*VMNet*' -Confirm:$False # Initial state at boot (Fixes NCSI issues). Enable manually or by WMI event.

if ( $model -like 'MS-7B12') {
Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
}