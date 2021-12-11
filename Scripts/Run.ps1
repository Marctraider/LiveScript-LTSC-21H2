# Commands to execute once after login
stop-dtc -Confirm:$False
Remove-NetFirewallRule -DisplayName '*(Temporary)*'
Remove-NetQosPolicy -Name "Bypass" -Force

Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\BasicThemer2-v0.5.1-Release\BasicThemer2.exe" -WorkingDirectory "C:\Windows\BasicThemer2-v0.5.1-Release"

$model = (gwmi Win32_ComputerSystem).Model; if ( $model -like 'MS-7B12') {
Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\XonarSwitch.exe" -WorkingDirectory "C:\Windows"
Start-Process -NoNewWindow -LoadUserProfile -FilePath "C:\Windows\CEE 0.3.39\CorsairEffectsEngine.exe" -WorkingDirectory "C:\Windows\CEE 0.3.39"
}