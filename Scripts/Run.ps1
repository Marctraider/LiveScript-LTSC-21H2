$model = (gwmi Win32_ComputerSystem).Model

# Commands to execute once after login
stop-dtc -Confirm:$False
Remove-NetFirewallRule -DisplayName '*(Temporary)*'
Remove-NetQosPolicy -Name "Bypass" -Force