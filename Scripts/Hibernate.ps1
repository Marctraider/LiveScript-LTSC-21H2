Write-Host "Hibernating in 5 seconds."
Stop-Process -processname 'XonarSwitch' -Force
Start-Sleep -Seconds 5
Stop-Service -Name "audiosrv" -Force
Start-Sleep -Seconds 1
Disable-PnpDevice -InstanceId 'PCI\VEN_13F6&DEV_8788&SUBSYS_85F41043&REV_00\5&19D6E015&0&200009' -Confirm:$False
Start-Sleep -Seconds 1
psshutdown -d -t 0