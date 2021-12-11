Write-Host "Hibernating in 5 seconds."
Start-Sleep -Seconds 5
Stop-Service -Name "audiosrv" -Force
Start-Sleep -Seconds 1
Disable-PnpDevice -InstanceId 'PCI\VEN_13F6&DEV_8788&SUBSYS_85F41043&REV_00\5&30FA9A89&0&2000E0' -Confirm:$False
Start-Sleep -Seconds 1
psshutdown -d -t 0