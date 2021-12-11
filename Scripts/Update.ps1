Start-Sleep -Seconds 5

# Update Hosts File
cd "C:\Windows\System32\drivers\etc"
Invoke-WebRequest "http://winhelp2002.mvps.org/hosts.txt" -OutFile hosts.txt
if($?)
    {
    del hosts
    ren hosts.txt hosts
    }

# Update Root Certificates
Get-ScheduledTask | ? {$_.TaskName -eq 'SynchonizeTimeZone'} | Start-ScheduledTask
Get-ScheduledTask | ? {$_.TaskName -eq 'ForceSynchronizeTime'} | Start-ScheduledTask
Get-ScheduledTask | ? {$_.TaskName -eq 'SynchronizeTime'} | Start-ScheduledTask
Start-Sleep -Seconds 1

cd "C:\Windows\System32"
del roots.sst
certutil.exe -generateSSTFromWU roots.sst
certutil -addstore -f root C:\Windows\System32\roots.sst