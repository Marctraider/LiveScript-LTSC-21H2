function LastBootUpMoreThan ($minutes){
  $dt = Get-CimInstance -ClassName win32_operatingsystem | Select LastBootUpTime
  if (($dt.LastBootUpTime).AddMinutes($minutes) -gt (get-date)) {$false}else {$true}
}

# Only purge log if system has less than specified uptime.
if (!(LastBootUpMoreThan 2))
    {
    del C:\Windows\Scripts\Logs\Ping.log
    }

Start-Transcript -path C:\Windows\Scripts\Logs\Ping.log -Append
Ping -t 10.0.0.1 | ForEach {"{0} - {1}" -f (Get-Date),$_}