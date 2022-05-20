# Automatically admin share newly mounted drives
$DrivesCount = (gwmi -Query "Select * from Win32_LogicalDisk").Count
$Drives = (gwmi -Query "Select * from Win32_LogicalDisk")

while(1) {
Start-Sleep -Milliseconds 10000
    $DrivesCountNew = (gwmi -Query "Select * from Win32_LogicalDisk").Count
        if ($DrivesCount -ne $DrivesCountNew) 
          {
          $DrivesNew = (gwmi -Query "Select * from Win32_LogicalDisk")
          $DriveLetter = Compare-Object -ReferenceObject $Drives -DifferenceObject $DrivesNew | Select -ExpandProperty InputObject | Select -ExpandProperty DeviceId
          if (!($DriveLetter -eq $null)) { 
          Write-host "New drive mounted $DriveLetter"
          
          $NewDriveLetter = $DriveLetter -replace ':','' # Remove ':' Symbol
          net share $NewDriveLetter$=$DriveLetter\ /GRANT:Administrator,FULL /CACHE:None

          $DrivesCount = (gwmi -Query "Select * from Win32_LogicalDisk").Count
          $Drives = (gwmi -Query "Select * from Win32_LogicalDisk")

          }
          $DrivesCount = (gwmi -Query "Select * from Win32_LogicalDisk").Count 
          }
         }