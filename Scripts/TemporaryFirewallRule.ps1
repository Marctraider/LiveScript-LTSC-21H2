param(
    [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [System.String]
    $Param1
    )

# Covert Minutes to Seconds
$Param2 = [int]$Param1
$Param3 = $Param2 * 60
Start-Sleep -Seconds $Param3
Remove-NetFirewallRule -DisplayName '*(Temporary)*'