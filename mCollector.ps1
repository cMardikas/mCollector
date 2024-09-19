#Small script to collect some windows data.

try{
	#Allow running unsigned scripts as current user
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
}
catch {
    #Do Nothing
}

$FormatEnumerationLimit = -1
$currentPath=(Split-Path((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path).Trim()

$MainFunction = {
    

$currentDate       = Get-Date -Format "dd-MM-yyyy HH:mm"
$compSys           = Get-CimInstance -ClassName CIM_ComputerSystem
Write-Host "Starting data collection $($currentDate) @ $($compSys.Name)"
$description       = read-host "Enter additional description for $($compSys.Name)"
Write-Host "Collecting osInfo."
$osInfo            = Get-CimInstance -ClassName CIM_OperatingSystem
$LastBoot		   = Get-Date($osInfo.lastbootuptime) -Format "dd.MM.yyyy HH:mm"
Write-Host "Collecting Azure info."
$azureTenantID 	   = Check-IfAzureJoined
$azureJoinedByUser = Check-WhoJoinedAzure
Write-Host "Collecting current user."
$currentUser       = (Get-CimInstance CIM_ComputerSystem | select username).username
Write-Host "Collecting current user group membership."
$currentUserGroups = Get-Groups
Write-Host "Collecting local admin accounts."
$allLocalAdmins    = net localgroup administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
Write-Host "Collecting BitLocker status."
$statusBitLocker   = Get-BitLockerStatus
Write-Host "Collecting Windows Update status."
$lastSearchSuccessDate     = Get-Date((New-Object -Com "Microsoft.Update.AutoUpdate").Results | Select -ExpandProperty "LastSearchSuccessDate") -Format "dd.MM.yyyy"
$lastInstallationSuccessDate     = Get-Date((New-Object -Com "Microsoft.Update.AutoUpdate").Results | Select -ExpandProperty "LastInstallationSuccessDate") -Format "dd.MM.yyyy"
$installedWindowsUpdates  = Get-CimInstance -ClassName Win32_QuickFixEngineering | sort installedon -des | Select-Object -Property HotFixID, InstalledOn
Write-Host "Collecting installed software."
$installedSoftware = Get-CimInstance -ClassName Win32_Product | Select Vendor,Name,Version,InstallDate | sort InstallDate -des
Write-Host "Collecting network configuration."
$ipConfig = Get-NetAdapter | Get-NetIPAddress  -Erroraction silentlycontinue |  Select ifIndex, InterfaceAlias, AddressFamily, IPv4Address, IPv6Address, PrefixLength
$routingTable = Get-NetRoute -AddressFamily IPv4 -State Alive | Select InterfaceIndex, InterfaceAlias,DestinationPrefix, NextHop, RouteMetric
$routesToNonLocalDST = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | Select ifIndex, DestinationPrefix, NextHop, RouteMetric
#NetworkCategogry={Public,Private, Domain}; IPv4Connectivity = {Disconnected, NoTraffic, Subnet, LocalNetwork, Internet}
$netConnectionProfile = Get-NetConnectionProfile | Select Name, InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity

#Get all services where its caption or its pathname doesn't contain Windows and where user has access to
#Exclusion for "policyhost.exe" removes Microsoft Policy Platform service
#Exclusion for service name "LSM" removes the Local Session Manager service
#Exclusion for "OSE.EXE" removes the Office Source Engine Service
#Exclusion for "OSPPSVC.EXE" removes the Office Software Protection Platform Service
#Exclusion for "Microsoft Security Client" removes Microsoft Security Client (SCEP)
Write-Host "Collecting list of non standard windows services."
$nonStandardWinServices = Get-CimInstance -ClassName win32_Service | where { $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows" -and $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client" -and $_.Name -notmatch "edgeupdate" -and $_.Name -notmatch "MicrosoftEdgeElevationService" -and $_.Name -notmatch "NetSetupSvc" -and $_.Name -notmatch "uhssvc" } | Select Name, PathName, StartMode, Status
#Non Microsoft tasks
Write-Host "Collecting list of non standard windows tasks."
$nonMSScheduledTasks = Get-ScheduledTask | Select URI, TaskPath, TaskName, State, Hidden | where { $_.TaskPath -notmatch "Microsoft"}
Write-Host "Collecting info about windows firewall."
$firewallStatus = Get-NetFireWallProfile | Select Profile, Enabled, DefaultInboundAction,DefaultOutboundAction,AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, AllowUserApps, AllowUserPorts, DisabledInterfaceAliases
#https://jdhitsolutions.com/blog/powershell/5187/get-antivirus-product-status-with-powershell/
Write-Host "Collecting info about antivirus."
$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select displayName, productState, timestamp 



Write-Host "Processing collected data."
$collectedData = New-Object -TypeName psobject

$collectedData | Add-Member -MemberType NoteProperty -Name ForensicsDate -Value $currentDate
$collectedData | Add-Member -MemberType NoteProperty -Name Description -Value $description
$collectedData | Add-Member -MemberType NoteProperty -Name ComputerName -Value $compSys.Name
$collectedData | Add-Member -MemberType NoteProperty -Name Domain -Value $compSys.Domain
$collectedData | Add-Member -MemberType NoteProperty -Name Workgroup -Value $compSys.Workgroup
$collectedData | Add-Member -MemberType NoteProperty -Name TenantID -Value $azureTenantID
$collectedData | Add-Member -MemberType NoteProperty -Name TenantJoinedBy -Value $azureJoinedByUser
$collectedData | Add-Member -MemberType NoteProperty -Name OS -Value $osInfo.Caption
$collectedData | Add-Member -MemberType NoteProperty -Name OS_Version -Value $("$($osInfo.Version) Build $($osInfo.BuildNumber)")
$collectedData | Add-Member -MemberType NoteProperty -Name LastBoot -Value $lastBoot
$collectedData | Add-Member -MemberType NoteProperty -Name Current_user -Value $currentUser
$collectedData | Add-Member -MemberType NoteProperty -Name User_belongs_to -Value $currentUserGroups
$collectedData | Add-Member -MemberType NoteProperty -Name All_local_admins -Value $allLocalAdmins
$collectedData | Add-Member -MemberType NoteProperty -Name Bitlocker-C -Value $statusBitLocker
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_lastSearchSuccessDate -Value $lastSearchSuccessDate
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_lastInstallationSuccessDate -Value $lastInstallationSuccessDate
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_installed -Value $installedWindowsUpdates
$collectedData | Add-Member -MemberType NoteProperty -Name Software -Value $installedSoftware
$collectedData | Add-Member -MemberType NoteProperty -Name Non_standard_win_services -Value $nonStandardWinServices
$collectedData | Add-Member -MemberType NoteProperty -Name Non_MS_scheduled_tasks -Value $nonMSScheduledTasks
$collectedData | Add-Member -MemberType NoteProperty -Name Firewall -Value $firewallStatus
$collectedData | Add-Member -MemberType NoteProperty -Name Antivirus -Value $avProducts

foreach ($avProduct in $avProducts)
{
  $avStatus = Get-AV-Status $avProduct.productState $avProduct.displayName
  $collectedData | Add-Member -MemberType NoteProperty -Name $avProduct.displayName -Value $avStatus
}

$collectedData | Add-Member -MemberType NoteProperty -Name IP_config -Value $ipConfig
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing -Value $routingTable
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing_non_local_dst -Value $routesToNonLocalDST
$collectedData | Add-Member -MemberType NoteProperty -Name Net_connection_profile -Value $netConnectionProfile

Write-Host "Saving collected data to $currentPath\$($compSys.Name).json"
$collectedData | ConvertTo-EnumsAsStrings | ConvertTo-Json -depth 100 | Set-Content "$currentPath\$($compSys.Name).json"
Get-FileHash "$currentPath\$($compSys.Name).json"
Write-Host "Hash written to $currentPath\$($compSys.Name).sha256"
Get-FileHash "$currentPath\$($compSys.Name).json" | Set-Content "$currentPath\$($compSys.Name).sha256"
Write-Host "All done, have fun!"

}

Filter ConvertTo-EnumsAsStrings ([int] $Depth = 10, [int] $CurrDepth = 0) {

  if ($CurrDepth -gt $Depth) {
    Write-Error "Recursion exceeded depth limit of $Depth"
    return $null
  }

  Switch ($_) {
    { $_ -is [enum] -or $_ -is [version] -or $_ -is [IPAddress] -or $_ -is [Guid] } {
      $_.ToString()
    }
    { $_ -is [datetimeoffset] } {
      $_.UtcDateTime.ToString('o')
    }
    { $_ -is [datetime] } {
      $_.ToUniversalTime().ToString('o')
    }
    { $_ -is [timespan] } {
      $_.TotalSeconds
    }
    { $null -eq $_ -or $_.GetType().IsPrimitive -or $_ -is [string] -or $_ -is [decimal] } {
      $_
    }
    { $_ -is [hashtable] } {
      $ht = [ordered]@{}
      $_.GetEnumerator() | ForEach-Object {
        $ht[$_.Key] = ($_.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth + 1))
      }
      if ($ht.Keys.Count) {
        $ht
      }
    }
    { $_ -is [pscustomobject] } {
      $ht = [ordered]@{}
      $_.PSObject.Properties | ForEach-Object {
        if ($_.MemberType -eq 'NoteProperty') {
          Switch ($_) {
            { $_.Value -is [array] -and $_.Value.Count -eq 0 } {
              $ht[$_.Name] = @()
            }
            { $_.Value -is [hashtable] -and $_.Value.Keys.Count -eq 0 } {
              $ht[$_.Name] = @{}
            }
            Default {
              $ht[$_.Name] = ($_.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth + 1))
            }
          }
        }
      }
      if ($ht.Keys.Count) {
        $ht
      }
    }
    Default {
      Write-Error "Type not supported: $($_.GetType().ToString())"
    }
  }
}

Function Get-AV-Status {
    Param([UInt32]$state,[string]$dName)

# define bit flags

[Flags()] enum ProductState 
{
      Off         = 0x0000
      On          = 0x1000
      Snoozed     = 0x2000
      Expired     = 0x3000
}

[Flags()] enum SignatureStatus
{
      UpToDate     = 0x00
      OutOfDate    = 0x10
}

[Flags()] enum ProductOwner
{
      NonMs        = 0x000
      Windows      = 0x100
}

# define bit masks

[Flags()] enum ProductFlags
{
      SignatureStatus = 0x00F0
      ProductOwner    = 0x0F00
      ProductState    = 0xF000
}


# decode bit flags by masking the relevant bits, then convert and return result

return [PSCustomObject]@{
      Product = $dName
      ProductState = [ProductState]($state -band [ProductFlags]::ProductState)
      SignatureStatus = [SignatureStatus]($state -band [ProductFlags]::SignatureStatus)
      Owner = [ProductOwner]($state -band [ProductFlags]::ProductOwner)
}
    
}


function Get-Groups {
    Param(
        [string]$isMember
    )

    if($isMember)
    {
        $mytoken = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $me = New-Object System.Security.Principal.WindowsPrincipal($mytoken)
        return $me.IsInRole($isMember)
    }
    else
    {
        $user_token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $groups = New-Object System.Collections.ArrayList
        foreach($group in $user_token.Groups)
        {
           [void] $groups.Add( $group.Translate("System.Security.Principal.NTAccount") )
        }
        return [string[]] $groups
    }
}


function Get-BitLockerStatus {
[CmdletBinding()]
	param (
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias("Drive")]
		[String]$DriveLetter = "C:"
)
	$cmd = "(New-Object -ComObject Shell.Application).NameSpace('$DriveLetter').Self.ExtendedProperty('System.Volume.BitLockerProtection')"
	$bitLockerResult = Invoke-Expression -Command $cmd
	if ($bitLockerResult -eq "1") {
		$BitLockerStatus = $true
	}	else{
	$BitLockerStatus = $false
	}
return $BitLockerStatus
}


function Check-IfAzureJoined {

$regKey = "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"

$test = test-path -path $regKey

if ($test) {
	$subKey = Get-Item $regKey
    $guids = $subKey.GetSubKeyNames()

	foreach($guid in $guids) {
		$guidSubKey = $subKey.OpenSubKey($guid);
		$tenantId = $guidSubKey.GetValue("TenantId");
	}

return $tenantId

}

return "Not joined."
}

function Check-WhoJoinedAzure {

$regKey = "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"

$test = test-path -path $regKey

if ($test) {
	$subKey = Get-Item $regKey
    $guids = $subKey.GetSubKeyNames()

	foreach($guid in $guids) {
		$guidSubKey = $subKey.OpenSubKey($guid);
		$tenantId = $guidSubKey.GetValue("UserEmail");
	}

return $userEmail

}

return "Not joined."

}

# Execute main function
& $MainFunction
