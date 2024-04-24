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
Write-Host "Collecting current user."
$currentUser       = (Get-CimInstance CIM_ComputerSystem | select username).username
Write-Host "Collecting current user group membership."
$currentUserGroups = Get-Groups
Write-Host "Collecting local admin accounts."
$allLocalAdmins    = Get-LocalGroupMember Administrators | Select Name
Write-Host "Collecting Enabled local admin accounts."
$activeLocalAdmins = Get-LocalGroupMember Administrators | Where-Object { (Get-LocalUser $_.SID -EA 0).Enabled } | Select Name
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
$antiVirusStatus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select displayName, productState, timestamp 

$hx = ConvertTo-Hex $antivirusStatus.ProductState

$AV_UpToDate = Get-AV-UpToDate $hx.Substring(5)
$AV_Enabled  = Get-AV-Enabled $hx.Substring(3, 2)

Write-Host "Processing collected data."
$collectedData = New-Object -TypeName psobject

$collectedData | Add-Member -MemberType NoteProperty -Name ForensicsDate -Value $currentDate
$collectedData | Add-Member -MemberType NoteProperty -Name Description -Value $description
$collectedData | Add-Member -MemberType NoteProperty -Name ComputerName -Value $compSys.Name
$collectedData | Add-Member -MemberType NoteProperty -Name Domain -Value $compSys.Domain
$collectedData | Add-Member -MemberType NoteProperty -Name Workgroup -Value $compSys.Workgroup
$collectedData | Add-Member -MemberType NoteProperty -Name OS -Value $osInfo.Caption
$collectedData | Add-Member -MemberType NoteProperty -Name OS_Version -Value $("$($osInfo.Version) Build $($osInfo.BuildNumber)")
$collectedData | Add-Member -MemberType NoteProperty -Name Current_user -Value $currentUser
$collectedData | Add-Member -MemberType NoteProperty -Name User_belongs_to -Value $currentUserGroups
$collectedData | Add-Member -MemberType NoteProperty -Name All_local_admins -Value $allLocalAdmins
$collectedData | Add-Member -MemberType NoteProperty -Name Enabled_local_admins -Value $activeLocalAdmins
$collectedData | Add-Member -MemberType NoteProperty -Name Bitlocker-C -Value $statusBitLocker
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_lastSearchSuccessDate -Value $lastSearchSuccessDate
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_lastInstallationSuccessDate -Value $lastInstallationSuccessDate
$collectedData | Add-Member -MemberType NoteProperty -Name Updates_installed -Value $installedWindowsUpdates
$collectedData | Add-Member -MemberType NoteProperty -Name Software -Value $installedSoftware
$collectedData | Add-Member -MemberType NoteProperty -Name Non_standard_win_services -Value $nonStandardWinServices
$collectedData | Add-Member -MemberType NoteProperty -Name Non_MS_scheduled_tasks -Value $nonMSScheduledTasks
$collectedData | Add-Member -MemberType NoteProperty -Name Firewall -Value $firewallStatus
$collectedData | Add-Member -MemberType NoteProperty -Name Antivirus -Value $antivirusStatus
$collectedData | Add-Member -MemberType NoteProperty -Name AV_enabled -Value $AV_Enabled
$collectedData | Add-Member -MemberType NoteProperty -Name AV_upToDate -Value $AV_UpToDate
$collectedData | Add-Member -MemberType NoteProperty -Name IP_config -Value $ipConfig
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing -Value $routingTable
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing_non_local_dst -Value $routesToNonLocalDST
$collectedData | Add-Member -MemberType NoteProperty -Name Net_connection_profile -Value $netConnectionProfile

Write-Host "Saving collected data to $currentPath\$($compSys.Name).json"
$collectedData | ConvertTo-Json -depth 100 | Set-Content "$currentPath\$($compSys.Name).json"
Get-FileHash "$currentPath\$($compSys.Name).json"
Write-Host "Hash written to $currentPath\$($compSys.Name).sha256"
Get-FileHash "$currentPath\$($compSys.Name).json" | Set-Content "$currentPath\$($compSys.Name).sha256"
Write-Host "All done, have fun!"

}



Function Get-AV-UpToDate {
    Param([string]$end)

if ($end -eq "00") {
    return $true
} else {
    return $false
}
    
}


Function Get-AV-Enabled {
    Param([string]$mid)

if ($mid -match "00|01") {
    return $false
} else {
    return $true
}
    
}

Function ConvertTo-Hex {
    Param([int]$Number)
		'0x{0:x}' -f $Number
}

function Get-Groups {
    
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
        return $groups
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

# Execute main function
& $MainFunction
