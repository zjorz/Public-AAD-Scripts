### Abstract: This PoSH Script Helps To Create A Report Regarding The Status Of The Azure AD Password Protection DC Agent Throughout The RWDCs In The AD Forest
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-08: Initial version of the script (v0.1)
### 2019-10-22: Improved output on screen to be more clear and added check for required .NET Framework version (v0.2)
### 2019-10-23: Added additional column/output to see difference between "registered in AD" and "installed on DC" (v0.3)
### 2019-10-31: Updated some minor bugs and added to the list if it is Full GUI or Server Core (v0.4)

<#
.SYNOPSIS
	With this PoSH script, one can create a report regarding the status of the Azure AD Password Protection DC Agent throughout the RWDCs in the AD forest.

.DESCRIPTION
	With this PoSH script, one can create a report regarding the status of the Azure AD Password Protection DC Agent throughout the RWDCs in the AD forest.

.PARAMETER scope
	The scope to use when targeting RWDCs. Options are forest, domain or rwdc
	
.PARAMETER domains
	The FQDN of the AD domain(s), in a comma separated list, to target

.PARAMETER servers
	The FQDN of the DC(s), in a comma separated list, to target

.EXAMPLE
	Check The Install Of The Azure AD Password Protection DC Agent Through The AD Forest
	
	.\AAD-Password-Protection-Install-DC-Agent-Check.ps1 -scope Forest

.EXAMPLE
	Check The Install Of The Azure AD Password Protection DC Agent Through The Specified AD Domain(s)
	
	.\AAD-Password-Protection-Install-DC-Agent-Check.ps1 -scope Domain -domains COMPANY.COM,CHILD.COMPANY.COM

.EXAMPLE
	Check The Install Of The Azure AD Password Protection DC Agent Through The Specified RWDCs(s)
	
	.\AAD-Password-Protection-Install-DC-Agent-Check.ps1 -scope RWDC -servers DC1.COMPANY.COM,DC2.COMPANY.COM,DC3.CHILD.COMPANY.COM

.NOTES
	Must be executed on the server with the Azure AD Password Protection Proxy Service!
	
	Requires the Active Directory PowerShell CMDlets!
	
	Requires the Azure AD Password Protection PowerShell CMDlets!
	
	Requires "Enterprise Admins" Permissions!
#>

Param(
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the scope of RWDCs to target')]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("Forest", "Domain", "RWDC")]
	[string]$scope,
	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the list of AD domains by specifying FQDNs in a comma-separated manner')]
	[string[]]$domains,
	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the list of RWDCs by specifying FQDNs in a comma-separated manner')]
	[string[]]$servers
)

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($PoSHModule) {
	If(@(Get-Module | Where-Object {$_.Name -eq $PoSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object {$_.Name -eq $PoSHModule} ).count -ne 0) {
			Import-Module $PoSHModule
			Write-Host ""
			Write-Host "PoSH Module '$PoSHModule' Has Been Loaded..." -ForeGroundColor Green
			Write-Host "Continuing Script..." -ForeGroundColor Green
			Write-Host ""
		} Else {
			Write-Host ""
			Write-Host "PoSH Module '$PoSHModule' Is Not Available To Load..." -ForeGroundColor Red
			Write-Host "Aborting Script..." -ForeGroundColor Red
			Write-Host ""
			
			EXIT
		}
	} Else {
		Write-Host ""
		Write-Host "PoSH Module '$PoSHModule' Already Loaded..." -ForeGroundColor Yellow
		Write-Host "Continuing Script..." -ForeGroundColor Yellow
		Write-Host ""
	}
}

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer, $port, $timeOut) {
	# Test To See If The HostName Is Resolvable At All
	Try {
		[System.Net.Dns]::gethostentry($fqdnServer) | Out-Null
	} Catch {
		Return "ERROR"
	}
	
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		#$error.Clear()
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Check .NET Version
Function checkDotNETVersion() {
	# Get Installed Version Of .NET
	$dotNETVersionNrInstalled = $null
	$dotNETVersionNrInstalled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release).Release
	
	# Determine .NET Framework Version Text
	If ($dotNETVersionNrInstalled) {
		$dotNETVErsionText = $null
		Switch ($dotNETVersionNr) {
			# SOURCE: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
			{$dotNETVersionNrInstalled -lt 378389} {$dotNETVErsionText = ".NET Framework 4 Or Lower"}
			{$dotNETVersionNrInstalled -eq 378389} {$dotNETVErsionText = ".NET Framework 4.5"}		# All Windows operating systems
			{$dotNETVersionNrInstalled -eq 378389} {$dotNETVErsionText = ".NET Framework 4.5"}		# All Windows operating systems
			{$dotNETVersionNrInstalled -eq 378675} {$dotNETVErsionText = ".NET Framework 4.5.1"}	# On Windows 8.1 and Windows Server 2012 R2
			{$dotNETVersionNrInstalled -eq 378758} {$dotNETVErsionText = ".NET Framework 4.5.1"}	# On all other Windows operating systems
			{$dotNETVersionNrInstalled -eq 379893} {$dotNETVErsionText = ".NET Framework 4.5.2"}
			{$dotNETVersionNrInstalled -eq 393295} {$dotNETVErsionText = ".NET Framework 4.6"}		# On Windows 10
			{$dotNETVersionNrInstalled -eq 393297} {$dotNETVErsionText = ".NET Framework 4.6"}		# On all other Windows operating systems
			{$dotNETVersionNrInstalled -eq 394254} {$dotNETVErsionText = ".NET Framework 4.6.1"}	# On Windows 10 November Update systems
			{$dotNETVersionNrInstalled -eq 394271} {$dotNETVErsionText = ".NET Framework 4.6.1"}	# On all other Windows operating systems (including Windows 10)
			{$dotNETVersionNrInstalled -eq 394802} {$dotNETVErsionText = ".NET Framework 4.6.2"}	# On Windows 10 Anniversary Update and Windows Server 2016
			{$dotNETVersionNrInstalled -eq 394806} {$dotNETVErsionText = ".NET Framework 4.6.2"}	# On all other Windows operating systems (including other Windows 10 operating systems)
			{$dotNETVersionNrInstalled -eq 460798} {$dotNETVErsionText = ".NET Framework 4.7"}		# On Windows 10 Creators Update
			{$dotNETVersionNrInstalled -eq 460805} {$dotNETVErsionText = ".NET Framework 4.7"}		# On all other Windows operating systems (including other Windows 10 operating systems)
			{$dotNETVersionNrInstalled -eq 461308} {$dotNETVErsionText = ".NET Framework 4.7.1"}	# On Windows 10 Fall Creators Update and Windows Server, version 1709
			{$dotNETVersionNrInstalled -eq 461310} {$dotNETVErsionText = ".NET Framework 4.7.1"}	# On all other Windows operating systems (including other Windows 10 operating systems)
			{$dotNETVersionNrInstalled -eq 461808} {$dotNETVErsionText = ".NET Framework 4.7.2"}	# On Windows 10 April 2018 Update and Windows Server, version 1803
			{$dotNETVersionNrInstalled -eq 461814} {$dotNETVErsionText = ".NET Framework 4.7.2"}	# On all Windows operating systems other than Windows 10 April 2018 Update and Windows Server, version 1803
			{$dotNETVersionNrInstalled -eq 528040} {$dotNETVErsionText = ".NET Framework 4.8"}		# On Windows 10 May 2019 Update
			{$dotNETVersionNrInstalled -eq 528049} {$dotNETVErsionText = ".NET Framework 4.8"}		# On all others Windows operating systems (including other Windows 10 operating systems)
			{$dotNETVersionNrInstalled -gt 528049} {$dotNETVErsionText = "Higher Than .NET Framework 4.8"}
			Default {$dotNETVErsionText = "Unable To Determine .NET Framework Version"}
		}
	} Else {
		$dotNETVErsionText = ".NET Framework Not Installed (Min. v4.7)"
	}

	If ($dotNETVersionNrInstalled -ge 460798) {
		Return "dotNETOK",$($dotNETVErsionText + " (Min. v4.7)")
	} Else {
		Return "dotNETNOK",$($dotNETVErsionText + " (Min. v4.7)")
	}
}
$checkDotNETVersionDef = "function checkDotNETVersion{${function:checkDotNETVersion}}"

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ CHECK INSTALL OF THE AZURE AD PASSWORD PROTECTION DC AGENT +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 140
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 140) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 140
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

Write-Host ""
Write-Host "                             **************************************************************************" -ForeGroundColor Cyan
Write-Host "                             *                                                                        *" -ForeGroundColor Cyan
Write-Host "                             *     --> Check Install Of Azure AD Password Protection DC Agent <--     *" -ForeGroundColor Cyan
Write-Host "                             *                                                                        *" -ForeGroundColor Cyan
Write-Host "                             *              Written By: Jorge de Almeida Pinto [MVP-EMS]              *" -ForeGroundColor Cyan
Write-Host "                             *                                                                        *" -ForeGroundColor Cyan
Write-Host "                             *            BLOG: http://jorgequestforknowledge.wordpress.com/          *" -ForeGroundColor Cyan
Write-Host "                             *                                                                        *" -ForeGroundColor Cyan
Write-Host "                             **************************************************************************" -ForeGroundColor Cyan
Write-Host ""

### Check The Arguments/Parameters
If ($psboundparameters.count -eq 0 -Or $args.count -gt 0) {
	Write-Host ""
	Write-Host "No Arguments/Parameters Were Specified..." -ForeGroundColor Red
	Write-Host "Showing Full Help..." -ForeGroundColor Red
	Write-Host ""
	Get-help $MyInvocation.MyCommand.Definition -full
	
	EXIT
}

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
"ActiveDirectory","AzureADPasswordProtection" | %{loadPoSHModules $_}

Write-Host ""
Write-Host "Operational Mode.......................: $($scope.ToUpper())" -ForegroundColor Magenta

### Definition Of Some Constants
$dateTime = Get-Date -Format "yyyy-MM-dd_HH.mm.ss"
$currentScriptPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$outputCSVFilePath = $currentScriptFolderPath + "\" + $dateTime + "_AAD-Pwd-Protection-DC-Agent-Status-Check_" + $($scope.ToUpper()) + ".CSV"

### Getting Basic AD Forest Info
$adForest  = Get-ADForest
$adForestDomainFQDNs = $adForest.Domains
$adForestRootADDomainFQDN = $adForest.RootDomain
$adForestRootDomainDN = "DC=" + $adForestRootADDomainFQDN.Replace(".",",DC=")
$adForestRootDomainDomainSID = (Get-ADDomain $adForestRootADDomainFQDN).DomainSID.Value
$adRwdcFQDN = ((Get-ADDomainController -Discover).HostName)[0]
$adRootDSENearestRWDC = Get-ADRootDSE -Server $adRwdcFQDN
$adForestConfigNC = $adRootDSENearestRWDC.configurationNamingContext

# Retrieve AD Domain FQDNs In AD Forest And Build The Order As Such The Forest Root AD Domain Is At The Top Of The List
$adDomainFQDNList = @()
$adDomainFQDNList += $adForestRootADDomainFQDN
If ($adForestDomainFQDNs.Count -gt 1) {
	$adForestDomainFQDNs | ?{$_ -ne $adForestRootADDomainFQDN -And $_ -match $adForestRootADDomainFQDN} | Sort-Object | %{
		$adDomainFQDNList += $_
	}
	$adDomainCrossRefs = $null
	$adDomainCrossRefs = Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))" -SearchBase "CN=Partitions,$adForestConfigNC" -Properties *
	$adRootDomainCrossRefDN = $null
	$adRootDomainCrossRefDN = ($adDomainCrossRefs | ?{$_.nCName -eq $adForestRootDomainDN}).DistinguishedName
	$adDomainCrossRefs | ?{$_.rootTrust -eq $adRootDomainCrossRefDN} | %{
		$ncName = $null
		$ncName = $_.nCName
		$adDomainFQDN = $null
		$adDomainFQDN = $ncName.Replace(",DC=",".").Replace("DC=","")
		$adDomainFQDNList += $adDomainFQDN
		$adForestDomainFQDNs | ?{$_ -ne $adDomainFQDN -And $_ -match $adDomainFQDN} | Sort-Object | %{
			$adDomainFQDNList += $_
		}
	}
}

# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
$enterpriseAdminRID = "519"
$enterpriseAdminObjectSID = $adForestRootDomainDomainSID + "-" + $enterpriseAdminRID
$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($enterpriseAdminObjectSID)).Translate([System.Security.Principal.NTAccount]).Value
$userIsEnterpriseAdmin = $null
$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
If (!$userIsEnterpriseAdmin) {
	# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
	Write-Host ""
	Write-Host "WARNING: Your User Account Is Not Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootADDomainFQDN'!..." -ForeGroundColor Red
	Write-Host "For This Script To Run Successfully, Enterprise Administrator Equivalent Permissions Are Required..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
} Else {
	# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
	Write-Host ""
	Write-Host "Your User Account Is Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootADDomainFQDN'!..." -ForeGroundColor Green
	Write-Host "Continuing Script..." -ForeGroundColor Green
	Write-Host ""
}


### Retrieve All The RWDCs In The AD Forest And The Ones That Have The Azure AD Password Protection Agent Installed
If ($scope.ToUpper() -eq "FOREST") {
	# Define Empty Array For Scoped RWDCs
	$scopedDCs = @()
	
	# For Every AD Domain In The AD Forest
	$adDomainFQDNList | %{
		# The AD Domain
		$adDomain = $null
		$adDomain = $_
		
		# Retrieve All The RWDCs In The AD Domain
		$dcsInADDomain = $null
		$dcsInADDomain = (Get-ADdomain $adDomain).ReplicaDirectoryServers
		
		# If There Are RWDCs, Then Add To The List Of Scoped RWDCs
		If ($dcsInADDomain) {
			$dcsInADDomain | %{
				$dcInDomain = $null
				$dcInDomain = $_
				$scopedDCs += $adDomain + "|" + $dcInDomain
			}
		}
	}

	# Get All RWDCs In The AD Forest With The Azure AD Password Protection DC Agent Installed
	$scopedDCsWithAADPwdProtectionDCAgent = Get-AzureADPasswordProtectionDCAgent -Forest $adForestRootADDomainFQDN
}

### Retrieve All The RWDCs In The Specified AD Domain(s) And The Ones That Have The Azure AD Password Protection Agent Installed
If ($scope.ToUpper() -eq "DOMAIN") {
	# If Any Domain(s) Has Been Specified
	If ($domains) {
		# Define Empty Array For Scoped RWDCs
		$scopedDCs = @()
		
		# Define Empty Array For Scoped RWDCs With The Azure AD Password Protection DC Agent Installed
		$scopedDCsWithAADPwdProtectionDCAgent = @()
		$domains | %{
			$adDomain = $null
			$adDomain = $_
			
			# If The Specified AD Domain Exists In The AD Forest, Get The List Of RWDCs In The AD Domain
			If ($adDomainFQDNList -contains $adDomain) {
				# Retrieve All The RWDCs In The AD Domain
				$dcsInADDomain = $null
				$dcsInADDomain = (Get-ADdomain $adDomain).ReplicaDirectoryServers
				
				# If There Are RWDCs, Then Add To The List Of Scoped RWDCs
				If ($dcsInADDomain) {
					$dcsInADDomain | %{
						$dcInDomain = $null
						$dcInDomain = $_
						$scopedDCs += $adDomain + "|" + $dcInDomain
					}
				}
				
				# Get All RWDCs In The AD Domain With The Azure AD Password Protection DC Agent Installed
				$dcsInADDomainWithAADPwdProtectionDCAgent = $null
				$dcsInADDomainWithAADPwdProtectionDCAgent = Get-AzureADPasswordProtectionDCAgent -Domain $adDomain
				$scopedDCsWithAADPwdProtectionDCAgent += $dcsInADDomainWithAADPwdProtectionDCAgent
			} Else {
				Write-Host ""
				Write-Host "The AD Domain '$adDomain' DOES NOT Exist..." -ForegroundColor Red
				Write-Host "Skipping AD Domain '$adDomain'..." -ForegroundColor Red
			}
		}
	}
}

### Retrieve For All The Specified RWDCs That Have The Azure AD Password Protection Agent Installed
If ($scope.ToUpper() -eq "RWDC") {
	# If Any RWDC(s) Has Been Specified
	If ($servers) {
		# Built A Temp List With All RWDCs In The AD Forest
		$listOfRWDCsTemp = @()
		$adDomainFQDNList | %{
			$adDomain = $null
			$adDomain = $_
			
			# Retrieve The RWDCs In The AD Domain
			$rwdcsInDomain = $null
			$rwdcsInDomain = (Get-ADDomain $adDomain).ReplicaDirectoryServers
			
			# Add Every RWDC To The List Of RWDCs
			$rwdcsInDomain | %{
				$dcInDomain = $null
				$dcInDomain = $_
				$listOfRWDCsTemp += $dcInDomain
			}
		}

		# Get All RWDCs In The AD Forest With The Azure AD Password Protection DC Agent Installed
		$dcsInADForestWithAADPwdProtectionDCAgent = Get-AzureADPasswordProtectionDCAgent -Forest $adForestRootADDomainFQDN
		
		# Define Empty Array For Scoped RWDCs With The Azure AD Password Protection DC Agent Installed
		$scopedDCsWithAADPwdProtectionDCAgent = @()
		
		# For Every Specified RWDC
		$servers | %{
			# The RWDC
			$server = $null
			$server = $_
			
			# If The Specified RWDC Exists In The AD Forest, Then Add It To The List Of Scoped RWDCs
			If ($listOfRWDCsTemp -contains $server) {
				$adDomain = $null
				$adDomain = $server.SubString($server.IndexOf(".") + 1)
				If ($scopedDCs -notcontains $($adDomain + "|" + $server)) {
					$scopedDCs += $($adDomain + "|" + $server)
				}
			} Else {
				Write-Host ""
				Write-Host "The RWDC '$server' DOES NOT Exist..." -ForegroundColor Red
				Write-Host "Skipping RWDC '$server'..." -ForegroundColor Red
			}
			
			# If The Specified RWDC Exists As Having The Azure AD Password Protection DC Agent Installed, Then Add It To The List Of Scoped RWDCs With The Azure AD Password Protection DC Agent Installed
			If ($dcsInADForestWithAADPwdProtectionDCAgent.ServerFQDN -contains $server) {
				$dcWithAADPwdProtectionDCAgent = $null
				$dcWithAADPwdProtectionDCAgent = $dcsInADForestWithAADPwdProtectionDCAgent | ?{$_.ServerFQDN -eq $server}
				$scopedDCsWithAADPwdProtectionDCAgent += $dcWithAADPwdProtectionDCAgent
			}
		}
	}
}

# Building Empty List Of Installation Results
$bplStatusResultOnRWDCs = @()

### For Every Scoped RWDC, If Any
If ($scopedDCs) {
	$scopedDCs | %{
		$entry = $null
		$entry = $_
		
		# Get The FQDN Of The AD Domain Of The RWDC
		$adDomain = $null
		$adDomain = $entry.SubString(0, $entry.IndexOf("|"))
		
		# Get The FQDN Of The RWDC
		$dcInDomain = $null
		$dcInDomain = $entry.SubString($entry.IndexOf("|") + 1)

		# Check The Connection To The RWDC
		$ports = 5985	# WinRM For Remote PowerShell
		$connectionCheckOK = $true
		$ports | %{
			$port = $null
			$port = $_
			$connectionResult = $null
			$connectionResult = portConnectionCheck $dcInDomain $port 500
			If ($connectionResult -eq "ERROR") {
				$connectionCheckOK = $false
			}
		}
			
		$checkResultOnDC = $null

		# If The Connection To The RWDC Is OK...
		If ($connectionCheckOK) {		
			# Setup A Session To The RWDC
			$targetedDCSession = $null
			$targetedDCSession = New-PSSession -ComputerName $dcInDomain

			# Connect To The RWDC And Execute The Scriptblock
			$checkResultOnDC = Invoke-Command -Session $targetedDCSession -ArgumentList $ports,$dcInDomain,$checkDotNETVersionDef -ScriptBlock {
				Param(
					$ports,
					$dcInDomain,
					$checkDotNETVersionDef
				)

				. ([ScriptBlock]::Create($checkDotNETVersionDef))

				# Retrieve The OS Version
				$operatingSystem = $null
				$operatingSystem = Get-WmiObject Win32_OperatingSystem
				$windowsCaption = $null
				$windowsCaption = $operatingSystem.Caption
				$windowsVersion = $null
				$windowsVersion = $operatingSystem.Version
				
				
				### Determine Full Server Or Server Core
				$windowsDirectoryFolderPath = (Get-WmiObject Win32_OperatingSystem).WindowsDirectory
				$explorerPath = Join-Path $windowsDirectoryFolderPath "explorer.exe"
				If (Test-Path $explorerPath) {
					$windowsType = "Full Server"
				} Else {
					$windowsType = "Server Core"
				}
				
				# Determine Pending/Required Reboot
				$rebootPending = $null
				$rebootPending = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\" -Name RebootPending -ErrorAction Ignore
				If ($rebootPending) {
					$rebootPending = $true
				} Else {
					$rebootPending = $false
				}
				$rebootRequired = $null
				$rebootRequired = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\" -Name RebootRequired -ErrorAction Ignore
				If ($rebootRequired) {
					$rebootRequired = $true
				} Else {
					$rebootRequired = $false
				}
				
				# Check The .NET Framework Version
				$checkDotNETVersionResult = $null
				$checkDotNETVersionResult = checkDotNETVersion

				# Retrieve The 'Azure AD Password Protection DC Agent' Product Installation
				$productAADPwdProtectDCAgent = $null
				$productAADPwdProtectDCAgent = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection DC Agent'"
				$productAADPwdProtectDCAgentInstalledVersion = $($productAADPwdProtectDCAgent.Version)
				If (!$productAADPwdProtectDCAgentInstalledVersion) {
					$productAADPwdProtectDCAgentInstalledVersion = "Not Installed"
				}

				Return $checkDotNETVersionResult + "serverOK" + "ALL Required Ports ($($ports -join ',')) To The Domain Controller '$dcInDomain' Are Available!..." + $windowsCaption + $windowsVersion + $windowsType + $rebootPending + $rebootRequired + $productAADPwdProtectDCAgentInstalledVersion
			}
		} Else {
			$checkResultOnDC = "dotNETNOK","Unable To Determine .NET Framework Version","serverNOK","ALL Required Ports ($($ports -join ',')) To The Domain Controller '$dcInDomain' ARE NOT Available!...`nSkipping Domain Controller '$dcInDomain' For .NET Framework Check...","Unable To Determine","Unable To Determine","Unable To Determine","Unable To Determine","Unable To Determine","Unable To Determine"
		}

		$dcWithAADPwdProtectionDCAgent = $($scopedDCsWithAADPwdProtectionDCAgent | ?{$_.ServerFQDN -eq $dcInDomain})

		Write-Host ""
		Write-Host "AD Domain..............................: $adDomain" -ForegroundColor Magenta
		Write-Host "--> Domain Controller..................: $dcInDomain" -ForegroundColor Cyan
		If ($checkResultOnDC[2] -eq "serverNOK") {
			Write-Host "  $($checkResultOnDC[3])" -ForegroundColor Red
		} Else {
			Write-Host "  $($checkResultOnDC[3])" -ForegroundColor Green
		}
		
		Write-Host "   * Version Operating System..........:" -NoNewLine -ForegroundColor Yellow
		If ($checkResultOnDC[2] -eq "serverNOK") {
			Write-Host " $($checkResultOnDC[4]) ($($checkResultOnDC[5]))" -ForegroundColor Red
		} Else {
			Write-Host " $($checkResultOnDC[4]) ($($checkResultOnDC[5]))" -ForegroundColor Green
		}
		
		Write-Host "   * Server Type.......................:" -NoNewLine -ForegroundColor Yellow
		If ($checkResultOnDC[2] -eq "serverNOK") {
			Write-Host " $($checkResultOnDC[6])" -ForegroundColor Red
		} Else {
			Write-Host " $($checkResultOnDC[6])" -ForegroundColor Green
		}
		
		Write-Host "   * Reboot Pending/Required...........:" -NoNewLine -ForegroundColor Yellow
		If ($checkResultOnDC[2] -eq "serverNOK") {
			$reboot = "Unable To Determine"
			Write-Host " $reboot" -ForegroundColor Red		
		} ElseIf ($checkResultOnDC[7] -eq $true -Or $checkResultOnDC[8] -eq $true) {
			$reboot = "TRUE"
			Write-Host " $reboot" -ForegroundColor Yellow
		} Else {
			$reboot = "FALSE"
			Write-Host " $reboot" -ForegroundColor Green
		}
		
		Write-Host "   * Status .NET Framework.............:" -NoNewLine -ForegroundColor Yellow
		If ($checkResultOnDC[0] -eq "dotNETNOK") {
			Write-Host " $($checkResultOnDC[1])" -ForegroundColor Red
		} Else {
			Write-Host " $($checkResultOnDC[1])" -ForegroundColor Green
		}
		
		Write-Host "   * Status BPL DC Agent...............:" -NoNewLine -ForegroundColor Yellow
		If ($checkResultOnDC[9] -eq "Unable To Determine") {
			Write-Host " $($checkResultOnDC[9])" -ForegroundColor Red
			Write-Host "   * Version DC Agent (Installed)......:" -NoNewLine -ForegroundColor Yellow
			Write-Host " $($checkResultOnDC[9])" -ForegroundColor Red
		} ElseIf ($checkResultOnDC[9] -eq "Not Installed") {
			Write-Host " $($checkResultOnDC[9])" -ForegroundColor Red
			Write-Host "   * Version DC Agent (Installed)......:" -NoNewLine -ForegroundColor Yellow
			Write-Host " $($checkResultOnDC[9])" -ForegroundColor Red
		} Else {
			Write-Host " Installed" -ForegroundColor Green
			Write-Host "   * Version DC Agent (Installed)......:" -NoNewLine -ForegroundColor Yellow
			Write-Host " $($checkResultOnDC[9])" -ForegroundColor Green
		}

		Write-Host "   * Version DC Agent (Registered).....:" -NoNewLine -ForegroundColor Yellow
		If ($($dcWithAADPwdProtectionDCAgent.SoftwareVersion)) {
			Write-Host " $($dcWithAADPwdProtectionDCAgent.SoftwareVersion)" -ForegroundColor Green	
		} Else {
			Write-Host " Not Registered/Unknown" -ForegroundColor Red
		}

		Write-Host "   * Password Policy Date (UTC)........:" -NoNewLine -ForegroundColor Yellow
		If ($($dcWithAADPwdProtectionDCAgent.PasswordPolicyDateUTC)) {
			Write-Host " $($dcWithAADPwdProtectionDCAgent.PasswordPolicyDateUTC)" -ForegroundColor Green	
		} Else {
			Write-Host " Not Registered/Unknown" -ForegroundColor Red
		}
		
		Write-Host "   * HeartBeat (UTC)...................:" -NoNewLine -ForegroundColor Yellow
		If ($($dcWithAADPwdProtectionDCAgent.HeartbeatUTC)) {
			Write-Host " $($dcWithAADPwdProtectionDCAgent.HeartbeatUTC)" -ForegroundColor Green
		} Else {
			Write-Host " Not Registered/Unknown" -ForegroundColor Red
		}

		Write-Host "   * Azure AD Tenant...................:" -NoNewLine -ForegroundColor Yellow
		If ($($dcWithAADPwdProtectionDCAgent.AzureTenant)) {
			Write-Host " $($dcWithAADPwdProtectionDCAgent.AzureTenant)" -ForegroundColor Green
		} Else {
			Write-Host " Not Registered/Unknown" -ForegroundColor Red
		}

		$bplStatusResultOnRWDC = New-Object -TypeName System.Object
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $adDomain
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $dcInDomain
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Operating System" -Value $($($checkResultOnDC[4]) + " " + $($checkResultOnDC[5]))
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Server Type" -Value $($checkResultOnDC[6])
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Reboot?" -Value $reboot
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "dotNET Version" -Value $($checkResultOnDC[1])
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "BPL DC Agent" -Value $(If ($checkResultOnDC[9] -eq "Unable To Determine") {"Unable To Determine"} ElseIf ($checkResultOnDC[9] -eq "Not Installed") {"Not Installed"} Else {"Installed"})
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "ver DC Agent (Inst)" -Value $($checkResultOnDC[9])
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "ver DC Agent (Reg)" -Value $(If ($($dcWithAADPwdProtectionDCAgent.SoftwareVersion)) {$($dcWithAADPwdProtectionDCAgent.SoftwareVersion)} Else {"Not Registered/Unknown"})
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Pwd Policy Date (UTC)" -Value $(If ($($dcWithAADPwdProtectionDCAgent.PasswordPolicyDateUTC)) {$($dcWithAADPwdProtectionDCAgent.PasswordPolicyDateUTC)} Else {"Not Registered/Unknown"})
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "HeartBeat (UTC)" -Value $(If ($($dcWithAADPwdProtectionDCAgent.HeartbeatUTC)) {$($dcWithAADPwdProtectionDCAgent.HeartbeatUTC)} Else {"Not Registered/Unknown"})
		$bplStatusResultOnRWDC | Add-Member -MemberType NoteProperty -Name "Azure AD Tenant" -Value $(If ($($dcWithAADPwdProtectionDCAgent.AzureTenant)) {$($dcWithAADPwdProtectionDCAgent.AzureTenant)} Else {"Not Registered/Unknown"})
		$bplStatusResultOnRWDCs += $bplStatusResultOnRWDC
	}
}

### Display The Results In A GridView And Export To A Csv
$bplStatusResultOnRWDCs | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
Write-Host ""
Write-Host "CSV Report File........................: $outputCSVFilePath" -ForegroundColor DarkCyan
$bplStatusResultOnRWDCs | Out-GridView
Write-Host ""
Write-Host "DONE!"
Write-Host ""