### Abstract: This PoSH Script Helps Gathering Azure AD Password Protection Statistics Across Targeted RWDCs
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-31: Initial version of the script (v0.1)
###

<#
.SYNOPSIS
	With this PoSH script, one can gather the Azure AD Password Protection Statistics throughout the RWDCs in the AD forest.

.DESCRIPTION
	With this PoSH script, one can gather the Azure AD Password Protection Statistics throughout the RWDCs in the AD forest.

.PARAMETER scope
	The scope to use when targeting RWDCs. Options are forest, domain or rwdc
	
.PARAMETER domains
	The FQDN of the AD domain(s), in a comma separated list, to target

.PARAMETER servers
	The FQDN of the DC(s), in a comma separated list, to target

.EXAMPLE
	Gather The Statistics Across All The RWDCs Through The AD Forest
	
	.\AAD-Password-Protection-Statistics.ps1 -scope Forest

.EXAMPLE
	Gather The Statistics Across All The RWDCs Through The Specified AD Domain(s)
	
	.\AAD-Password-Protection-Statistics.ps1 -scope Domain -domains COMPANY.COM,CHILD.COMPANY.COM

.EXAMPLE
	Gather The Statistics Across All The Specified RWDCs(s)
	
	.\AAD-Password-Protection-Statistics.ps1 -scope RWDC -servers DC1.COMPANY.COM,DC2.COMPANY.COM,DC3.CHILD.COMPANY.COM

.NOTES
	Must be executed on the server with the Azure AD Password Protection Proxy Service!
	
	Requires the Active Directory PowerShell CMDlets!
	
	Requires the Azure AD Password Protection PowerShell CMDlets!
	
	Requires "Enterprise Admin" Permissions!
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
$scope = "forest"
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

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ RETRIEVE THE AZURE AD PASSWORD PROTECTION STATISTICS +++"
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
Write-Host "                             *      --> Retrieve The Azure AD Password Protection Statistics  <--     *" -ForeGroundColor Cyan
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
$dateTimeUTC = (Get-Date).ToUniversalTime()
$dateTimeUTCCustomFormat = Get-Date $dateTimeUTC -Format "yyyy-MM-dd_HH.mm.ss"
$currentScriptPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$outputCSVFilePath = $currentScriptFolderPath + "\" + $dateTimeUTCCustomFormat + "_AAD-Pwd-Protection-DC-Agent-Statistics-Check_" + $($scope.ToUpper()) + ".CSV"

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

### Building Empty List For The Statistics Of All RWDCs Together
$aadPasswordProtectionStatisticsTotal = @()

### Building Empty List For The Statistics Summary Report Containing An Entry For Individual RWDC And In Total
$aadPasswordProtectionStatisticsSummaryReport = @()

### For Every Scoped RWDC, If Any
If ($scopedDCs) {
	$scopedDCs | %{
		# Entry Stored In The Array
		$entry = $null
		$entry = $_
		
		# Get The FQDN Of The AD Domain Of The RWDC
		$adDomain = $null
		$adDomain = $entry.SubString(0, $entry.IndexOf("|"))
		
		# Get The FQDN Of The RWDC
		$dcInDomain = $null
		$dcInDomain = $entry.SubString($entry.IndexOf("|") + 1)

		# Building Empty List For The Statistics Of Individual RWDC
		$aadPasswordProtectionStatisticsIndividual = @()

		# From The List Of RWDCs With The Azure AD Password Protection DC Agent Installed, Retrieve The Info Of The RWDC Being Processed
		$dcWithAADPwdProtectionDCAgent = $null
		$dcWithAADPwdProtectionDCAgent = $($scopedDCsWithAADPwdProtectionDCAgent | ?{$_.ServerFQDN -eq $dcInDomain})
		
		Write-Host ""
		Write-Host "AD Domain..............................: $adDomain" -ForegroundColor Magenta
		Write-Host "--> Domain Controller..................: $dcInDomain" -ForegroundColor Cyan
		# The Info Of The RWDC Being Processed If An Entry For It Exists In The List Of RWDCs With The Azure AD Password Protection DC Agent Installed
		If ($dcWithAADPwdProtectionDCAgent) {
			# Retrieve The Heartbeat Info
			$dcWithAADPwdProtectionDCAgentHeartBeat = $null
			$dcWithAADPwdProtectionDCAgentHeartBeat = $dcWithAADPwdProtectionDCAgent.HeartbeatUTC

			# Calculate The Time Difference Between The Last Heartbeat And The (Start) Date
			$timeDiff = $null
			$timeDiff = (New-Timespan -Start $(Get-Date $dcWithAADPwdProtectionDCAgentHeartBeat) -End $(Get-Date $dateTimeUTC)).TotalHours

			# We Find It Acceptable If The Time Difference Is 24 Hours Or Less
			If ($timeDiff -lt 24) {
				Write-Host "The Azure AD Password Protection DC Agent Is Installed And Registered With An Up-To-Date Heartbeat..." -ForegroundColor Green

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

				# If The Connection To The RWDC Is OK...
				If ($connectionCheckOK) {
					Write-Host "ALL Required Ports ($($ports -join ",")) To The Domain Controller '$dcInDomain' Are Available!..." -ForegroundColor Green

					# Get The Azure AD Password Protection Statistics / Summary Report For This RWDC
					$rwdcAADPwdProtectionStats = $null
					$rwdcAADPwdProtectionStats = Get-AzureADPasswordProtectionSummaryReport -DomainController $dcInDomain

					# If The Statistics Of This RWDC Together Is Still Empty Then The "Schema" Of The Array Needs To Be Build Using The Very First RWDC As A Source For The Properties
					If (!$aadPasswordProtectionStatisticsIndividual) {
						# An Empty List For All The Available Properties
						$rwdcAADPwdProtectionStatProperties = @()
						
						# From The Statistics Of The RWDC Retrieve The Name Of The Properties And Put Those In The List With Available Properties
						$rwdcAADPwdProtectionStats | Get-Member | ?{$_.MemberType -eq "NoteProperty" -And $_.Name -ne "DomainController"} | %{$rwdcAADPwdProtectionStatProperties += $_.Name}
						
						# Determine The Number Of Properties Available In The List - MUST NOT BE NULLED DUE TO THE REQUIRED COUNT IN THE FOR LOOP
						$rwdcAADPwdProtectionStatPropertyCount = $rwdcAADPwdProtectionStatProperties.Count
						
						# Add Every Property To The List For The Statistics Of Individual RWDC With An Initial Value Of 0 (Zero)
						# Within The Array Every Entry Consists Of An Array
						$rwdcAADPwdProtectionStatProperties | %{
							$statPropArray = $null
							$statPropArray = [string]$_,[decimal]0
							$aadPasswordProtectionStatisticsIndividual += ,$statPropArray
						}	
					}
					
					# If The Statistics Of All RWDCs Together Is Still Empty Then The "Schema" Of The Array Needs To Be Build Using The Very First RWDC As A Source For The Properties
					If (!$aadPasswordProtectionStatisticsTotal) {
						# An Empty List For All The Available Properties
						$rwdcAADPwdProtectionStatProperties = @()

						# From The Statistics Of The RWDC Retrieve The Name Of The Properties And Put Those In The List With Available Properties
						$rwdcAADPwdProtectionStats | Get-Member | ?{$_.MemberType -eq "NoteProperty" -And $_.Name -ne "DomainController"} | %{$rwdcAADPwdProtectionStatProperties += $_.Name}
						
						# Determine The Number Of Properties Available In The List - MUST NOT BE NULLED DUE TO THE REQUIRED COUNT IN THE FOR LOOP
						$rwdcAADPwdProtectionStatPropertyCount = $rwdcAADPwdProtectionStatProperties.Count
						
						# Add Every Property To The Statistics List Of Individual RWDC With An Initial Value Of 0 (Zero)
						$rwdcAADPwdProtectionStatProperties | %{
							$statPropArray = $null
							$statPropArray = [string]$_,[decimal]0
							$aadPasswordProtectionStatisticsTotal += ,$statPropArray						
						}	
					}
					
					# Both The Statistics List Of Individual RWDC And The Statistics List Of All RWDCs Together, Add The Statistics Values Of The Inidividual RWDC To The Corresponding Statistics Properties
					# Iterate Through Statistics List Of Individual RWDC And The Statistics List Of All RWDCs Together At The Same Time And Add Value To The Corresponding Property
					For ($i = 0; $i -le $rwdcAADPwdProtectionStatPropertyCount - 1; $i++) {
						# While Iterating Through The Overall Array Get The Name Of The Property By Looking First Entry In The Slave Array
						$rwdcAADPwdProtectionStatPropertyName = $null
						$rwdcAADPwdProtectionStatPropertyName = $aadPasswordProtectionStatisticsTotal[$i][0]

						# While Iterating Through The Overall Array Add The Value To The Corresponding Property
						$aadPasswordProtectionStatisticsIndividual[$i][1] += $rwdcAADPwdProtectionStats.$rwdcAADPwdProtectionStatPropertyName
						$aadPasswordProtectionStatisticsTotal[$i][1] += $rwdcAADPwdProtectionStats.$rwdcAADPwdProtectionStatPropertyName
					}
				} Else {
					Write-Host "ALL Required Ports ($($ports -join ",")) To The Domain Controller '$dcInDomain' ARE NOT Available!..." -ForegroundColor Red
					Write-Host "Skipping Domain Controller '$dcInDomain'..." -ForegroundColor Red
				}
			} Else {
				Write-Host "The Azure AD Password Protection DC Agent Appears To Be Installed And Registered But Its Heartbeat is NOT Up-To-Date..." -ForegroundColor Red
				Write-Host "Needs To Be Checked!..." -ForegroundColor Red
				Write-Host "Skipping Domain Controller '$dcInDomain'..." -ForegroundColor Red
			}
		} Else {
			Write-Host "The Azure AD Password Protection DC Agent Is NOT Registered And Appears NOT To Be Installed..." -ForegroundColor Red
			Write-Host "Needs To Be Checked!..." -ForegroundColor Red
			Write-Host "Skipping Domain Controller '$dcInDomain'..." -ForegroundColor Red
		}

		# Add An Entry For The RWDC Being Process To The Overall Summary Report.
		$aadPwdProtectionStatsForRWDC = New-Object -TypeName System.Object
		$aadPwdProtectionStatsForRWDC | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $adDomain
		$aadPwdProtectionStatsForRWDC | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $dcInDomain
		$aadPasswordProtectionStatisticsIndividual | %{
			$rwdcAADPwdProtectionStatPropertyNameForRWDC = $null
			$rwdcAADPwdProtectionStatPropertyNameForRWDC = $_[0]
			$rwdcAADPwdProtectionStatPropertyValueForRWDC = $null
			$rwdcAADPwdProtectionStatPropertyValueForRWDC = $_[1]
			Write-Host "   * $($rwdcAADPwdProtectionStatPropertyNameForRWDC.PadRight(34, ".")): $rwdcAADPwdProtectionStatPropertyValueForRWDC"
			$aadPwdProtectionStatsForRWDC | Add-Member -MemberType NoteProperty -Name $rwdcAADPwdProtectionStatPropertyNameForRWDC -Value $($rwdcAADPwdProtectionStatPropertyValueForRWDC.ToString())
		}
		$aadPasswordProtectionStatisticsSummaryReport += $aadPwdProtectionStatsForRWDC
	}
	Write-Host ""
	Write-Host "Scope..................................: $($scope.ToUpper())" -ForegroundColor Magenta
	Write-Host "--> All Scoped RWDCs" -ForegroundColor Cyan
	
	# Add An Entry For TOTAL Values.
	$aadPwdProtectionStatsTotal = New-Object -TypeName System.Object
	$aadPwdProtectionStatsTotal | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value "TOTAL"
	$aadPwdProtectionStatsTotal | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value "TOTAL"
	$aadPasswordProtectionStatisticsTotal | %{
		$rwdcAADPwdProtectionStatPropertyNameTotal = $null
		$rwdcAADPwdProtectionStatPropertyNameTotal = $_[0]
		$rwdcAADPwdProtectionStatPropertyValueTotal = $null
		$rwdcAADPwdProtectionStatPropertyValueTotal = $_[1]
		Write-Host "   * $($rwdcAADPwdProtectionStatPropertyNameTotal.PadRight(34, ".")): $rwdcAADPwdProtectionStatPropertyValueTotal"
		$aadPwdProtectionStatsTotal | Add-Member -MemberType NoteProperty -Name $rwdcAADPwdProtectionStatPropertyNameTotal -Value $($rwdcAADPwdProtectionStatPropertyValueTotal.ToString())
	}
	$aadPasswordProtectionStatisticsSummaryReport += $aadPwdProtectionStatsTotal
}

### Display The Results In A GridView And Export To A Csv
$aadPasswordProtectionStatisticsSummaryReport | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
Write-Host ""
Write-Host "CSV Report File........................: $outputCSVFilePath" -ForegroundColor DarkCyan
$aadPasswordProtectionStatisticsSummaryReport | Out-GridView
Write-Host ""
Write-Host "DONE!"
Write-Host ""