### Abstract: This PoSH Script Helps Install The Azure AD Password Protection DC Agent
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-08: Initial version of the script (v0.1)
### 2019-10-22: Improved output on screen to be more clear and added check for required .NET Framework version (v0.2)
### 2019-10-30: Updated the portConnectionCheck to also check name resolution (v0.3)
###

<#
.SYNOPSIS
	With this PoSH script, one can install The Azure AD Password Protection DC Agent on all RWDCs Within An AD Forest.

.DESCRIPTION
	With this PoSH script, one can install The Azure AD Password Protection DC Agent on all RWDCs Within An AD Forest.

.PARAMETER scope
	The scope to use when targeting RWDCs. Options are forest, domain or rwdc
	
.PARAMETER domains
	The FQDN of the AD domain(s), in a comma separated list, to target

.PARAMETER servers
	The FQDN of the DC(s), in a comma separated list, to target

.PARAMETER installSourceFullPath
	The full path to the MSI/EXE install source

.EXAMPLE
	Install The Azure AD Password Protection DC Agent on all RWDCs in the AD Forest
	
	.\AAD-Password-Protection-Install-DC-Agent.ps1 -scope Forest -installSourceFullPath "<Full Path To The MSI/EXE Install Source>"

.EXAMPLE
	Install The Azure AD Password Protection DC Agent on all RWDCs in the AD Domain COMPANY.COM and CHILD.COMPANY.COM
	
	.\AAD-Password-Protection-Install-DC-Agent.ps1 -scope Domain -domains COMPANY.COM,CHILD.COMPANY.COM -installSourceFullPath "<Full Path To The MSI/EXE Install Source>"
	
.EXAMPLE
	Install The Azure AD Password Protection DC Agent on the RWDCs DC1.COMPANY.COM and DC2.COMPANY.COM
	
	.\AAD-Password-Protection-Install-DC-Agent.ps1 -scope rwdc -servers DC1.COMPANY.COM,C2.COMPANY.COM -installSourceFullPath "<Full Path To The MSI/EXE Install Source>"

.NOTES
	This script requires local administrator equivalent permissions on every RWDC that is targeted to install the oftware.
	In general, and it depends on the scope, that generally means the requirement for either domain administrator or enterprise administrator equivalent permissions.
	As it is too difficult to determine the permissions for all possible options, the choice has been made to require Enterprise Adminisrtator permissions for the script
	to work!
	The script should also support non-english versions of Windows/AD
	The path for installation source files must be the same on each targeted Windows Server
	It creates a log for the machine in the same location as the MSI/EXE Install Source
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
	[string[]]$servers,
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the full path to the MSI/EXE to install the Azure AD Password Protection DC Agent')]
	[ValidateNotNullOrEmpty()]
	[string]$installSourceFullPath
)

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

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
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

### FUNCTION: Retrieve The Product Version From Within The MSI
Function retrieveMsiProductVersion($installSourceFullPath) {
	Try {
		$windowsInstaller = New-Object -com WindowsInstaller.Installer

		$msiDatabase = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $windowsInstaller, @($installSourceFullPath, 0))
	
        $msiQuery = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $msiView = $msiDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $msiDatabase, ($msiQuery))
        $msiView.GetType().InvokeMember("Execute", "InvokeMethod", $null, $msiView, $null)
        $record = $msiView.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $msiView, $null)
        $msiProductVersion = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
        $msiView.GetType().InvokeMember("Close", "InvokeMethod", $null, $msiView, $null)
        
		Return $msiProductVersion
    } catch {
        #Throw "Unable To Determine Product Version. The Error Was: {0}." -f $_
		Return "0.0.0.0"
    }
}
$retrieveMsiProductVersionDef = "function retrieveMsiProductVersion{${function:retrieveMsiProductVersion}}"

### FUNCTION: Check .NET Version
Function checkDotNETVersion() {
	# Get Installed Version Of .NET
	$dotNETVersionNrInstalled = $null
	$dotNETVersionNrInstalled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release).Release
	
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
		$dotNETVErsionText = ".NET Framework Not Installed"
	}

	If ($dotNETVersionNrInstalled -ge 460798) {
		Return "SUCCESS","Minimum Required .NET Framework Version (4.7) IS Installed",$dotNETVErsionText
	} Else {
		Return "FAILURE","Minimum Required .NET Framework Version (4.7) IS NOT Installed",$dotNETVErsionText
	}
}
$checkDotNETVersionDef = "function checkDotNETVersion{${function:checkDotNETVersion}}"

### FUNCTION: Install The Azure AD Password Protection DC Agent
Function installAADPwdProtectDCAgent($installSourceFullPath, $installSourceVersion, $execArgs) {
	If ($installSourceFullPath.EndsWith(".msi")) {
		$installCommand = Start-Process C:\WINDOWS\SYSTEM32\MSIEXEC.EXE -ArgumentList $execArgs -wait -PassThru
	}
	If ($installSourceFullPath.EndsWith(".exe")) {
		$installCommand = Start-Process $installSourceFullPath -ArgumentList $execArgs -wait -PassThru
	}
	
	Start-Sleep 3
	
	# Old School --> WMIC PRODUCT GET NAME | FIND /I "Azure AD Password Protection DC Agent"
	$productAADPwdProtectDCAgent = $null
	$productAADPwdProtectDCAgent = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection DC Agent'"
	
	If ($productAADPwdProtectDCAgent -And $([System.Version]$($productAADPwdProtectDCAgent.Version) -eq $installSourceVersion)) {
		Return "SUCCESS","Azure AD Password Protection DC Agent INSTALLED SUCCESSFULLY On '$dcInDomain'",$(If ($productAADPwdProtectDCAgent) {$($productAADPwdProtectDCAgent.Version)} Else {"NO-VERSION-INSTALLED"}),$installSourceVersion
	} Else {
		Return "FAILURE","Azure AD Password Protection DC Agent FAILED TO INSTALL On '$dcInDomain'",$(If ($productAADPwdProtectDCAgent) {$($productAADPwdProtectDCAgent.Version)} Else {"NO-VERSION-INSTALLED"}),$installSourceVersion
	}
}
$installAADPwdProtectDCAgentDef = "function installAADPwdProtectDCAgent{${function:installAADPwdProtectDCAgent}}"

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ INSTALL THE AZURE AD PASSWORD PROTECTION DC AGENT +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 160
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 160) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 160
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

Write-Host ""
Write-Host "                                       **************************************************************************" -ForeGroundColor Cyan
Write-Host "                                       *                                                                        *" -ForeGroundColor Cyan
Write-Host "                                       *       --> Install The Azure AD Password Protection DC Agent <--        *" -ForeGroundColor Cyan
Write-Host "                                       *                                                                        *" -ForeGroundColor Cyan
Write-Host "                                       *              Written By: Jorge de Almeida Pinto [MVP-EMS]              *" -ForeGroundColor Cyan
Write-Host "                                       *                                                                        *" -ForeGroundColor Cyan
Write-Host "                                       *            BLOG: http://jorgequestforknowledge.wordpress.com/          *" -ForeGroundColor Cyan
Write-Host "                                       *                                                                        *" -ForeGroundColor Cyan
Write-Host "                                       **************************************************************************" -ForeGroundColor Cyan
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
loadPoSHModules ActiveDirectory

Write-Host ""
Write-Host "Operational Mode.......................: $($scope.ToUpper())" -ForegroundColor Magenta

### Definition Of Some Constants
$dateTime = Get-Date -Format "yyyy-MM-dd_HH.mm.ss"
$currentScriptPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$outputCSVFilePath = $currentScriptFolderPath + "\" + $dateTime + "_AAD-Pwd-Protection-DC-Agent-Install_" + $($scope.ToUpper()) + ".CSV"

### Getting Basic AD Forest Info And Define Empty List Of RWDCs To Populate
$adForest  = Get-ADForest
$adForestDomainFQDNs = $adForest.Domains
$adForestRootDomainFQDN = $adForest.RootDomain
$adForestRootDomainDN = "DC=" + $adForestRootDomainFQDN.Replace(".",",DC=")
$adForestRootDomainDomainSID = (Get-ADDomain $adForestRootDomainFQDN).DomainSID.Value
$adRwdcFQDN = ((Get-ADDomainController -Discover).HostName)[0]
$adRootDSENearestRWDC = Get-ADRootDSE -Server $adRwdcFQDN
$adForestConfigNC = $adRootDSENearestRWDC.configurationNamingContext

# Retrieve AD Domain FQDNs In AD Forest And Build The Order As Such The Forest Root AD Domain Is At The Top Of The List
$adDomainFQDNList = @()
$adDomainFQDNList += $adForestRootDomainFQDN
If ($adForestDomainFQDNs.Count -gt 1) {
	$adForestDomainFQDNs | ?{$_ -ne $adForestRootDomainFQDN -And $_ -match $adForestRootDomainFQDN} | Sort-Object | %{
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
$listOfRWDCs = @()

# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
$enterpriseAdminRID = "519"
$enterpriseAdminObjectSID = $adForestRootDomainDomainSID + "-" + $enterpriseAdminRID
$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($enterpriseAdminObjectSID)).Translate([System.Security.Principal.NTAccount]).Value
$userIsEnterpriseAdmin = $null
$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
If (!$userIsEnterpriseAdmin) {
	# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
	Write-Host ""
	Write-Host "WARNING: Your User Account Is Not Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootDomainFQDN'!..." -ForeGroundColor Red
	Write-Host "For This Script To Run Successfully, Enterprise Administrator Equivalent Permissions Are Required..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
} Else {
	# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
	Write-Host ""
	Write-Host "Your User Account Is Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootDomainFQDN'!..." -ForeGroundColor Green
	Write-Host "Continuing Script..." -ForeGroundColor Green
	Write-Host ""
}

### Getting List Of RWDCs To Target When Scope Is AD Forest
If ($scope.ToUpper() -eq "FOREST") {
	# For Every AD Domain In The AD Forest Retrieve The RWDCs
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
			$listOfRWDCs += $($adDomain + "|" + $dcInDomain)
		}
	}
}

### Getting List Of RWDCs To Target When Scope Is AD Domain
If ($scope.ToUpper() -eq "DOMAIN") {
	If ($domains) {
		# For Every AD Domain Specified Retrieve The RWDCs
		$domains | %{
			$adDomain = $null
			$adDomain = $_
			
			# If The Specified AD Domain Exists In The AD Forest, Get The List Of RWDCs In The AD Domain
			If ($adDomainFQDNList -contains $adDomain) {
				$rwdcsInDomain = $null
				$rwdcsInDomain = (Get-ADDomain $adDomain).ReplicaDirectoryServers
				
				# Add Every RWDC To The List Of RWDCs
				$rwdcsInDomain | %{
					$dcInDomain = $null
					$dcInDomain = $_
					If ($listOfRWDCs -notcontains $($adDomain + "|" + $dcInDomain)) {
						$listOfRWDCs += $($adDomain + "|" + $dcInDomain)
					}
				}
			} Else {
				Write-Host ""
				Write-Host "The AD Domain '$adDomain' DOES NOT Exist..." -ForegroundColor Red
				Write-Host "Skipping AD Domain '$adDomain'..." -ForegroundColor Red
			}
		}
	}
}

### Getting List Of RWDCs To Target When Scope Is Individual RWDCs
If ($scope.ToUpper() -eq "RWDC") {
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
	
	# For Every RWDC Specified Check If It Exists
	$servers | %{
		$dcInDomain = $null
		$dcInDomain = $_
		
		# If The Specified RWDC Exists In The AD Forest, Add It To The List Of RWDCs To Process
		If ($listOfRWDCsTemp -contains $dcInDomain) {
			$adDomain = $null
			$adDomain = $dcInDomain.SubString($dcInDomain.IndexOf(".") + 1)
			If ($listOfRWDCs -notcontains $($adDomain + "|" + $dcInDomain)) {
				$listOfRWDCs += $($adDomain + "|" + $dcInDomain)
			}
		} Else {
			Write-Host ""
			Write-Host "The RWDC '$dcInDomain' DOES NOT Exist..." -ForegroundColor Red
			Write-Host "Skipping RWDC '$dcInDomain'..." -ForegroundColor Red
		}
	}
}

# Building Empty List Of Installation Results
$installResults = @()

If ($listOfRWDCs) {
	$listOfRWDCs | %{
		$entry = $null
		$entry = $_
		
		# Get The FQDN Of The AD Domain Of The RWDC
		$adDomain = $null
		$adDomain = $entry.SubString(0, $entry.IndexOf("|"))
		
		# Get The FQDN Of The RWDC
		$dcInDomain = $null
		$dcInDomain = $entry.SubString($entry.IndexOf("|") + 1)
		
		Write-Host ""
		Write-Host "AD Domain..............................: $adDomain" -ForegroundColor Magenta
		Write-Host "--> Domain Controller..................: $dcInDomain" -ForegroundColor Cyan		
		
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
			
		$installResultOnDC = $null

		# If The Connection To The RWDC Is OK...
		If ($connectionCheckOK) {		
			Write-Host "ALL Required Ports ($($ports -join ",")) To The Domain Controller '$dcInDomain' Are Available!..." -ForegroundColor Green
			
			# Setup A Session To The RWDC
			$targetedDCSession = $null
			$targetedDCSession = New-PSSession -ComputerName $dcInDomain

			# Connect To The RWDC And Execute The Scriptblock
			$installResultOnDC = Invoke-Command -Session $targetedDCSession -ArgumentList $dateTime,$dcInDomain,$installSourceFullPath,$retrieveMsiProductVersionDef,$checkDotNETVersionDef,$installAADPwdProtectDCAgentDef -ScriptBlock {
				Param(
					$dateTime,
					$dcInDomain,
					$installSourceFullPath,
					$retrieveMsiProductVersionDef,
					$checkDotNETVersionDef,
					$installAADPwdProtectDCAgentDef
				)
				
				. ([ScriptBlock]::Create($retrieveMsiProductVersionDef))

				. ([ScriptBlock]::Create($checkDotNETVersionDef))

				. ([ScriptBlock]::Create($installAADPwdProtectDCAgentDef))

				# If The Correct .NET Version Is Installed Then Continue, Otherwise Abort
				$checkDotNETVersionResult = $null
				$checkDotNETVersionResult = checkDotNETVersion
				$result = $null
				$result = $checkDotNETVersionResult[0]
				$message = $null
				$message = $checkDotNETVersionResult[1]
				$dotNETVersion = $null
				$dotNETVersion = $checkDotNETVersionResult[2]
				If ($result.ToUpper() -eq "SUCCESS") {
					Write-Host "$message on '$dcInDomain'" -ForegroundColor Green
					Write-Host "Installed Version: $dotNETVersion" -ForegroundColor Green
					Write-Host "Continuing..." -ForegroundColor Green

					# If The Full Path To The MSI/EXE Exists Then Continue, Otherwise Abort
					If (Test-Path $installSourceFullPath) {
						$installSourceVersion = $null
						# Determine The Version If It Is An MSI
						If ($installSourceFullPath.EndsWith(".msi")) {
							[string]$installSourceVersion = retrieveMsiProductVersion $installSourceFullPath
							$installSourceVersion = $installSourceVersion.Trim()
						}
						
						# Determine The Version If It Is An EXE
						If ($installSourceFullPath.EndsWith(".exe")) {
							$installSourceVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installSourceFullPath).FileVersion
						}
						
						# Specify The Full Path For The Log File
						$logFolder = $null
						$logFolder = Split-Path $installSourceFullPath
						$logFile = $null
						$logFile = Join-Path $logFolder $("AzureADPasswordProtectionDCAgent_Install_v" + $installSourceVersion + "_" + $dcInDomain + "_" + $dateTime + ".log")
						
						# Specify The Arguments For When Using An MSI
						$execArgs = $null
						If ($installSourceFullPath.EndsWith(".msi")) {
							$execArgs = @(
								"/I"
								"$installSourceFullPath"
								"/LV"
								"$logFile"
								"/NoRestart"
							)
						}
						
						# Specify The Arguments For When Using An EXE
						If ($installSourceFullPath.EndsWith(".exe")) {
							$execArgs = @(
								"/install"
								"/quiet"
								"/log"
								"$logFile"
								"/NoRestart"
							)
						}

						# Retrieve The 'Azure AD Password Protection DC Agent' Product Installation
						$productAADPwdProtectDCAgent = $null
						$productAADPwdProtectDCAgent = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection DC Agent'"
						
						# If It Does Not Yet Exist, Then Install It
						# If It Does Exist, Then Either Upgrade (Newer Version) Or Reinstall (Same Version) It After Confirmation
						If (!$productAADPwdProtectDCAgent) {
							Write-Host "Azure AD Password Protection DC Agent Service Not Yet Installed On '$dcInDomain'" -ForegroundColor Yellow
							Write-Host "Installing Azure AD Password Protection DC Agent Service On '$dcInDomain'" -ForegroundColor Yellow
							$installAADPwdProtectDCAgentResult = installAADPwdProtectDCAgent $installSourceFullPath $installSourceVersion $execArgs
							Write-Host "Installation Completed!..." -ForegroundColor Yellow
							Write-Host "New Version............................: $installSourceVersion" -ForegroundColor Yellow
							Write-Host "A Restart Of '$dcInDomain' Is Required! The Script WILL NOT Restart The RWDC, You Need To Do That Yourself!" -ForegroundColor Yellow
							Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
							Return $installAADPwdProtectDCAgentResult + $dotNETVersion
						} Else {
							Write-Host "Azure AD Password Protection DC Agent Service ALREADY INSTALLED On '$dcInDomain'" -ForegroundColor Yellow
							Write-Host "Installed Version......................: $($productAADPwdProtectDCAgent.Version)" -ForegroundColor Yellow
							Write-Host "New Version............................: $installSourceVersion" -ForegroundColor Yellow
							Write-Host ""
							
							# If The Current Product Version Is Lower Than The New Product Version, Upgrade It
							# If The Current Product Version Is Equal To The New Product Version, Reinstall It
							# If The Current Product Version Is Higher Than The New Product Version, Do Not Do Anything
							$response = $null
							If ([System.Version]$($productAADPwdProtectDCAgent.Version) -lt [System.Version]$installSourceVersion) {
								$response = Read-Host "Do You Want To UPGRADE The Current Version? (Y|N)"
							} ElseIf ([System.Version]$($productAADPwdProtectDCAgent.Version) -eq [System.Version]$installSourceVersion) {
								$response = Read-Host "Do You Want To Reinstall The Current Version? (Y|N)"
							} Else {
								$response = "N"
							}
							
							# When Confirmed To Upgrade/Reinstall, Then Actually Do It
							Write-Host ""
							If ($response.ToUpper() -eq "Y" -Or $response.ToUpper() -eq "YES") {
								Write-Host "Installing Azure AD Password Protection DC Agent Service On '$dcInDomain'" -ForegroundColor Yellow
								$installAADPwdProtectDCAgentResult = installAADPwdProtectDCAgent $installSourceFullPath $installSourceVersion $execArgs
								Write-Host "Installation Completed!..." -ForegroundColor Yellow
								Write-Host "A Restart Of '$dcInDomain' Is Required! The Script WILL NOT Restart The RWDC, You Need To Do That Yourself!" -ForegroundColor Yellow
								Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
								Return $installAADPwdProtectDCAgentResult + $dotNETVersion
							} Else {
								Write-Host "Nothing Was Installed On '$dcInDomain' As It Was Not Confirmed..." -ForegroundColor Yellow
								Return "NO-INSTALL","Azure AD Password Protection DC Agent Was NOT Upgraded/Reinstalled On '$dcInDomain'",$($productAADPwdProtectDCAgent.Version),$installSourceVersion,$dotNETVersion
							}
						}
					} Else {
						Write-Host "Nothing Was Installed On '$dcInDomain' As The Installation Source '$installSourceFullPath' Was Not Found..." -ForegroundColor Red
						Return "NO-SOURCE","Azure AD Password Protection DC Agent MSI IS NOT AVAILABLE/ACCESSIBLE On '$dcInDomain'",$(If ($productAADPwdProtectDCAgent) {$($productAADPwdProtectDCAgent.Version)} Else {"NO-VERSION-INSTALLED"}),"VERSION-NOT-AVAILABLE",$dotNETVersion
					}
				} Else {
					Write-Host "$message on '$dcInDomain'" -ForegroundColor Red
					Write-Host "Installed Version: $dotNETVersion" -ForegroundColor Red
					Write-Host "Skipping '$dcInDomain'..." -ForegroundColor Red
					Return "NO-DOTNET","$message on '$dcInDomain'","NO-VERSION-INSTALLED","VERSION-NOT-AVAILABLE",$dotNETVersion
				}
			}
			
			Remove-PSSession $targetedDCSession
		} Else {
			Write-Host "ALL Required Ports ($($ports -join ",")) To The Domain Controller '$dcInDomain' ARE NOT Available!..." -ForegroundColor Red
			Write-Host "Skipping Domain Controller '$dcInDomain'..." -ForegroundColor Red
			$installResultOnDC = @("NO-CONNECTION","NOT ALL Required Ports ($($ports -join ",")) To The Domain Controller '$dcInDomain' Are Available!...","VERSION-NOT-AVAILABLE","VERSION-NOT-AVAILABLE","UNABLE-TO-DETERMINE")
		}

		# Add The Result For This RWDC To The Install Results List
		$resultStatus = $null
		$resultStatus = $installResultOnDC[0]
		$messageStatus = $null
		$messageStatus = $installResultOnDC[1]
		$previousDCAgentVersion = $null
		$previousDCAgentVersion = $installResultOnDC[2]
		$newDCAgentVersion = $null
		$newDCAgentVersion = $installResultOnDC[3]
		$dotNETVersion = $null
		$dotNETVersion = $installResultOnDC[4]

		$installStatus = New-Object -TypeName System.Object
		$installStatus | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $adDomain
		$installStatus | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $dcInDomain
		$installStatus | Add-Member -MemberType NoteProperty -Name "Result" -Value $resultStatus
		$installStatus | Add-Member -MemberType NoteProperty -Name "Message" -Value $messageStatus
		$installStatus | Add-Member -MemberType NoteProperty -Name "dotNET Version" -Value $dotNETVersion
		$installStatus | Add-Member -MemberType NoteProperty -Name "Prev. Version" -Value $previousDCAgentVersion
		$installStatus | Add-Member -MemberType NoteProperty -Name "New Version" -Value $newDCAgentVersion
		$installResults += $installStatus
	}
}
Write-Host ""

### Display The Results In A GridView And Export To A Csv
# $installResults | FT -Autosize -Wrap
$installResults | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
Write-Host "CSV Report File........................: $outputCSVFilePath" -ForegroundColor DarkCyan
$installResults | Out-GridView
Write-Host ""
Write-Host "DONE!"
Write-Host ""