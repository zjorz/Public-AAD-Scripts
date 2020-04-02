### Abstract: This PoSH Script Helps Install The Azure AD Password Protection Proxy Service
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-08: Initial version of the script (v0.1)
### 2019-10-22: Improved output on screen to be more clear and added check for required .NET Framework version (v0.2)
### 2019-10-30: Updated the portConnectionCheck to also check name resolution (v0.3)
###

<#
.SYNOPSIS
	With this PoSH script, one can install The Azure AD Password Protection Proxy Service on targeted Windows Servers

.DESCRIPTION
	With this PoSH script, one can install The Azure AD Password Protection Proxy Service on targeted Windows Servers

.PARAMETER servers
	The FQDN of the server(s), in a comma separated list, to target

.PARAMETER installSourceFullPath
	The full path to the MSI/EXE install source

.EXAMPLE
	Install The Azure AD Password Protection Proxy Service on the LOCAL Server
	
	.\AAD-Password-Protection-Install-Proxy-Service.ps1 -servers LOCAL -installSourceFullPath "<Full Path To The MSI/EXE Install Source>"

.EXAMPLE
	Install The Azure AD Password Protection Proxy Service on the LOCAL Server and a remote Server
	
	.\AAD-Password-Protection-Install-Proxy-Service.ps1 -servers LOCAL,SERVER1.COMPANY.COM -installSourceFullPath "<Full Path To The MSI/EXE Install Source>"
	
.NOTES
	This script requires local administrator equivalent permissions on Windows Server to install the software.
	The path for installation source files must be the same on each targeted Windows Server
	It creates a log for the machine in the same location as the MSI/EXE Install Source
#>

Param(
	[Parameter(Mandatory=$FALSE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the list of servers by specifying FQDNs in a comma-separated manner')]
	[string[]]$servers,
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the full path to the MSI/EXE to install the Azure AD Password Protection Proxy Service')]
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

### FUNCTION: Test Credentials For Remote Admin Privileges
Function testRemoteAdmin ($server) {
	$adminShare = "\\" + $server + "\admin$"
	If (Test-Path $adminShare) {
		Return $True
	} Else {
		Return $False
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

### FUNCTION: Install The Azure AD Password Protection Proxy Service
Function installAADPwdProtectPrx($installSourceFullPath, $installSourceVersion, $execArgs) {
	If ($installSourceFullPath.EndsWith(".msi")) {
		$installCommand = Start-Process C:\WINDOWS\SYSTEM32\MSIEXEC.EXE -ArgumentList $execArgs -wait -PassThru
	}
	If ($installSourceFullPath.EndsWith(".exe")) {
		$installCommand = Start-Process $installSourceFullPath -ArgumentList $execArgs -wait -PassThru
	}
	
	Start-Sleep 3
	
	# Old School --> WMIC PRODUCT GET NAME | FIND /I "Azure AD Password Protection Proxy"
	$productAADPwdProtectPrx = $null
	$productAADPwdProtectPrx = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection Proxy'"
	
	If ($productAADPwdProtectPrx -And $([System.Version]$($productAADPwdProtectPrx.Version) -eq $installSourceVersion)) {
		Return "SUCCESS","Azure AD Password Protection Proxy Service INSTALLED SUCCESSFULLY On '$server'",$(If ($productAADPwdProtectPrx) {$($productAADPwdProtectPrx.Version)} Else {"NO-VERSION-INSTALLED"}),$installSourceVersion
	} Else {
		Return "FAILURE","Azure AD Password Protection Proxy Service FAILED TO INSTALL On '$server'",$(If ($productAADPwdProtectPrx) {$($productAADPwdProtectPrx.Version)} Else {"NO-VERSION-INSTALLED"}),$installSourceVersion
	}
}
$installAADPwdProtectPrxDef = "function installAADPwdProtectPrx{${function:installAADPwdProtectPrx}}"

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ INSTALL THE AZURE AD PASSWORD PROTECTION PROXY SERVICE +++"
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
Write-Host "                                       *     --> Install The Azure AD Password Protection Proxy Service <--     *" -ForeGroundColor Cyan
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

### Definition Of Some Constants
$dateTime = Get-Date -Format "yyyy-MM-dd_HH.mm.ss"
$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name
$fqdnDomainName = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
$fqdnLocalComputer = $localComputerName + "." + $fqdnDomainName
$currentScriptPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$outputCSVFilePath = $currentScriptFolderPath + "\" + $dateTime + "_AAD-Pwd-Protection-Proxy-Service-Install.CSV"

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
loadPoSHModules ActiveDirectory

### Determine A Global Catalog To Query
$gcFQDN = (Get-ADDomainController -Discover -Service GlobalCatalog).Hostname[0]

### Create A New List Of Servers To Process, Replace LOCAL With The Actual FQDN Of The Local Server, And Count The Number Of Specified Servers
$listOfServers = @()
$servers | %{
	$server = $null
	$server = $_
	
	# If LOCAL Was Specified, Translate It To The FQDN
	If ($server.ToUpper() -eq "LOCAL") {
		$serverToAdd = $fqdnLocalComputer
	} Else {
		$serverToAdd = $server 
	}
	
	# If The Server To Add Is The Local Computer Check Permissions
	If ($serverToAdd -eq $fqdnLocalComputer) {
		$localAdminObjectSID = "S-1-5-32-544"
		$localAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($localAdminObjectSID)).Translate([System.Security.Principal.NTAccount]).Value
		$userIsLocalAdmin = $null
		$userIsLocalAdmin = testAdminRole $localAdminRole
		If (!$userIsLocalAdmin) {
			# The User Account Running This Script Has Been Validated Not Being A Member Of The Local Admins Group Of The Local Server
			Write-Host ""
			Write-Host "No Admin Permissions For The Server '$serverToAdd'..." -ForegroundColor Red
			Write-Host "Skipping Server '$serverToAdd'..." -ForegroundColor Red
		} Else {
			If ($listOfServers -notcontains $serverToAdd) {
				$listOfServers += $serverToAdd
			}
		}
	} Else {
		# Check If The Object Exists In AD. If It Exists Check If The Required Permissions Are In Place And If Yes Add To The List, Otherwise Skip
		$adObject = Get-ADComputer -LDAPFilter "(dNSHostName=$serverToAdd)" -Server $gcFQDN`:3268
		If ($adObject) {
			$userIsRemoteAdmin = $null
			$userIsRemoteAdmin = testRemoteAdmin $serverToAdd
			If (!$userIsRemoteAdmin) {
				# The User Account Running This Script Has Been Validated Not Being A Member Of The Local Admins Group Of The Remote Server
				Write-Host ""
				Write-Host "Server Not Accessible Or No Admin Permissions For The Server '$serverToAdd'..." -ForegroundColor Red
				Write-Host "Skipping Server '$serverToAdd'..." -ForegroundColor Red
			} Else {
				If ($listOfServers -notcontains $serverToAdd) {
					$listOfServers += $serverToAdd
				}
			}
		} Else {
			Write-Host ""
			Write-Host "The Server '$serverToAdd' DOES NOT Exist..." -ForegroundColor Red
			Write-Host "Skipping Server '$serverToAdd'..." -ForegroundColor Red
		}
	}
}
### Check For The Number Of Server. Azure AD Password Protection Only Supports 2 Servers Per AD Forest With The Azure AD Password Protection Proxy Service
If ($listOfServers.Count -gt 2) {
	Write-Host ""
	Write-Host "It Is NOT Supported To Have More Than 2 Servers With The Azure AD Password Protection Proxy Service Role..." -ForeGroundColor Red
	Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""
	
	EXIT
}

### Building Empty List Of Installation Results
$installResults = @()

### If A List Of Servers Exists Process It
If ($listOfServers) {
	$listOfServers | %{
		# Get The FQDN Of The Server
		$server = $null
		$server = $_
		
		Write-Host ""
		Write-Host "--> Server.............................: $server" -ForegroundColor Cyan
		
		# Applicable For The Local Computer, Otherwise Applicable For The Remote Computer
		If ($server -eq $fqdnLocalComputer) {
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
				Write-Host "$message on '$server'" -ForegroundColor Green
				Write-Host "Installed .NET Version.................: $dotNETVersion" -ForegroundColor Green
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
					$logFile = Join-Path $logFolder $("AzureADPasswordProtectionProxyService_Install_v" + $installSourceVersion + "_" + $server + "_" + $dateTime + ".log")
				
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

					# Retrieve The 'Azure AD Password Protection Proxy' Product Installation
					$productAADPwdProtectPrx = $null
					$productAADPwdProtectPrx = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection Proxy'"
					
					# If It Does Not Yet Exist, Then Install It
					# If It Does Exist, Then Either Upgrade (Newer Version) Or Reinstall (Same Version) It After Confirmation
					If (!$productAADPwdProtectPrx) {
						Write-Host "Azure AD Password Protection Proxy Service Not Yet Installed On '$server'" -ForegroundColor Yellow
						Write-Host "Installing Azure AD Password Protection Proxy Service On '$server'" -ForegroundColor Yellow
						$productAADPwdProtectPrxResult = installAADPwdProtectPrx $installSourceFullPath $installSourceVersion $execArgs
						Write-Host "Installation Completed!..." -ForegroundColor Yellow
						Write-Host "New Version............................: $installSourceVersion" -ForegroundColor Yellow
						Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
						$installResultOnServer = $productAADPwdProtectPrxResult
						$installResultOnServer += $dotNETVersion
					} Else {
						Write-Host "Azure AD Password Protection Proxy Service ALREADY INSTALLED On '$server'" -ForegroundColor Yellow
						Write-Host "Installed Version......................: $($productAADPwdProtectPrx.Version)" -ForegroundColor Yellow
						Write-Host "New Version............................: $installSourceVersion" -ForegroundColor Yellow
						Write-Host ""
						
						# If The Current Product Version Is Lower Than The New Product Version, Upgrade It
						# If The Current Product Version Is Equal To The New Product Version, Reinstall It
						# If The Current Product Version Is Higher Than The New Product Version, Do Not Do Anything
						$response = $null
						If ([System.Version]$($productAADPwdProtectPrx.Version) -lt [System.Version]$installSourceVersion) {
							$response = Read-Host "Do You Want To UPGRADE The Current Version? (Y|N)"
						} ElseIf ([System.Version]$($productAADPwdProtectPrx.Version) -eq [System.Version]$installSourceVersion) {
							$response = Read-Host "Do You Want To Reinstall The Current Version? (Y|N)"
						} Else {
							$response = "N"
						}
						
						# When Confirmed To Upgrade/Reinstall, Then Actually Do It
						Write-Host ""
						If ($response.ToUpper() -eq "Y" -Or $response.ToUpper() -eq "YES") {
							Write-Host "Installing Azure AD Password Protection DC Agent Service On '$server'" -ForegroundColor Yellow
							$productAADPwdProtectPrxResult = installAADPwdProtectPrx $installSourceFullPath $installSourceVersion $execArgs
							Write-Host "Installation Completed!..." -ForegroundColor Yellow
							Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
							$installResultOnServer = $productAADPwdProtectPrxResult
							$installResultOnServer += $dotNETVersion
						} Else {
							Write-Host "Nothing Was Installed On '$server' As It Was Not Confirmed..." -ForegroundColor Yellow
							$installResultOnServer = "NO-INSTALL","Azure AD Password Protection Proxy Service Was NOT Upgraded/Reinstalled On '$server'",$($productAADPwdProtectPrx.Version),$installSourceVersion,$dotNETVersion
						}
					}
				} Else {
					Write-Host "Nothing Was Installed On '$server' As The Installation Source '$installSourceFullPath' Was Not Found..." -ForegroundColor Red
					$installResultOnServer = "NO-SOURCE","Azure AD Password Protection Proxy Service MSI IS NOT AVAILABLE/ACCESSIBLE On '$server'",$(If ($productAADPwdProtectPrx) {$($productAADPwdProtectPrx.Version)} Else {"NO-VERSION-INSTALLED"}),"VERSION-NOT-AVAILABLE",$dotNETVersion
				}
			} Else {
				Write-Host "$message on '$server'" -ForegroundColor Red
				Write-Host "Installed Version: $dotNETVersion" -ForegroundColor Red
				Write-Host "Skipping '$server'..." -ForegroundColor Red
				$installResultOnServer = "NO-DOTNET","$message on '$server'","NO-VERSION-INSTALLED","VERSION-NOT-AVAILABLE",$dotNETVersion
			}
		} Else {
			# Check The Connection To The Server If Remote
			$ports = 5985	# WinRM For Remote PowerShell
			$connectionCheckOK = $true
			$ports | %{
				$port = $null
				$port = $_
				$connectionResult = $null
				$connectionResult = portConnectionCheck $server $port 500
				If ($connectionResult -eq "ERROR") {
					$connectionCheckOK = $false
				}
			}
				
			$installResultOnServer = $null

			# If The Connection To The Server Is OK...
			If ($connectionCheckOK) {		
				Write-Host "ALL Required Ports ($($ports -join ",")) To The Server '$server' Are Available!..." -ForegroundColor Green
				
				# Setup A Session To The RWDC
				$targetedServerSession = $null
				$targetedServerSession = New-PSSession -ComputerName $server

				# Connect To The Server And Execute The Scriptblock
				$installResultOnServer = Invoke-Command -Session $targetedServerSession -ArgumentList $dateTime,$server,$installSourceFullPath,$retrieveMsiProductVersionDef,$checkDotNETVersionDef,$installAADPwdProtectPrxDef -ScriptBlock {
					Param(
						$dateTime,
						$server,
						$installSourceFullPath,
						$retrieveMsiProductVersionDef,
						$checkDotNETVersionDef,
						$installAADPwdProtectPrxDef
					)
					
					. ([ScriptBlock]::Create($retrieveMsiProductVersionDef))

					. ([ScriptBlock]::Create($checkDotNETVersionDef))

					. ([ScriptBlock]::Create($installAADPwdProtectPrxDef))

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
						Write-Host "$message on '$server'" -ForegroundColor Green
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
							$logFile = Join-Path $logFolder $("AzureADPasswordProtectionProxyService_Install_v" + $installSourceVersion + "_" + $server + "_" + $dateTime + ".log")
						
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

							# Retrieve The 'Azure AD Password Protection Proxy' Product Installation
							$productAADPwdProtectPrx = $null
							$productAADPwdProtectPrx = Get-WmiObject -Class win32_product -Filter "Name like 'Azure AD Password Protection Proxy'"
							
							# If It Does Not Yet Exist, Then Install It
							# If It Does Exist, Then Either Upgrade (Newer Version) Or Reinstall (Same Version) It After Confirmation
							If (!$productAADPwdProtectPrx) {
								$productAADPwdProtectPrxResult = installAADPwdProtectPrx $installSourceFullPath $installSourceVersion $execArgs
								Write-Host "Done!..." -ForegroundColor Yellow
								Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
								Return $productAADPwdProtectPrxResult,$dotNETVersion
							} Else {
								Write-Host "Azure AD Password Protection Proxy Service ALREADY INSTALLED On '$server'" -ForegroundColor Yellow
								Write-Host "Installed Version......................: $($productAADPwdProtectPrx.Version)" -ForegroundColor Yellow
								Write-Host "New Version............................: $installSourceVersion" -ForegroundColor Yellow
								Write-Host ""
								
								# If The Current Product Version Is Lower Than The New Product Version, Upgrade It
								# If The Current Product Version Is Equal To The New Product Version, Reinstall It
								# If The Current Product Version Is Higher Than The New Product Version, Do Not Do Anything
								$response = $null
								If ([System.Version]$($productAADPwdProtectPrx.Version) -lt [System.Version]$installSourceVersion) {
									$response = Read-Host "Do You Want To UPGRADE The Current Version? (Y|N)"
								} ElseIf ([System.Version]$($productAADPwdProtectPrx.Version) -eq [System.Version]$installSourceVersion) {
									$response = Read-Host "Do You Want To Reinstall The Current Version? (Y|N)"
								} Else {
									$response = "N"
								}
								
								# When Confirmed To Upgrade/Reinstall, Then Actually Do It
								Write-Host ""
								If ($response.ToUpper() -eq "Y" -Or $response.ToUpper() -eq "YES") {
									Write-Host "Installing Azure AD Password Protection DC Agent Service On '$server'" -ForegroundColor Yellow
									$productAADPwdProtectPrxResult = installAADPwdProtectPrx $installSourceFullPath $installSourceVersion $execArgs
									Write-Host "Installation Completed!..." -ForegroundColor Yellow
									Write-Host "Log File...............................: $logFile" -ForegroundColor Yellow
									Return $productAADPwdProtectPrxResult + $dotNETVersion
								} Else {
									Write-Host "Nothing Was Installed On '$server' As It Was Not Confirmed..." -ForegroundColor Yellow
									Return "NO-INSTALL","Azure AD Password Protection Proxy Service Was NOT Upgraded/Reinstalled On '$server'",$($productAADPwdProtectPrx.Version),$installSourceVersion,$dotNETVersion
								}
							}
						} Else {
							Write-Host "Nothing Was Installed On '$server' As The Installation Source '$installSourceFullPath' Was Not Found..." -ForegroundColor Red
							Return "NO-SOURCE","Azure AD Password Protection Proxy Service MSI IS NOT AVAILABLE/ACCESSIBLE On '$server'",$(If ($productAADPwdProtectPrx) {$($productAADPwdProtectPrx.Version)} Else {"NO-VERSION-INSTALLED"}),"VERSION-NOT-AVAILABLE",$dotNETVersion
						}
					} Else {
						Write-Host "$message on '$server'" -ForegroundColor Red
						Write-Host "Installed Version: $dotNETVersion" -ForegroundColor Red
						Write-Host "Skipping '$server'..." -ForegroundColor Red
						Return "NO-DOTNET","$message on '$server'","NO-VERSION-INSTALLED","VERSION-NOT-AVAILABLE",$dotNETVersion
					}						
				}

				Remove-PSSession $targetedServerSession
			} Else {
				Write-Host "ALL Required Ports ($($ports -join ",")) To The Server '$server' ARE NOT Available!..." -ForegroundColor Red
				Write-Host "Skipping Server '$server'..." -ForegroundColor Red
				$installResultOnServer = @("NO-CONNECTION","NOT ALL Required Ports ($($ports -join ",")) To The Server '$server' Are Available!...","VERSION-NOT-AVAILABLE","VERSION-NOT-AVAILABLE","UNABLE-TO-DETERMINE")
			}
		}

		# Add The Result For This RWDC To The Install Results List
		$resultStatus = $null
		$resultStatus = $installResultOnServer[0]
		$messageStatus = $null
		$messageStatus = $installResultOnServer[1]
		$previousPrxServiceVersion = $null
		$previousPrxServiceVersion = $installResultOnServer[2]
		$newPrxServiceVersion = $null
		$newPrxServiceVersion = $installResultOnServer[3]
		$dotNETVersion = $null
		$dotNETVersion = $installResultOnServer[4]
		
		$installStatus = New-Object -TypeName System.Object
		$installStatus | Add-Member -MemberType NoteProperty -Name "Server FQDN" -Value $server
		$installStatus | Add-Member -MemberType NoteProperty -Name "Result" -Value $resultStatus
		$installStatus | Add-Member -MemberType NoteProperty -Name "Message" -Value $messageStatus
		$installStatus | Add-Member -MemberType NoteProperty -Name "\.NET Version" -Value $dotNETVersion
		$installStatus | Add-Member -MemberType NoteProperty -Name "Prev. Version" -Value $previousPrxServiceVersion
		$installStatus | Add-Member -MemberType NoteProperty -Name "New Version" -Value $newPrxServiceVersion
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