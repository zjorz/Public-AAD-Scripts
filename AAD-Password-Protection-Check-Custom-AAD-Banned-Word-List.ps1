### Abstract: This PoSH Script Helps You In Azure AD Password Protection To Evaluate If Candidate Words For The Per Tenant List Already Are Listed In The Microsoft Global List
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-20: Initial version of the script (v0.1)

<#
.SYNOPSIS
	With this PoSH script, one can in Azure AD Password Protection evaluate if candidate words for the per Tenant List already are listed in the Microsoft Global List

.DESCRIPTION
	With this PoSH script, one can in Azure AD Password Protection evaluate if candidate words for the per Tenant List already are listed in the Microsoft Global List

.PARAMETER accountName
	The account name to use in the format "<Domain FQDN>\<sAMAccountName>"

.PARAMETER inputFileWordsFullPath
	The full path to the input file containing all words that need to be evaluated

.EXAMPLE
	Evaluate All The Words In The File Specified
	
	.\AAD-Password-Protection-Check-Custom-AAD-Banned-Word-List.ps1 -accountName "<domain account>" -inputFileWordsFullPath "<Full Path To The Word List>"

.NOTES
	The input file should have all the words that are a candidate to be put in the per tenant banned word list.
	
	No connection is needed to Azure AD.
	
	This script basically uses each word and appends three characters and sets the end result as the password on the specified user account. During that password set
	an event is generated in the 'Microsoft-AzureADPasswordProtection-DCAgent/Admin' event log on the RWDC where the password is being set. Based upon the event ID
	it is possible to determine if the word is on the global MSFT list and/or the per tenant list or not listed in any list.
	To be able to set the password on the targeted, the account executing this script requires at least the "Reset Password" Control Access Right on the targeted account.
	To be able to read the event log on the DC, in general Domain Admin equivalent permissions are needed, although reading an event log from an RWDC can be delegated.
	Looking at all this, all possible options, but also to keep this script as simple as possible from all kinds of checks, it was chosen to require at least
	"Domain Admins" or "Enterprise Admins" permissions. The script checks for this. I truely know this is not a best practice. I also highlive recommended that you
	delegate the required permissions and leave that up to you. It is possible to disable this check if you are using delegated permissions (perferred!) to run this script.
	
	Regarding the targeted account, it should be disabled and configured with a PSO that allows a minimum password length of 7 (minimum word length of 4 + 3 additional characters)

	Active Directory PowerShell CMDlets are required!
#>

Param(
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the account name in the format <Domain FQDN>\<sAMAccountName>')]
	[ValidateNotNullOrEmpty()]
	[string]$accountName,
	[Parameter(Mandatory=$TRUE, ValueFromPipeline=$TRUE, ValueFromPipelineByPropertyName=$TRUE,
		HelpMessage='Please specify the full path to the word list containing all the words for the custom per tenant list')]
	[ValidateNotNullOrEmpty()]
	[string]$inputFileWordsFullPath
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

### FUNCTION: Test Credentials For Domain Admin Privileges
Function testDomainAdmin ($domainName) {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole("$domainName\Domain Admins")
}

### FUNCTION: Test Credentials For Enterprise Admin Privileges
Function testEnterpriseAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	$thisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$rootDomainInThisADForest = $thisADForest.RootDomain
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole("$rootDomainInThisADForest\Enterprise Admins")
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ AAD PASSWORD PROTECTION - CHECK WORDS FOR CUSTOM PER TENANT LIST +++"
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
Write-Host "                                  ********************************************************************************" -ForeGroundColor Cyan
Write-Host "                                  *                                                                              *" -ForeGroundColor Cyan
Write-Host "                                  *   --> AAD Password Protection - Check Words For Custom Per Tenant List <--   *" -ForeGroundColor Cyan
Write-Host "                                  *                                                                              *" -ForeGroundColor Cyan
Write-Host "                                  *                 Written By: Jorge de Almeida Pinto [MVP-EMS]                 *" -ForeGroundColor Cyan
Write-Host "                                  *                                                                              *" -ForeGroundColor Cyan
Write-Host "                                  *               BLOG: http://jorgequestforknowledge.wordpress.com/             *" -ForeGroundColor Cyan
Write-Host "                                  *                                                                              *" -ForeGroundColor Cyan
Write-Host "                                  ********************************************************************************" -ForeGroundColor Cyan
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
$currentScriptPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition
$outputCSVFilePath = $currentScriptFolderPath + "\" + $dateTime + "_AAD-Pwd-Protection-Banned-Word-List-Check.CSV"

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
loadPoSHModules ActiveDirectory

### Get AD Forest Info
$adForest  = Get-ADForest
$adForestRootADDomainFQDN = $adForest.RootDomain
$adForestDomains = $adForest.Domains
Write-Host ""
Write-Host "AD Forest..............................: $adForestRootADDomainFQDN" -ForegroundColor Yellow

### Validate The AD Account Format
$domainFQDN = $accountName.SubString(0, $accountName.IndexOf("\"))
$accountFormatRegEx = "^.*\..*\\.*$"
If ($accountName -notmatch $accountFormatRegEx) {
	Write-Host ""
	Write-Host "The Account '$accountName' Is Not In The Format '<Domain FQDN>\<sAMAccountName>' (e.g. AD.NET\aadPasswordProtection)..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
}

If ($adForestDomains -notcontains $domainFQDN) {
	Write-Host ""
	Write-Host "The AD Domain '$domainFQDN' Does Not Exist In The AD Forest '$adForestRootADDomainFQDN'..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
}

### Test For Domain/Enterprise Admin Credentials
$userIsDomainAdmin = testDomainAdmin $domainFQDN
If (!$userIsDomainAdmin) {
	$userIsEnterpriseAdmin = testEnterpriseAdmin
	If (!$userIsEnterpriseAdmin) {
		Write-Host ""
		Write-Host "WARNING: Your User Account Is Not Running With Domain Administrator Equivalent Permissions In The AD Domain '$domainFQDN'!..." -ForeGroundColor Red
		Write-Host "WARNING: Your User Account Is Not Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootADDomainFQDN'!..." -ForeGroundColor Red
		Write-Host "For This Script To Run Successfully, Domain/Enterprise Administrator Equivalent Permissions Are Required..."  -ForegroundColor Red
		Write-Host "Aborting Script..."
		Write-Host ""
		
		EXIT
	} Else {
		Write-Host ""
		Write-Host "Your User Account Is Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootADDomainFQDN'!..." -ForeGroundColor Green
		Write-Host "Continuing Script..." -ForeGroundColor Green
		Write-Host ""
	}
} Else {
	Write-Host ""
	Write-Host "Your User Account Is Running With Domain Administrator Equivalent Permissions In The AD Domain '$domainFQDN'!..." -ForeGroundColor Green
	Write-Host "Continuing Script..." -ForeGroundColor Green
	Write-Host ""
}

### Validate The AD Account Exists
$sAMAccountName = $accountName.SubString($accountName.IndexOf("\") + 1)
$rwdcFQDN = (Get-ADDomainController -Discover -DomainName $domainFQDN -Writable).HostName[0]
$adUserAccount = Get-ADUser $sAMAccountName -Properties * -Server $rwdcFQDN
If (!$adUserAccount) {
	Write-Host ""
	Write-Host "The AD User Account '$sAMAccountName' Does Not Exist In The AD Domain '$domainFQDN'..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
} Else {
	Write-Host "Account For AAD Pwd Protection Word Check...: $accountName" -ForegroundColor Yellow
}

### Test For Existence Of/Access To Word List File
Write-Host "File With Banned Words To Check........: $inputFileWordsFullPath" -ForegroundColor Yellow
If (Test-Path $inputFileWordsFullPath) {
	$wordList = Get-Content $inputFileWordsFullPath
	$wordCount = $wordList.Count
	$sizeOfUpperValue = $wordCount.ToString().length
} Else {
	Write-Host ""
	Write-Host "The Word List File '$inputFileWordsFullPath' Does Not Exist Or Is Not Accessible..." -ForegroundColor Red
	Write-Host "Aborting Script..." -ForegroundColor Red
	Write-Host ""
	
	EXIT
}

### Retrieve Applicable Password Policy And With That The Min Pwd Length
$resultantPwdPolicy = $adUserAccount."msDS-ResultantPSO"
If ($resultantPwdPolicy) {
	$resultantPwdPolicySettings = Get-ADObject $resultantPwdPolicy -Properties * -Server $rwdcFQDN
	$minPwdLength = $resultantPwdPolicySettings."msDS-MinimumPasswordLength"
} Else {
	$resultantPwdPolicySettings = Get-ADObject $("DC=" + $domainFQDN.Replace(".",",DC=")) -Properties * -Server $rwdcFQDN
	$minPwdLength = $resultantPwdPolicySettings.minPwdLength
}
Write-Host "Min. Pwd Length Applicable To Account..: $minPwdLength" -ForegroundColor Yellow
Write-Host ""

### Setup Some Empty Arrays And Go Through The List Of Words
$processedWords = @()
$results = @()
$wordNr = 0
$WordInANNr = 0
$WordInGLNr = 0
$WordInPLNr = 0
$WordInBLNr = 0
$WordInNLNr = 0
$WordInULNr = 0

### For Every Word In The Wordlist
$wordList | %{
	# Increase The Counter
	$wordNr++
	
	# Get The Word
	$word = $null
	$word = $_
	
	# Get The Word Length
	$wordLength = $null
	$wordLength = $word.Length	

	# Set Check Values To 0 And Define An Empty Error List
	$minLengthCheck = 0
	$maxLengthCheck = 0
	$uniqueCheck = 0
	$pwdPolicyLengthCheck = 0
	$errorList = @()
	
	# Perform The Checks Of The Word
	If ($wordLength -ge 4) {
		$minLengthCheck = 1
	} Else {
		$errorList += "Too Short"
	}
	If ($wordLength -le 16) {
		$maxLengthCheck = 1
	} Else {
		$errorList += "Too Long"
	}
	If ($processedWords -notcontains $word) {
		$uniqueCheck = 1
		$processedWords += $word
	} Else {
		$errorList += "Duplicate/Already Tested"
	}
	If ($($wordLength + 3) -ge $minPwdLength) {
		$pwdPolicyLengthCheck = 1
	} Else {
		$errorList += "Cannot Test"
	}

	# Calculate The Full Score
	$fullCheck = $null
	$fullCheck = $minLengthCheck + $maxLengthCheck + $uniqueCheck + $pwdPolicyLengthCheck
	
	# Determine Whether Or Not To Process The Word
	If ($fullCheck -eq 4) {
		$execTime = $null
		$execTime = Get-Date
		$execTimeDisplay = $null
		$execTimeDisplay = Get-Date $execTime -Format "yyyy-MM-dd HH:mm:ss"

		Try {
			# When A Password Does Not Contain Any Word From The Forbidden List, No Score Is Calculated And From An Azure AD Password Protection Perspective The Password Is OK!
			# When A Password Contains At Least 1 Word From The Forbidden List, A Score Will Be Calculated. When The Score Is 5 Or Higher The Password With The Forbidden Word(s) Is Accepted.
			# Therefore To Check If A Word Is On Either The MSFT Global List Or The Per Tenant List Or Both, The Score Should Never Exceed The Score Of 4
			# Too make sure any AD complexity requirements are met three additional characters "z0Y" are added with the thought that those DO NOT create or extend a (new) word
			Set-ADAccountPassword -Identity $sAMAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $($word + "z0Y") -Force) -Server $rwdcFQDN
		} Catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
			# PlaceHolder
		}

		Start-Sleep -s 1 # Give The System Time To Process This Before Trying To Get The Event!
		
		# Retrieve The Event From The RWDC Caused By The Password Reset
		$events = $null
		$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-AzureADPasswordProtection-DCAgent/Admin';StartTime=$execTime} -ComputerName $rwdcFQDN -ErrorAction SilentlyContinue
		
		$status = $null
		$eventDateTimeCreation = $null
		$activityID = $null
		
		# If An Event Exist Process It, Determine What Is Applicable
		# https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-password-ban-bad-on-premises-monitor
		If ($events) {
			# Word Matches User's Account Name
			If ($events.id -contains 30023 -Or $events.id -contains 30022) {
				# Event ID 30023: Audit Mode, Word Matches User's Account Name
				# Event ID 30022: Enforce Mode, Word Matches User's Account Name
				$status = "Matches User's Account Name"
				$event = $events | ?{$_.id -eq 30023 -Or $_.id -eq 30022}
				Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:$($event.id) - Word '$word' Status: '$status'" -ForegroundColor DarkRed
				$WordInANNr++
			}

			# Word In Global List Only
			If ($events.id -contains 30009 -Or $events.id -contains 30005) {
				# Event ID 30009: Audit Mode, Word In Global List Only
				# Event ID 30005: Enforce Mode, Word In Global List Only
				$status = "In MSFT Global List"
				$event = $events | ?{$_.id -eq 30009 -Or $_.id -eq 30005}
				Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:$($event.id) - Word '$word' Status: '$status'" -ForegroundColor DarkCyan
				$WordInGLNr++
			}
			
			# Word In Per-Tenant List Only
			If ($events.id -contains 30007 -Or $events.id -contains 30003) {
				# Event ID 30007: Audit Mode, Word In Per-Tenant List Only
				# Event ID 30003: Enforce Mode, Word In Per-Tenant List Only
				$status = "In Per-Tenant List"
				$event = $events | ?{$_.id -eq 30007 -Or $_.id -eq 30003}
				Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:$($event.id) - Word '$word' Status: '$status'" -ForegroundColor Cyan
				$WordInPLNr++
			}
			
			# Word In Global List And In Per-Tenant List
			If ($events.id -contains 30029 -Or $events.id -contains 30027) {
				# Event ID 30029: Audit Mode, Word In Global List And In Per-Tenant List
				# Event ID 30027: Enforce Mode, Word In Global List And In Per-Tenant List
				$status = "In Global List And Per-Tenant List"
				$event = $events | ?{$_.id -eq 30029 -Or $_.id -eq 30027}
				Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:$($event.id) - Word '$word' Status: '$status'" -ForegroundColor Magenta
				$WordInBLNr++
			}
			
			# Word NOT In Global List And NOT In Per-Tenant List
			If ($events.id -contains 10015) {
				# Event ID 10015: Audit/Enforce Mode, Word NOT In Global List And NOT In Per-Tenant List
				$status = "Not In Any List"
				$event = $events | ?{$_.id -eq 10015}
				Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:$($event.id) - Word '$word' Status: '$status'" -ForegroundColor Green
				$WordInNLNr ++
			}
			
			$eventDateTimeCreation = $event.TimeCreated 
			$activityID = $event.ActivityId
		} Else {
			# There Is A Very Small Chance The Time Does Not Meet The Time Of The Event. Because Of That It May Not Find The Event ID
			$status = "Unable To Determine List"
			$eventDateTimeCreation = "UNKNOWN"
			$activityID = "UNKNOWN"
			Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID:ERROR - Word '$word' Status: '$status'" -ForegroundColor Red
			$WordInULNr++
		}
	} Else {
		$status = $errorList -join ", "
		$eventDateTimeCreation = "N.A."
		$activityID = "N.A."
		Write-Host "$($wordNr.ToString().PadLeft($sizeOfUpperValue,'0')) Of $wordCount - $execTimeDisplay - ID: N.A. - Word '$word' Status: '$status'" -ForegroundColor Red
		$WordInULNr++
	}

	# Define The Object And Store Data In iT
	$resultEntry = New-Object -TypeName System.Object
	$resultEntry | Add-Member -MemberType NoteProperty -Name "Nr" -Value $($wordNr.ToString().PadLeft($sizeOfUpperValue,'0'))
	$resultEntry | Add-Member -MemberType NoteProperty -Name "Word" -Value $word
	$resultEntry | Add-Member -MemberType NoteProperty -Name "Status" -Value $status
	$resultEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $rwdcFQDN
	$resultEntry | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value $eventDateTimeCreation
	$resultEntry | Add-Member -MemberType NoteProperty -Name "ActivityId" -Value $activityID
	$results += $resultEntry
}

Write-Host ""
Write-Host "CSV Report File........................: $outputCSVFilePath" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "Words Processed........................: $wordNr" -ForegroundColor DarkCyan
Write-Host "Words User's Account Name..............: $WordInANNr" -ForegroundColor DarkCyan
Write-Host "Words In Global List Only..............: $WordInGLNr" -ForegroundColor DarkCyan
Write-Host "Words In Per Tenant List Only..........: $WordInPLNr" -ForegroundColor DarkCyan
Write-Host "Words In Both Lists....................: $WordInBLNr" -ForegroundColor DarkCyan
Write-Host "Words Not In Any List..................: $WordInNLNr" -ForegroundColor DarkCyan
Write-Host "Words Unable To Check..................: $WordInULNr" -ForegroundColor DarkCyan
Write-Host ""

$results | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
$results | Out-GridView