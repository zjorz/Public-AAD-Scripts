<#
	AUTHOR
		Written By....................: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS]
		Re-Written By.................: N.A.
		Blog..........................: http://jorgequestforknowledge.wordpress.com/
		For Feedback/Questions........: scripts.gallery@iamtec.eu
			--> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
			--> If Applicable Describe What Does and/Or Does Not Work.
			--> If Applicable Describe What Should Be/Work Different And Explain Why/How.
			--> Please Add Screendumps.

	TODO
		- N.A.

	KNOWN ISSUES/BUGS
		- N.A.

	CURRENT VERSION
		v0.1, 2021-09-08 (UPDATE THE VERSION VARIABLE BELOW)

	RELEASE NOTES
		v0.1, 2021-09-08, Jorge de Almeida Pinto [MVP-EMS]:
			- Initial version of the script
#>

<#
.SYNOPSIS
	This PoSH Script Adds And Removes Assignments To Administrative Units For Which A Filter Exist

.DESCRIPTION
	Based upon the filters defined for users and groups at AU level, the script will process the addition or removal of any user and/or group to/from the AU

.NOTES
	This script requires:
	* Registered Application In Azure AD
	* Application Level Permissions:
		- Microsoft Graph: AdministrativeUnit.ReadWrite.All (Read and write all administrative units)
		- Microsoft Graph: Group.Read.All (Read all groups)
		- Microsoft Graph: User.Read.All (Read all users' full profiles)
	* A Configured Certificate (Public) In The Registered Application
	* Automation Account In Azure AD
	* A Configured Certificate (Private) In The Automation Account
	* Variables defined for 'tenantFQDN' and ''
#>

### FUNCTION: Retrieve The Tenant ID From The Tenant FQDN
Function retrieveTenantIDFromTenantFDQN () {
	Param (
		[string]$tenantFQDN
	)

	# Specify The Tenant Specific Discovery Endpoint URL
	$oidcConfigDiscoveryURL = $null
	$oidcConfigDiscoveryURL = "https://login.microsoftonline.com/$tenantFQDN/v2.0/.well-known/openid-configuration"
	$oidcConfigDiscoveryResult = $null

	# Retrieve The Information From The Discovery Endpoint URL
	$tenantID = $null
	$oidcConfigDiscoveryResult = $null
	Try {
		$oidcConfigDiscoveryResult = Invoke-RestMethod -Uri $oidcConfigDiscoveryURL -ErrorAction Stop
	}
	Catch {
		# Placeholder
	}

	# If There Is A Result Determine The Tenant ID
	If ($null -ne $oidcConfigDiscoveryResult) {
		$tenantID = $oidcConfigDiscoveryResult.authorization_endpoint.Split("/")[3]
	}

	Return $tenantID
}

### FUNCTION: Authenticate With Application/Client ID And Application Secret
Function getAccessTokenForAppClientCredentials () {
	Param (
		[string]$tenantID,
		[string]$scope,
		[string]$appClientID,
		[string]$appClientSecret,
		$jwtAssertion
	)

	# Load Assembly To Use The URLEncode Function
	Add-Type -AssemblyName System.Web

	# Azure AD Token Request Endpoint URL
	$aadTokenRequestEndpointURL = $null
	$aadTokenRequestEndpointURL = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"

	# Build The Request Body To Request An Access Token
	$tokenRequestBody = "scope=$([System.Web.HttpUtility]::UrlEncode($scope))"
	$tokenRequestBody += "&grant_type=client_credentials"
	$tokenRequestBody += "&client_id=$appClientID"
	If ($appClientSecret -ne "") {
		$tokenRequestBody += "&client_secret=$appClientSecret"
	}
	If ($jwtAssertion -ne "") {
		$tokenRequestBody += "&client_assertion_type=$([System.Web.HttpUtility]::UrlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))"
		$tokenRequestBody += "&client_assertion=$jwtAssertion"
	}

	# Request New Tokens For The Scoped Resource
	$tokenRequestResponse = Invoke-RestMethod -uri $aadTokenRequestEndpointURL -ContentType "application/x-www-form-urlencoded" -Method POST -Body $tokenRequestBody -ErrorAction Stop

	Return $tokenRequestResponse
}

### FUNCTION: Authenticate With Application/Client ID And Application Secret
Function generateJWTAssertionForCertAuthN () {
	Param (
		[string]$tenantID,
		[string]$appClientID,
		$x509PrivateKeyAndCertificate
	)

	# Create base64 hash of certificate
	$authNcertificateBase64Hash = [System.Convert]::ToBase64String($x509PrivateKeyAndCertificate.GetCertHash())

	# Create JWT timestamp for validity/expiration
	$jwtStartDateTime = (Get-Date).ToUniversalTime()
	$jwtStartDateTime = [Math]::Floor([decimal](Get-Date($jwtStartDateTime) -UFormat "%s"))
	$jwtEndDateTime = $jwtStartDateTime + 1000

	# Create JWT header
	$jwtHeader = @{
		alg = "RS256"
		typ = "JWT"
		# Use the CertificateBase64Hash and replace/strip to match web encoding of base64
		x5t = $authNcertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
	}

	# Create JWT payload
	$jwtPayLoad = @{
		# What endpoint is allowed to use this JWT
		aud = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"

		# Issued at
		iat = $jwtStartDateTime

		# Not to be used before
		nbf = $jwtStartDateTime

		# Not to be used after
		exp = $jwtEndDateTime
		# Issuer = your application

		iss = $appClientID

		# JWT ID: random guid
		jti = [guid]::NewGuid()

		# JWT Subject
		sub = $appClientID
	}

	# Convert header and payload to base64
	$jwtHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
	$encodedHeader = [System.Convert]::ToBase64String($jwtHeaderToByte)
	$jwtPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayload | ConvertTo-Json))
	$encodedPayload = [System.Convert]::ToBase64String($jwtPayLoadToByte)

	# Join header and Payload with "." to create a valid (unsigned) JWT and encode it
	$jwtAssertion = $encodedHeader + "." + $encodedPayload
	$jwtAssertionEncoded = [System.Text.Encoding]::UTF8.GetBytes($jwtAssertion)

	# Get the private key object of your certificate
	$certPrivateKey = $x509PrivateKeyAndCertificate.PrivateKey

	# Define RSA signature and hashing algorithm
	$rsaPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
	$hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

	# Create a signature of the JWT
	$signature = [Convert]::ToBase64String(
		$certPrivateKey.SignData($jwtAssertionEncoded, $hashAlgorithm, $rsaPadding)
	) -replace '\+', '-' -replace '/', '_' -replace '='

	# Join the signature to the JWT with "."
	$jwtAssertion = $jwtAssertion + "." + $signature

	Return $jwtAssertion
}

### Version Of Script
$version = "v0.1, 2021-09-08"

### Definition Of Some Constants
$msftGraphFQDN = "graph.microsoft.com" # FQDN For Microsoft Graph
$scope = $('https://' + $msftGraphFQDN + '/.default')
$tenantFQDN = Get-AutomationVariable -Name 'tenantFQDN'
$appClientID = Get-AutomationVariable -Name 'appClientID'
$x509PrivateKeyAndCertificate = Get-AutomationCertificate -Name 'mgmt-Admin-Units-MSFT-Graph'

Write-Output ""
Write-Output "                                                                            *******************************************************************************"
Write-Output "                                                                            *                                                                             *"
Write-Output "                                                                            *              --> Automating Administrative Unit Assignment <--              *"
Write-Output "                                                                            *                                                                             *"
Write-Output "                                                                            *                Written By: Jorge de Almeida Pinto [MVP-EMS]                 *"
Write-Output "                                                                            *                      Lead Identity/Security Architect                       *"
Write-Output "                                                                            *               IAMTEC - Identity/Security Consultancy Services               *"
Write-Output "                                                                            *                                                                             *"
Write-Output "                                                                            *                      BLOG: Jorge's Quest For Knowledge                      *"
Write-Output "                                                                            *             (URL: http://jorgequestforknowledge.wordpress.com/)             *"
Write-Output "                                                                            *                                                                             *"
Write-Output "                                                                            *                              $version                               *"
Write-Output "                                                                            *                                                                             *"
Write-Output "                                                                            *******************************************************************************"
Write-Output ""

# Determine The Tenant ID
$tenantID = retrieveTenantIDFromTenantFDQN -tenantFQDN $tenantFQDN
If (!$([guid]::TryParse($tenantID, $([ref][guid]::Empty)))) {
	Write-Output ""
	Write-Output "Specified Tenant '$tenantFQDN' DOES NOT Exist..."
	Write-Output ""
	Write-Output " => Aborting Script..."
	Write-Output ""

	BREAK
}

# Get An Access Token Response
$jwtAssertion = generateJWTAssertionForCertAuthN -tenantID $tenantID -appClientID $appClientID -x509PrivateKeyAndCertificate $x509PrivateKeyAndCertificate
$accessTokenResponseForScopedResource = getAccessTokenForAppClientCredentials -tenantID $tenantID -scope $scope -appClientID $appClientID -jwtAssertion $jwtAssertion
$accessTokenType = $($accessTokenResponseForScopedResource.token_type)
$accessToken = $($accessTokenResponseForScopedResource.access_token)

# Determine The Administrative Units
Write-Output ""
Write-Output "Getting List Of Administrative Units From The Azure AD Tenant '$tenantFQDN'..."
$totalResultsAUs = @()
$endpointURLAUs = "https://graph.microsoft.com/beta/administrativeunits`?`$select=id,displayName,Description"
$queryPageResultAUs = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUs -Method Get
$totalResultsAUs += $queryPageResultAUs.value
$nextResultPage = $queryPageResultAUs.'@odata.nextLink'
$i = 1
While ($null -ne $nextResultPage) {
	$i++
	$queryPageResultAUs = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $nextResultPage -Method Get
	$nextResultPage = $queryPageResultAUs."@odata.nextLink"
	$totalResultsAUs += $queryPageResultAUs.value
}
#$totalResultsAUs
$totalResultsAUs | ForEach-Object {
	$auObject = $_
	$auObjectID = $auObject.id
	$auDisplayName = $auObject.DisplayName
	Write-Output " > Administrative Unit: $auObjectID | $auDisplayName"
}

Write-Output ""
Write-Output "Processing Memberships For Each Administrative Unit In The Azure AD Tenant '$tenantFQDN'..."
$totalResultsAUs | ForEach-Object {
	# Let's Get And Refresh The Access Token
	$jwtAssertion = $null
	$jwtAssertion = generateJWTAssertionForCertAuthN -tenantID $tenantID -appClientID $appClientID -x509PrivateKeyAndCertificate $x509PrivateKeyAndCertificate
	$accessTokenResponseForScopedResource = $null
	$accessTokenResponseForScopedResource = getAccessTokenForAppClientCredentials -tenantFQDN $tenantFQDN -tenantID $tenantID -scope $scope -appClientID $appClientID -jwtAssertion $jwtAssertion
	$accessTokenType = $null
	$accessTokenType = $($accessTokenResponseForScopedResource.token_type)
	$accessToken = $null
	$accessToken = $($accessTokenResponseForScopedResource.access_token)

	$auObject = $_
	$auObjectID = $auObject.id
	$auDisplayName = $auObject.DisplayName
	$auDescription = $auObject.description
	If ($auDescription -like "*|*") {
		$userFilter = $auDescription.Split("|")[1].Replace("filter:user=", "")
		$groupFilter = $auDescription.Split("|")[2].Replace("filter:group=", "")
		Write-Output " > Administrative Unit: $auObjectID | $auDisplayName"
		Write-Output "   # AU User Filter.......................: $userFilter"
		Write-Output "   # AU Group Filter......................: $groupFilter"

		If (($userFilter -ne "NA" -And $userFilter -ne "" -And $userFilter -ne $null) -Or ($groupFilter -ne "NA" -And $groupFilter -ne "" -And $groupFilter -ne $null)) {
			Write-Output "   # Getting List Of User/Groups Objects Already Assigned To This AU '$auDisplayName'..."
			$endpointURLAUMembers = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auObjectID/members/"
			$totalResultsMemberUsers = @()
			$totalResultsMemberGroups = @()
			$queryPageResultMembers = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUMembers -Method Get
			$totalResultsMemberUsers += $queryPageResultMembers.value | Where-Object { $_."@odata.type" -eq "#microsoft.graph.user" }
			$totalResultsMemberGroups += $queryPageResultMembers.value | Where-Object { $_."@odata.type" -eq "#microsoft.graph.group" }
			$nextResultPage = $queryPageResultMembers.'@odata.nextLink'
			$i = 1
			While ($null -ne $nextResultPage) {
				$i++
				$queryPageResultMembers = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $nextResultPage -Method Get
				$nextResultPage = $queryPageResultMembers."@odata.nextLink"
				$totalResultsMemberUsers += $queryPageResultMembers.value | Where-Object { $_."@odata.type" -eq "#microsoft.graph.user" }
				$totalResultsMemberGroups += $queryPageResultMembers.value | Where-Object { $_."@odata.type" -eq "#microsoft.graph.group" }
			}
			#$totalResultsMemberUsers
			#$totalResultsMemberGroups
		}

		If ($userFilter -ne "NA" -And $userFilter -ne "" -And $userFilter -ne $null) {
			Write-Output "   # Getting List Of User Objects Matching The User Filter For The AU '$auDisplayName'..."
			$endpointURLAUMembershipAdd = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auObjectID/members/`$ref"
			$totalResultsQueriedUsers = @()
			$endpointURLUsers = "https://graph.microsoft.com/v1.0/users`?`$filter=$userFilter&`$select=id,displayName,userPrincipalName"
			$queryPageResultUsers = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLUsers -Method Get
			$totalResultsQueriedUsers += $queryPageResultUsers.value
			$nextResultPage = $queryPageResultUsers.'@odata.nextLink'
			$i = 1
			While ($null -ne $nextResultPage) {
				$i++
				$queryPageResultUsers = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $nextResultPage -Method Get
				$nextResultPage = $queryPageResultUsers."@odata.nextLink"
				$totalResultsQueriedUsers += $queryPageResultUsers.value
			}
			#$totalResultsQueriedUsers

			Write-Output "   # Determining User Objects To Remove Assignment For The AU '$auDisplayName'..."
			$totalResultsMemberUsers | ForEach-Object {
				$userMemberObject = $_
				$userMemberObjectID = $userMemberObject.id
				#$userMemberDisplayName = $userMemberObject.DisplayName
				$userMemberUserPrincipalName = $userMemberObject.userPrincipalName
				If ($totalResultsQueriedUsers.id -contains $userMemberObjectID) {
					$totalResultsQueriedUsers = $totalResultsQueriedUsers | Where-Object { $_.id -ne $userMemberObjectID }
				}
				Else {
					Write-Output "     - Removing Assignment | User Object '$userMemberUserPrincipalName' ($userMemberObjectID) From AU '$auDisplayName' ($auObjectID)..."
					$endpointURLAUMembershipDel = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auObjectID/members/$userMemberObjectID/`$ref"
					Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUMembershipDel -Method DELETE -ErrorAction Stop | Out-Null
				}
			}

			Write-Output "   # Determining User Objects To Add Assignment For The AU '$auDisplayName'..."
			$totalResultsQueriedUsers | ForEach-Object {
				$userObject = $_
				$userObjectID = $userObject.id
				#$userDisplayName = $userObject.DisplayName
				$userUserPrincipalName = $userObject.userPrincipalName
				$endpointURLUserAUMembership = "https://graph.microsoft.com/v1.0/users/$userObjectID/memberOf/microsoft.graph.administrativeUnit"
				$queryResultUserAUMembership = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLUserAUMembership -Method Get
				If ($queryResultUserAUMembership.value.id -notcontains $auObjectID) {
					Write-Output "     - Add Assignment | User Object '$userUserPrincipalName' ($userObjectID) To AU '$auDisplayName' ($auObjectID)..."
					$requestBody = @"
{
	"`@odata.id": "https://graph.microsoft.com/v1.0/users/$userObjectID"
}
"@
					Try {
						Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUMembershipAdd -ContentType "application/json" -Method POST -Body $requestBody -ErrorAction Stop | Out-Null
					}
					Catch {
						Write-Output ""
						Write-Output "   # === ERROR ==="
						Write-Output ""
						Write-Output "Exception Type......: $($_.Exception.GetType().FullName)"
						Write-Output ""
						Write-Output "Exception Message...: $($_.Exception.Message)"
						Write-Output ""
						Write-Output "Exception Stck Trace: $($_.Exception.StackTrace)"
						Write-Output ""
						Write-Output "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)"
						Write-Output ""
					}
				}
				Else {
					Write-Output "     - Existing Assignment | User Object '$userUserPrincipalName' ($userObjectID) Already In AU '$auDisplayName' ($auObjectID)..."
				}
			}
		}

		If ($groupFilter -ne "NA" -And $groupFilter -ne "" -And $groupFilter -ne $null) {
			Write-Output "   # Getting List Of Group Objects Matching The User Filter For The AU '$auDisplayName'..."
			$endpointURLAUMembershipAdd = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auObjectID/members/`$ref"
			$totalResultsQueriedGroups = @()
			$endpointURLGroups = "https://graph.microsoft.com/v1.0/groups`?`$filter=$groupFilter&`$select=id,displayName"
			$queryPageResultGroups = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLGroups -Method Get
			$totalResultsQueriedGroups += $queryPageResultGroups.value
			$nextResultPage = $queryPageResultGroups.'@odata.nextLink'
			$i = 1
			While ($null -ne $nextResultPage) {
				$i++
				$queryPageResultGroups = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $nextResultPage -Method Get
				$nextResultPage = $queryPageResultGroups."@odata.nextLink"
				$totalResultsQueriedGroups += $queryPageResultGroups.value
			}
			#$totalResultsQueriedGroups

			Write-Output "   # Determining Group Objects To Remove Assignment For The AU '$auDisplayName'..."
			$totalResultsMemberGroups | ForEach-Object {
				$groupMemberObject = $_
				$groupMemberObjectID = $groupMemberObject.id
				$groupMemberDisplayName = $groupMemberObject.DisplayName
				If ($totalResultsQueriedGroups.id -contains $groupMemberObjectID) {
					$totalResultsQueriedGroups = $totalResultsQueriedGroups | Where-Object { $_.id -ne $groupMemberObjectID }
				}
				Else {
					Write-Output "     - Removing Assignment | Group Object '$groupMemberDisplayName' ($groupMemberObjectID) From AU '$auDisplayName' ($auObjectID)..."
					$endpointURLAUMembershipDel = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auObjectID/members/$groupMemberObjectID/`$ref"
					Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUMembershipDel -Method DELETE -ErrorAction Stop | Out-Null
				}
			}

			Write-Output "   # Determining Group Objects To Add Assignment For The AU '$auDisplayName'..."
			$totalResultsQueriedGroups | ForEach-Object {
				$groupObject = $_
				$groupObjectID = $groupObject.id
				$groupDisplayName = $groupObject.DisplayName

				$endpointURLGroupAUMembership = "https://graph.microsoft.com/v1.0/groups/$groupObjectID/memberOf/microsoft.graph.administrativeUnit"

				$queryResultGroupAUMembership = Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLGroupAUMembership -Method Get

				If ($queryResultGroupAUMembership.value.id -notcontains $auObjectID) {
					Write-Output "     - Add Assignment | Group Object '$groupDisplayName' ($groupObjectID) To AU '$auDisplayName' ($auObjectID)..."

					$requestBody = @"
{
	"`@odata.id": "https://graph.microsoft.com/v1.0/groups/$groupObjectID"
}
"@
					Try {
						Invoke-RestMethod -Headers @{Authorization = "$accessTokenType $accessToken" } -Uri $endpointURLAUMembershipAdd -ContentType "application/json" -Method POST -Body $requestBody -ErrorAction Stop | Out-Null
					}
					Catch {
						Write-Output ""
						Write-Output "   # === ERROR ==="
						Write-Output ""
						Write-Output "Exception Type......: $($_.Exception.GetType().FullName)"
						Write-Output ""
						Write-Output "Exception Message...: $($_.Exception.Message)"
						Write-Output ""
						Write-Output "Exception Stck Trace: $($_.Exception.StackTrace)"
						Write-Output ""
						Write-Output "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)"
						Write-Output ""
					}
				}
				Else {
					Write-Output "     - Existing Assignment | Group Object '$groupDisplayName' ($groupObjectID) Already In AU '$auDisplayName' ($auObjectID)..."
				}
			}
		}
		Write-Output ""
	}
 Else {
		Write-Output " > SKIPPING Administrative Unit: $auObjectID | $auDisplayName"
		Write-Output ""
	}
}