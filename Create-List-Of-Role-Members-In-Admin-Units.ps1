# TO DO: Output to HTML!


# TABLE: # AU Display Name | AU Object ID | Role Within AU | User Display Name | User UPN | User Object ID
Clear-Host
### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ GET AUs WITH ROLES AND ROLE MEMBERS +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 200
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 200) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 200
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

$aUs = Get-AzureADAdministrativeUnit
$auRoleMemberList = @()
$aadRolesHT = New-Object System.Collections.Hashtable
If ($aUs) {
	$aUs | %{
		$auDisplayName = $null
		$auDisplayName = $_.DisplayName
		$auObjectID = $null
		$auObjectID = $_.ObjectId
		$auRolesAndMembers = $null
		$auRolesAndMembers = Get-AzureADScopedRoleMembership -ObjectId $auObjectID
		If ($auRolesAndMembers) {
			$auRolesAndMembers | %{
				$auRoleObjectID = $null
				$auRoleObjectID = $_.RoleObjectId
				$auRoleDisplayName = $null
				$auRoleDisplayName = $aadRolesHT[$auRoleObjectID]
				If (!$auRoleDisplayName) {
					$auRole = $null
					$auRole = Get-AzureADDirectoryRole -ObjectId $auRoleObjectID
					$auRoleDisplayName = $null
					$auRoleDisplayName = $auRole.DisplayName
					$aadRolesHT[$auRoleObjectID] = $auRoleDisplayName
				}
				$auRoleMembers = $_.RoleMemberInfo
				If ($auRoleMembers) {
					$auRoleMembers | %{
						$userObject = $null
						$userObject = $_
						$userDisplayName = $null
						$userDisplayName = $userObject.Displayname
						$userUPN = $null
						$userUPN = $userObject.UserPrincipalname
						$userObjectID = $null
						$userObjectID = $userObject.ObjectId
			
						$auRoleMemberEntry = New-Object -TypeName System.Object
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[AU Display Name]" -Value $auDisplayName
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[AU Object ID]" -Value $auObjectID
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[Role Within AU]" -Value $auRoleDisplayName
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[User Display Name]" -Value $userDisplayName
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[User UPN]" -Value $userUPN
						$auRoleMemberEntry | Add-Member -MemberType NoteProperty -Name "[User Object ID]" -Value $userObjectID
						$auRoleMemberList += $auRoleMemberEntry
					}
				}
			}
		}
	}
}
If ($auRoleMemberList) {
	$auRoleMemberList | Sort -Property @{Expression={$_."[AU Display Name]"};Descending=$true},@{Expression={$_."[Role Within AU]"};Descending=$true},@{Expression={$_."[User Display Name]"};Descending=$true} | FT -AutoSize -Wrap
	#$auAndUserListString = $auRoleMemberList | Sort -Property @{Expression={$_."[AU Display Name]"};Descending=$true},@{Expression={$_."[Role Within AU]"};Descending=$true},@{Expression={$_."[User Display Name]"};Descending=$true} | FT -AutoSize -Wrap
} Else {
	Write-Host ""
	Write-Host "No Role Members In The AU!..." -ForegroundColor Red
	Write-Host ""
}
