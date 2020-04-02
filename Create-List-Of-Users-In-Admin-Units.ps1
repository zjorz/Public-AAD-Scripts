# TO DO: Output to HTML!

# TABLE: AU Display Name | AU Object ID | User Display Name | User UPN | User Object ID
Clear-Host
### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ GET AUs WITH AU MEMBERS +++"
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
$auAndUserList = @()
If ($aUs) {
	$aUs | %{
		$aUDisplayName = $null
		$aUDisplayName = $_.DisplayName
		$auObjectID = $null
		$auObjectID = $_.ObjectId
		$auMembers = $null
		$auMembers = Get-AzureADAdministrativeUnitMember -ObjectId $auObjectID
		If ($auMembers) {
			$auMembers | %{
				$auMemberObjectID = $null
				$auMemberObjectID = $_.ObjectId
				$userObject = $null
				$userObject = Get-AzureADUser -ObjectId $auMemberObjectID
				$userDisplayName = $null
				$userDisplayName = $userObject.Displayname
				$userUPN = $null
				$userUPN = $userObject.UserPrincipalname
				
				$auAndUserEntry = New-Object -TypeName System.Object
				$auAndUserEntry | Add-Member -MemberType NoteProperty -Name "[AU Display Name]" -Value $auDisplayName
				$auAndUserEntry | Add-Member -MemberType NoteProperty -Name "[AU Object ID]" -Value $auObjectID
				$auAndUserEntry | Add-Member -MemberType NoteProperty -Name "[User Display Name]" -Value $userDisplayName
				$auAndUserEntry | Add-Member -MemberType NoteProperty -Name "[User UPN]" -Value $userUPN
				$auAndUserEntry | Add-Member -MemberType NoteProperty -Name "[User Object ID]" -Value $auMemberObjectID
				$auAndUserList += $auAndUserEntry
			}
		}
	}
}
If ($auAndUserList) {
	$auAndUserList | Sort -Property @{Expression={$_."[AU Display Name]"};Descending=$true},@{Expression={$_."[User Display Name]"};Descending=$true} | FT -AutoSize -Wrap
	#$auAndUserListString = $auAndUserList | Sort -Property @{Expression={$_."[AU Display Name]"};Descending=$true},@{Expression={$_."[User Display Name]"};Descending=$true} | FT -AutoSize -Wrap | Out-String
} Else {
	Write-Host ""
	Write-Host "No Members In The AU!..." -ForegroundColor Red
	Write-Host ""
}