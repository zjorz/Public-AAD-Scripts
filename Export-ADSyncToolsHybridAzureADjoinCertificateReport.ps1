<#
.Synopsis
   This script generates a report about certificates stored in Active Directory Computer objects, specifically, 
   certificates issued by the Hybrid Azure AD join feature.
   
   Original Source: https://gallery.technet.microsoft.com/scriptcenter/Export-Hybrid-Azure-AD-f8e51436
   Original Writer: Nuno Alex (https://social.technet.microsoft.com/profile/nuno%20alex/)
   Updated by: Jorge de Almeida Pinto (https://jorgequestforknowledge.wordpress.com/)
		Contains the changes as described in: https://jorgequestforknowledge.wordpress.com/2019/10/08/synched-computers-devices-being-cleaned-up-from-azure-ad/
   
   
.DESCRIPTION
   It checks the certificates present in the UserCertificate property of a Computer object in AD and, for each 
   non-expired certificate present, validates if the certificate was issued for the Hybrid Azure AD join feature 
   (i.e. Subject Name matches CN={ObjectGUID}).
   Before, Azure AD Connect would synchronize to Azure AD any Computer that contained at least one valid 
   certificate but starting on Azure AD Connect version 1.4, the sync engine can identify Hybrid 
   Azure AD join certificates and will ‘cloudfilter’ the computer object from synchronizing to Azure AD unless 
   there’s a valid Hybrid Azure AD join certificate.
   Azure AD Device objects that were already synchronized to AD but do not have a valid Hybrid Azure AD join 
   certificate will be deleted (CloudFiltered=TRUE) by the sync engine.
.EXAMPLE
	Looking at a specific computer

   .\Export-ADSyncToolsHybridAzureADjoinCertificateReport.ps1 -DN 'CN=Computer1,OU=SYNC,DC=Fabrikam,DC=com'
.EXAMPLE
	Looking at computer objects within a specific OU
	
   .\Export-ADSyncToolsHybridAzureADjoinCertificateReport.ps1 -DN 'OU=SYNC,DC=Fabrikam,DC=com' -Filename "MyHybridAzureADjoinReport.csv" -Verbose
.EXAMPLE
	Looking at computer objects within a specific AD domain
	
   .\Export-ADSyncToolsHybridAzureADjoinCertificateReport.ps1 -DN 'DC=child,DC=Fabrikam,DC=com' -Filename "MyHybridAzureADjoinReport.csv" -Verbose
.EXAMPLE
	Looking at computer objects within a specific AD forest
	
   .\Export-ADSyncToolsHybridAzureADjoinCertificateReport.ps1 -DN PhantomRoot -Filename "MyHybridAzureADjoinReport.csv" -Verbose
#>
    [CmdletBinding()]
    Param
    (
        # DistinguishedName of computer, OU, or domain
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [String]
        $DN,

        # Output CSV filename (optional)
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=1)]
        [String]
        $Filename
    )

    # Generate Output filename if not provided
    If ($Filename -eq "")
    {
        $Filename = [string] "$([string] $(Get-Date -Format yyyyMMddHHmmss))_ADSyncAADHybridJoinCertificateReport.csv"
    }
    Write-Verbose "Output filename: '$Filename'"
    
	# Retrieve Object Type Of DN
	If ($DN -ne "PhantomRoot")
	{
		$objectType = (Get-ADObject -LDAPFilter "(distinguishedname=$DN)").objectClass # Do not use Get-ADObject $DN as it will throw an error if the object does not exist (even with ErrorAction defined)!
	}
	Else
	{
		$objectType = "forestDNS" # Madeup, not for real!
		$DN = ""
	}
	
		
	# Read AD object(s)
	If ($objectType -eq "computer")
	{
		$domainFQDN = $($DN.SubString($DN.IndexOf(",DC=") + 1)).Replace(",DC=",".").Replace("DC=","")
		$directoryObjs = @(Get-ADObject $DN -Properties userCertificate -Server $domainFQDN)
	}
	ElseIf ($objectType -eq "domainDNS" -Or $objectType -eq "organizationalUnit" -Or $objectType -eq "container" -Or $objectType -eq "forestDNS")
	{
		$gcFQDN = $(Get-ADDomainController -Discover -Service GlobalCatalog).HostName[0]
		$directoryObjs = Get-ADObject -Filter { ObjectClass -like 'computer' } -SearchBase $DN -Properties userCertificate -Server $gcFQDN`:3268
	}
	Else{
		Write-Host "Specified DN '$DN'" -Foregroundcolor Red
		Write-Host "Incorrect object type of specified DN or DN does not exist!" -Foregroundcolor Red
		Write-Host "Aborting Script..." -Foregroundcolor Red
		
		EXIT
	}

    Write-Host "Processing $($directoryObjs.Count) directory object(s). Please wait..."
    # Check Certificates on each AD Object
    $results = @()
    ForEach ($obj in $directoryObjs)
    {
        # Read UserCertificate multi-value property
        $objDN = [string] $obj.DistinguishedName
        $objectGuid = [string] ($obj.ObjectGUID).Guid
        $userCertificateList = @($obj.UserCertificate)
        $validEntries = @()
        $totalEntriesCount = $userCertificateList.Count
        Write-verbose "'$objDN' ObjectGUID: $objectGuid"
        Write-verbose "'$objDN' has $totalEntriesCount entries in UserCertificate property."
        If ($totalEntriesCount -eq 0)
        {
            Write-verbose "'$objDN' has no Certificates - Skipped."
            Continue
        }

        # Check each UserCertificate entry and build array of valid certs
        ForEach($entry in $userCertificateList)
        {
            Try
            {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $entry
            }
            Catch
            {
                Write-verbose "'$objDN' has an invalid Certificate!"
                Continue
            }
            Write-verbose "'$objDN' has a Certificate with Subject: $($cert.Subject); Thumbprint:$($cert.Thumbprint)."
            $validEntries += $cert

        }
        
        $validEntriesCount = $validEntries.Count
        Write-verbose "'$objDN' has a total of $validEntriesCount certificates (shown above)."
        
        # Get non-expired Certs (Valid Certificates)
        $validCerts = @($validEntries | Where-Object {$_.NotAfter -ge (Get-Date)})
        $validCertsCount = $validCerts.Count
        Write-verbose "'$objDN' has $validCertsCount valid certificates (not-expired)."

        # Check for AAD Hybrid Join Certificates
        $hybridJoinCerts = @()
        $hybridJoinCertsThumbprints = [string] "|"
        ForEach ($cert in $validCerts)
        {
            $certSubjectName = $cert.Subject
            If ($certSubjectName.StartsWith($("CN=$objectGuid")) -or $certSubjectName.StartsWith($("CN={$objectGuid}")))
            {
                $hybridJoinCerts += $cert
                $hybridJoinCertsThumbprints += [string] $($cert.Thumbprint) + '|'
            }
        }

        $hybridJoinCertsCount = $hybridJoinCerts.Count
        if ($hybridJoinCertsCount -gt 0)
        {
            $cloudFiltered = 'FALSE'
            Write-verbose "'$objDN' has $hybridJoinCertsCount AAD Hybrid Join Certificates with Thumbprints: $hybridJoinCertsThumbprints (cloudFiltered=FALSE)"
        }
        Else
        {
            $cloudFiltered = 'TRUE'
            Write-verbose "'$objDN' has no AAD Hybrid Join Certificates (cloudFiltered=TRUE)."
        }
        
        # Save results
        $r = "" | Select ObjectDN, ObjectGUID, TotalEntriesCount, CertsCount, ValidCertsCount, HybridJoinCertsCount, CloudFiltered
        $r.ObjectDN = $objDN
        $r.ObjectGUID = $objectGuid
        $r.TotalEntriesCount = $totalEntriesCount
        $r.CertsCount = $validEntriesCount
        $r.ValidCertsCount = $validCertsCount
        $r.HybridJoinCertsCount = $hybridJoinCertsCount
        $r.CloudFiltered = $cloudFiltered
        $results += $r
    }

    # Export results to CSV
    Try
    {        
        $results | Export-Csv $Filename -NoTypeInformation -Delimiter ';'
        Write-Host "Exported Hybrid Azure AD Domain Join Certificate Report to '$Filename'.`n"
    }
    Catch
    {
        Throw "There was an error saving the file '$Filename': $($_.Exception.Message)"
    }
