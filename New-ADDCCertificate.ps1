<#
.SYNOPSIS

    Creates a custom Domain Controller certificate request for universal usage across platforms.

.DESCRIPTION

    Creates a custom Domain Controller certificate request for universal usage across platforms.
    We do this by adding subject alternative names including the root DNS, IP addresses and SLB names.
    This allows the DC to be used as a generic LDAP server on Linux servers, whilst taking advantage of DC
    failover.

.PARAMETER Template
    The template name from the certificate server.

.PARAMETER LBIpAddresses 
	An array of additional IP addresses to add to the certificate. Useful for load balanced LDAP(S).
	
.PARAMETER LBDNSNames
	An array of additional DNS names to add to the certificate.

.PARAMETER OrganizationalUnit
	X509 OU attribute

.PARAMETER Organization
	X509 Organization Attribute

.PARAMETER Street
    X509 Street attribute

.PARAMETER Locality
    X509 Locality Attribute

.PARAMETER Province
    X509 Province Attribute

.PARAMETER Country
    X509 Country Attribute

.PARAMETER ReqOut
    If specified, the script will about the CSR to the file path.

.PARAMETER CertOut
    If specified, the script will about the certificate to the file path.

.PARAMETER Submit
    Submit automatically to the CA.

.EXAMPLE
   
    .\New-ADDCCertificate.ps1 -Template AdvDomainControllerAuthentication -LBIpAddresses @("10.10.10.1","10.10.10.2") -LBDNSNames @("ldap-ad.local") \
     -Organization "Contoso" -Street "1 Redmond Drive" -Locality "Seattle" -Country US -ReqOut dc1.csr -CertOut dc1.crt -Submit

.NOTES
	Naadir Jeewa (2013)


#>

[CmdletBinding()]
Param(
[String]$Template = "DomainControllerAuthentication",
$LBIpAddresses,
$LBDNSNames,
$OrganizationalUnit,
$Organization,
$Street,
$Locality,
$Province,
$Country,
$reqout,
$certout,
[switch]$Submit
)
$ScriptDir = (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) 

# Load enumerations
import-module $ScriptDir\CERTLibraries.psm1

# Load ActiveDirectory module
import-module ActiveDirectory -ErrorAction SilentlyContinue

# Get the hostname
$hostname = [System.Net.Dns]::GetHostName() 
$hostFqdn = [System.Net.Dns]::GetHostByName("localhost").HostName
# Get the domain name
$domainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

# Build the DN attribute
$dn = "CN=$hostfqdn"

if($OrganizationalUnit)
{
    $dn = "$dn,OU=$organizationalUnit"
}


if($Organization)
{
    $dn = "$dn,OU=$Organization"
}

if($Street)
{
    $dn = "$dn,STREET=$Street"
}

if($Locality)
{
    $dn = "$dn,L=$Locality"
}

if($Province)
{
    $dn = "$dn,ST=$Province"
}

if($Country)
{
    $dn = "$dn,C=$Country"
}

# Create the COM objects for this request

$Pkcs10 = new-object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$DNObject = new-object -ComObject X509Enrollment.CX500DistinguishedName
$Enroll = new-object -ComObject X509Enrollment.CX509Enrollment
$ObjectIds = new-object -ComObject X509Enrollment.CObjectIds



# Use the specified template from the CA server and create a private key in the local machine context
$Pkcs10.InitializeFromTemplateName([CERTENROLLLib.X509CertificateEnrollmentContext]::ContextAdministratorForceMachine,$Template)

# Build the SAN attributes
$AlternativeNames = new-object -ComObject X509Enrollment.CAlternativeNames
$ExtensionAlternativeNames = new-object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
$AltNamesOID = new-object -ComObject X509Enrollment.CObjectId
$ExtensionAltNamesAdder = new-object -ComObject X509Enrollment.CX509Extension

# Encode the DN for the certificate
$DNObject.Encode($dn,[CERTENROLLLib.X500NameFlags]::XCN_CERT_NAME_STR_NONE)

# Add all the DNS entries into the SAN attributes

$DnsNames = @()

$DnsNames += $hostFqdn
$DnsNames += $domainName
$DnsNames += $LBDnsNames



foreach ($strDNS in $DnsNames)
{

 if(-not ([String]::IsNullOrEmpty($strDNS)))
 {
    $strDNS = $strDNS.ToLower()
     $DNSName = new-object -ComObject X509Enrollment.CAlternativeName
     $DNSName.InitializeFromString([CERTENROLLLib.AlternativeNameType]::XCN_CERT_ALT_NAME_DNS_NAME,$strDNS)
     $AlternativeNames.Add($DNSName)
 }
}

# Get all the IP addresses of this computer, and add these and those specified into the SAN attributes.
$IPAddresses =@()
$IPAddresses += $LBIpAddresses
$IPAddresses += gwmi Win32_NetworkAdapterConfiguration | Where { $_.IPAddress  }  | Select -Expand IPAddress  

foreach ($strIPAddress in $IpAddresses.GetEnumerator())
{
 if((-not ([String]::IsNullOrEmpty($strIPAddress))) -and ($strIPAddress -notcontains "%"))
 {

    $parseIP = [IPAddress]$strIPAddress
    if ($ParseIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) 
    {
      $IPAddress = new-object -ComObject X509Enrollment.CAlternativeName
      $octetIPAddress = [Convert]::ToBase64String($parseIP.GetAddressBytes())
      $IPAddress.InitializeFromRawData([CERTENROLLLib.AlternativeNameType]::XCN_CERT_ALT_NAME_IP_ADDRESS,[CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_BASE64,$octetIPAddress)
      $AlternativeNames.Add($IPAddress)
    }



 }
}

# Add the LDAP GUID of the computer as a SAN attribute
# Convert the GUID into an octet string
$dsGuid = ((get-adcomputer $hostname).objectguid).ToByteArray()
$dsGuidEnum = $dsGuid.GetEnumerator()
$dsGuidN = $dsGuidEnum.MoveNext()
$dsGuidString = $dsGuidEnum.Current.ToString('x2')
$dsGuidN = $dsGuidEnum.MoveNext()
while($dsGuidEnum.MoveNext())
{
    $dsGuidString += " " + $dsGuidEnum.Current.ToString('x2')
}
$dsGuidAltName = new-object -ComObject X509Enrollment.CAlternativeName
$dsGuidAltName.InitializeFromRawData([CERTENROLLLib.AlternativeNameType]::XCN_CERT_ALT_NAME_GUID,[CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_HEX,$dsGuidString)
$AlternativeNames.Add($dsGuidAltName)


# Add all the SAN attributes into the certificate request
$ExtensionAlternativeNames.InitializeEncode($AlternativeNames)
$altNamesRawData = $ExtensionAlternativeNames.RawData([CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_BINARY)
$AltNamesOID.InitializeFromName([CERTENROLLLib.CERTENROLL_OBJECTID]::XCN_OID_SUBJECT_ALT_NAME2)
$ExtensionAltNamesAdder.Initialize($AltNamesOID,[CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_BINARY,$altNamesRawData)
$Pkcs10.X509Extensions.Add($ExtensionAltNamesAdder)
$Pkcs10.Subject = $DNObject

# Create the request, and output to file if required.
$enroll.InitializeFromRequest($Pkcs10)
$request = $Enroll.CreateRequest([CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_BASE64REQUESTHEADER)
if ($reqout)
{
    $request | Out-File -FilePath $reqout -Encoding ascii
}


if ($submit)
{

# Find the CA to submit to 
$CertConfig = new-object -ComObject CertificateAuthority.Config
$CertRequest = new-object -ComObject CertificateAuthority.Request

$CAConfig = $CertConfig.GetConfig([CERTCliLib.ConfigFlags]::UIPickConfig)

# Submit the CSR
$disposition = $CertRequest.Submit([CERTCliLib.CertRequestFormat]::Base64 -xor [CERTCliLib.CertRequestFormat]::FormatAny, $request, $null, $CAConfig)

# See what the result is
if([CERTCliLib.CertDisposition]::Issued -ne $disposition)
{
    $dispositionMessage = $CertRequest.GetDispositionMessage()
    if ([CERTCliLib.CertDisposition]::UnderSubmission -eq $disposition)
    {
        write-host Submission is pending
        write-host $dispositionMessage
        Read-Host Press enter when authorised
    }
    else
    {
        write-host Submission failed
        write-host $dispositionMessage

    }
}

# If the certificate is ready, get it
$cert = $CertRequest.GetCertificate([CERTCliLib.CertOutput]::Base64 -xor [CERTCliLib.CertOutput]::Chain)

# Output the certificate to file if needed
if ($certout)
{
    $cert | Out-File -FilePath $certout -Encoding ascii
}

$enroll = new-object -ComObject X509Enrollment.CX509Enrollment
$enroll.Initialize([CERTENROLLLib.X509CertificateEnrollmentContext]::ContextAdministratorForceMachine)
$enroll.InstallResponse([CERTENROLLLib.InstallResponseRestrictionFlags]::AllowUntrustedRoot,$cert,[CERTENROLLLib.EncodingType]::XCN_CRYPT_STRING_BASE64HEADER,$null)

}