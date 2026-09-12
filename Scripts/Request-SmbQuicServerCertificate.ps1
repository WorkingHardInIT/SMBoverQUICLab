#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [Uri]$EnrollmentPolicyUrl = 'ldap:',

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateTemplate,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$DnsName,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$RenewalThresholdDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The first DNS name is used as the certificate subject. Every supplied name is added
# as a SAN because SMB over QUIC requires a separate mapping for every client-facing name.
$subject = "CN=$($DnsName[0])"
$serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'
$renewalDate = (Get-Date).AddDays($RenewalThresholdDays)

function Test-CertificateEnhancedKeyUsage {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$Oid
    )

    # EKUs are stored in extension 2.5.29.37, not as a property on every certificate
    # provider object. This works in Windows PowerShell 5.1 and PowerShell 7.
    $ekuExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    return $Oid -in @($ekuExtension | ForEach-Object { $_.EnhancedKeyUsages.Value })
}

function Test-CertificateDnsName {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string[]]$DnsName
    )

    # Pass the certificate explicitly so nested pipeline variables cannot be confused
    # with the DNS names being compared.
    $certificateDnsNames = @($Certificate.DnsNameList | ForEach-Object Unicode)
    return @($DnsName | Where-Object { $_ -notin $certificateDnsNames }).Count -eq 0
}

# Reuse a healthy existing certificate. This makes scheduled runs safe and only requests
# a replacement when no matching certificate exists or it is close to expiry.
$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.HasPrivateKey -and
        $_.NotBefore -le (Get-Date) -and
        $_.NotAfter -gt $renewalDate -and
        $_.Subject -eq $subject -and
        (Test-CertificateEnhancedKeyUsage -Certificate $_ -Oid $serverAuthenticationOid) -and
        (Test-CertificateDnsName -Certificate $_ -DnsName $DnsName)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($certificate) {
    Write-Verbose "Reusing certificate $($certificate.Thumbprint), valid until $($certificate.NotAfter)."
} elseif ($PSCmdlet.ShouldProcess($subject, "Request server certificate using template '$CertificateTemplate'")) {
    # Prefer native PowerShell where it can express the complete request. Get-Certificate
    # submits the selected template with the requested subject and SAN values, then installs
    # an immediately issued certificate in the Local Computer personal certificate store.
    $enrollmentResult = Get-Certificate -Template $CertificateTemplate -SubjectName $subject -DnsName $DnsName -Url $EnrollmentPolicyUrl -CertStoreLocation 'Cert:\LocalMachine\My'
    if ($enrollmentResult.Status -ne 'Issued') {
        throw "Certificate enrollment did not complete immediately. Status: $($enrollmentResult.Status)."
    }

    $certificate = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.HasPrivateKey -and
            $_.Subject -eq $subject -and
            $_.NotAfter -gt (Get-Date) -and
            (Test-CertificateEnhancedKeyUsage -Certificate $_ -Oid $serverAuthenticationOid) -and
            (Test-CertificateDnsName -Certificate $_ -DnsName $DnsName)
        } |
        Sort-Object NotBefore -Descending |
        Select-Object -First 1
}

if (-not $certificate) { throw 'No usable server certificate was found or issued.' }

$certificate | Select-Object Subject, Thumbprint, NotBefore, NotAfter, DnsNameList

<#
Example:
.\Request-SmbQuicServerCertificate.ps1 `
    -CertificateTemplate 'SMBOverQUICServer' `
    -DnsName 'file01', 'file01.datawisetech.corp', 'file01.datawisetech.com', 'file01.workinghardinit.work', 'fsquic', 'fsquic.datawisetech.corp', 'fsquic.datawisetech.com', 'fsquic.workinghardinit.work', 'kps.datawisetech.com'

The default ldap: policy URL discovers the Enterprise CA through Active Directory.
Include a short name only when clients use it in a UNC path. Include kps.datawisetech.com
only when this certificate is installed on the KDC Proxy server; a separate KDC Proxy
server should request its own certificate with that name.
#>