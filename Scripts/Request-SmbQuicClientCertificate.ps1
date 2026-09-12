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
    [string]$CertificateSubject,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$RenewalThresholdDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$clientAuthenticationOid = '1.3.6.1.5.5.7.3.2'
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

# The requested subject identifies the client certificate and lets scheduled runs reuse
# it. The certificate template must permit the requester to supply the subject name.
$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.HasPrivateKey -and
        $_.NotBefore -le (Get-Date) -and
        $_.NotAfter -gt $renewalDate -and
        $_.Subject -eq $CertificateSubject -and
        (Test-CertificateEnhancedKeyUsage -Certificate $_ -Oid $clientAuthenticationOid)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($certificate) {
    Write-Verbose "Reusing certificate $($certificate.Thumbprint), valid until $($certificate.NotAfter)."
} elseif ($PSCmdlet.ShouldProcess($CertificateSubject, "Request client certificate using template '$CertificateTemplate'")) {
    # Prefer native PowerShell where it can express the complete request. The template
    # supplies the Client Authentication EKU and the Enterprise CA installs the result.
    # SubjectName is required when the template uses "Supply in the request".
    $enrollmentResult = Get-Certificate -Template $CertificateTemplate -SubjectName $CertificateSubject -Url $EnrollmentPolicyUrl -CertStoreLocation 'Cert:\LocalMachine\My'
    if ($enrollmentResult.Status -ne 'Issued') {
        throw "Certificate enrollment did not complete immediately. Status: $($enrollmentResult.Status)."
    }

    $certificate = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.HasPrivateKey -and
            $_.Subject -eq $CertificateSubject -and
            $_.NotAfter -gt (Get-Date) -and
            (Test-CertificateEnhancedKeyUsage -Certificate $_ -Oid $clientAuthenticationOid)
        } |
        Sort-Object NotBefore -Descending |
        Select-Object -First 1
}

if (-not $certificate) { throw "No usable client certificate with subject '$CertificateSubject' was found or issued." }

# ConfigClientAccessControl.ps1 uses the certificate's SHA-256 thumbprint. This is
# different from the default SHA-1 Thumbprint property used for client mapping.
$certificateSha256Hash = $certificate.GetCertHashString('SHA256')
$certificate | Select-Object Subject, Thumbprint, NotBefore, NotAfter
"ClientCertificateSha256Hash: $certificateSha256Hash"

<#
Example:
.\Request-SmbQuicClientCertificate.ps1 `
    -CertificateTemplate 'SMBOverQUICClient' `
    -CertificateSubject 'CN=CLIENT01'

The default ldap: policy URL discovers the Enterprise CA through Active Directory.
#>