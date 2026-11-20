<#
  A TLS server that is served by Windows Schannel (.NET SslStream), for the test
  `tls::tests::windows_schannel_server_is_inspected` (core/src/tls.rs) and for manual checks.
  No administrator rights are needed and nothing is added to a certificate store: the
  self-signed certificate is created in memory and round-tripped through PFX bytes, because
  Schannel refuses an ephemeral key ("the platform does not support ephemeral keys"). The
  imported key is a temporary key container of the current user that is deleted when the
  certificate object is disposed at the end of the run.

  pwsh -NoProfile -File lab/schannel_server.ps1 [-Port 0] [-Seconds 60]

  Prints one line, "READY <port>", then answers every connection with an HTTP 200 and closes
  it, until -Seconds have passed. The protocol versions and cipher suites are the ones the
  operating system enables for Schannel; nothing is configured here, on purpose: the test
  asserts what the machine does, and prints it.
#>
param(
  [int]$Port = 0,
  [int]$Seconds = 60
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=ns-schannel.invalid', $rsa,
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$ekuOids = [System.Security.Cryptography.OidCollection]::new()
[void]$ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
$request.CertificateExtensions.Add(
  [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
$ephemeral = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
$pfx = $ephemeral.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'x')
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
  $pfx, 'x', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Output ("READY " + $listener.LocalEndpoint.Port)
[Console]::Out.Flush()
$deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
while ([DateTime]::UtcNow -lt $deadline) {
  if (-not $listener.Pending()) { Start-Sleep -Milliseconds 20; continue }
  $client = $listener.AcceptTcpClient()
  try {
    $client.ReceiveTimeout = 3000
    $client.SendTimeout = 3000
    $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
    $ssl.AuthenticateAsServer($cert)
    $body = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nServer: schannel-lab`r`nContent-Length: 3`r`nConnection: close`r`n`r`nok`n")
    $ssl.Write($body, 0, $body.Length)
    $ssl.Flush()
    $ssl.Close()
  } catch {
    # a probe that ends the handshake early (the scanner does) is normal; say why on stderr
    $inner = $_.Exception.InnerException
    [Console]::Error.WriteLine("handshake: " + $_.Exception.Message + $(if ($inner) { " / " + $inner.Message } else { "" }))
  } finally {
    $client.Close()
  }
}
$listener.Stop()
$cert.Dispose()
