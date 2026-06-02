param(
    [int]$NodeCount = 16,
    [string]$OutputRoot = $PSScriptRoot,
    [string]$BinaryPath,
    [int]$SeedCount = 2,
    [int]$ClientPortBase = 20000,
    [int]$StatusPortBase = 21000,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if ($NodeCount -lt 1 -or $NodeCount -gt 4095) {
    throw "NodeCount must be in the range 1..4095."
}

if ($SeedCount -lt 0) {
    throw "SeedCount must be greater than or equal to 0."
}

if ($ClientPortBase -lt 1 -or $ClientPortBase + $NodeCount -gt 65535) {
    throw "ClientPortBase plus NodeCount must fit in TCP/UDP port range."
}

if ($StatusPortBase -lt 1 -or $StatusPortBase + $NodeCount -gt 65535) {
    throw "StatusPortBase plus NodeCount must fit in TCP port range."
}

if (-not ("System.Security.Cryptography.PemEncoding" -as [type])) {
    throw "This generator requires PowerShell 7 on .NET 5 or newer."
}

$scriptDir = [System.IO.Path]::GetFullPath($PSScriptRoot)
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\.."))
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $repoRoot "target\x86_64-unknown-linux-musl\debug\shitspeak-rs"
}
$BinaryPath = [System.IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "Linux musl binary not found at $BinaryPath. Build it first, for example: cross build --target=x86_64-unknown-linux-musl"
}

$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$sharedDir = Join-Path $OutputRoot "shared"
$nodesDir = Join-Path $OutputRoot "nodes"
$imageDir = Join-Path $OutputRoot "image"
$composePath = Join-Path $OutputRoot "compose.yaml"
$manifestPath = Join-Path $OutputRoot "manifest.json"

$generatedPaths = @($sharedDir, $nodesDir, $imageDir, $composePath, $manifestPath)
$existingPaths = @($generatedPaths | Where-Object { Test-Path -LiteralPath $_ })
if ($existingPaths.Count -gt 0 -and -not $Force) {
    throw "Docker Compose demo material already exists under $OutputRoot. Re-run with -Force to replace generated files."
}

if ($Force) {
    foreach ($path in @($sharedDir, $imageDir, $composePath, $manifestPath)) {
        Remove-Item -Recurse -Force -LiteralPath $path -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $nodesDir) {
        Get-ChildItem -LiteralPath $nodesDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Force -LiteralPath `
                (Join-Path $_.FullName "config.toml"), `
                (Join-Path $_.FullName "s2s-cert.pem"), `
                (Join-Path $_.FullName "s2s-key.pem") `
                -ErrorAction SilentlyContinue
        }
    }
}

New-Item -ItemType Directory -Force -Path $sharedDir, $nodesDir, $imageDir | Out-Null

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Text
    )
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Write-RsaPrivateKeyPem {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [System.Security.Cryptography.RSA]$Key
    )
    Write-Utf8NoBom -Path $Path -Text ($Key.ExportPkcs8PrivateKeyPem() + "`n")
}

function Write-EcdsaPrivateKeyPem {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [System.Security.Cryptography.ECDsa]$Key
    )
    Write-Utf8NoBom -Path $Path -Text ($Key.ExportPkcs8PrivateKeyPem() + "`n")
}

function New-SerialNumber {
    $serial = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
    $serial[0] = $serial[0] -band 0x7f
    if ($serial[0] -eq 0) {
        $serial[0] = 1
    }
    return $serial
}

function New-CertificateAuthority {
    param(
        [Parameter(Mandatory)] [string]$CertPath,
        [Parameter(Mandatory)] [string]$KeyPath
    )

    $key = [System.Security.Cryptography.RSA]::Create(3072)
    $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=ShitSpeak Compose S2S Test CA")
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true
        )
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = $notBefore.AddYears(5)
    $cert = $request.CreateSelfSigned($notBefore, $notAfter)

    Write-Utf8NoBom -Path $CertPath -Text ($cert.ExportCertificatePem() + "`n")
    Write-RsaPrivateKeyPem -Path $KeyPath -Key $key

    return [pscustomobject]@{
        Certificate = $cert
        Key = $key
    }
}

function New-NodeCertificate {
    param(
        [Parameter(Mandatory)] [int]$NodeId,
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$CaCertificate,
        [Parameter(Mandatory)] [System.Security.Cryptography.RSA]$CaKey,
        [Parameter(Mandatory)] [string]$CertPath,
        [Parameter(Mandatory)] [string]$KeyPath
    )

    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$NodeId")
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )

    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName("node-$NodeId")
    $san.AddDnsName($HostName)
    $san.AddDnsName("s2s-seed.local")
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true
        )
    )

    $eku = [System.Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))
    [void]$eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2"))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = $notBefore.AddYears(2)
    $cert = $request.Create(
        $CaCertificate.SubjectName,
        [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($CaKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1),
        $notBefore,
        $notAfter,
        (New-SerialNumber)
    )

    Write-Utf8NoBom -Path $CertPath -Text ($cert.ExportCertificatePem() + "`n")
    Write-EcdsaPrivateKeyPem -Path $KeyPath -Key $key
}

function New-ServerCertificate {
    param(
        [Parameter(Mandatory)] [string[]]$HostNames,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$CaCertificate,
        [Parameter(Mandatory)] [System.Security.Cryptography.RSA]$CaKey,
        [Parameter(Mandatory)] [string]$CertPath,
        [Parameter(Mandatory)] [string]$KeyPath
    )

    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=localhost")
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    foreach ($hostName in ($HostNames | Sort-Object -Unique)) {
        $san.AddDnsName($hostName)
    }
    $san.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
    $san.AddIpAddress([System.Net.IPAddress]::Parse("::1"))
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
            $true
        )
    )

    $eku = [System.Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false)
    )

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = $notBefore.AddYears(2)
    $cert = $request.Create(
        $CaCertificate.SubjectName,
        [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($CaKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1),
        $notBefore,
        $notAfter,
        (New-SerialNumber)
    )

    Write-Utf8NoBom -Path $CertPath -Text ($cert.ExportCertificatePem() + "`n")
    Write-RsaPrivateKeyPem -Path $KeyPath -Key $key
}

function New-NodeConfig {
    param(
        [Parameter(Mandatory)] [int]$NodeId,
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [array]$Nodes,
        [Parameter(Mandatory)] [int]$SeedCount
    )

    $orderedNodes = @($Nodes | Sort-Object node_id)
    $currentIndex = -1
    for ($i = 0; $i -lt $orderedNodes.Count; $i++) {
        if ([int]$orderedNodes[$i].node_id -eq $NodeId) {
            $currentIndex = $i
            break
        }
    }
    if ($currentIndex -lt 0) {
        throw "Node $NodeId is missing from the node list."
    }

    $actualSeedCount = [Math]::Min($SeedCount, [Math]::Max(0, $orderedNodes.Count - 1))
    $seedNodes = for ($offset = 1; $offset -le $actualSeedCount; $offset++) {
        $orderedNodes[($currentIndex + $offset) % $orderedNodes.Count]
    }
    $seedLines = $seedNodes |
        ForEach-Object { '    { transport = "tcp", addr = "' + $_.host + ':64739" },' }

    $seedBlock = ($seedLines -join "`n")

    return @"
node_id = $NodeId
listen = "[::]:64738"
register_name = "ShitSpeak Compose node $NodeId"
register_hostname = "$HostName"
cert_path = "cert.pem"
key_path = "key.pem"
send_version = true
send_build_info = true
send_os_info = true
allowed_proxies = []
min_client_version = 0
max_users = 100

welcome_text = "Welcome to ShitSpeak Compose node $NodeId"
max_bandwidth = 72000
allow_html = true
max_text_message_length = 5000
max_image_message_length = 131072
default_channel = 1
cert_required = false

udp_voice_enabled = true
udp_ping_enabled = true
udp_ping_user_count_scope = "cluster"
udp_channel_size = 2048

client_idle_timeout_secs = 30
pending_delete_timeout_ms = 5000

blob_storage_dir = "data"
channel_log_max_entries = 10000
client_log_max_entries = 10000
channel_snapshot_every_ops = 10
channel_snapshot_every_secs = 60
channel_wal_compaction_expire_count = 2000

[debug]
debug_acl_enter = false

[s2s]
enabled = true
ca_path = "s2s-ca-cert.pem"
cert_path = "s2s-cert.pem"
key_path = "s2s-key.pem"
tcp_listen = "[::]:64739"
kcp_listen = "[::]:64740"
quic_listen = "[::]:64741"
udp_listen = "[::]:64742"
tcp_advertise = ["${HostName}:64739"]
kcp_advertise = ["${HostName}:64740"]
quic_advertise = ["${HostName}:64741"]
udp_advertise = ["${HostName}:64742"]
status_http_listen = "[::]:64750"
persistence_dir = "s2s-state"
seed_addresses = [
$seedBlock
]

[s2s.transport]
latency_ewma_alpha = 0.2
jitter_ewma_alpha = 0.0625
throughput_ewma_alpha = 0.3
packet_loss_ewma_alpha = 0.02
ping_interval_secs = 2
idle_ping_interval_secs = 10
native_stats_interval_secs = 10
max_pending_pings = 64
recent_probe_retry_cap_secs = 30
stale_probe_retry_cap_secs = 600
stale_probe_age_secs = 3600
max_outgoing_connections = 1024

[s2s.overlay]
lsdb_sync_max_response_lsas = 2048
route_transit_messages = true

[s2s.replications]
fallback_clock_tick_ms = 250
min_clock_tick_ms = 100
max_clock_tick_ms = 5000
delivery_tick_interval_ms = 50
propose_ttl_ms = 10000
propose_semaphore_size = 32
strict_max_catchup_ops = 256
pending_propose_ttl_ms = 20000
recovery_ttl_ms = 10000
owner_catchup_timeout_ms = 5000
owner_max_catchup_ops = 256
blob_chunk_size = 65536
blob_request_timeout_ms = 10000
blob_offer_wait_ms = 250
blob_retry_interval_ms = 500
blob_max_parallel_peers = 3
blob_decay_interval_ms = 60000
blob_unused_grace_ms = 600000

[web]
enabled = false
listen = "[::]:64740"
public_base_url = "https://${HostName}:64740"
allowed_origins = ["https://${HostName}:64740"]

[web.auth]
modes = ["password", "sso"]
password_enabled = true

[web.auth.sso]
issuer = "https://idp.example.com"
jwks_url = "https://idp.example.com/.well-known/jwks.json"
audience = "shitspeak-web"
subject_claim = "sub"
username_claim = "preferred_username"
groups_claim = "groups"

[web.webrtc]
max_speaker_ssrcs = 64
audio_bitrate = 64000
ice_servers = [
  { urls = ["stun:stun.l.google.com:19302"] },
]

[web.moq]
enabled = false
listen = "[::]:64741"
public_url = "https://${HostName}:64741/web/moq"
max_speaker_tracks = 64
audio_bitrate = 64000
"@
}

function Write-ComposeFile {
    param(
        [Parameter(Mandatory)] [array]$Nodes,
        [Parameter(Mandatory)] [string]$Path
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("name: shitspeak-16node-demo")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("services:")
    foreach ($node in $Nodes) {
        $nodeId = [int]$node.node_id
        $nodeName = [string]$node.name
        $legacyAlias = "node-$nodeId"
        $clientPort = $ClientPortBase + $nodeId
        $statusPort = $StatusPortBase + $nodeId

        [void]$sb.AppendLine("  ${nodeName}:")
        [void]$sb.AppendLine("    build:")
        [void]$sb.AppendLine("      context: ./image")
        [void]$sb.AppendLine("    image: shitspeak-rs-16node-demo:local")
        [void]$sb.AppendLine("    container_name: shitspeak-${nodeName}")
        [void]$sb.AppendLine("    init: true")
        [void]$sb.AppendLine("    restart: unless-stopped")
        [void]$sb.AppendLine("    stop_signal: SIGINT")
        [void]$sb.AppendLine("    cap_add:")
        [void]$sb.AppendLine("      - PERFMON")
        [void]$sb.AppendLine("      - SYS_PTRACE")
        [void]$sb.AppendLine("    security_opt:")
        [void]$sb.AppendLine("      - seccomp=unconfined")
        [void]$sb.AppendLine("    working_dir: /app")
        [void]$sb.AppendLine("    environment:")
        [void]$sb.AppendLine("      RUST_LOG: shitspeak_rs=debug")
        [void]$sb.AppendLine("    ports:")
        [void]$sb.AppendLine("      - `"${clientPort}:64738/tcp`"")
        [void]$sb.AppendLine("      - `"${clientPort}:64738/udp`"")
        [void]$sb.AppendLine("      - `"${statusPort}:64750/tcp`"")
        [void]$sb.AppendLine("    volumes:")
        [void]$sb.AppendLine("      - ./shared/cert.pem:/app/cert.pem:ro")
        [void]$sb.AppendLine("      - ./shared/key.pem:/app/key.pem:ro")
        [void]$sb.AppendLine("      - ./shared/s2s-ca-cert.pem:/app/s2s-ca-cert.pem:ro")
        [void]$sb.AppendLine("      - ./nodes/${nodeName}/config.toml:/app/config.toml:ro")
        [void]$sb.AppendLine("      - ./nodes/${nodeName}/s2s-cert.pem:/app/s2s-cert.pem:ro")
        [void]$sb.AppendLine("      - ./nodes/${nodeName}/s2s-key.pem:/app/s2s-key.pem:ro")
        [void]$sb.AppendLine("      - ./nodes/${nodeName}/data:/app/data")
        [void]$sb.AppendLine("      - ./nodes/${nodeName}/s2s-state:/app/s2s-state")
        [void]$sb.AppendLine("    networks:")
        [void]$sb.AppendLine("      s2s-demo:")
        [void]$sb.AppendLine("        aliases:")
        [void]$sb.AppendLine("          - ${legacyAlias}")
        [void]$sb.AppendLine("    logging:")
        [void]$sb.AppendLine("      options:")
        [void]$sb.AppendLine("        max-size: `"10m`"")
        [void]$sb.AppendLine("        max-file: `"3`"")
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("networks:")
    [void]$sb.AppendLine("  s2s-demo:")
    [void]$sb.AppendLine("    driver: bridge")

    Write-Utf8NoBom -Path $Path -Text $sb.ToString()
}

function Write-ImageDockerfile {
    param([Parameter(Mandatory)] [string]$Path)

    Write-Utf8NoBom -Path $Path -Text @'
FROM alpine:3.20

RUN addgroup -S shitspeak \
    && adduser -S -G shitspeak -h /app shitspeak \
    && apk add --no-cache ca-certificates \
    && mkdir -p /app/data /app/s2s-state \
    && chown -R shitspeak:shitspeak /app

COPY shitspeak-rs /usr/local/bin/shitspeak-rs
RUN chmod 755 /usr/local/bin/shitspeak-rs

USER shitspeak
WORKDIR /app

EXPOSE 64738/tcp 64738/udp 64739/tcp 64740/udp 64741/tcp 64742/udp 64750/tcp

ENTRYPOINT ["/usr/local/bin/shitspeak-rs"]
'@
}

$nodes = for ($i = 1; $i -le $NodeCount; $i++) {
    $hostName = "node-{0:D2}" -f $i
    [pscustomobject]@{
        node_id = $i
        name = $hostName
        host = $hostName
        client_tcp_port = $ClientPortBase + $i
        client_udp_port = $ClientPortBase + $i
        status_http_port = $StatusPortBase + $i
        data_dir = "nodes/$hostName/data"
        s2s_state_dir = "nodes/$hostName/s2s-state"
    }
}

$ca = New-CertificateAuthority `
    -CertPath (Join-Path $sharedDir "s2s-ca-cert.pem") `
    -KeyPath (Join-Path $sharedDir "s2s-ca-key.pem")

$serverHostNames = @("localhost", "host.docker.internal") + @($nodes | ForEach-Object { $_.host })
New-ServerCertificate `
    -HostNames $serverHostNames `
    -CaCertificate $ca.Certificate `
    -CaKey $ca.Key `
    -CertPath (Join-Path $sharedDir "cert.pem") `
    -KeyPath (Join-Path $sharedDir "key.pem")

foreach ($node in $nodes) {
    $nodeId = [int]$node.node_id
    $nodeDir = Join-Path $nodesDir ([string]$node.name)
    New-Item -ItemType Directory -Force -Path `
        $nodeDir, `
        (Join-Path $nodeDir "data"), `
        (Join-Path $nodeDir "s2s-state") | Out-Null

    New-NodeCertificate `
        -NodeId $nodeId `
        -HostName ([string]$node.host) `
        -CaCertificate $ca.Certificate `
        -CaKey $ca.Key `
        -CertPath (Join-Path $nodeDir "s2s-cert.pem") `
        -KeyPath (Join-Path $nodeDir "s2s-key.pem")

    Write-Utf8NoBom -Path (Join-Path $nodeDir "config.toml") -Text (New-NodeConfig `
        -NodeId $nodeId `
        -HostName ([string]$node.host) `
        -Nodes $nodes `
        -SeedCount $SeedCount)
}

Copy-Item -Force -LiteralPath $BinaryPath -Destination (Join-Path $imageDir "shitspeak-rs")
Write-ImageDockerfile -Path (Join-Path $imageDir "Dockerfile")
Write-ComposeFile -Nodes $nodes -Path $composePath

$manifest = [pscustomobject]@{
    generated_at_utc = [System.DateTimeOffset]::UtcNow.ToString("o")
    node_count = $NodeCount
    seed_count = $SeedCount
    binary_path = $BinaryPath
    image_context = $imageDir
    compose_path = $composePath
    internal_ports = [pscustomobject]@{
        client_tcp = 64738
        client_udp = 64738
        s2s_tcp = 64739
        s2s_kcp = 64740
        s2s_quic = 64741
        s2s_udp = 64742
        s2s_status_http = 64750
    }
    nodes = $nodes
}

Write-Utf8NoBom -Path $manifestPath -Text (($manifest | ConvertTo-Json -Depth 6) + "`n")

$ca.Key.Dispose()
$ca.Certificate.Dispose()

Write-Host "Generated Docker Compose 16-node demo material in $OutputRoot"
Write-Host "Compose file: $composePath"
Write-Host "Client ports use $($ClientPortBase + 1)..$($ClientPortBase + $NodeCount) for TCP and UDP."
Write-Host "Status ports use $($StatusPortBase + 1)..$($StatusPortBase + $NodeCount)."
