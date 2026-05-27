param(
    [ValidateSet("all", "tcp", "kcp", "quic", "udp")]
    [string[]]$Transport = @("all"),
    [int]$NodeCount = 16,
    [int]$StatusPortBase = 21000,
    [int]$SettleSeconds = 45,
    [int]$WindowSeconds = 30,
    [int]$UdpBootstrapSeconds = 45,
    [int]$TopKinds = 16,
    [switch]$Build,
    [switch]$CleanState,
    [switch]$SkipUdpBootstrap,
    [switch]$NoRestoreConfig
)

$ErrorActionPreference = "Stop"

$scriptDir = [System.IO.Path]::GetFullPath($PSScriptRoot)
$composeFile = Join-Path $scriptDir "compose.yaml"
$nodesDir = Join-Path $scriptDir "nodes"
$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$workDir = Join-Path $scriptDir ".transport-survey"
$backupDir = Join-Path $workDir "config-backup-$runStamp"
$resultDir = Join-Path $workDir "results-$runStamp"

$modes = if ($Transport -contains "all") {
    @("tcp", "kcp", "quic", "udp")
} else {
    @($Transport | Select-Object -Unique)
}

New-Item -ItemType Directory -Force -Path $backupDir, $resultDir | Out-Null

function Invoke-Compose {
    param([Parameter(Mandatory)] [string[]]$ComposeArgs)

    $output = & docker compose -f $composeFile @ComposeArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($output) {
            $output | ForEach-Object { Write-Host $_ }
        }
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
    if ($output) {
        $output | ForEach-Object { Write-Host $_ }
    }
}

function Invoke-Container {
    param(
        [Parameter(Mandatory)] [string]$Container,
        [Parameter(Mandatory)] [string[]]$Command
    )

    $output = & docker exec $Container @Command
    if ($LASTEXITCODE -ne 0) {
        throw "docker exec $Container $($Command -join ' ') failed with exit code $LASTEXITCODE"
    }
    return ($output -join "`n").Trim()
}

function Get-TransportPort {
    param([Parameter(Mandatory)] [string]$Mode)

    switch ($Mode) {
        "tcp" { 64739 }
        "kcp" { 64740 }
        "quic" { 64741 }
        "udp" { 64742 }
        default { throw "unknown transport $Mode" }
    }
}

function Get-TransportTitle {
    param([Parameter(Mandatory)] [string]$Mode)

    switch ($Mode) {
        "tcp" { "TCP" }
        "kcp" { "KCP" }
        "quic" { "QUIC" }
        "udp" { "UDP" }
        default { $Mode.ToUpperInvariant() }
    }
}

function Backup-NodeConfigs {
    Get-ChildItem -LiteralPath $nodesDir -Directory -Filter "node-*" | ForEach-Object {
        $dest = Join-Path $backupDir $_.Name
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Force -LiteralPath (Join-Path $_.FullName "config.toml") -Destination (Join-Path $dest "config.toml")
    }
}

function Restore-NodeConfigs {
    if (-not (Test-Path -LiteralPath $backupDir)) {
        return
    }

    Get-ChildItem -LiteralPath $backupDir -Directory -Filter "node-*" | ForEach-Object {
        $dest = Join-Path (Join-Path $nodesDir $_.Name) "config.toml"
        Copy-Item -Force -LiteralPath (Join-Path $_.FullName "config.toml") -Destination $dest
    }
}

function Clear-GeneratedS2sState {
    Get-ChildItem -LiteralPath $nodesDir -Directory -Filter "node-*" | ForEach-Object {
        $stateDir = Join-Path $_.FullName "s2s-state"
        if (-not (Test-Path -LiteralPath $stateDir)) {
            return
        }
        Get-ChildItem -LiteralPath $stateDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Recurse -Force -LiteralPath $_.FullName
        }
    }
}

function Set-NodeConfigTransport {
    param(
        [Parameter(Mandatory)] [string]$Mode,
        [Parameter(Mandatory)] [string]$Path
    )

    $port = Get-TransportPort -Mode $Mode
    $hostName = Split-Path -Leaf (Split-Path -Parent $Path)
    $lines = [System.IO.File]::ReadAllLines($Path)
    $out = [System.Collections.Generic.List[string]]::new()
    $insertedListen = $false
    $insideSeeds = $false

    foreach ($line in $lines) {
        if ($line -match "^(tcp|kcp|quic|udp)_(listen|advertise) = ") {
            continue
        }

        if ($line -match "^seed_addresses = \[") {
            $insideSeeds = $true
            $out.Add($line)
            continue
        }

        if ($insideSeeds) {
            if ($line -match "^\]") {
                $insideSeeds = $false
                $out.Add($line)
                continue
            }

            $seed = [regex]::Match($line, 'addr = "([^:"]+):\d+"')
            if ($seed.Success) {
                $seedHost = $seed.Groups[1].Value
                $out.Add("    { transport = `"$Mode`", addr = `"$seedHost`:$port`" },")
            } else {
                $out.Add($line)
            }
            continue
        }

        if (-not $insertedListen -and $line -match "^status_http_listen = ") {
            $out.Add("${Mode}_listen = `"0.0.0.0:$port`"")
            $out.Add("${Mode}_advertise = [`"$hostName`:$port`"]")
            $insertedListen = $true
        }

        $out.Add($line)
    }

    [System.IO.File]::WriteAllLines($Path, $out, [System.Text.UTF8Encoding]::new($false))
}

function Set-AllNodeConfigsTransport {
    param([Parameter(Mandatory)] [string]$Mode)

    Get-ChildItem -LiteralPath $nodesDir -Directory -Filter "node-*" | ForEach-Object {
        Set-NodeConfigTransport -Mode $Mode -Path (Join-Path $_.FullName "config.toml")
    }
}

function Wait-ClusterHealth {
    $deadline = (Get-Date).AddSeconds(90)
    $ports = 1..$NodeCount | ForEach-Object { $StatusPortBase + $_ }
    $ok = 0

    do {
        $ok = 0
        foreach ($port in $ports) {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/s2s/health" -TimeoutSec 2
                if ($health.status -eq "ok") {
                    $ok++
                }
            } catch {
            }
        }
        if ($ok -eq $NodeCount) {
            return [pscustomobject]@{
                healthy = $ok
                expected = $NodeCount
            }
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    return [pscustomobject]@{
        healthy = $ok
        expected = $NodeCount
    }
}

function Get-TopologySummary {
    param([Parameter(Mandatory)] [array]$Topology)

    $healthy = @($Topology | Where-Object { -not $_.error })
    if ($healthy.Count -eq 0) {
        return [pscustomobject]@{
            min_nodes = 0
            max_nodes = 0
            min_links = 0
            max_links = 0
            min_routes = 0
            max_routes = 0
        }
    }

    $nodes = @($healthy | ForEach-Object { [int]$_.nodes } | Sort-Object)
    $links = @($healthy | ForEach-Object { [int]$_.links } | Sort-Object)
    $routes = @($healthy | ForEach-Object { [int]$_.routes } | Sort-Object)

    return [pscustomobject]@{
        min_nodes = $nodes[0]
        max_nodes = $nodes[$nodes.Count - 1]
        min_links = $links[0]
        max_links = $links[$links.Count - 1]
        min_routes = $routes[0]
        max_routes = $routes[$routes.Count - 1]
    }
}

function Get-TopologySnapshots {
    $ports = 1..$NodeCount | ForEach-Object { $StatusPortBase + $_ }
    $snapshots = @()

    foreach ($port in $ports) {
        try {
            $snapshot = Invoke-RestMethod -Uri "http://127.0.0.1:$port/s2s/topology.json" -TimeoutSec 5
            $snapshots += [pscustomobject]@{
                port = $port
                local_node = $snapshot.local_node
                nodes = $snapshot.nodes.Count
                links = $snapshot.links.Count
                routes = $snapshot.routes.Count
                packets = @($snapshot.debug_packet_io)
            }
        } catch {
            $snapshots += [pscustomobject]@{
                port = $port
                error = $_.Exception.Message
                packets = @()
            }
        }
    }

    return @($snapshots)
}

function Get-PacketDeltas {
    param(
        [Parameter(Mandatory)] [array]$Before,
        [Parameter(Mandatory)] [array]$After
    )

    $beforeByNodeKind = @{}
    foreach ($node in $Before) {
        foreach ($packet in @($node.packets)) {
            $beforeByNodeKind["$($node.local_node)|$($packet.kind)"] = $packet
        }
    }

    $byKind = @{}
    foreach ($node in $After) {
        foreach ($packet in @($node.packets)) {
            $key = "$($node.local_node)|$($packet.kind)"
            $old = $beforeByNodeKind[$key]
            $sentBytes = [int64]$packet.sent_bytes - [int64]$(if ($old) { $old.sent_bytes } else { 0 })
            $recvBytes = [int64]$packet.recv_bytes - [int64]$(if ($old) { $old.recv_bytes } else { 0 })
            $sentCount = [int64]$packet.sent_count - [int64]$(if ($old) { $old.sent_count } else { 0 })
            $recvCount = [int64]$packet.recv_count - [int64]$(if ($old) { $old.recv_count } else { 0 })

            if (-not $byKind.ContainsKey($packet.kind)) {
                $byKind[$packet.kind] = [pscustomobject]@{
                    kind = $packet.kind
                    bytes = [int64]0
                    sent_bytes = [int64]0
                    recv_bytes = [int64]0
                    count = [int64]0
                    sent_count = [int64]0
                    recv_count = [int64]0
                    avg_bytes = 0.0
                }
            }

            $row = $byKind[$packet.kind]
            $row.sent_bytes += $sentBytes
            $row.recv_bytes += $recvBytes
            $row.bytes += $sentBytes + $recvBytes
            $row.sent_count += $sentCount
            $row.recv_count += $recvCount
            $row.count += $sentCount + $recvCount
        }
    }

    foreach ($row in $byKind.Values) {
        if ($row.count -gt 0) {
            $row.avg_bytes = [Math]::Round($row.bytes / $row.count, 1)
        }
    }

    return @($byKind.Values | Sort-Object bytes -Descending)
}

function Convert-SnmpPair {
    param(
        [Parameter(Mandatory)] [string[]]$Lines,
        [Parameter(Mandatory)] [string]$Prefix
    )

    $matches = @($Lines | Where-Object { $_ -like "${Prefix}:*" })
    $map = @{}
    if ($matches.Count -lt 2) {
        return $map
    }

    $headers = $matches[0] -split "\s+"
    $values = $matches[1] -split "\s+"
    for ($i = 1; $i -lt $headers.Count -and $i -lt $values.Count; $i++) {
        $map[$headers[$i]] = [int64]$values[$i]
    }
    return $map
}

function Get-NetCounters {
    $rows = @()

    foreach ($i in 1..$NodeCount) {
        $container = "shitspeak-node-{0:D2}" -f $i
        try {
            $rx = [int64](Invoke-Container -Container $container -Command @("cat", "/sys/class/net/eth0/statistics/rx_bytes"))
            $tx = [int64](Invoke-Container -Container $container -Command @("cat", "/sys/class/net/eth0/statistics/tx_bytes"))
            $snmp = Invoke-Container -Container $container -Command @("cat", "/proc/net/snmp")
            $lines = $snmp -split "\r?\n"
            $rows += [pscustomobject]@{
                container = $container
                rx_bytes = $rx
                tx_bytes = $tx
                tcp = Convert-SnmpPair -Lines $lines -Prefix "Tcp"
                udp = Convert-SnmpPair -Lines $lines -Prefix "Udp"
            }
        } catch {
            $rows += [pscustomobject]@{
                container = $container
                error = $_.Exception.Message
                rx_bytes = 0
                tx_bytes = 0
                tcp = @{}
                udp = @{}
            }
        }
    }

    return @($rows)
}

function Get-MapValue {
    param(
        [Parameter(Mandatory)] [hashtable]$Map,
        [Parameter(Mandatory)] [string]$Key
    )

    if ($Map.ContainsKey($Key)) {
        return [int64]$Map[$Key]
    }
    return [int64]0
}

function Get-NetDeltas {
    param(
        [Parameter(Mandatory)] [array]$Before,
        [Parameter(Mandatory)] [array]$After
    )

    $beforeByContainer = @{}
    foreach ($row in $Before) {
        $beforeByContainer[$row.container] = $row
    }

    $perNode = @()
    $sumRx = [int64]0
    $sumTx = [int64]0
    $sumTcpIn = [int64]0
    $sumTcpOut = [int64]0
    $sumTcpRetrans = [int64]0
    $sumUdpIn = [int64]0
    $sumUdpOut = [int64]0
    $sumUdpErrors = [int64]0
    $sumUdpRcvbufErrors = [int64]0
    $sumUdpSndbufErrors = [int64]0

    foreach ($row in $After) {
        $old = $beforeByContainer[$row.container]
        if (-not $old) {
            continue
        }

        $rx = [int64]$row.rx_bytes - [int64]$old.rx_bytes
        $tx = [int64]$row.tx_bytes - [int64]$old.tx_bytes
        $tcpIn = (Get-MapValue -Map $row.tcp -Key "InSegs") - (Get-MapValue -Map $old.tcp -Key "InSegs")
        $tcpOut = (Get-MapValue -Map $row.tcp -Key "OutSegs") - (Get-MapValue -Map $old.tcp -Key "OutSegs")
        $tcpRetrans = (Get-MapValue -Map $row.tcp -Key "RetransSegs") - (Get-MapValue -Map $old.tcp -Key "RetransSegs")
        $udpIn = (Get-MapValue -Map $row.udp -Key "InDatagrams") - (Get-MapValue -Map $old.udp -Key "InDatagrams")
        $udpOut = (Get-MapValue -Map $row.udp -Key "OutDatagrams") - (Get-MapValue -Map $old.udp -Key "OutDatagrams")
        $udpErrors = (Get-MapValue -Map $row.udp -Key "InErrors") - (Get-MapValue -Map $old.udp -Key "InErrors")
        $udpRcvbufErrors = (Get-MapValue -Map $row.udp -Key "RcvbufErrors") - (Get-MapValue -Map $old.udp -Key "RcvbufErrors")
        $udpSndbufErrors = (Get-MapValue -Map $row.udp -Key "SndbufErrors") - (Get-MapValue -Map $old.udp -Key "SndbufErrors")

        $sumRx += $rx
        $sumTx += $tx
        $sumTcpIn += $tcpIn
        $sumTcpOut += $tcpOut
        $sumTcpRetrans += $tcpRetrans
        $sumUdpIn += $udpIn
        $sumUdpOut += $udpOut
        $sumUdpErrors += $udpErrors
        $sumUdpRcvbufErrors += $udpRcvbufErrors
        $sumUdpSndbufErrors += $udpSndbufErrors

        $perNode += [pscustomobject]@{
            container = $row.container
            rx_bytes = $rx
            tx_bytes = $tx
            total_bytes = $rx + $tx
            tcp_in_segments = $tcpIn
            tcp_out_segments = $tcpOut
            tcp_retrans_segments = $tcpRetrans
            udp_in_datagrams = $udpIn
            udp_out_datagrams = $udpOut
            udp_in_errors = $udpErrors
            udp_rcvbuf_errors = $udpRcvbufErrors
            udp_sndbuf_errors = $udpSndbufErrors
        }
    }

    return [pscustomobject]@{
        rx_bytes = $sumRx
        tx_bytes = $sumTx
        total_bytes = $sumRx + $sumTx
        tcp_in_segments = $sumTcpIn
        tcp_out_segments = $sumTcpOut
        tcp_retrans_segments = $sumTcpRetrans
        udp_in_datagrams = $sumUdpIn
        udp_out_datagrams = $sumUdpOut
        udp_in_errors = $sumUdpErrors
        udp_rcvbuf_errors = $sumUdpRcvbufErrors
        udp_sndbuf_errors = $sumUdpSndbufErrors
        per_node = @($perNode | Sort-Object total_bytes -Descending)
    }
}

function Get-UpArgs {
    $upArgs = @("up", "-d")
    if ($Build) {
        $upArgs += "--build"
    } else {
        $upArgs += "--no-build"
    }
    return $upArgs
}

function Invoke-UdpBootstrap {
    Write-Host "Bootstrapping UDP peer identities with all generated transports..."
    Restore-NodeConfigs
    Invoke-Compose -ComposeArgs (Get-UpArgs)
    try {
        $health = Wait-ClusterHealth
        Write-Host "Bootstrap health: $($health.healthy)/$($health.expected)"
        if ($health.healthy -ne $health.expected) {
            throw "UDP bootstrap cluster did not become healthy"
        }
        Start-Sleep -Seconds $UdpBootstrapSeconds
        $topology = Get-TopologySnapshots
        $summary = Get-TopologySummary -Topology $topology
        Write-Host "Bootstrap topology: nodes=$($summary.min_nodes)..$($summary.max_nodes) links=$($summary.min_links)..$($summary.max_links)"
        if ($summary.min_nodes -lt $NodeCount) {
            Write-Warning "UDP bootstrap did not converge to all $NodeCount nodes before the isolated UDP run"
        }
    } finally {
        # UDP cannot seed by unidentified address, so it relies on the
        # peer-address file learned during bootstrap. Stop instead of down so
        # Docker keeps the bridge network and the persisted IP addresses stay
        # valid for the isolated UDP restart.
        Invoke-Compose -ComposeArgs @("stop")
    }
}

function Invoke-TransportSurvey {
    param([Parameter(Mandatory)] [string]$Mode)

    $title = Get-TransportTitle -Mode $Mode
    Write-Host ""
    Write-Host "== $title survey =="

    Invoke-Compose -ComposeArgs @("down", "--remove-orphans")
    Restore-NodeConfigs
    if ($CleanState) {
        Clear-GeneratedS2sState
    }
    $usedUdpBootstrap = $false
    if ($Mode -eq "udp" -and $CleanState -and -not $SkipUdpBootstrap) {
        Invoke-UdpBootstrap
        $usedUdpBootstrap = $true
    }

    Restore-NodeConfigs
    Set-AllNodeConfigsTransport -Mode $Mode
    if ($usedUdpBootstrap) {
        Invoke-Compose -ComposeArgs @("start")
    } else {
        Invoke-Compose -ComposeArgs (Get-UpArgs)
    }

    try {
        $health = Wait-ClusterHealth
        Write-Host "Health: $($health.healthy)/$($health.expected)"
        if ($health.healthy -ne $health.expected) {
            throw "$title cluster did not become healthy"
        }

        Write-Host "Settling for $SettleSeconds seconds..."
        Start-Sleep -Seconds $SettleSeconds

        $topologyBefore = Get-TopologySnapshots
        $netBefore = Get-NetCounters
        Start-Sleep -Seconds $WindowSeconds
        $netAfter = Get-NetCounters
        $topologyAfter = Get-TopologySnapshots

        $packetDeltas = Get-PacketDeltas -Before $topologyBefore -After $topologyAfter
        $netDeltas = Get-NetDeltas -Before $netBefore -After $netAfter
        $topologySummary = Get-TopologySummary -Topology $topologyAfter

        $result = [pscustomobject]@{
            transport = $Mode
            window_seconds = $WindowSeconds
            settle_seconds = $SettleSeconds
            health = $health
            topology_summary = $topologySummary
            packet_deltas = @($packetDeltas)
            net_delta = $netDeltas
            topology = @($topologyAfter | Select-Object port, local_node, nodes, links, routes, error)
        }

        $resultPath = Join-Path $resultDir "$Mode.json"
        [System.IO.File]::WriteAllText(
            $resultPath,
            (($result | ConvertTo-Json -Depth 10) + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )

        Write-Host "Wire bytes over ${WindowSeconds}s: rx=$($netDeltas.rx_bytes) tx=$($netDeltas.tx_bytes) total=$($netDeltas.total_bytes)"
        Write-Host "Topology: nodes=$($topologySummary.min_nodes)..$($topologySummary.max_nodes) links=$($topologySummary.min_links)..$($topologySummary.max_links) routes=$($topologySummary.min_routes)..$($topologySummary.max_routes)"
        if ($topologySummary.min_nodes -lt $NodeCount) {
            Write-Warning "$title topology did not converge to all $NodeCount nodes during the measurement"
        }
        Write-Host "TCP segments: in=$($netDeltas.tcp_in_segments) out=$($netDeltas.tcp_out_segments) retrans=$($netDeltas.tcp_retrans_segments)"
        Write-Host "UDP datagrams: in=$($netDeltas.udp_in_datagrams) out=$($netDeltas.udp_out_datagrams) errors=$($netDeltas.udp_in_errors) rcvbuf=$($netDeltas.udp_rcvbuf_errors)"
        Write-Host "Top packet deltas:"
        $packetDeltas |
            Select-Object -First $TopKinds kind, bytes, sent_bytes, recv_bytes, count, sent_count, recv_count, avg_bytes |
            Format-Table -AutoSize |
            Out-Host

        return $result
    } finally {
        Invoke-Compose -ComposeArgs @("down", "--remove-orphans")
    }
}

Backup-NodeConfigs
$results = @()

try {
    foreach ($mode in $modes) {
        $results += Invoke-TransportSurvey -Mode $mode
    }

    $summary = @($results | ForEach-Object {
        $top = @($_.packet_deltas | Select-Object -First 6)
        [pscustomobject]@{
            transport = $_.transport
            wire_total_bytes = $_.net_delta.total_bytes
            wire_rx_bytes = $_.net_delta.rx_bytes
            wire_tx_bytes = $_.net_delta.tx_bytes
            tcp_segments = $_.net_delta.tcp_in_segments + $_.net_delta.tcp_out_segments
            tcp_retrans_segments = $_.net_delta.tcp_retrans_segments
            udp_datagrams = $_.net_delta.udp_in_datagrams + $_.net_delta.udp_out_datagrams
            udp_errors = $_.net_delta.udp_in_errors
            udp_rcvbuf_errors = $_.net_delta.udp_rcvbuf_errors
            top_kinds = (($top | ForEach-Object { "$($_.kind)=$($_.bytes)" }) -join "; ")
        }
    })

    $summaryPath = Join-Path $resultDir "summary.json"
    [System.IO.File]::WriteAllText(
        $summaryPath,
        (($summary | ConvertTo-Json -Depth 6) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host ""
    Write-Host "== Summary =="
    $summary | Format-Table -AutoSize | Out-Host
    Write-Host "Results written to $resultDir"
} finally {
    Invoke-Compose -ComposeArgs @("down", "--remove-orphans")
    if (-not $NoRestoreConfig) {
        Restore-NodeConfigs
    }
}
