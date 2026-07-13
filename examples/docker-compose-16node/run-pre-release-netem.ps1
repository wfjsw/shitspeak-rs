param(
    [string]$ScenarioPath = (Join-Path $PSScriptRoot "pre-release-netem-scenario.json"),
    [string]$ArtifactRoot = (Join-Path $PSScriptRoot ".pre-release-netem"),
    [int]$DurationSeconds,
    [string]$WorkloadScript = (Join-Path $PSScriptRoot "pre-release-workload-driver.ps1"),
    [switch]$Build,
    [switch]$NoStart,
    [switch]$SkipAcceptance,
    [switch]$KeepNetem
)

$ErrorActionPreference = "Stop"
$scriptDir = [IO.Path]::GetFullPath($PSScriptRoot)
$composeFile = Join-Path $scriptDir "compose.yaml"
$controller = Join-Path $scriptDir "netem-controller.ps1"
$acceptanceScript = Join-Path $scriptDir "test-pre-release-netem.ps1"
$scenario = Get-Content -LiteralPath $ScenarioPath -Raw | ConvertFrom-Json
if ($scenario.schema_version -ne 2 -or $scenario.node_groups.all.Count -ne 16) {
    throw "scenario must use schema version 2 and exactly 16 nodes"
}
if (-not $PSBoundParameters.ContainsKey("DurationSeconds")) {
    $DurationSeconds = [int]$scenario.duration_seconds
}
if ($DurationSeconds -le 0) {
    throw "DurationSeconds must be positive"
}
if (-not $SkipAcceptance -and (-not $WorkloadScript -or -not (Test-Path -LiteralPath $WorkloadScript -PathType Leaf))) {
    throw "The release gate requires -WorkloadScript. The production status API cannot inject semantic ACK loss or export strict ordered histories."
}
if (-not (Test-Path -LiteralPath $composeFile) -or
    -not (Select-String -LiteralPath $composeFile -SimpleMatch "SHITSPEAK_PRE_RELEASE_ARTIFACT_PATH" -Quiet)) {
    throw "compose.yaml was not generated for the pre-release workload. Rebuild the feature binary and run generate-compose-16node.ps1 -PreReleaseWorkload -Force."
}

$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$artifactDir = Join-Path $ArtifactRoot "results-$runStamp"
$topologyDir = Join-Path $artifactDir "topology"
$metricsDir = Join-Path $artifactDir "metrics"
$tcDir = Join-Path $artifactDir "tc"
$logDir = Join-Path $artifactDir "logs"
New-Item -ItemType Directory -Force -Path $artifactDir, $topologyDir, $metricsDir, $tcDir, $logDir | Out-Null
$eventPath = Join-Path $artifactDir "events.ndjson"
$samplePath = Join-Path $artifactDir "sample-summary.ndjson"
$cpuPath = Join-Path $artifactDir "cpu-samples.ndjson"
$scenarioClockPath = Join-Path $artifactDir "scenario-clock.json"

function Write-Ndjson {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [object]$Value)
    [IO.File]::AppendAllText($Path, ($Value | ConvertTo-Json -Compress -Depth 12) + "`n", [Text.UTF8Encoding]::new($false))
}

function Write-JsonAtomic {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [object]$Value)
    $temporary = "$Path.tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Invoke-Compose {
    param([Parameter(Mandatory)] [string[]]$Arguments)
    $output = & docker compose -f $composeFile @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Wait-Healthy {
    $deadline = (Get-Date).AddSeconds(120)
    do {
        $healthy = 0
        foreach ($node in 1..16) {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$((21000 + $node))/s2s/health" -TimeoutSec 2
                if ($health.status -eq "ok") { $healthy++ }
            } catch {}
        }
        if ($healthy -eq 16) { return }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "cluster health reached only $healthy/16 nodes"
}

function Get-MetricSum {
    param([string[]]$Lines, [string]$Name)
    $sum = 0.0
    foreach ($line in $Lines) {
        if ($line -match ("^" + [regex]::Escape($Name) + '(?:\{[^}]*\})?\s+([-+0-9.eE]+)$')) {
            $sum += [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    return $sum
}

function Capture-Sample {
    param([int]$Elapsed)
    $stamp = "{0:D4}" -f $Elapsed
    foreach ($nodeNumber in 1..16) {
        $node = "node-{0:D2}" -f $nodeNumber
        $port = 21000 + $nodeNumber
        try {
            $topology = Invoke-RestMethod -Uri "http://127.0.0.1:$port/s2s/topology.json" -TimeoutSec 5
            $topologyJson = $topology | ConvertTo-Json -Depth 15
            [IO.File]::WriteAllText((Join-Path $topologyDir "$stamp-$node.json"), $topologyJson + "`n", [Text.UTF8Encoding]::new($false))

            $metricText = (Invoke-WebRequest -Uri "http://127.0.0.1:$port/s2s/metrics" -TimeoutSec 5).Content
            $metricLines = @($metricText -split "`n" | Where-Object {
                $_ -match '^(# (HELP|TYPE) )?shitspeak_s2s_'
            })
            [IO.File]::WriteAllLines((Join-Path $metricsDir "$stamp-$node.prom"), $metricLines, [Text.UTF8Encoding]::new($false))
            $lsa = @($topology.debug_packet_io | Where-Object kind -eq "overlay.lsa_flood")
            $lsaSent = if ($lsa.Count) { [int64](($lsa | Measure-Object -Property sent_count -Sum).Sum) } else { 0 }
            Write-Ndjson -Path $samplePath -Value ([pscustomobject]@{
                elapsed_seconds = $Elapsed
                node = $node
                nodes = @($topology.nodes).Count
                alive_nodes = @($topology.nodes | Where-Object status -eq "alive").Count
                links = @($topology.links).Count
                routes = @($topology.routes).Count
                tree_edges_total = Get-MetricSum -Lines $metricLines -Name "shitspeak_s2s_distribution_tree_edges"
                lsa_sent_count = $lsaSent
                lsa_metric_present = $lsa.Count -gt 0
                error = $null
            })
        } catch {
            Write-Ndjson -Path $samplePath -Value ([pscustomobject]@{
                elapsed_seconds = $Elapsed; node = $node; nodes = 0; alive_nodes = 0
                links = 0; routes = 0; tree_edges_total = 0; lsa_sent_count = $null
                lsa_metric_present = $false
                error = $_.Exception.Message
            })
        }
    }

    $stats = & docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker stats failed: $($stats -join [Environment]::NewLine)" }
    foreach ($line in $stats) {
        $parts = $line -split '\|', 3
        if ($parts.Count -ne 3 -or $parts[0] -notlike "shitspeak-node-*") { continue }
        $cpu = [double]::Parse($parts[1].Trim().TrimEnd('%'), [Globalization.CultureInfo]::InvariantCulture)
        Write-Ndjson -Path $cpuPath -Value ([pscustomobject]@{
            elapsed_seconds = $Elapsed; container = $parts[0]; cpu_percent = $cpu; memory_usage = $parts[2]
        })
    }
}

function Invoke-TimelineEvent {
    param([Parameter(Mandatory)] [object]$Event, [int]$Elapsed)
    $statePath = Join-Path $tcDir (("{0:D4}-{1}" -f $Elapsed, $Event.action) + ".json")
    if ($Event.action -eq "netem") {
        & $controller -Action Apply -RuleSet $Event.rule_set -ScenarioPath $ScenarioPath -StateOutputPath $statePath
        if ($LASTEXITCODE -ne 0) { throw "netem controller failed" }
        $script:activeRuleSet = [string]$Event.rule_set
    } elseif ($Event.action -eq "restart") {
        $readyPath = Join-Path $artifactDir ("workload/restart-ready-{0:D4}.json" -f [int]$Event.at_seconds)
        if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
            throw "restart at $($Event.at_seconds)s lacks deterministic in-flight strict proposal evidence"
        }
        Invoke-Compose -Arguments (@("restart") + @($Event.nodes)) | Out-Null
        if (-not $script:activeRuleSet) { throw "restart occurred before a netem rule set was active" }
        & $controller -Action Apply -RuleSet $script:activeRuleSet -ScenarioPath $ScenarioPath -StateOutputPath $statePath
        if ($LASTEXITCODE -ne 0) { throw "netem reapply failed after restart" }
    } else {
        throw "unsupported timeline action '$($Event.action)'"
    }
    Write-Ndjson -Path $eventPath -Value ([pscustomobject]@{
        scheduled_seconds = [int]$Event.at_seconds
        observed_seconds = $Elapsed
        action = $Event.action
        rule_set = $Event.rule_set
        nodes = @($Event.nodes)
        reason = $Event.reason
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    })
}

$scenarioHash = (Get-FileHash -LiteralPath $ScenarioPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runId = [Guid]::NewGuid().ToString("N")
$env:SHITSPEAK_PRE_RELEASE_SEED = [string]$scenario.deterministic_seed
$metadata = [pscustomobject]@{
    schema_version = 1
    scenario = $scenario.name
    scenario_sha256 = $scenarioHash
    deterministic_seed = $scenario.deterministic_seed
    run_id = $runId
    workload_script = if ($WorkloadScript) { [IO.Path]::GetFullPath($WorkloadScript) } else { $null }
    workload_script_sha256 = if ($WorkloadScript) { (Get-FileHash -LiteralPath $WorkloadScript -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    requested_duration_seconds = $DurationSeconds
    started_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    artifact_policy = "topology, public S2S metrics, tc state, container stats, workload output, and container logs; no configs, environment, certificates, or keys"
}
[IO.File]::WriteAllText((Join-Path $artifactDir "metadata.json"), ($metadata | ConvertTo-Json -Depth 6) + "`n", [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $ScenarioPath -Destination (Join-Path $artifactDir "scenario.json")

$runError = $null
$script:activeRuleSet = $null
$workloadProcess = $null
try {
    if (-not $NoStart) {
        foreach ($nodeNumber in 1..16) {
            $node = "node-{0:D2}" -f $nodeNumber
            Remove-Item -LiteralPath (Join-Path $scriptDir "nodes/$node/data/pre-release-workload.json") -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $scriptDir "nodes/$node/data/pre-release-workload-control.json") -Force -ErrorAction SilentlyContinue
        }
        $up = @("up", "-d")
        if ($Build) { $up += "--build" } else { $up += "--no-build" }
        Invoke-Compose -Arguments $up | Out-Null
    }
    Wait-Healthy

    if ($WorkloadScript) {
        $workloadStdout = Join-Path $logDir "workload.stdout.log"
        $workloadStderr = Join-Path $logDir "workload.stderr.log"
        $arguments = @(
            "-NoProfile", "-File", ('"{0}"' -f [IO.Path]::GetFullPath($WorkloadScript)),
            "-ArtifactDirectory", ('"{0}"' -f $artifactDir),
            "-ScenarioPath", ('"{0}"' -f [IO.Path]::GetFullPath($ScenarioPath)),
            "-DurationSeconds", [string]$DurationSeconds,
            "-RunId", $runId
        )
        $workloadProcess = Start-Process -FilePath "pwsh" -ArgumentList $arguments -PassThru `
            -RedirectStandardOutput $workloadStdout -RedirectStandardError $workloadStderr
    }

    $events = @($scenario.timeline | Where-Object { [int]$_.at_seconds -le $DurationSeconds } | Sort-Object at_seconds)
    $nextEvent = 0
    $nextSample = 0
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ([int]$clock.Elapsed.TotalSeconds -le $DurationSeconds) {
        $elapsed = [int][Math]::Floor($clock.Elapsed.TotalSeconds)
        while ($nextEvent -lt $events.Count -and [int]$events[$nextEvent].at_seconds -le $elapsed) {
            Invoke-TimelineEvent -Event $events[$nextEvent] -Elapsed $elapsed
            $nextEvent++
        }
        Write-JsonAtomic -Path $scenarioClockPath -Value ([ordered]@{
            schema_version = 1
            run_id = $runId
            elapsed_seconds = $elapsed
            completed_events = $nextEvent
            active_rule_set = $script:activeRuleSet
            written_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
        })
        if ($elapsed -ge $nextSample) {
            Capture-Sample -Elapsed $elapsed
            $nextSample += [int]$scenario.sample_interval_seconds
        }
        if ($elapsed -ge $DurationSeconds) { break }
        Start-Sleep -Milliseconds 250
    }
} catch {
    $runError = $_
    Write-Ndjson -Path $eventPath -Value ([pscustomobject]@{
        action = "runner_error"; message = $_.Exception.Message; at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    })
} finally {
    try {
        $composeLogs = Invoke-Compose -Arguments @("logs", "--no-color", "--timestamps")
        [IO.File]::WriteAllLines((Join-Path $logDir "containers.log"), $composeLogs, [Text.UTF8Encoding]::new($false))
    } catch {}
    if (-not $KeepNetem) {
        try { & $controller -Action Clear -ScenarioPath $ScenarioPath | Out-Null } catch {}
    }
}

if ($null -ne $workloadProcess) {
    if (-not $workloadProcess.HasExited) {
        $workloadProcess.WaitForExit(120000)
    }
    if (-not $workloadProcess.HasExited) {
        try { $workloadProcess.Kill($true) } catch {}
        throw "workload driver did not finish within 120 seconds after the scenario"
    }
    if ($workloadProcess.ExitCode -ne 0) {
        throw "workload driver failed with exit code $($workloadProcess.ExitCode); see logs/workload.stderr.log"
    }
}

Write-Host "Artifacts: $artifactDir"
if ($null -ne $runError) { throw $runError }
if (-not $SkipAcceptance) {
    & $acceptanceScript -ArtifactDirectory $artifactDir -ScenarioPath $ScenarioPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
