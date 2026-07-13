param(
    [Parameter(Mandatory)] [string]$ArtifactDirectory,
    [Parameter(Mandatory)] [string]$ScenarioPath,
    [Parameter(Mandatory)] [int]$DurationSeconds,
    [Parameter(Mandatory)] [string]$RunId
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($DurationSeconds -le 0) {
    throw "DurationSeconds must be positive"
}

$scriptDir = [IO.Path]::GetFullPath($PSScriptRoot)
$artifactDir = [IO.Path]::GetFullPath($ArtifactDirectory)
$scenario = Get-Content -LiteralPath $ScenarioPath -Raw | ConvertFrom-Json
$scenarioHash = (Get-FileHash -LiteralPath $ScenarioPath -Algorithm SHA256).Hash.ToLowerInvariant()
$nodes = @($scenario.node_groups.all | ForEach-Object { [string]$_ })
if ($scenario.schema_version -ne 2 -or $nodes.Count -ne 16) {
    throw "scenario must use schema version 2 and contain exactly 16 nodes"
}

$workloadDir = Join-Path $artifactDir "workload"
$nodeArtifactDir = Join-Path $workloadDir "nodes"
$controlLogPath = Join-Path $workloadDir "control-actions.ndjson"
$summaryPath = Join-Path $artifactDir "workload-summary.json"
New-Item -ItemType Directory -Force -Path $workloadDir, $nodeArtifactDir | Out-Null
$startedAtUtc = [DateTime]::UtcNow
$runId = $RunId.Trim()
if ($runId -notmatch '^[A-Za-z0-9_-]{8,128}$') { throw "RunId has an invalid format" }
$phaseBoundarySeconds = [int]([double]$DurationSeconds / 2.0)
if (($phaseBoundarySeconds * 2) -ne $DurationSeconds) {
    throw "DurationSeconds must divide into two exact performance phases"
}
$script:controlGeneration = 0
$script:ackDropRequested = $false
$trackedCounterNames = @(
    "whole_group_fallbacks_after_initial_activation",
    "candidate_builds",
    "candidate_trigger_changes",
    "topology_epoch_changes_during_metric_mask_churn",
    "metric_lsa_emissions",
    "tree_activations",
    "restart_tree_send_calls",
    "tree_encode_send_operations",
    "legacy_encode_send_operations"
)
$counterTracker = @{}
foreach ($node in $nodes) {
    $counterTracker[$node] = @{}
    foreach ($name in $trackedCounterNames) {
        $counterTracker[$node][$name] = [pscustomobject]@{
            seen = $false
            last = [uint64]0
            total = [uint64]0
        }
    }
}

function Write-Ndjson {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [object]$Value)
    [IO.File]::AppendAllText(
        $Path,
        ($Value | ConvertTo-Json -Compress -Depth 12) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
}

function Write-JsonAtomic {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [object]$Value)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $temporary = "$Path.tmp"
    [IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 12) + "`n",
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-NodeDataDirectory {
    param([Parameter(Mandatory)] [string]$Node)
    return Join-Path $scriptDir ("nodes/{0}/data" -f $Node)
}

function Set-WorkloadControl {
    param(
        [Parameter(Mandatory)] [string]$Phase,
        [Parameter(Mandatory)] [bool]$SendTree,
        [Parameter(Mandatory)] [bool]$RecordTree,
        [Parameter(Mandatory)] [bool]$MetricMaskWindow,
        [Parameter(Mandatory)] [bool]$RestartWindow,
        [Parameter(Mandatory)] [bool]$HoldStrictAcks,
        [Parameter(Mandatory)] [int]$Elapsed,
        [Parameter(Mandatory)] [string[]]$Reasons
    )
    $script:controlGeneration++
    $control = [ordered]@{
        schema_version = 2
        run_id = $runId
        generation = $script:controlGeneration
        phase = $Phase
        send_tree = $SendTree
        record_tree = $RecordTree
        arm_ack_drop = $script:ackDropRequested
        metric_mask_window = $MetricMaskWindow
        restart_window = $RestartWindow
        hold_strict_acks = $HoldStrictAcks
        scenario_elapsed_seconds = $Elapsed
        reasons = @($Reasons)
        written_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    foreach ($node in $nodes) {
        $path = Join-Path (Get-NodeDataDirectory $node) "pre-release-workload-control.json"
        Write-JsonAtomic -Path $path -Value $control
    }
    Write-Ndjson -Path $controlLogPath -Value $control
    Write-Host "workload control: run=$runId phase=$Phase elapsed=$Elapsed send=$SendTree record=$RecordTree ack=$script:ackDropRequested reasons=$($Reasons -join ',')"
}

function Test-FullPartitionRuleSet {
    param([Parameter(Mandatory)] [string]$RuleSet)
    $rulesProperty = $scenario.rule_sets.PSObject.Properties[$RuleSet]
    if ($null -eq $rulesProperty) { throw "unknown scenario rule set '$RuleSet'" }
    $transportCount = @($scenario.transport_ports.PSObject.Properties).Count
    foreach ($rule in @($rulesProperty.Value)) {
        $profileProperty = $scenario.profiles.PSObject.Properties[[string]$rule.profile]
        if ($null -eq $profileProperty) { throw "unknown profile '$($rule.profile)'" }
        if ([double]$profileProperty.Value.loss_percent -ge 100.0 -and
            @($rule.transports).Count -ge $transportCount) {
            return $true
        }
    }
    return $false
}

$restartGuardBeforeSeconds = 5
$restartGuardAfterSeconds = 30
$timeline = @($scenario.timeline | Where-Object { [int]$_.at_seconds -le $DurationSeconds } | Sort-Object at_seconds)
$faultsStoppedAt = if ($timeline.Count) {
    [double](($timeline | Measure-Object -Property at_seconds -Maximum).Maximum)
} else { 0.0 }

function Get-WorkloadControlState {
    param([Parameter(Mandatory)] [int]$Elapsed)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $activeRuleSet = $null
    foreach ($event in $timeline) {
        if ([int]$event.at_seconds -gt $Elapsed) { break }
        if ([string]$event.action -eq "netem") { $activeRuleSet = [string]$event.rule_set }
    }
    if ($null -ne $activeRuleSet -and (Test-FullPartitionRuleSet $activeRuleSet)) {
        $reasons.Add("full_partition:$activeRuleSet")
    }
    foreach ($event in @($timeline | Where-Object action -eq "netem")) {
        $at = [int]$event.at_seconds
        if ($Elapsed -ge ($at - 2) -and $Elapsed -lt $at -and
            (Test-FullPartitionRuleSet ([string]$event.rule_set))) {
            $reasons.Add("full_partition_guard:$($event.rule_set)")
        }
    }
    foreach ($event in @($timeline | Where-Object action -eq "restart")) {
        $at = [int]$event.at_seconds
        if ($Elapsed -ge ($at - $restartGuardBeforeSeconds) -and
            $Elapsed -lt ($at + $restartGuardAfterSeconds)) {
            $reasons.Add("node_restart:$(@($event.nodes) -join ',')")
        }
    }
    $restartWindow = @($reasons | Where-Object { $_ -like "node_restart:*" }).Count -gt 0
    $holdStrictAcks = @($timeline | Where-Object action -eq "restart" | Where-Object {
        $at = [int]$_.at_seconds
        $Elapsed -ge ($at - $restartGuardBeforeSeconds) -and $Elapsed -lt ($at + 2)
    }).Count -gt 0
    $metricMaskWindow = @($scenario.metric_mask_observation_windows | Where-Object {
        $Elapsed -ge [int]$_.start_seconds -and $Elapsed -lt [int]$_.end_seconds
    }).Count -gt 0
    return [pscustomobject]@{
        phase = if ($Elapsed -lt $phaseBoundarySeconds) { "tree" } else { "legacy" }
        send_tree = $true
        record_tree = $reasons.Count -eq 0
        metric_mask_window = $metricMaskWindow
        restart_window = $restartWindow
        hold_strict_acks = $holdStrictAcks
        reasons = @($reasons)
    }
}

function Read-NodeEvidence {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        # The server atomically replaces this file, but tolerate a concurrently
        # opened file on platforms where rename does not provide that guarantee.
        return $null
    }
}

function Get-HostEvidencePath {
    param([Parameter(Mandatory)] [string]$Node)
    return Join-Path (Get-NodeDataDirectory $Node) "pre-release-workload.json"
}

function Test-StrictConverged {
    param([Parameter(Mandatory)] [hashtable]$Evidence)
    if ($Evidence.Count -ne $nodes.Count) { return $false }
    $canonical = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($node in $nodes) {
        $entry = $Evidence[$node]
        if ($null -eq $entry -or @($entry.strict_log).Count -eq 0) { return $false }
        [void]$canonical.Add((@($entry.strict_log | ForEach-Object { [string]$_ }) -join "`n"))
    }
    return $canonical.Count -eq 1
}

function Copy-EvidenceFromContainer {
    param(
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string]$Destination
    )
    $container = "shitspeak-$Node"
    foreach ($containerPath in @("/data/pre-release-workload.json", "/app/data/pre-release-workload.json")) {
        $output = & docker cp ("{0}:{1}" -f $container, $containerPath) $Destination 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Destination -PathType Leaf)) {
            return
        }
    }
    throw "missing evidence for $Node in its bind mount and container /data or /app/data"
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string]$Name,
        [switch]$Required
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        if ($Required) { throw "required evidence field '$Name' is unavailable" }
        return $null
    }
    return $property.Value
}

function Get-SummedEvidenceCounter {
    param(
        [Parameter(Mandatory)] [string]$Name
    )
    $sum = [uint64]0
    foreach ($node in $nodes) {
        $sum += Get-TrackedEvidenceCounter -Node $node -Name $Name
    }
    return $sum
}

function Update-EvidenceCounters {
    param(
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [object]$Evidence
    )
    foreach ($name in $trackedCounterNames) {
        $property = $Evidence.PSObject.Properties[$name]
        if ($null -eq $property) { continue }
        $current = [uint64]$property.Value
        $tracked = $counterTracker[$Node][$name]
        if (-not $tracked.seen) {
            $tracked.total = $current
            $tracked.seen = $true
        } elseif ($current -ge $tracked.last) {
            $tracked.total += $current - $tracked.last
        } else {
            # A smaller counter is a new server process after restart.
            $tracked.total += $current
        }
        $tracked.last = $current
    }
}

function Get-TrackedEvidenceCounter {
    param(
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string]$Name
    )
    $tracked = $counterTracker[$Node][$Name]
    if ($null -eq $tracked -or -not $tracked.seen) {
        throw "required evidence counter '$Name' is unavailable for $Node"
    }
    return [uint64]$tracked.total
}

function Get-SourceEvidence {
    param([Parameter(Mandatory)] [hashtable]$Evidence)
    $sources = @($nodes | Where-Object { @($Evidence[$_].expected_delivery_ids).Count -gt 0 })
    if ($sources.Count -ne 1) {
        throw "expected exactly one tree source evidence file, found $($sources.Count)"
    }
    return $Evidence[$sources[0]]
}

function Get-MeanSourceCpu {
    param(
        [Parameter(Mandatory)] [double]$StartExclusive,
        [Parameter(Mandatory)] [double]$EndExclusive,
        [Parameter(Mandatory)] [int]$Take
    )
    $cpuPath = Join-Path $artifactDir "cpu-samples.ndjson"
    if (-not (Test-Path -LiteralPath $cpuPath -PathType Leaf)) {
        throw "cpu-samples.ndjson is required for phase CPU evidence"
    }
    $samples = @(Get-Content -LiteralPath $cpuPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object {
            [string]$_.container -eq "shitspeak-node-01" -and
            [double]$_.elapsed_seconds -gt $StartExclusive -and
            [double]$_.elapsed_seconds -lt $EndExclusive
        } | Sort-Object elapsed_seconds | Select-Object -First $Take)
    if ($samples.Count -ne $Take -or $Take -le 0) {
        throw "insufficient equal-count source CPU samples for a performance phase"
    }
    return [double](($samples | Measure-Object -Property cpu_percent -Average).Average)
}

function Get-PrometheusValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Metric,
        [Parameter(Mandatory)] [hashtable]$Labels
    )
    $sum = 0.0
    $matched = $false
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch ('^' + [regex]::Escape($Metric) + '(?:\{(?<labels>[^}]*)\})?\s+(?<value>[-+0-9.eE]+)$')) {
            continue
        }
        $labelText = [string]$Matches.labels
        $valueText = [string]$Matches.value
        $hasLabels = $true
        foreach ($entry in $Labels.GetEnumerator()) {
            $needle = '(?:^|,)' + [regex]::Escape([string]$entry.Key) + '="' +
                [regex]::Escape([string]$entry.Value) + '"(?:,|$)'
            if ($labelText -notmatch $needle) {
                $hasLabels = $false
                break
            }
        }
        if ($hasLabels) {
            $sum += [double]::Parse($valueText, [Globalization.CultureInfo]::InvariantCulture)
            $matched = $true
        }
    }
    return [pscustomobject]@{ matched = $matched; value = $sum }
}

function Get-PrometheusCounterDelta {
    param(
        [Parameter(Mandatory)] [string]$Metric,
        [Parameter(Mandatory)] [hashtable]$Labels,
        [Parameter(Mandatory)] [int]$StartSeconds,
        [Parameter(Mandatory)] [int]$EndSeconds
    )
    $metricsDir = Join-Path $artifactDir "metrics"
    if (-not (Test-Path -LiteralPath $metricsDir -PathType Container)) {
        throw "metrics artifacts are required to derive '$Metric'"
    }
    $total = 0.0
    $matchedAnywhere = $false
    foreach ($node in $nodes) {
        $points = @()
        foreach ($file in Get-ChildItem -LiteralPath $metricsDir -Filter "*-$node.prom") {
            if ($file.BaseName -notmatch '^(?<elapsed>\d+)-node-\d+$') { continue }
            $elapsed = [int]$Matches.elapsed
            if ($elapsed -lt $StartSeconds -or $elapsed -gt $EndSeconds) { continue }
            $sample = Get-PrometheusValue -Path $file.FullName -Metric $Metric -Labels $Labels
            $points += [pscustomobject]@{
                elapsed = $elapsed
                matched = [bool]$sample.matched
                value = [double]$sample.value
            }
        }
        $points = @($points | Sort-Object elapsed)
        if ($points.Count -eq 0 -or [int]$points[0].elapsed -ne $StartSeconds -or
            [int]$points[-1].elapsed -ne $EndSeconds) {
            throw "missing exact $StartSeconds/$EndSeconds metric boundaries for $node"
        }
        $previous = [double]$points[0].value
        $matchedAnywhere = $matchedAnywhere -or [bool]$points[0].matched
        foreach ($point in @($points | Select-Object -Skip 1)) {
            $current = [double]$point.value
            $matchedAnywhere = $matchedAnywhere -or [bool]$point.matched
            if ($current -ge $previous) { $total += $current - $previous } else { $total += $current }
            $previous = $current
        }
    }
    if (-not $matchedAnywhere) {
        throw "metric '$Metric' with the required labels was not exported"
    }
    return [uint64][Math]::Round($total)
}

function Get-CandidateBuilds {
    $allEmbedded = @($nodes | Where-Object {
        $counterTracker[$_]["candidate_builds"].seen
    }).Count -eq $nodes.Count
    if ($allEmbedded) { return Get-SummedEvidenceCounter -Name "candidate_builds" }
    return Get-PrometheusCounterDelta `
        -Metric "shitspeak_s2s_distribution_events_total" `
        -Labels @{ profile = "other"; event = "candidate_build"; result = "attempt" } `
        -StartSeconds 0 -EndSeconds $DurationSeconds
}

function Get-PerformanceOperations {
    param([Parameter(Mandatory)] [object]$SourceEvidence)
    $source = [string]$SourceEvidence.node
    $treeTracked = $counterTracker[$source]["tree_encode_send_operations"]
    $legacyTracked = $counterTracker[$source]["legacy_encode_send_operations"]
    if ($treeTracked.seen -and $legacyTracked.seen) {
        return [pscustomobject]@{
            tree = [uint64]$treeTracked.total
            legacy = [uint64]$legacyTracked.total
        }
    }
    $phaseBoundary = [int]([Math]::Floor([double]$DurationSeconds / 2.0))
    $labels = @{ packet_kind = "overlay.data.tag.251" }
    return [pscustomobject]@{
        tree = Get-PrometheusCounterDelta `
            -Metric "shitspeak_s2s_debug_packet_io_send_attempts_total" `
            -Labels $labels -StartSeconds 0 -EndSeconds $phaseBoundary
        legacy = Get-PrometheusCounterDelta `
            -Metric "shitspeak_s2s_debug_packet_io_send_attempts_total" `
            -Labels $labels -StartSeconds $phaseBoundary -EndSeconds $DurationSeconds
    }
}

$scenarioClockPath = Join-Path $artifactDir "scenario-clock.json"
$driverDeadline = (Get-Date).AddSeconds($DurationSeconds + 300)
$lastControl = $null
$strictConvergedAt = $null
$nextEvidencePoll = 0
try {
    while ($true) {
        if ((Get-Date) -ge $driverDeadline) { throw "runner scenario clock did not complete before the driver deadline" }
        $runnerClock = Read-NodeEvidence -Path $scenarioClockPath
        if ($null -eq $runnerClock -or [string]$runnerClock.run_id -ne $runId) {
            Start-Sleep -Milliseconds 100
            continue
        }
        $elapsed = [int]$runnerClock.elapsed_seconds
        $control = Get-WorkloadControlState -Elapsed $elapsed
        $controlKey = "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f $control.phase, $control.send_tree,
            $control.record_tree, $control.metric_mask_window, $control.restart_window,
            $control.hold_strict_acks, ($control.reasons -join ',')
        if ($controlKey -ne $lastControl) {
            Set-WorkloadControl -Phase $control.phase -SendTree $control.send_tree `
                -RecordTree $control.record_tree -MetricMaskWindow $control.metric_mask_window `
                -RestartWindow $control.restart_window -HoldStrictAcks $control.hold_strict_acks `
                -Elapsed $elapsed -Reasons $control.reasons
            $lastControl = $controlKey
        }

        if ($elapsed -ge $nextEvidencePoll) {
            $nextEvidencePoll = $elapsed + 1
            $liveEvidence = @{}
            foreach ($node in $nodes) {
                $path = Get-HostEvidencePath $node
                $entry = Read-NodeEvidence -Path $path
                if ($null -ne $entry -and
                    (Get-Item -LiteralPath $path).LastWriteTimeUtc -ge $startedAtUtc.AddSeconds(-5) -and
                    [int]$entry.schema_version -eq 2 -and
                    [string]$entry.node -eq $node -and
                    [string]$entry.run_id -eq $runId -and
                    [uint64]$entry.control_generation -gt 0) {
                    $liveEvidence[$node] = $entry
                    Update-EvidenceCounters -Node $node -Evidence $entry
                }
            }
            if (-not $script:ackDropRequested -and $elapsed -ge [int]$scenario.distribution_ack_arm_seconds -and
                $liveEvidence.ContainsKey("node-01") -and
                [uint64](Get-PropertyValue -Object $liveEvidence["node-01"] -Name "tree_activations" -Required) -gt 0) {
                $script:ackDropRequested = $true
                $lastControl = $null
            }
            foreach ($restart in @($timeline | Where-Object action -eq "restart")) {
                $at = [int]$restart.at_seconds
                $readyPath = Join-Path $workloadDir ("restart-ready-{0:D4}.json" -f $at)
                if ($elapsed -ge ($at - $restartGuardBeforeSeconds) -and $elapsed -lt $at -and
                    -not (Test-Path -LiteralPath $readyPath) -and
                    @($liveEvidence.Values | Where-Object {
                        [bool]$_.strict_ack_hold_active -and [uint64]$_.strict_in_flight -gt 0
                    }).Count -gt 0) {
                    Write-JsonAtomic -Path $readyPath -Value ([ordered]@{
                        run_id = $runId; scheduled_restart_seconds = $at
                        observed_seconds = $elapsed; strict_in_flight = [uint64](($liveEvidence.Values |
                            ForEach-Object { [uint64]$_.strict_in_flight } | Measure-Object -Sum).Sum)
                    })
                }
            }
            if ($null -eq $strictConvergedAt -and $elapsed -ge $faultsStoppedAt -and
                (Test-StrictConverged -Evidence $liveEvidence)) {
                $strictConvergedAt = [double]$elapsed
            }
        }
        if ($elapsed -ge $DurationSeconds) { break }
        Start-Sleep -Milliseconds 250
    }
} finally {
    Set-WorkloadControl -Phase "legacy" -SendTree $false -RecordTree $false `
        -MetricMaskWindow $false -RestartWindow $false -HoldStrictAcks $false -Elapsed $DurationSeconds `
        -Reasons @("scenario_complete")
}

# The runner and this process start adjacent to one another. Allow its final
# sample write to complete before deriving phase CPU evidence.
$sampleDeadline = (Get-Date).AddSeconds(15)
do {
    $samplePath = Join-Path $artifactDir "sample-summary.ndjson"
    $hasFinalSample = $false
    if (Test-Path -LiteralPath $samplePath -PathType Leaf) {
        $lastRows = @(Get-Content -LiteralPath $samplePath -Tail 32 | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
        $hasFinalSample = @($lastRows | Where-Object { [int]$_.elapsed_seconds -ge $DurationSeconds }).Count -gt 0
    }
    if (-not $hasFinalSample) { Start-Sleep -Milliseconds 250 }
} while (-not $hasFinalSample -and (Get-Date) -lt $sampleDeadline)
if (-not $hasFinalSample) { throw "runner did not publish a final sample at $DurationSeconds seconds" }

$finalEvidence = @{}
foreach ($node in $nodes) {
    $destination = Join-Path $nodeArtifactDir "$node.json"
    $hostPath = Get-HostEvidencePath $node
    if (Test-Path -LiteralPath $hostPath -PathType Leaf) {
        Copy-Item -LiteralPath $hostPath -Destination $destination -Force
    } else {
        Copy-EvidenceFromContainer -Node $node -Destination $destination
    }
    $entry = Read-NodeEvidence -Path $destination
    if ($null -eq $entry) { throw "invalid JSON evidence for $node" }
    if ([int]$entry.schema_version -ne 2 -or [string]$entry.node -ne $node -or
        [string]$entry.run_id -ne $runId) {
        throw "evidence identity/schema mismatch for $node"
    }
    $heartbeatAgeMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - [int64]$entry.heartbeat_unix_ms
    if ($heartbeatAgeMs -lt 0 -or $heartbeatAgeMs -gt 15000) {
        throw "stale heartbeat for $node is $heartbeatAgeMs ms old"
    }
    Update-EvidenceCounters -Node $node -Evidence $entry
    $finalEvidence[$node] = $entry
}

if ($null -eq $strictConvergedAt) {
    if (-not (Test-StrictConverged -Evidence $finalEvidence)) {
        throw "strict logs were not converged when final evidence was harvested"
    }
    # This is an upper bound, not an inferred earlier convergence time.
    $strictConvergedAt = [double]$DurationSeconds
}

$sourceEvidence = Get-SourceEvidence -Evidence $finalEvidence
$performanceOperations = Get-PerformanceOperations -SourceEvidence $sourceEvidence
$logsByNode = [ordered]@{}
$deliveriesByNode = [ordered]@{}
$lsaByNode = [ordered]@{}
foreach ($node in $nodes) {
    $logsByNode[$node] = @($finalEvidence[$node].strict_log | ForEach-Object { [string]$_ })
    $deliveriesByNode[$node] = @($finalEvidence[$node].deliveries | ForEach-Object { [string]$_ })
    $lsaByNode[$node] = Get-TrackedEvidenceCounter -Node $node -Name "metric_lsa_emissions"
}
$expectedStrictIds = @($nodes | ForEach-Object {
    @($finalEvidence[$_].expected_strict_ids | ForEach-Object { [string]$_ })
} | Sort-Object -Unique)
$strictFailuresByKind = [ordered]@{}
foreach ($node in $nodes) {
    foreach ($property in @($finalEvidence[$node].strict_proposal_failures_by_kind.PSObject.Properties)) {
        if (-not $strictFailuresByKind.Contains($property.Name)) { $strictFailuresByKind[$property.Name] = [uint64]0 }
        $strictFailuresByKind[$property.Name] += [uint64]$property.Value
    }
}
$restartMarkers = @(Get-ChildItem -LiteralPath $workloadDir -Filter "restart-ready-*.json" -ErrorAction SilentlyContinue)
$metricObservationSeconds = [double](($scenario.metric_mask_observation_windows | ForEach-Object {
    [int]$_.end_seconds - [int]$_.start_seconds
} | Measure-Object -Sum).Sum)

$treeCpuEvidence = Get-PropertyValue -Object $sourceEvidence -Name "tree_source_cpu_percent"
$legacyCpuEvidence = Get-PropertyValue -Object $sourceEvidence -Name "legacy_source_cpu_percent"
if ($null -eq $treeCpuEvidence -or $null -eq $legacyCpuEvidence) {
    if ([uint64]$sourceEvidence.scored_tree_send_calls -eq 0 -or
        [uint64]$sourceEvidence.scored_legacy_send_calls -eq 0) {
        throw "source CPU cannot be compared because a scored workload phase is empty"
    }
    $phaseBoundary = [double]$phaseBoundarySeconds
    $cpuPath = Join-Path $artifactDir "cpu-samples.ndjson"
    $allCpu = @(Get-Content -LiteralPath $cpuPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    $treeCount = @($allCpu | Where-Object {
        [string]$_.container -eq "shitspeak-node-01" -and [double]$_.elapsed_seconds -gt 10 -and [double]$_.elapsed_seconds -lt $phaseBoundary
    }).Count
    $legacyCount = @($allCpu | Where-Object {
        [string]$_.container -eq "shitspeak-node-01" -and [double]$_.elapsed_seconds -gt $phaseBoundary -and [double]$_.elapsed_seconds -lt $DurationSeconds
    }).Count
    $equalCount = [Math]::Min($treeCount, $legacyCount)
    $treeCpuEvidence = Get-MeanSourceCpu -StartExclusive 10 -EndExclusive $phaseBoundary -Take $equalCount
    $legacyCpuEvidence = Get-MeanSourceCpu -StartExclusive $phaseBoundary -EndExclusive $DurationSeconds -Take $equalCount
}

$summary = [ordered]@{
    schema_version = 2
    run_id = $runId
    scenario_sha256 = $scenarioHash
    faults_stopped_at_seconds = $faultsStoppedAt
    strict = [ordered]@{
        proposal_count = [uint64](($nodes | ForEach-Object { [uint64]$finalEvidence[$_].strict_proposals } | Measure-Object -Sum).Sum)
        # This is the exact typed timeout counter, not the broader proposal
        # failure counter.
        propose_timeouts = [uint64](($nodes | ForEach-Object {
            [uint64](Get-PropertyValue -Object $finalEvidence[$_] -Name "strict_propose_timeouts" -Required)
        } | Measure-Object -Sum).Sum)
        proposal_failures = [uint64](($nodes | ForEach-Object { [uint64]$finalEvidence[$_].strict_proposal_failures } | Measure-Object -Sum).Sum)
        failures_by_kind = $strictFailuresByKind
        expected_operation_ids = $expectedStrictIds
        restart_inflight_evidence_count = $restartMarkers.Count
        converged_at_seconds = $strictConvergedAt
        logs_by_node = $logsByNode
    }
    tree = [ordered]@{
        expected_delivery_ids = @($sourceEvidence.expected_delivery_ids | ForEach-Object { [string]$_ })
        deliveries_by_node = $deliveriesByNode
        selected_ack_drops = [uint64](($nodes | ForEach-Object { [uint64]$finalEvidence[$_].selected_ack_drops } | Measure-Object -Sum).Sum)
        restart_tree_send_calls = Get-SummedEvidenceCounter -Name "restart_tree_send_calls"
        whole_group_fallbacks_after_initial_activation = Get-SummedEvidenceCounter -Name "whole_group_fallbacks_after_initial_activation"
        candidate_builds = Get-CandidateBuilds
        candidate_trigger_changes = Get-SummedEvidenceCounter -Name "candidate_trigger_changes"
    }
    control_plane = [ordered]@{
        topology_epoch_changes_during_metric_mask_churn = Get-SummedEvidenceCounter -Name "topology_epoch_changes_during_metric_mask_churn"
        metric_lsa_observation_seconds = $metricObservationSeconds
        metric_lsa_emissions_by_node = $lsaByNode
    }
    performance = [ordered]@{
        tree_encode_send_operations = [uint64]$performanceOperations.tree
        legacy_encode_send_operations = [uint64]$performanceOperations.legacy
        tree_logical_sends = [uint64]$sourceEvidence.scored_tree_send_calls
        legacy_logical_sends = [uint64]$sourceEvidence.scored_legacy_send_calls
        tree_source_cpu_percent = [double]$treeCpuEvidence
        legacy_source_cpu_percent = [double]$legacyCpuEvidence
    }
}

Write-JsonAtomic -Path $summaryPath -Value $summary
$schemaPath = Join-Path $scriptDir "workload-summary.schema.json"
if (-not ((Get-Content -LiteralPath $summaryPath -Raw) | Test-Json -SchemaFile $schemaPath -ErrorAction SilentlyContinue)) {
    throw "generated workload summary does not satisfy workload-summary.schema.json"
}

Write-Host "workload evidence: $summaryPath"
