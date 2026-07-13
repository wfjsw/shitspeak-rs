param(
    [Parameter(Mandatory)] [string]$ArtifactDirectory,
    [string]$ScenarioPath = (Join-Path $PSScriptRoot "pre-release-netem-scenario.json")
)

$ErrorActionPreference = "Stop"
$scenario = Get-Content -LiteralPath $ScenarioPath -Raw | ConvertFrom-Json
$limits = $scenario.acceptance
$samplePath = Join-Path $ArtifactDirectory "sample-summary.ndjson"
$cpuPath = Join-Path $ArtifactDirectory "cpu-samples.ndjson"
$workloadPath = Join-Path $ArtifactDirectory "workload-summary.json"
$workloadSchemaPath = Join-Path $PSScriptRoot "workload-summary.schema.json"
$containerLogPath = Join-Path $ArtifactDirectory "logs/containers.log"
$reportPath = Join-Path $ArtifactDirectory "acceptance.json"
$metadataPath = Join-Path $ArtifactDirectory "metadata.json"
$capturedScenarioPath = Join-Path $ArtifactDirectory "scenario.json"

$samples = if (Test-Path -LiteralPath $samplePath) {
    @(Get-Content -LiteralPath $samplePath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
} else { @() }
$cpuSamples = if (Test-Path -LiteralPath $cpuPath) {
    @(Get-Content -LiteralPath $cpuPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
} else { @() }
$workload = if (Test-Path -LiteralPath $workloadPath) {
    Get-Content -LiteralPath $workloadPath -Raw | ConvertFrom-Json
} else { $null }
$workloadSchemaValid = $null -ne $workload -and (Get-Content -LiteralPath $workloadPath -Raw | Test-Json -SchemaFile $workloadSchemaPath -ErrorAction SilentlyContinue)
$metadata = if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
    Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
} else { $null }
$requestedScenarioHash = (Get-FileHash -LiteralPath $ScenarioPath -Algorithm SHA256).Hash.ToLowerInvariant()
$capturedScenarioHash = if (Test-Path -LiteralPath $capturedScenarioPath -PathType Leaf) {
    (Get-FileHash -LiteralPath $capturedScenarioPath -Algorithm SHA256).Hash.ToLowerInvariant()
} else { $null }

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [bool]$Passed, [object]$Observed, [object]$Expected)
    $checks.Add([pscustomobject]@{ name = $Name; passed = $Passed; observed = $Observed; expected = $Expected })
}

Add-Check "artifact_metadata_present" ($null -ne $metadata) ($null -ne $metadata) $true
Add-Check "scenario_matches_artifact" (
    $null -ne $metadata -and
    $requestedScenarioHash -eq [string]$metadata.scenario_sha256 -and
    $capturedScenarioHash -eq [string]$metadata.scenario_sha256
) "$requestedScenarioHash/$capturedScenarioHash" $(if ($null -ne $metadata) { [string]$metadata.scenario_sha256 } else { "missing" })
Add-Check "workload_run_matches_artifact" (
    $null -ne $metadata -and $null -ne $workload -and
    [string]$workload.run_id -eq [string]$metadata.run_id -and
    [string]$workload.scenario_sha256 -eq [string]$metadata.scenario_sha256
) $(if ($null -ne $workload) { [string]$workload.run_id } else { "missing" }) $(if ($null -ne $metadata) { [string]$metadata.run_id } else { "missing" })

function Test-ConvergedGroup {
    param([Parameter(Mandatory)] [object]$Group)
    $rows = @($Group.Group)
    if ($rows.Count -ne [int]$limits.expected_nodes) { return $false }
    return @($rows | Where-Object {
        $_.error -or [int]$_.nodes -ne [int]$limits.expected_nodes -or
        [int]$_.alive_nodes -ne [int]$limits.expected_nodes -or
        [int]$_.routes -lt [int]$limits.expected_routes_per_node
    }).Count -eq 0
}

function ConvertTo-CanonicalSequence {
    param([object]$Sequence)
    return (@($Sequence) | ForEach-Object { [string]$_ }) -join "`n"
}

function Get-DuplicateCount {
    param([object]$Sequence)
    return @(@($Sequence) | Group-Object | Where-Object Count -gt 1 | ForEach-Object { $_.Count - 1 } | Measure-Object -Sum).Sum
}

Add-Check "workload_summary_present" ($null -ne $workload -and [int]$workload.schema_version -eq 2) `
    $(if ($null -eq $workload) { "missing" } else { $workload.schema_version }) 2
Add-Check "workload_summary_schema" $workloadSchemaValid $workloadSchemaValid $true

$groups = @($samples | Group-Object elapsed_seconds | Sort-Object { [int]$_.Name })
$lastEvent = [int](($scenario.timeline | Measure-Object -Property at_seconds -Maximum).Maximum)
$postFaultGroups = @($groups | Where-Object { [int]$_.Name -ge $lastEvent })
$firstConverged = @($postFaultGroups | Where-Object { Test-ConvergedGroup $_ } | Select-Object -First 1)
$convergenceSeconds = if ($firstConverged.Count) { [int]$firstConverged[0].Name - $lastEvent } else { $null }
Add-Check "routing_final_convergence" ($null -ne $convergenceSeconds -and $convergenceSeconds -le [int]$limits.maximum_final_convergence_seconds) $convergenceSeconds $limits.maximum_final_convergence_seconds

$requiredFinal = [int]$limits.minimum_final_converged_samples
$finalGroups = @($groups | Select-Object -Last $requiredFinal)
$finalConverged = @($finalGroups | Where-Object { Test-ConvergedGroup $_ }).Count
Add-Check "routing_final_stability" ($finalGroups.Count -eq $requiredFinal -and $finalConverged -eq $requiredFinal) $finalConverged $requiredFinal

$treeSamples = @($samples | Where-Object { [double]$_.tree_edges_total -gt 0 }).Count
Add-Check "distribution_tree_active" ($treeSamples -ge [int]$limits.minimum_tree_edge_samples) $treeSamples $limits.minimum_tree_edge_samples

if ($workloadSchemaValid) {
    $expectedNodeNames = @($scenario.node_groups.all | ForEach-Object { [string]$_ })
    $strictLogs = @($workload.strict.logs_by_node.PSObject.Properties)
    $strictCanonical = @($strictLogs | ForEach-Object { ConvertTo-CanonicalSequence $_.Value } | Select-Object -Unique)
    $strictMissingNodes = @($expectedNodeNames | Where-Object { $_ -notin @($strictLogs.Name) }).Count
    Add-Check "strict_proposals_generated" ([int]$workload.strict.proposal_count -gt 0) $workload.strict.proposal_count "> 0"
    $strictFailureKindsTotal = [uint64](($workload.strict.failures_by_kind.PSObject.Properties |
        ForEach-Object { [uint64]$_.Value } | Measure-Object -Sum).Sum)
    Add-Check "strict_no_proposal_failure" ([uint64]$workload.strict.proposal_failures -eq 0) $workload.strict.proposal_failures 0
    Add-Check "strict_failure_classification_exact" ($strictFailureKindsTotal -eq [uint64]$workload.strict.proposal_failures) $strictFailureKindsTotal $workload.strict.proposal_failures
    Add-Check "strict_no_propose_timeout" ([int]$workload.strict.propose_timeouts -eq 0) $workload.strict.propose_timeouts 0
    Add-Check "strict_all_replica_logs_present" ($strictLogs.Count -eq [int]$limits.expected_nodes) $strictLogs.Count $limits.expected_nodes
    Add-Check "strict_expected_replica_names" ($strictMissingNodes -eq 0) $strictMissingNodes 0
    Add-Check "strict_identical_ordered_logs" ($strictLogs.Count -eq [int]$limits.expected_nodes -and $strictCanonical.Count -eq 1 -and $strictCanonical[0].Length -gt 0) $strictCanonical.Count 1
    $strictDuplicates = if ($strictLogs.Count) { [int](Get-DuplicateCount $strictLogs[0].Value) } else { 0 }
    Add-Check "strict_no_duplicate_operation_ids" ($strictLogs.Count -gt 0 -and $strictDuplicates -eq 0) $strictDuplicates 0
    $expectedStrictIds = @($workload.strict.expected_operation_ids | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $committedStrictIds = if ($strictLogs.Count) { @($strictLogs[0].Value | ForEach-Object { [string]$_ } | Sort-Object -Unique) } else { @() }
    $strictIdDifference = @($expectedStrictIds | Where-Object { $_ -notin $committedStrictIds }).Count +
        @($committedStrictIds | Where-Object { $_ -notin $expectedStrictIds }).Count
    Add-Check "strict_expected_ids_exact" ($strictIdDifference -eq 0) $strictIdDifference 0
    $restartEventCount = @($scenario.timeline | Where-Object action -eq "restart").Count
    Add-Check "strict_inflight_proven_at_each_restart" ([int]$workload.strict.restart_inflight_evidence_count -eq $restartEventCount) $workload.strict.restart_inflight_evidence_count $restartEventCount
    $strictRecovery = [double]$workload.strict.converged_at_seconds - [double]$workload.faults_stopped_at_seconds
    Add-Check "strict_converged_within_deadline" ($strictRecovery -ge 0 -and $strictRecovery -le [double]$limits.maximum_final_strict_convergence_seconds) $strictRecovery $limits.maximum_final_strict_convergence_seconds

    $expectedIds = @($workload.tree.expected_delivery_ids | ForEach-Object { [string]$_ })
    $deliverySets = @($workload.tree.deliveries_by_node.PSObject.Properties)
    $deliveryMissingNodes = @($expectedNodeNames | Where-Object { $_ -notin @($deliverySets.Name) }).Count
    $missing = 0
    $duplicates = 0
    $unexpected = 0
    foreach ($entry in $deliverySets) {
        $actual = @($entry.Value | ForEach-Object { [string]$_ })
        $duplicates += [int](Get-DuplicateCount $actual)
        $missing += @($expectedIds | Where-Object { $_ -notin $actual }).Count
        $unexpected += @($actual | Where-Object { $_ -notin $expectedIds }).Count
    }
    Add-Check "tree_traffic_generated" ($expectedIds.Count -gt 0) $expectedIds.Count "> 0"
    Add-Check "tree_all_recipient_logs_present" ($deliverySets.Count -eq [int]$limits.expected_nodes) $deliverySets.Count $limits.expected_nodes
    Add-Check "tree_expected_recipient_names" ($deliveryMissingNodes -eq 0) $deliveryMissingNodes 0
    Add-Check "tree_no_missing_delivery" ($missing -eq 0) $missing 0
    Add-Check "tree_no_duplicate_delivery" ($duplicates -eq 0) $duplicates 0
    Add-Check "tree_no_unexpected_delivery" ($unexpected -eq 0) $unexpected 0
    Add-Check "selected_distribution_ack_dropped" ([int]$workload.tree.selected_ack_drops -gt 0) $workload.tree.selected_ack_drops "> 0"
    Add-Check "tree_traffic_continued_during_restart" ([int]$workload.tree.restart_tree_send_calls -gt 0) $workload.tree.restart_tree_send_calls "> 0"
    Add-Check "no_metric_mask_topology_epoch_churn" ([int]$workload.control_plane.topology_epoch_changes_during_metric_mask_churn -eq 0) $workload.control_plane.topology_epoch_changes_during_metric_mask_churn 0
    Add-Check "no_whole_group_fallback_after_activation" ([int]$workload.tree.whole_group_fallbacks_after_initial_activation -eq 0) $workload.tree.whole_group_fallbacks_after_initial_activation 0

    $candidateLimit = [Math]::Max(1.0, [double]$workload.tree.candidate_trigger_changes * [double]$limits.maximum_candidate_builds_per_change)
    Add-Check "candidate_builds_bounded_by_changes" ([double]$workload.tree.candidate_builds -le $candidateLimit) $workload.tree.candidate_builds $candidateLimit

    $lsaRates = @()
    $lsaSeconds = [double]$workload.control_plane.metric_lsa_observation_seconds
    foreach ($entry in @($workload.control_plane.metric_lsa_emissions_by_node.PSObject.Properties)) {
        if ($lsaSeconds -gt 0) { $lsaRates += [double]$entry.Value / $lsaSeconds }
    }
    $maxLsaRate = if ($lsaRates.Count) { ($lsaRates | Measure-Object -Maximum).Maximum } else { [double]::PositiveInfinity }
    Add-Check "metric_lsa_emission_rate" ($lsaRates.Count -eq [int]$limits.expected_nodes -and $maxLsaRate -le [double]$limits.maximum_metric_lsa_emissions_per_node_per_second) $maxLsaRate $limits.maximum_metric_lsa_emissions_per_node_per_second

    $treeLogical = [double]$workload.performance.tree_logical_sends
    $legacyLogical = [double]$workload.performance.legacy_logical_sends
    $logicalImbalance = [Math]::Abs($treeLogical - $legacyLogical) / [Math]::Max($treeLogical, $legacyLogical)
    Add-Check "performance_phase_workload_comparable" ($logicalImbalance -le [double]$limits.maximum_phase_logical_send_imbalance_ratio) $logicalImbalance $limits.maximum_phase_logical_send_imbalance_ratio
    $opsRatio = if ([double]$workload.performance.legacy_encode_send_operations -gt 0 -and $treeLogical -gt 0 -and $legacyLogical -gt 0) {
        ([double]$workload.performance.tree_encode_send_operations / $treeLogical) /
            ([double]$workload.performance.legacy_encode_send_operations / $legacyLogical)
    } else { [double]::PositiveInfinity }
    Add-Check "tree_operations_below_half_legacy" ($opsRatio -lt [double]$limits.maximum_tree_to_legacy_operations_ratio) $opsRatio $limits.maximum_tree_to_legacy_operations_ratio
    $cpuRatio = if ([double]$workload.performance.legacy_source_cpu_percent -gt 0) {
        [double]$workload.performance.tree_source_cpu_percent / [double]$workload.performance.legacy_source_cpu_percent
    } else { [double]::PositiveInfinity }
    Add-Check "tree_source_cpu_not_above_legacy" ($cpuRatio -le [double]$limits.maximum_tree_to_legacy_cpu_ratio) $cpuRatio $limits.maximum_tree_to_legacy_cpu_ratio
}

$logTimeoutCount = if (Test-Path -LiteralPath $containerLogPath) {
    @(Select-String -LiteralPath $containerLogPath -Pattern 'ProposeTimeout|propose timed out' -CaseSensitive:$false).Count
} else { -1 }
Add-Check "container_logs_captured" ($logTimeoutCount -ge 0) $(if ($logTimeoutCount -lt 0) { "missing" } else { "present" }) "present"
Add-Check "container_logs_no_propose_timeout" ($logTimeoutCount -eq 0) $logTimeoutCount 0

$maxCpu = if ($cpuSamples.Count) { [double](($cpuSamples | Measure-Object -Property cpu_percent -Maximum).Maximum) } else { [double]::PositiveInfinity }
Add-Check "cpu_sample_count" ($cpuSamples.Count -ge [int]$limits.minimum_cpu_samples) $cpuSamples.Count $limits.minimum_cpu_samples
Add-Check "absolute_node_cpu_ceiling" ($maxCpu -le [double]$limits.maximum_node_cpu_percent) $maxCpu $limits.maximum_node_cpu_percent

$passed = @($checks | Where-Object { -not $_.passed }).Count -eq 0
$report = [pscustomobject]@{ schema_version = 2; scenario = $scenario.name; passed = $passed; evaluated_at_utc = [DateTimeOffset]::UtcNow.ToString("o"); checks = @($checks) }
[IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 8) + "`n", [Text.UTF8Encoding]::new($false))
foreach ($check in $checks) {
    Write-Host "$(if ($check.passed) { 'PASS' } else { 'FAIL' }) $($check.name): observed=$($check.observed) expected=$($check.expected)"
}
if (-not $passed) { exit 1 }
