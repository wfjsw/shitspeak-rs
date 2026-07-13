param(
    [ValidateSet("Apply", "Clear", "Show", "Validate")]
    [string]$Action = "Apply",
    [string]$RuleSet = "baseline",
    [string]$ScenarioPath = (Join-Path $PSScriptRoot "pre-release-netem-scenario.json"),
    [string]$Device = "eth0",
    [string]$StateOutputPath
)

$ErrorActionPreference = "Stop"
$scenario = Get-Content -LiteralPath $ScenarioPath -Raw | ConvertFrom-Json

function Invoke-Docker {
    param([Parameter(Mandatory)] [string[]]$Arguments)

    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Invoke-Tc {
    param(
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [switch]$AllowFailure
    )

    $container = "shitspeak-$Node"
    $output = & docker exec -u 0 $container tc @Arguments 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "tc failed in ${container}: tc $($Arguments -join ' '): $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Invoke-TcBatch {
    param(
        [Parameter(Mandatory)] [string]$Node,
        [Parameter(Mandatory)] [string[]]$CommandLines
    )

    $container = "shitspeak-$Node"
    $batch = ($CommandLines -join "`n") + "`n"
    $output = $batch | & docker exec -i -u 0 $container tc -batch - 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "tc batch failed in ${container}: $($output -join [Environment]::NewLine)"
    }
    return @($output)
}

function Get-NodeIpMap {
    $result = @{}
    foreach ($node in @($scenario.node_groups.all)) {
        if ($node -notmatch '^node-\d{2}$') {
            throw "invalid node name in scenario: $node"
        }
        $container = "shitspeak-$node"
        $address = (Invoke-Docker -Arguments @(
            "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", $container
        ) | Select-Object -First 1).Trim()
        if ($address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            throw "could not resolve an IPv4 address for $container"
        }
        $result[$node] = $address
    }
    return $result
}

function Add-DirectionalRules {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[object]]$Output,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [hashtable]$Seen,
        [Parameter(Mandatory)] [array]$Sources,
        [Parameter(Mandatory)] [array]$Targets,
        [Parameter(Mandatory)] [object]$Rule
    )

    foreach ($source in $Sources) {
        foreach ($target in $Targets) {
            if ($source -eq $target) {
                continue
            }
            foreach ($transportName in @($Rule.transports)) {
                $transport = $scenario.transport_ports.$transportName
                if ($null -eq $transport) {
                    throw "unknown transport '$transportName'"
                }
                $key = "$source|$target|$($transport.protocol)|$($transport.port)"
                # Earlier rules are intentionally more specific and win.
                if ($Seen.ContainsKey($key)) {
                    continue
                }
                $Seen[$key] = $true
                $Output.Add([pscustomobject]@{
                    source = [string]$source
                    target = [string]$target
                    protocol = [string]$transport.protocol
                    port = [int]$transport.port
                    profile = [string]$Rule.profile
                })
            }
        }
    }
}

function Expand-RuleSet {
    param([Parameter(Mandatory)] [string]$Name)

    $sourceRules = @($scenario.rule_sets.$Name)
    if ($sourceRules.Count -eq 0) {
        throw "unknown or empty rule set '$Name'"
    }
    $expanded = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($rule in $sourceRules) {
        if ($null -eq $scenario.profiles.$($rule.profile)) {
            throw "unknown profile '$($rule.profile)'"
        }
        $from = @($scenario.node_groups.$($rule.from_group))
        $to = @($scenario.node_groups.$($rule.to_group))
        if ($from.Count -eq 0 -or $to.Count -eq 0) {
            throw "rule references an unknown or empty node group"
        }
        if ($rule.direction -notin @("egress", "ingress", "both")) {
            throw "invalid direction '$($rule.direction)'"
        }
        if ($rule.direction -in @("egress", "both")) {
            Add-DirectionalRules -Output $expanded -Seen $seen -Sources $from -Targets $to -Rule $rule
        }
        if ($rule.direction -in @("ingress", "both")) {
            Add-DirectionalRules -Output $expanded -Seen $seen -Sources $to -Targets $from -Rule $rule
        }
    }
    return @($expanded)
}

function Get-NetemArguments {
    param([Parameter(Mandatory)] [object]$Profile)

    $delay = [int]$Profile.delay_ms
    $jitter = [int]$Profile.jitter_ms
    $loss = [double]$Profile.loss_percent
    $seed = [int]$Profile.seed
    if ($delay -lt 0 -or $jitter -lt 0 -or $loss -lt 0 -or $loss -gt 100 -or $seed -le 0) {
        throw "invalid netem profile values"
    }
    if ([string]$Profile.rate -notmatch '^\d+(kbit|mbit|gbit)$') {
        throw "invalid netem rate '$($Profile.rate)'"
    }

    $args = @("netem")
    if ($delay -gt 0) {
        $args += @("delay", "${delay}ms")
        if ($jitter -gt 0) {
            $args += "${jitter}ms"
        }
    }
    if ($null -ne $Profile.loss_model) {
        if ([string]$Profile.loss_model.kind -ne "gemodel") {
            throw "unsupported loss model '$($Profile.loss_model.kind)'"
        }
        $values = @("p", "r", "h", "k") | ForEach-Object { [double]$Profile.loss_model.$_ }
        if (@($values | Where-Object { $_ -lt 0 -or $_ -gt 100 }).Count -gt 0) {
            throw "gemodel values must be percentages in [0, 100]"
        }
        $fmt = { param($value) $value.ToString("0.###", [Globalization.CultureInfo]::InvariantCulture) + "%" }
        $args += @("loss", "gemodel", (& $fmt $values[0]), (& $fmt $values[1]), (& $fmt $values[2]), (& $fmt $values[3]))
    } elseif ($loss -gt 0) {
        $args += @("loss", "random", ($loss.ToString("0.###", [Globalization.CultureInfo]::InvariantCulture) + "%"))
    }
    $args += @("rate", [string]$Profile.rate, "seed", [string]$seed)
    return $args
}

function Clear-Netem {
    foreach ($node in @($scenario.node_groups.all)) {
        Invoke-Tc -Node $node -Arguments @("qdisc", "del", "dev", $Device, "root") -AllowFailure | Out-Null
    }
}

function Get-TcState {
    $rows = @()
    foreach ($node in @($scenario.node_groups.all)) {
        $rows += [pscustomobject]@{
            node = $node
            qdisc = @((Invoke-Tc -Node $node -Arguments @("-s", "qdisc", "show", "dev", $Device)))
            filters = @((Invoke-Tc -Node $node -Arguments @("filter", "show", "dev", $Device, "parent", "1:") -AllowFailure))
        }
    }
    return @($rows)
}

if ($Action -eq "Validate") {
    foreach ($profileName in @($scenario.profiles.PSObject.Properties.Name)) {
        Get-NetemArguments -Profile $scenario.profiles.$profileName | Out-Null
    }
    foreach ($name in @($scenario.rule_sets.PSObject.Properties.Name)) {
        $expanded = @(Expand-RuleSet -Name $name)
        if ($expanded.Count -eq 0) { throw "rule set '$name' expands to no filters" }
    }
    $timeline = @($scenario.timeline | Sort-Object at_seconds)
    if ($timeline.Count -eq 0 -or [int]$timeline[-1].at_seconds -gt [int]$scenario.duration_seconds) {
        throw "timeline must be nonempty and fit within duration_seconds"
    }
    $profileCount = @($scenario.profiles.PSObject.Properties).Count
    $ruleSetCount = @($scenario.rule_sets.PSObject.Properties).Count
    Write-Host "Validated $profileCount profiles, $ruleSetCount rule sets, and $($timeline.Count) timeline events."
    exit 0
}

if ($Action -eq "Clear") {
    Clear-Netem
    Write-Host "Cleared netem from all scenario nodes."
    exit 0
}

if ($Action -eq "Show") {
    $state = Get-TcState | ConvertTo-Json -Depth 6
    if ($StateOutputPath) {
        [System.IO.File]::WriteAllText($StateOutputPath, $state + "`n", [Text.UTF8Encoding]::new($false))
    } else {
        $state
    }
    exit 0
}

$rules = Expand-RuleSet -Name $RuleSet
$ipByNode = Get-NodeIpMap
$profileNames = @($rules.profile | Select-Object -Unique)
if ($profileNames.Count -gt 14) {
    throw "rule set uses too many distinct profiles for the prio qdisc"
}

$bandByProfile = @{}
for ($i = 0; $i -lt $profileNames.Count; $i++) {
    $bandByProfile[$profileNames[$i]] = $i + 2
}

foreach ($node in @($scenario.node_groups.all)) {
    $commands = [System.Collections.Generic.List[string]]::new()
    $commands.Add("qdisc replace dev $Device root handle 1: prio bands $($profileNames.Count + 1)")
    foreach ($profileName in $profileNames) {
        $band = $bandByProfile[$profileName]
        $handle = 10 * $band
        $netem = Get-NetemArguments -Profile $scenario.profiles.$profileName
        $commands.Add("qdisc replace dev $Device parent 1:$band handle ${handle}: $($netem -join ' ')")
    }

    $priority = 1
    foreach ($rule in @($rules | Where-Object source -eq $node)) {
        $band = $bandByProfile[$rule.profile]
        $commands.Add("filter add dev $Device protocol ip parent 1: prio $priority flower ip_proto $($rule.protocol) dst_ip $($ipByNode[$rule.target]) dst_port $($rule.port) classid 1:$band")
        $priority++
        # TCP replies leave the listening endpoint with an ephemeral destination
        # port. Match the source service port as well so shaping is genuinely
        # bidirectional rather than applying only to connection initiators.
        if ($rule.protocol -eq "tcp") {
            $commands.Add("filter add dev $Device protocol ip parent 1: prio $priority flower ip_proto tcp dst_ip $($ipByNode[$rule.target]) src_port $($rule.port) classid 1:$band")
            $priority++
        }
    }
    Invoke-TcBatch -Node $node -CommandLines $commands | Out-Null
}

if ($StateOutputPath) {
    $state = Get-TcState | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($StateOutputPath, $state + "`n", [Text.UTF8Encoding]::new($false))
}
Write-Host "Applied '$RuleSet' with $($rules.Count) directional per-port filters."
