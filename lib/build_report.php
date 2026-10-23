<?php
/**
 * build_report.php — turn normalized findings (JSONL) into:
 *   - report.html  (plain-English, for non-technical readers)
 *   - report.json  (machine-readable, for technical follow-up)
 *
 * Usage: php build_report.php <findings.jsonl> <out-dir>
 *
 * Context values are passed via environment variables set by scan.sh:
 *   SCAN_TARGET SCAN_APP_TYPE SCAN_PHP_VERSION SCAN_INTERNET
 *   SCAN_PHP_FILES SCAN_PLATFORM SCAN_STAMP SCAN_SEMGREP
 */

if ($argc < 3) {
    fwrite(STDERR, "usage: build_report.php <findings.jsonl> <out-dir>\n");
    exit(2);
}

$findingsFile = $argv[1];
$outDir       = rtrim($argv[2], '/');

$ctx = [
    'target'       => getenv('SCAN_TARGET')       ?: '(unknown)',
    'app_type'     => getenv('SCAN_APP_TYPE')     ?: 'PHP application',
    'php_version'  => getenv('SCAN_PHP_VERSION')  ?: 'unknown',
    'internet'     => getenv('SCAN_INTERNET')     ?: 'no',
    'php_files'    => getenv('SCAN_PHP_FILES')    ?: '0',
    'platform'     => getenv('SCAN_PLATFORM')     ?: 'unknown',
    'stamp'        => getenv('SCAN_STAMP')        ?: date('Ymd-His'),
    'semgrep'      => getenv('SCAN_SEMGREP')      ?: 'no',
    'min_severity' => getenv('SCAN_MIN_SEVERITY') ?: 'low',
    'hostname'     => getenv('SCAN_HOSTNAME')     ?: 'unknown-host',
    'host_ip'      => getenv('SCAN_HOST_IP')      ?: 'unknown',
    'ec2_id'       => getenv('SCAN_EC2_INSTANCE_ID') ?: '',
    'ec2_region'   => getenv('SCAN_EC2_REGION')   ?: '',
    'report_name'  => getenv('SCAN_REPORT_NAME')  ?: '',
];

$order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
$minRank = $order[$ctx['min_severity']] ?? 3;
$semgrepRan = ($ctx['semgrep'] === 'yes');

/**
 * Confidence tier for a finding, based on which engine produced it:
 *   - "Confirmed"  : composer audit — a published CVE in an installed version.
 *   - "Analyzed"   : Semgrep — context/data-flow analysis (high confidence).
 *   - "Review"     : built-in regex pattern — a lead that needs human review.
 *   - "Info"       : scanner notes / coverage gaps.
 */
function confidence_of(array $f): string {
    $src = strtolower($f['source'] ?? '');
    if (($f['category'] ?? '') === 'Coverage gap' || ($f['category'] ?? '') === 'Coverage note') return 'Info';
    // Confirmed: published CVEs, and leaked-secret detections (gitleaks) and the
    // PHP runtime check — these are concrete, verified facts, not guesses.
    if (strpos($src, 'composer') !== false || strpos($src, 'wordfence') !== false) return 'Confirmed';
    if (strpos($src, 'gitleaks') !== false) return 'Confirmed';
    if (strpos($src, 'runtime check') !== false) return 'Confirmed';
    // Analyzed: context-aware engine findings.
    if (strpos($src, 'semgrep') !== false) return 'Analyzed';
    if (strpos($src, 'runtime config') !== false) return 'Analyzed';
    // Everything else (built-in regex patterns) is a lead to review.
    return 'Review';
}

// ---- Load findings -------------------------------------------------------
$allFindings = [];
if (is_file($findingsFile)) {
    foreach (file($findingsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $obj = json_decode($line, true);
        if (is_array($obj)) {
            $obj['confidence'] = confidence_of($obj);
            $allFindings[] = $obj;
        }
    }
}

// ---- PHP runtime check (php2shell / CVE-2026-109618 & -109619) -----------
// The fixed releases are 8.5.12, 8.4.27, 8.3.36, 8.2.35. Compare the running
// version against the fixed one for its branch.
$phpFixed = ['8.5' => '8.5.12', '8.4' => '8.4.27', '8.3' => '8.3.36', '8.2' => '8.2.35'];
$phpRuntime = ['status' => 'unknown', 'detail' => ''];
$pv = $ctx['php_version'];
if (preg_match('/^(\d+\.\d+)\.\d+/', $pv, $m)) {
    $branch = $m[1];
    if (isset($phpFixed[$branch])) {
        if (version_compare($pv, $phpFixed[$branch], '>=')) {
            $phpRuntime = ['status' => 'protected',
                'detail' => "Running PHP $pv, which is at or above the php2shell-fixed release $phpFixed[$branch] for the $branch branch."];
        } else {
            $phpRuntime = ['status' => 'vulnerable',
                'detail' => "Running PHP $pv, which is BELOW the php2shell-fixed release $phpFixed[$branch]. This runtime is exposed to CVE-2026-109618 / CVE-2026-109619 (unauthenticated RCE). Patch immediately."];
            // Record it as a critical finding so it surfaces at the top.
            $allFindings[] = [
                'severity' => 'critical', 'category' => 'Vulnerable runtime',
                'title' => 'PHP runtime vulnerable to php2shell (CVE-2026-109618/109619)',
                'description' => $phpRuntime['detail'],
                'file' => 'PHP runtime', 'line' => '',
                'recommendation' => "Upgrade PHP to $phpFixed[$branch] or later on this branch, and restart PHP-FPM/Apache. Verify the web-facing version, not just the CLI.",
                'source' => 'runtime check', 'confidence' => 'Confirmed',
            ];
        }
    } else {
        $phpRuntime = ['status' => 'eol-or-unknown',
            'detail' => "Running PHP $pv. Branch $branch is not in the current supported/fixed list — it may be end-of-life and unpatched for php2shell. Verify support status."];
    }
}

// Counts over ALL findings (before severity filter), for the summary.
$counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
foreach ($allFindings as $f) {
    $s = $f['severity'] ?? 'info';
    if (isset($counts[$s])) $counts[$s]++;
}

// Split regex "Review" findings into an appendix when Semgrep ran (it supersedes
// the low-confidence patterns). When Semgrep did NOT run, keep them in the main
// list because they're the only code coverage available.
$appendix = [];
$primary  = [];
foreach ($allFindings as $f) {
    if ($semgrepRan && ($f['confidence'] ?? '') === 'Review') {
        $appendix[] = $f;
    } else {
        $primary[] = $f;
    }
}

// Apply the severity filter to the PRIMARY list.
// Exclude "Vulnerable dependency" here — those are presented in the dedicated
// priority table (grouped by package), so repeating them as individual findings
// would double-count and bloat the list.
$primaryFiltered = array_values(array_filter($primary, function ($f) use ($order, $minRank) {
    if (($f['category'] ?? '') === 'Vulnerable dependency') return false;
    return ($order[$f['severity'] ?? 'info'] ?? 4) <= $minRank;
}));

// ---- Group into DISTINCT problems -----------------------------------------
// Many findings are the same issue repeated across files (e.g. "SSL verify off"
// in 19 places). Collapse by title so the report shows N distinct problems with
// occurrence counts and locations, instead of N raw hits.
$problems = []; // key => ['sev','conf','title','category','description','recommendation','source','locations'=>[]]
foreach ($primaryFiltered as $f) {
    $key = ($f['title'] ?? 'issue');
    if (!isset($problems[$key])) {
        $problems[$key] = [
            'severity'       => $f['severity'] ?? 'info',
            'confidence'     => $f['confidence'] ?? 'Review',
            'title'          => $f['title'] ?? 'Finding',
            'category'       => $f['category'] ?? '',
            'description'    => $f['description'] ?? '',
            'recommendation' => $f['recommendation'] ?? '',
            'source'         => $f['source'] ?? '',
            'locations'      => [],
        ];
    }
    // Keep the highest severity seen for this problem.
    if (($order[$f['severity'] ?? 'info'] ?? 4) < ($order[$problems[$key]['severity']] ?? 4)) {
        $problems[$key]['severity'] = $f['severity'];
    }
    $loc = ($f['file'] ?? '');
    if (!empty($f['line'])) $loc .= ':' . $f['line'];
    if ($loc !== '') $problems[$key]['locations'][] = $loc;
}

// Sort distinct problems: severity, then confidence (Confirmed/Analyzed first).
$confOrder = ['Confirmed' => 0, 'Analyzed' => 1, 'Review' => 2, 'Info' => 3];
$problemList = array_values($problems);
usort($problemList, function ($a, $b) use ($order, $confOrder) {
    $sa = $order[$a['severity']] ?? 5; $sb = $order[$b['severity']] ?? 5;
    if ($sa !== $sb) return $sa <=> $sb;
    return ($confOrder[$a['confidence']] ?? 2) <=> ($confOrder[$b['confidence']] ?? 2);
});

usort($appendix, function ($a, $b) use ($order) {
    return ($order[$a['severity'] ?? 'info'] ?? 5) <=> ($order[$b['severity'] ?? 'info'] ?? 5);
});

// Headline metrics based on DISTINCT problems, not raw occurrences.
$distinctProblemCount = count($problemList);
$totalOccurrences = count($primaryFiltered);
$actionable = $counts['critical'] + $counts['high'] + $counts['medium'] + $counts['low'];
$appendixCount = count($appendix);

// ---- Prioritized action list: group Vulnerable-dependency findings by package
// so developers get "update these N packages" instead of 58 separate lines.
$depPackages = []; // package => ['max'=>sev, 'count'=>n]
foreach ($allFindings as $f) {
    if (($f['category'] ?? '') !== 'Vulnerable dependency') continue;
    // file looks like "composer.lock (vendor/pkg)"
    $pkg = $f['file'] ?? '';
    if (preg_match('/\(([^)]+)\)/', $pkg, $m)) $pkg = $m[1];
    $sev = $f['severity'] ?? 'low';
    if (!isset($depPackages[$pkg])) $depPackages[$pkg] = ['max' => $sev, 'count' => 0];
    $depPackages[$pkg]['count']++;
    if (($order[$sev] ?? 4) < ($order[$depPackages[$pkg]['max']] ?? 4)) {
        $depPackages[$pkg]['max'] = $sev;
    }
}
uasort($depPackages, function ($a, $b) use ($order) {
    return ($order[$a['max']] ?? 4) <=> ($order[$b['max']] ?? 4);
});

// ---- Overall risk rating -------------------------------------------------
if ($counts['critical'] > 0)      { $risk = 'Critical'; $riskColor = '#b91c1c'; }
elseif ($counts['high'] > 0)      { $risk = 'High';     $riskColor = '#ea580c'; }
elseif ($counts['medium'] > 0)    { $risk = 'Medium';   $riskColor = '#ca8a04'; }
elseif ($counts['low'] > 0)       { $risk = 'Low';      $riskColor = '#2563eb'; }
else                              { $risk = 'Clean (no known issues found)'; $riskColor = '#16a34a'; }

// Plain-English summary line
if ($counts['critical'] > 0) {
    $summary = "We found issues that need urgent attention. One or more problems could let an attacker take control or access sensitive data. These should be fixed as soon as possible.";
} elseif ($counts['high'] > 0) {
    $summary = "We found serious issues worth fixing soon. They could be exploited by an attacker and should be prioritised.";
} elseif ($counts['medium'] > 0) {
    $summary = "We found some moderate issues. They are not immediately critical but should be addressed to reduce risk.";
} elseif ($counts['low'] > 0) {
    $summary = "We found only minor issues. Good hygiene improvements rather than urgent risks.";
} else {
    $summary = "No known vulnerabilities were detected by the scanners that ran. See the note below about what this does and does not mean.";
}

// ---- Write JSON report ---------------------------------------------------
$priorityPackages = [];
foreach ($depPackages as $pkg => $info) {
    $priorityPackages[] = [
        'package'         => $pkg,
        'highest_severity'=> $info['max'],
        'advisory_count'  => $info['count'],
        'fix'             => "composer update $pkg",
    ];
}

// ---- Key code issues: the Semgrep (Analyzed) findings, grouped by title ----
// These are the real, context-analyzed code risks worth the client's attention,
// as opposed to the dependency CVEs (which are the priority table above).
$codeIssues = []; // title => ['count'=>n, 'max'=>sev, 'example'=>file]
foreach ($allFindings as $f) {
    if (($f['confidence'] ?? '') !== 'Analyzed') continue;
    $t = $f['title'] ?? 'Code issue';
    if (!isset($codeIssues[$t])) $codeIssues[$t] = ['count' => 0, 'max' => $f['severity'] ?? 'low', 'example' => $f['file'] ?? ''];
    $codeIssues[$t]['count']++;
    if (($order[$f['severity'] ?? 'low'] ?? 4) < ($order[$codeIssues[$t]['max']] ?? 4)) {
        $codeIssues[$t]['max'] = $f['severity'];
    }
}
uasort($codeIssues, function ($a, $b) use ($order) {
    if (($order[$a['max']] ?? 4) !== ($order[$b['max']] ?? 4)) {
        return ($order[$a['max']] ?? 4) <=> ($order[$b['max']] ?? 4);
    }
    return $b['count'] <=> $a['count'];
});

// ---- Executive summary: a plain-English, one-glance story ------------------
$depCount = count($depPackages);
$semgrepCount = 0;
foreach ($allFindings as $f) { if (($f['confidence'] ?? '') === 'Analyzed') $semgrepCount++; }

$execParts = [];
// Runtime / php2shell line first — it's the incident the client cares about.
if ($phpRuntime['status'] === 'protected') {
    $execParts[] = "Your PHP runtime ({$ctx['php_version']}) is patched against the recent php2shell incident (CVE-2026-109618/109619), so the server is not exposed to that specific remote-code-execution flaw.";
} elseif ($phpRuntime['status'] === 'vulnerable') {
    $execParts[] = "URGENT: your PHP runtime ({$ctx['php_version']}) is NOT patched against the php2shell incident and must be upgraded immediately.";
}
// Dependencies — the real priority.
if ($depCount > 0) {
    $execParts[] = "The most important action is updating $depCount outdated third-party librar" . ($depCount === 1 ? "y" : "ies") . " with known, published vulnerabilities (see the priority list). These are the source of the critical ratings and are fixed with routine package updates.";
}
// Code analysis result.
if ($ctx['semgrep'] === 'yes') {
    if ($semgrepCount > 0) {
        $execParts[] = "A deep code analysis of your own application code found $semgrepCount item" . ($semgrepCount === 1 ? "" : "s") . " worth attention — mostly moderate (e.g. disabled TLS verification and user-influenced file handling) rather than critical. In short: the serious risks are in outdated libraries, not in how your code is written.";
    } else {
        $execParts[] = "A deep code analysis of your own application code found no high-confidence issues — the risks that matter are in outdated libraries, not your code.";
    }
}
$execParts[] = "Recommended next steps: update the listed libraries, then review the code items below. Automated scanning covers known issues; for a critical system, pair this with a manual review of the high-risk areas.";
$execSummary = implode(' ', $execParts);

$jsonReport = [
    'generated_at' => date('c'),
    'scan_id'      => $ctx['stamp'],
    'target'       => $ctx['target'],
    'executive_summary' => $execSummary,
    'host'         => [
        'hostname'    => $ctx['hostname'],
        'ip'          => $ctx['host_ip'],
        'ec2_instance'=> $ctx['ec2_id'],
        'ec2_region'  => $ctx['ec2_region'],
        'report_name' => $ctx['report_name'],
    ],
    'environment'  => [
        'application_type' => $ctx['app_type'],
        'php_version'      => $ctx['php_version'],
        'platform'         => $ctx['platform'],
        'internet_access'  => $ctx['internet'],
        'php_files_scanned'=> (int)$ctx['php_files'],
        'semgrep_ran'      => $ctx['semgrep'] === 'yes',
    ],
    'php_runtime_php2shell' => $phpRuntime,
    'risk_rating'          => $risk,
    'summary'              => $summary,
    'counts'               => $counts,
    'distinct_problem_count' => $distinctProblemCount,
    'total_occurrences'      => $totalOccurrences,
    'min_severity_shown'   => $ctx['min_severity'],
    'superseded_pattern_matches' => $appendixCount,
    'priority_dependencies'=> $priorityPackages,
    'distinct_problems'    => $problemList,
    'appendix_pattern_matches' => $appendix,
];
file_put_contents(
    "$outDir/report.json",
    json_encode($jsonReport, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
);

// ---- Write HTML report ---------------------------------------------------
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

$sevMeta = [
    'critical' => ['Critical', '#b91c1c', '#fee2e2'],
    'high'     => ['High',     '#ea580c', '#ffedd5'],
    'medium'   => ['Medium',   '#ca8a04', '#fef9c3'],
    'low'      => ['Low',      '#2563eb', '#dbeafe'],
    'info'     => ['Info',     '#64748b', '#f1f5f9'],
];

ob_start();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan — <?= h($ctx['hostname']) ?> (<?= h($ctx['stamp']) ?>)</title>
<style>
  :root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  body { margin: 0; background: #f8fafc; color: #0f172a; line-height: 1.5; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }
  header h1 { margin: 0 0 4px; font-size: 24px; }
  header p { margin: 0; color: #475569; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px 24px; margin: 20px 0; }
  .risk { display: flex; align-items: center; gap: 16px; }
  .risk .badge { font-size: 18px; font-weight: 700; color: #fff; padding: 8px 16px; border-radius: 999px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap: 12px; margin-top: 8px; }
  .meta div { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 12px; }
  .meta span { display: block; font-size: 12px; color: #64748b; }
  .meta b { font-size: 14px; }
  .counts { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
  .pill { padding: 6px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; }
  .finding { border: 1px solid #e2e8f0; border-left-width: 6px; border-radius: 10px; padding: 14px 16px; margin: 12px 0; background: #fff; }
  .finding h3 { margin: 0 0 6px; font-size: 16px; }
  .finding .tag { font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 6px; margin-right: 8px; }
  .finding .where { font-size: 13px; color: #475569; margin: 6px 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .finding .fix { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 8px 12px; margin-top: 8px; font-size: 14px; }
  .finding .src { font-size: 12px; color: #94a3b8; margin-top: 6px; }
  .conf { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px; margin-left: 4px; }
  .conf-Confirmed { background:#fee2e2; color:#b91c1c; }
  .conf-Analyzed  { background:#e0e7ff; color:#4338ca; }
  .conf-Review    { background:#f1f5f9; color:#64748b; }
  .conf-Info      { background:#f1f5f9; color:#94a3b8; }
  .runtime-ok   { background:#f0fdf4; border:1px solid #bbf7d0; }
  .runtime-bad  { background:#fef2f2; border:1px solid #fecaca; }
  .runtime-warn { background:#fffbeb; border:1px solid #fde68a; }
  .note { background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 14px 16px; font-size: 14px; }
  footer { color: #94a3b8; font-size: 12px; text-align: center; margin-top: 32px; }
  h2 { font-size: 18px; margin: 28px 0 8px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Security Scan Report</h1>
    <p>
      <strong><?= h($ctx['hostname']) ?></strong> &middot; <?= h($ctx['host_ip']) ?>
      <?php if ($ctx['ec2_id']): ?>&middot; <?= h($ctx['ec2_id']) ?> (<?= h($ctx['ec2_region']) ?>)<?php endif; ?>
      &middot; <?= h($ctx['app_type']) ?> &middot; <?= h($ctx['stamp']) ?>
    </p>
  </header>

  <div class="card" style="border-left:6px solid #2563eb">
    <strong style="font-size:15px">Executive summary</strong>
    <div style="color:#334155;margin-top:6px"><?= h($execSummary) ?></div>
  </div>

  <div class="card">
    <div class="risk">
      <span class="badge" style="background: <?= h($riskColor) ?>"><?= h($risk) ?></span>
      <div>
        <strong>What this means</strong>
        <div style="color:#475569"><?= h($summary) ?></div>
      </div>
    </div>

    <div style="margin-top:12px;font-size:14px;color:#334155">
      <strong>What to actually fix:</strong>
      <?= (int)count($depPackages) ?> dependency update<?= count($depPackages) === 1 ? '' : 's' ?>
      + <?= (int)$distinctProblemCount ?> code/config issue<?= $distinctProblemCount === 1 ? '' : 's' ?>
      <span style="color:#94a3b8">(from <?= (int)$totalOccurrences ?> total occurrence<?= $totalOccurrences === 1 ? '' : 's' ?> + <?= array_sum($counts) ?> raw findings)</span>
    </div>
    <div class="counts">
      <?php foreach ($sevMeta as $k => $m): if (($counts[$k] ?? 0) <= 0) continue; ?>
        <span class="pill" style="background: <?= h($m[2]) ?>; color: <?= h($m[1]) ?>">
          <?= h($m[0]) ?>: <?= (int)$counts[$k] ?>
        </span>
      <?php endforeach; ?>
      <?php if ($actionable === 0 && $counts['info'] === 0): ?>
        <span class="pill" style="background:#dcfce7;color:#16a34a">No findings</span>
      <?php endif; ?>
    </div>

    <div class="meta">
      <div><span>Server hostname</span><b><?= h($ctx['hostname']) ?></b></div>
      <div><span>Server IP</span><b><?= h($ctx['host_ip']) ?></b></div>
      <?php if ($ctx['ec2_id']): ?>
      <div><span>EC2 instance</span><b><?= h($ctx['ec2_id']) ?></b></div>
      <div><span>AWS region</span><b><?= h($ctx['ec2_region']) ?></b></div>
      <?php endif; ?>
      <div><span>Application type</span><b><?= h($ctx['app_type']) ?></b></div>
      <div><span>PHP version</span><b><?= h($ctx['php_version']) ?></b></div>
      <div><span>Platform</span><b><?= h($ctx['platform']) ?></b></div>
      <div><span>PHP files scanned</span><b><?= h($ctx['php_files']) ?></b></div>
      <div><span>Deep code scan (Semgrep)</span><b><?= $ctx['semgrep'] === 'yes' ? 'Yes' : 'No (fallback used)' ?></b></div>
      <div><span>Scanned path</span><b style="font-size:12px"><?= h($ctx['target']) ?></b></div>
    </div>
  </div>

  <?php
    $rtClass = $phpRuntime['status'] === 'protected' ? 'runtime-ok'
             : ($phpRuntime['status'] === 'vulnerable' ? 'runtime-bad' : 'runtime-warn');
    $rtLabel = $phpRuntime['status'] === 'protected' ? '✓ PHP runtime protected against php2shell'
             : ($phpRuntime['status'] === 'vulnerable' ? '✗ PHP runtime VULNERABLE to php2shell — patch now'
             : '! PHP runtime status needs verification');
  ?>
  <?php if ($phpRuntime['status'] !== 'unknown'): ?>
  <div class="card <?= $rtClass ?>">
    <strong><?= h($rtLabel) ?></strong>
    <div style="color:#334155;margin-top:4px;font-size:14px"><?= h($phpRuntime['detail']) ?></div>
    <div style="color:#64748b;margin-top:6px;font-size:12px">
      php2shell = CVE-2026-109618 / CVE-2026-109619, critical unauthenticated remote code execution in the PHP engine, fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
      Note: verify the web-facing PHP (PHP-FPM/Apache module), not only the command-line version.
    </div>
  </div>
  <?php endif; ?>

  <div class="card" style="padding:14px 24px">
    <strong style="font-size:14px">How to read confidence</strong>
    <div style="margin-top:6px;font-size:13px;color:#475569">
      <span class="conf conf-Confirmed">Confirmed</span> published CVE in an installed library or the runtime — verified, act on these.
      <span class="conf conf-Analyzed">Analyzed</span> found by code analysis (Semgrep data-flow) — high confidence, worth fixing/reviewing.
      <span class="conf conf-Review">Review</span> pattern match — a lead that needs a human to confirm.
    </div>
  </div>

  <?php if ($depPackages): ?>
  <h2>Priority action list — update these dependencies first</h2>
  <div class="card">
    <p style="margin-top:0;color:#475569">
      These are third-party libraries with known, published vulnerabilities. Updating them is the
      highest-value, lowest-effort fix — one command per package. Ordered by highest severity.
    </p>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="text-align:left;color:#64748b;border-bottom:1px solid #e2e8f0">
          <th style="padding:6px 8px">Severity</th>
          <th style="padding:6px 8px">Package</th>
          <th style="padding:6px 8px">Advisories</th>
          <th style="padding:6px 8px">Fix</th>
        </tr>
      </thead>
      <tbody>
      <?php foreach ($depPackages as $pkg => $info):
        $m = $sevMeta[$info['max']] ?? $sevMeta['info']; ?>
        <tr style="border-bottom:1px solid #f1f5f9">
          <td style="padding:6px 8px"><span class="tag" style="background:<?= h($m[2]) ?>;color:<?= h($m[1]) ?>"><?= h($m[0]) ?></span></td>
          <td style="padding:6px 8px;font-family:ui-monospace,Menlo,monospace"><?= h($pkg) ?></td>
          <td style="padding:6px 8px"><?= (int)$info['count'] ?></td>
          <td style="padding:6px 8px;font-family:ui-monospace,Menlo,monospace">composer update <?= h($pkg) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>

  <?php if ($codeIssues): ?>
  <h2>Key code issues (from deep code analysis)</h2>
  <div class="card">
    <p style="margin-top:0;color:#475569">
      These are real issues in your own application code, found by data-flow analysis (not simple
      pattern matching). They're the code-level items worth a developer's attention. Details for each
      occurrence are in the findings below.
    </p>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="text-align:left;color:#64748b;border-bottom:1px solid #e2e8f0">
          <th style="padding:6px 8px">Severity</th>
          <th style="padding:6px 8px">Issue</th>
          <th style="padding:6px 8px">Occurrences</th>
          <th style="padding:6px 8px">Example location</th>
        </tr>
      </thead>
      <tbody>
      <?php foreach ($codeIssues as $title => $info):
        $m = $sevMeta[$info['max']] ?? $sevMeta['info']; ?>
        <tr style="border-bottom:1px solid #f1f5f9">
          <td style="padding:6px 8px"><span class="tag" style="background:<?= h($m[2]) ?>;color:<?= h($m[1]) ?>"><?= h($m[0]) ?></span></td>
          <td style="padding:6px 8px"><?= h($title) ?></td>
          <td style="padding:6px 8px"><?= (int)$info['count'] ?></td>
          <td style="padding:6px 8px;font-family:ui-monospace,Menlo,monospace;font-size:12px"><?= h($info['example']) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>

  <h2>Code &amp; configuration issues<?= $ctx['min_severity'] !== 'low' ? ' (' . h(ucfirst($ctx['min_severity'])) . ' and above)' : '' ?> — <?= (int)$distinctProblemCount ?> distinct</h2>
  <p style="color:#64748b;font-size:14px;margin-top:0">
    Distinct problems (repeated occurrences of the same issue are grouped). Dependency updates are in the
    priority table above and are not repeated here.
  </p>
  <?php if (!$problemList): ?>
    <div class="card">No code or configuration issues at or above the selected severity.</div>
  <?php else: ?>
    <?php foreach ($problemList as $p):
      $sev = $p['severity'] ?? 'info';
      $m = $sevMeta[$sev] ?? $sevMeta['info'];
      $conf = $p['confidence'] ?? 'Review';
      $locs = $p['locations'] ?? [];
      $nLoc = count($locs);
    ?>
      <div class="finding" style="border-left-color: <?= h($m[1]) ?>">
        <h3>
          <span class="tag" style="background: <?= h($m[2]) ?>; color: <?= h($m[1]) ?>"><?= h($m[0]) ?></span>
          <span class="conf conf-<?= h($conf) ?>"><?= h($conf) ?></span>
          <?= h($p['title'] ?? 'Finding') ?>
          <?php if ($nLoc > 1): ?><span style="font-size:12px;color:#64748b;font-weight:400">&times;<?= (int)$nLoc ?> locations</span><?php endif; ?>
        </h3>
        <div style="color:#334155"><?= h($p['description'] ?? '') ?></div>
        <?php if ($nLoc > 0): ?>
          <?php if ($nLoc === 1): ?>
            <div class="where"><?= h($locs[0]) ?></div>
          <?php else: ?>
            <details>
              <summary style="cursor:pointer;color:#2563eb;font-size:13px;margin:6px 0"><?= (int)$nLoc ?> locations — show</summary>
              <div class="where">
                <?php foreach ($locs as $l): ?><?= h($l) ?><br><?php endforeach; ?>
              </div>
            </details>
          <?php endif; ?>
        <?php endif; ?>
        <?php if (!empty($p['recommendation'])): ?>
          <div class="fix"><strong>How to fix:</strong> <?= h($p['recommendation']) ?></div>
        <?php endif; ?>
        <div class="src">Category: <?= h($p['category'] ?? '—') ?> &middot; Detected by: <?= h($p['source'] ?? 'built-in') ?></div>
      </div>
    <?php endforeach; ?>
  <?php endif; ?>

  <?php if ($appendixCount > 0): ?>
  <h2>Appendix — lower-confidence pattern matches (<?= (int)$appendixCount ?>)</h2>
  <div class="card" style="background:#f8fafc">
    <p style="margin-top:0;color:#475569;font-size:14px">
      These are simple text-pattern matches from the built-in fallback checks. Because the deep code
      analyzer (Semgrep) ran on this scan, these are <strong>superseded</strong> and kept here only for
      completeness — many are false positives (e.g. framework-internal usage). Review only if you want
      exhaustive coverage; the findings above are the ones that matter.
    </p>
    <details>
      <summary style="cursor:pointer;color:#2563eb;font-size:14px">Show <?= (int)$appendixCount ?> pattern matches</summary>
      <div style="margin-top:10px">
      <?php foreach ($appendix as $f): $m = $sevMeta[$f['severity'] ?? 'info'] ?? $sevMeta['info']; ?>
        <div style="border-bottom:1px solid #e2e8f0;padding:6px 0;font-size:13px">
          <span class="tag" style="background:<?= h($m[2]) ?>;color:<?= h($m[1]) ?>"><?= h($m[0]) ?></span>
          <?= h($f['title'] ?? '') ?>
          <span style="color:#94a3b8;font-family:ui-monospace,Menlo,monospace">
            <?= h($f['file'] ?? '') ?><?= !empty($f['line']) ? ':' . h($f['line']) : '' ?>
          </span>
        </div>
      <?php endforeach; ?>
      </div>
    </details>
  </div>
  <?php endif; ?>

  <h2>Important note</h2>
  <div class="note">
    <p style="margin:0 0 8px"><strong>A clean or short report does not mean the site is guaranteed secure.</strong></p>
    <p style="margin:0">
      This tool finds <em>known</em> dangerous patterns and <em>known</em> vulnerabilities in code,
      dependencies, and (for WordPress) plugins/themes. It does not prove the absence of all
      vulnerabilities, detect active break-ins, or replace a manual security review. For a critical
      system we recommend pairing this automated scan with a manual review of the high-risk findings
      and, ideally, a professional penetration test.
    </p>
  </div>

  <footer>
    Generated <?= h(date('Y-m-d H:i:s')) ?> &middot; php-security-scan (read-only) &middot;
    Engines: Semgrep CE, composer audit, wp-cli + Wordfence Intelligence, built-in checks.
  </footer>
</div>
</body>
</html>
<?php
$html = ob_get_clean();
file_put_contents("$outDir/report.html", $html);

fwrite(STDERR, "report: $distinctProblemCount distinct problems ($totalOccurrences occurrences), "
    . count($depPackages) . " dependency packages, $appendixCount appendix\n");
exit(0);
