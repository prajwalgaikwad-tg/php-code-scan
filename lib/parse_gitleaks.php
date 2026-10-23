<?php
/**
 * parse_gitleaks.php — convert gitleaks JSON output into our normalized
 * findings schema (one JSON object per line).
 *
 * Usage: php parse_gitleaks.php <gitleaks.json> <target-dir>
 *
 * gitleaks JSON is an array of objects with keys like:
 *   RuleID, Description, File, StartLine, Secret, Match, ...
 * We never print the secret value itself — only its location and rule.
 */

if ($argc < 2) {
    fwrite(STDERR, "usage: parse_gitleaks.php <gitleaks.json> [target]\n");
    exit(2);
}

$raw = @file_get_contents($argv[1]);
if ($raw === false || $raw === '') exit(0);
$target = rtrim($argv[2] ?? '', '/');

$data = json_decode($raw, true);
if (!is_array($data)) exit(0);

function jstr($v): string {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

$count = 0;
foreach ($data as $hit) {
    if (!is_array($hit)) continue;
    $count++;

    $rule = (string)($hit['RuleID'] ?? ($hit['Description'] ?? 'secret'));
    $desc = (string)($hit['Description'] ?? 'A hardcoded secret or credential was detected.');
    $file = (string)($hit['File'] ?? '');
    if ($target && strpos($file, $target) === 0) $file = ltrim(substr($file, strlen($target)), '/');
    $line = (string)($hit['StartLine'] ?? '');

    // Severity by rule type: concrete credential formats are critical; the
    // broad "generic-api-key" rule is noisier, so mark it medium/needs-review.
    $r = strtolower($rule);
    if (strpos($r, 'generic') !== false) {
        $sev = 'medium';
    } elseif (strpos($r, 'private-key') !== false || strpos($r, 'aws') !== false
           || strpos($r, 'azure') !== false || strpos($r, 'gcp') !== false
           || strpos($r, 'rsa') !== false || strpos($r, 'ssh') !== false) {
        $sev = 'critical';
    } else {
        $sev = 'high';
    }
    // Secrets in an .env / backup / config file are especially serious.
    if (preg_match('/\.env(\.|_|$)|\.env_bkp|config\.php$/i', $file) && $sev === 'medium') {
        $sev = 'high';
    }

    // Deliberately do NOT include the secret value in the report.
    $full = "A hardcoded secret/credential was detected ($rule). In plain terms: a password, API key, "
          . "or token appears to be written directly into a file. If this file is ever exposed (backup, "
          . "repo leak, misconfigured server), the secret is compromised. Detail: $desc";

    echo '{'
        . '"severity":'       . jstr($sev) . ','
        . '"category":'       . jstr('Hardcoded secret') . ','
        . '"title":'          . jstr('Hardcoded secret: ' . $rule) . ','
        . '"description":'    . jstr($full) . ','
        . '"file":'           . jstr($file) . ','
        . '"line":'           . jstr($line) . ','
        . '"recommendation":' . jstr('Remove the secret from the code, rotate it immediately (assume it is compromised), and load it from an environment variable or a secrets manager instead.') . ','
        . '"source":'         . jstr('gitleaks')
        . "}\n";
}

fwrite(STDERR, "gitleaks findings parsed: $count\n");
exit(0);
