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

    // Deliberately do NOT include the secret value in the report.
    $full = "A hardcoded secret/credential was detected ($rule). In plain terms: a password, API key, "
          . "or token appears to be written directly into a file. If this file is ever exposed (backup, "
          . "repo leak, misconfigured server), the secret is compromised. Detail: $desc";

    echo '{'
        . '"severity":'       . jstr('high') . ','
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
