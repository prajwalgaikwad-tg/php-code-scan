<?php
/**
 * match_wordfence.php — match installed WordPress plugins/themes/core against
 * the Wordfence Intelligence vulnerability feed, emitting normalized findings.
 *
 * Usage: php match_wordfence.php <wordfence-feed.json> <raw-dir>
 *   reads <raw-dir>/wp-plugins.csv, wp-themes.csv, wp-core-version.txt
 *   (and wp-core-fallback.csv) produced by scan.sh.
 *   prints JSONL findings to stdout.
 *
 * The Wordfence "scanner" feed is a JSON object keyed by vulnerability id.
 * Each entry contains "software" entries describing affected slugs and the
 * affected version ranges. We do a conservative version-range match.
 */

if ($argc < 3) {
    fwrite(STDERR, "usage: match_wordfence.php <feed.json> <raw-dir>\n");
    exit(2);
}

$feedPath = $argv[1];
$rawDir   = rtrim($argv[2], '/');

$feedRaw = @file_get_contents($feedPath);
if ($feedRaw === false || $feedRaw === '') {
    fwrite(STDERR, "cannot read feed: $feedPath\n");
    exit(1);
}
$feed = json_decode($feedRaw, true);
if (!is_array($feed)) {
    fwrite(STDERR, "feed is not valid JSON\n");
    exit(1);
}

/** Read a wp-cli CSV (name,status,version) into [slug => version]. */
function read_csv_versions(string $path): array {
    $out = [];
    if (!is_file($path)) return $out;
    $fh = fopen($path, 'r');
    if (!$fh) return $out;
    $header = fgetcsv($fh);
    if (!$header) { fclose($fh); return $out; }
    $idx = array_flip(array_map('strtolower', $header));
    while (($row = fgetcsv($fh)) !== false) {
        $name = $row[$idx['name'] ?? 0] ?? '';
        $ver  = $row[$idx['version'] ?? 2] ?? '';
        if ($name !== '') $out[strtolower($name)] = $ver;
    }
    fclose($fh);
    return $out;
}

$plugins = read_csv_versions("$rawDir/wp-plugins.csv");
$themes  = read_csv_versions("$rawDir/wp-themes.csv");

$coreVersion = '';
if (is_file("$rawDir/wp-core-version.txt")) {
    $coreVersion = trim((string)@file_get_contents("$rawDir/wp-core-version.txt"));
}
if ($coreVersion === '' && is_file("$rawDir/wp-core-fallback.csv")) {
    $c = read_csv_versions("$rawDir/wp-core-fallback.csv");
    $coreVersion = $c['wordpress-core'] ?? '';
}

/**
 * Decide whether $version falls within a Wordfence affected range.
 * A range has from_version/from_inclusive and to_version/to_inclusive.
 * "*" means unbounded.
 */
function in_range(string $version, array $range): bool {
    if ($version === '') return false;
    $from = $range['from_version'] ?? '*';
    $to   = $range['to_version']   ?? '*';
    $fi   = !empty($range['from_inclusive']);
    $ti   = !empty($range['to_inclusive']);

    if ($from !== '*') {
        $cmp = version_compare($version, $from);
        if ($cmp < 0) return false;
        if ($cmp === 0 && !$fi) return false;
    }
    if ($to !== '*') {
        $cmp = version_compare($version, $to);
        if ($cmp > 0) return false;
        if ($cmp === 0 && !$ti) return false;
    }
    return true;
}

function jstr($v): string {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function cvss_to_sev($score): string {
    $s = (float)$score;
    if ($s >= 9.0) return 'critical';
    if ($s >= 7.0) return 'high';
    if ($s >= 4.0) return 'medium';
    if ($s >  0.0) return 'low';
    return 'medium';
}

function emit(string $sev, string $cat, string $title, string $desc, string $file, string $rec): void {
    echo '{'
        . '"severity":'       . jstr($sev)   . ','
        . '"category":'       . jstr($cat)   . ','
        . '"title":'          . jstr($title) . ','
        . '"description":'    . jstr($desc)  . ','
        . '"file":'           . jstr($file)  . ','
        . '"line":'           . jstr('')     . ','
        . '"recommendation":' . jstr($rec)   . ','
        . '"source":'         . jstr('Wordfence Intelligence')
        . "}\n";
}

$matches = 0;

foreach ($feed as $vulnId => $vuln) {
    if (!is_array($vuln)) continue;

    $title = (string)($vuln['title'] ?? $vulnId);
    $cvss  = $vuln['cvss']['score'] ?? ($vuln['cvss']['rating'] ?? 0);
    $sev   = cvss_to_sev(is_numeric($cvss) ? $cvss : 0);

    $cve = '';
    if (!empty($vuln['cve'])) {
        $cve = is_array($vuln['cve']) ? ($vuln['cve'][0] ?? '') : (string)$vuln['cve'];
    }

    $software = $vuln['software'] ?? [];
    if (!is_array($software)) continue;

    foreach ($software as $sw) {
        if (!is_array($sw)) continue;
        $type = strtolower((string)($sw['type'] ?? ''));   // plugin / theme / core
        $slug = strtolower((string)($sw['slug'] ?? ''));
        if ($slug === '') continue;

        // Pick the installed version for this software, if present.
        $installed = '';
        $where = '';
        if ($type === 'plugin' && isset($plugins[$slug])) { $installed = $plugins[$slug]; $where = "plugin: $slug"; }
        elseif ($type === 'theme' && isset($themes[$slug])) { $installed = $themes[$slug]; $where = "theme: $slug"; }
        elseif ($type === 'core') { $installed = $coreVersion; $where = 'WordPress core'; }
        else continue;

        if ($installed === '') continue;

        $affected = $sw['affected_versions'] ?? [];
        if (!is_array($affected)) continue;

        $hit = false;
        $fixedIn = '';
        foreach ($affected as $range) {
            if (!is_array($range)) continue;
            if (in_range($installed, $range)) {
                $hit = true;
                // Wordfence often lists the fix as to_version + next; keep a hint.
                if (!empty($sw['remediation'])) $fixedIn = (string)$sw['remediation'];
                break;
            }
        }

        if ($hit) {
            $matches++;
            $desc = "A known vulnerability affects $where (installed version $installed). "
                  . "Attackers can target sites running this version. "
                  . ($cve ? "Reference: $cve. " : '')
                  . "Vulnerability: $title";
            $rec  = $fixedIn !== ''
                  ? "Update to a fixed version: $fixedIn."
                  : "Update this component to the latest available version, or remove it if unused.";
            emit($sev, 'WordPress vulnerable component', $title, $desc, $where, $rec);
        }
    }
}

fwrite(STDERR, "wordfence matches: $matches\n");
exit(0);
