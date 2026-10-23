<?php
/**
 * parse_composer.php — convert `composer audit --format=json` into our
 * normalized findings schema (one JSON object per line).
 *
 * Usage: php parse_composer.php <composer-audit.json>   (prints JSONL to stdout)
 *
 * composer audit JSON shape (relevant part):
 *   { "advisories": { "<package>": [ { title, cve, link, severity,
 *                                      affectedVersions, ... }, ... ] } }
 */

if ($argc < 2) {
    fwrite(STDERR, "usage: parse_composer.php <composer-audit.json>\n");
    exit(2);
}

$raw = @file_get_contents($argv[1]);
if ($raw === false || $raw === '') exit(0);

$data = json_decode($raw, true);
if (!is_array($data) || empty($data['advisories']) || !is_array($data['advisories'])) {
    exit(0);
}

function norm_sev($s): string {
    $s = strtolower((string)$s);
    if (in_array($s, ['critical', 'high', 'medium', 'low'], true)) return $s;
    // composer sometimes omits severity; default to high so it isn't ignored.
    return 'high';
}

function jstr($v): string {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

$count = 0;
foreach ($data['advisories'] as $package => $advisories) {
    if (!is_array($advisories)) continue;
    foreach ($advisories as $adv) {
        if (!is_array($adv)) continue;
        $count++;

        $sev   = norm_sev($adv['severity'] ?? '');
        $title = (string)($adv['title'] ?? 'Known vulnerability');
        $cve   = (string)($adv['cve'] ?? '');
        $link  = (string)($adv['link'] ?? '');
        $affected = (string)($adv['affectedVersions'] ?? '');

        $desc = "The installed library \"$package\" has a known security vulnerability. "
              . "In plain terms: this is third-party code the app depends on, and this "
              . "version has a publicly documented flaw that attackers already understand. "
              . ($cve ? "Reference: $cve. " : '')
              . ($affected ? "Affected versions: $affected. " : '')
              . "Issue: $title";

        $rec = "Update \"$package\" to a patched version with: composer update $package"
             . ($link ? " — details: $link" : '');

        echo '{'
            . '"severity":'       . jstr($sev)   . ','
            . '"category":'       . jstr('Vulnerable dependency') . ','
            . '"title":'          . jstr($package . ' — ' . $title) . ','
            . '"description":'    . jstr($desc)  . ','
            . '"file":'           . jstr('composer.lock (' . $package . ')') . ','
            . '"line":'           . jstr('')     . ','
            . '"recommendation":' . jstr($rec)   . ','
            . '"source":'         . jstr('composer audit')
            . "}\n";
    }
}

fwrite(STDERR, "composer advisories parsed: $count\n");
exit(0);
