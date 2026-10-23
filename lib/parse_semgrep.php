<?php
/**
 * parse_semgrep.php — convert Semgrep JSON output into our normalized
 * findings schema (one JSON object per line, appended to findings.jsonl).
 *
 * Usage: php parse_semgrep.php /path/to/semgrep.json   (prints JSONL to stdout)
 */

if ($argc < 2) {
    fwrite(STDERR, "usage: parse_semgrep.php <semgrep.json>\n");
    exit(2);
}

$file = $argv[1];
$raw  = @file_get_contents($file);
if ($raw === false || $raw === '') {
    fwrite(STDERR, "cannot read semgrep json: $file\n");
    exit(1);
}

$data = json_decode($raw, true);
if (!is_array($data) || !isset($data['results']) || !is_array($data['results'])) {
    // No results key — nothing to add, not an error.
    exit(0);
}

/** Map Semgrep severity to our scale. */
function map_severity(array $result): string {
    $extra = $result['extra'] ?? [];
    // Prefer the explicit security severity if present.
    $meta = $extra['metadata'] ?? [];
    $impact = strtolower((string)($meta['impact'] ?? ''));
    if ($impact === 'high')   return 'high';
    if ($impact === 'medium') return 'medium';
    if ($impact === 'low')    return 'low';

    switch (strtoupper((string)($extra['severity'] ?? ''))) {
        case 'ERROR':   return 'high';
        case 'WARNING': return 'medium';
        case 'INFO':    return 'low';
        default:        return 'medium';
    }
}

/** Derive a human category from the rule metadata/id. */
function category(array $result): string {
    $meta = $result['extra']['metadata'] ?? [];
    if (!empty($meta['category'])) return ucfirst((string)$meta['category']);
    if (!empty($meta['owasp'])) {
        $o = is_array($meta['owasp']) ? implode(', ', $meta['owasp']) : (string)$meta['owasp'];
        return 'OWASP: ' . $o;
    }
    if (!empty($meta['cwe'])) {
        $c = is_array($meta['cwe']) ? ($meta['cwe'][0] ?? '') : $meta['cwe'];
        return (string)$c;
    }
    return 'Code issue';
}

function jstr($v): string {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

foreach ($data['results'] as $r) {
    if (!is_array($r)) continue;

    $sev   = map_severity($r);
    $cat   = category($r);
    $ruleId = (string)($r['check_id'] ?? 'semgrep.rule');
    $title = $ruleId;
    // A shorter title: last dotted segment, humanised.
    $parts = explode('.', $ruleId);
    if (count($parts)) {
        $title = str_replace(['-', '_'], ' ', end($parts));
        $title = ucfirst($title);
    }

    $extra = $r['extra'] ?? [];
    $desc  = trim((string)($extra['message'] ?? 'Semgrep flagged a potential security issue.'));
    $fix   = (string)($extra['fix'] ?? '');
    $meta  = $extra['metadata'] ?? [];
    $ref   = '';
    if (!empty($meta['references'])) {
        $refs = is_array($meta['references']) ? $meta['references'] : [$meta['references']];
        $ref  = $refs[0] ?? '';
    }

    $rec = $fix !== '' ? "Suggested fix: $fix" : 'Review this location and apply the secure pattern.';
    if ($ref !== '') $rec .= " Reference: $ref";

    $path = (string)($r['path'] ?? '');
    $line = '';
    if (isset($r['start']['line'])) $line = (string)$r['start']['line'];

    echo '{'
        . '"severity":'       . jstr($sev)   . ','
        . '"category":'       . jstr($cat)   . ','
        . '"title":'          . jstr($title) . ','
        . '"description":'    . jstr($desc)  . ','
        . '"file":'           . jstr($path)  . ','
        . '"line":'           . jstr($line)  . ','
        . '"recommendation":' . jstr($rec)   . ','
        . '"source":'         . jstr('Semgrep')
        . "}\n";
}

exit(0);
