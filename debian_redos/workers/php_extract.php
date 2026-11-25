<?php
// Extracts preg_* pattern arguments from PHP sources using token_get_all.
//
// Usage: php php_extract.php path/to/file.php < path/to/file.php
// Prints JSON: {"ok":true,"regexes":[{line,function,pattern,raw_pattern,flags,
//                                    source_type,input_expr,notes}]}
//
// The scanner only resolves values that are genuinely constant in the file:
// string literals, concatenations of literals, and variables assigned exactly
// once to such a value.  Everything else is reported as an unresolved dynamic
// pattern instead of being dropped.

$sinks = [
    'preg_match' => [0, 1],
    'preg_match_all' => [0, 1],
    'preg_replace' => [0, 2],
    'preg_replace_callback' => [0, 2],
    'preg_filter' => [0, 2],
    'preg_split' => [0, 1],
    'preg_grep' => [0, 1],
];

$src = stream_get_contents(STDIN);
$tokens = @token_get_all($src);
$count = count($tokens);
$results = [];
$seen = [];

function is_trivia($token): bool
{
    return is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
}

function next_sig(array $tokens, int $i): ?int
{
    $n = count($tokens);
    for (; $i < $n; $i++) {
        if (!is_trivia($tokens[$i])) {
            return $i;
        }
    }
    return null;
}

function token_text($token): string
{
    return is_array($token) ? $token[1] : $token;
}

function unquote(string $raw): ?string
{
    if (strlen($raw) < 2) {
        return null;
    }
    $quote = $raw[0];
    if (($quote !== "'" && $quote !== '"') || substr($raw, -1) !== $quote) {
        return null;
    }
    $body = substr($raw, 1, -1);
    if ($quote === "'") {
        return str_replace(["\\\\", "\\'"], ["\\", "'"], $body);
    }
    $out = '';
    $len = strlen($body);
    for ($i = 0; $i < $len; $i++) {
        $ch = $body[$i];
        if ($ch !== '\\' || $i + 1 >= $len) {
            $out .= $ch;
            continue;
        }
        $next = $body[$i + 1];
        switch ($next) {
            case 'n': $out .= "\n"; $i++; break;
            case 'r': $out .= "\r"; $i++; break;
            case 't': $out .= "\t"; $i++; break;
            case 'v': $out .= "\v"; $i++; break;
            case 'f': $out .= "\f"; $i++; break;
            case 'e': $out .= "\x1b"; $i++; break;
            case '\\': $out .= '\\'; $i++; break;
            case '$': $out .= '$'; $i++; break;
            case '"': $out .= '"'; $i++; break;
            case 'x':
                if (preg_match('/^[0-9A-Fa-f]{1,2}/', substr($body, $i + 2), $m)) {
                    $out .= chr(hexdec($m[0]));
                    $i += 1 + strlen($m[0]);
                } else {
                    $out .= '\\x';
                    $i++;
                }
                break;
            default:
                if (preg_match('/^[0-7]{1,3}/', substr($body, $i + 1), $m)) {
                    $out .= chr(octdec($m[0]) & 0xFF);
                    $i += strlen($m[0]);
                } else {
                    $out .= '\\' . $next;
                    $i++;
                }
        }
    }
    return $out;
}

function split_top_level(array $tokens, array $separators): array
{
    $parts = [];
    $current = [];
    $depth = 0;
    foreach ($tokens as $token) {
        $text = token_text($token);
        if (in_array($text, ['(', '[', '{'], true)) {
            $depth++;
        } elseif (in_array($text, [')', ']', '}'], true)) {
            $depth--;
        }
        if ($depth === 0 && in_array($text, $separators, true)) {
            $parts[] = $current;
            $current = [];
            continue;
        }
        $current[] = $token;
    }
    $parts[] = $current;
    return $parts;
}

function trim_tokens(array $tokens): array
{
    while ($tokens && is_trivia($tokens[0])) {
        array_shift($tokens);
    }
    while ($tokens && is_trivia($tokens[count($tokens) - 1])) {
        array_pop($tokens);
    }
    return $tokens;
}

function resolve_scalar(array $tokens, array $vars): ?array
{
    $tokens = trim_tokens($tokens);
    if (!$tokens) {
        return null;
    }
    // Class constants: self::NAME, static::NAME, Some\\Class::NAME
    if (count($tokens) === 3 && is_array($tokens[1]) && $tokens[1][0] === T_DOUBLE_COLON) {
        $constName = is_array($tokens[2]) ? $tokens[2][1] : null;
        $constants = $GLOBALS['redos_constants'] ?? [];
        if ($constName !== null && array_key_exists($constName, $constants)) {
            return ['value' => $constants[$constName], 'source_type' => 'variable',
                    'notes' => ['resolved class constant ' . $constName]];
        }
    }
    $parts = split_top_level($tokens, ['.']);
    if (count($parts) > 1) {
        $value = '';
        $notes = [];
        $sourceType = 'literal';
        foreach ($parts as $part) {
            $resolved = resolve_scalar($part, $vars);
            if ($resolved === null || $resolved['value'] === null) {
                return null;
            }
            $value .= $resolved['value'];
            if ($resolved['source_type'] !== 'literal') {
                $sourceType = 'concat';
            }
            $notes = array_merge($notes, $resolved['notes']);
        }
        if ($sourceType === 'literal') {
            $sourceType = 'concat';
        }
        return ['value' => $value, 'source_type' => $sourceType, 'notes' => $notes];
    }
    if (count($tokens) === 1) {
        $token = $tokens[0];
        if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING) {
            $value = unquote($token[1]);
            if ($value !== null) {
                return ['value' => $value, 'source_type' => 'literal', 'notes' => []];
            }
        }
        if (is_array($token) && $token[0] === T_VARIABLE) {
            if (array_key_exists($token[1], $vars)) {
                return ['value' => $vars[$token[1]], 'source_type' => 'variable',
                        'notes' => ['resolved variable ' . $token[1]]];
            }
            return ['value' => null, 'source_type' => 'dynamic',
                    'notes' => ['unresolved variable ' . $token[1]]];
        }
    }
    if (count($tokens) >= 2 && is_array($tokens[0]) && $tokens[0][0] === T_START_HEREDOC) {
        $value = '';
        foreach ($tokens as $token) {
            if (is_array($token) && $token[0] === T_ENCAPSED_AND_WHITESPACE) {
                $value .= $token[1];
            } elseif (is_array($token) && $token[0] === T_VARIABLE) {
                return null;
            }
        }
        return ['value' => rtrim($value, "\r\n"), 'source_type' => 'literal',
                'notes' => ['heredoc literal']];
    }
    return null;
}

function resolve_patterns(array $tokens, array $vars): array
{
    $tokens = trim_tokens($tokens);
    if (!$tokens) {
        return [];
    }
    $first = $tokens[0];
    $isArray = (is_array($first) && $first[0] === T_ARRAY) || (!is_array($first) && $first === '[');
    if ($isArray) {
        $elements = [];
        $depth = 0;
        $current = [];
        foreach ($tokens as $token) {
            $text = token_text($token);
            if (in_array($text, ['(', '[', '{'], true)) {
                $depth++;
                if ($depth === 1) {
                    continue;
                }
            } elseif (in_array($text, [')', ']', '}'], true)) {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            }
            if ($depth === 1 && $text === ',') {
                $elements[] = $current;
                $current = [];
                continue;
            }
            if ($depth >= 1) {
                $current[] = $token;
            }
        }
        if ($current) {
            $elements[] = $current;
        }
        $out = [];
        foreach ($elements as $element) {
            $resolved = resolve_scalar($element, $vars);
            $out[] = $resolved ?? ['value' => null, 'source_type' => 'dynamic',
                                   'notes' => ['array element is not a constant string']];
        }
        return $out;
    }
    $resolved = resolve_scalar($tokens, $vars);
    return [$resolved ?? ['value' => null, 'source_type' => 'dynamic',
                          'notes' => ['pattern argument is not a constant string']]];
}

function parse_delimited(string $pattern): array
{
    if ($pattern === '') {
        return [null, '', false];
    }
    $delimiter = $pattern[0];
    if (ctype_alnum($delimiter) || $delimiter === '\\' || ctype_space($delimiter)) {
        return [$pattern, '', false];
    }
    $pairs = ['(' => ')', '[' => ']', '{' => '}', '<' => '>'];
    $closing = $pairs[$delimiter] ?? $delimiter;
    $paired = isset($pairs[$delimiter]);
    $length = strlen($pattern);
    $depth = 1;
    $body = '';
    $i = 1;
    while ($i < $length) {
        $ch = $pattern[$i];
        if ($ch === '\\' && $i + 1 < $length) {
            $body .= $ch . $pattern[$i + 1];
            $i += 2;
            continue;
        }
        if ($paired && $ch === $delimiter) {
            $depth++;
            $body .= $ch;
            $i++;
            continue;
        }
        if ($ch === $closing) {
            $depth--;
            $i++;
            if ($depth === 0) {
                break;
            }
            $body .= $ch;
            continue;
        }
        $body .= $ch;
        $i++;
    }
    if ($depth !== 0) {
        return [null, '', false];
    }
    $modifiers = substr($pattern, $i);
    if ($modifiers !== '' && !preg_match('/^[A-Za-z]+$/', $modifiers)) {
        $modifiers = '';
    }
    return [$body, $modifiers, true];
}

function collect_args(array $tokens, int $open): array
{
    $n = count($tokens);
    $stack = [];
    $args = [];
    $current = [];
    for ($i = $open; $i < $n; $i++) {
        $text = token_text($tokens[$i]);
        if ($text === '(' || $text === '[' || $text === '{') {
            $stack[] = $text;
            if (count($stack) === 1) {
                continue;
            }
        } elseif ($text === ')' || $text === ']' || $text === '}') {
            array_pop($stack);
            if (count($stack) === 0) {
                if ($current || $args) {
                    $args[] = $current;
                }
                return [$args, $i];
            }
        } elseif ($text === ',' && count($stack) === 1) {
            $args[] = $current;
            $current = [];
            continue;
        }
        $current[] = $tokens[$i];
    }
    return [$args, $n - 1];
}

function render(array $tokens): string
{
    $out = '';
    foreach ($tokens as $token) {
        $out .= token_text($token);
    }
    return trim(preg_replace('/\s+/', ' ', $out) ?? $out);
}

// ---- pass 1: variables assigned exactly once to a constant string --------
$assignment_count = [];
$literal_vars = [];
for ($i = 0; $i < $count; $i++) {
    if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_VARIABLE) {
        continue;
    }
    $name = $tokens[$i][1];
    $eq = next_sig($tokens, $i + 1);
    if ($eq === null || $tokens[$eq] !== '=') {
        continue;
    }
    $assignment_count[$name] = ($assignment_count[$name] ?? 0) + 1;
    $expr = [];
    $j = $eq + 1;
    $depth = 0;
    while ($j < $count) {
        $text = token_text($tokens[$j]);
        if (in_array($text, ['(', '[', '{'], true)) {
            $depth++;
        } elseif (in_array($text, [')', ']', '}'], true)) {
            $depth--;
        }
        if ($depth === 0 && ($text === ';' || $text === ',')) {
            break;
        }
        $expr[] = $tokens[$j];
        if ($depth === 0 && $text === ';') {
            break;
        }
        $j++;
    }
    $resolved = resolve_scalar($expr, []);
    if ($resolved !== null && $resolved['value'] !== null) {
        $literal_vars[$name] = $resolved['value'];
    } else {
        unset($literal_vars[$name]);
    }
}
foreach ($literal_vars as $name => $value) {
    if (($assignment_count[$name] ?? 0) !== 1) {
        unset($literal_vars[$name]);
    }
}

// ---- pass 1b: class constants and define() ------------------------------
$constants = [];
for ($i = 0; $i < $count; $i++) {
    if (is_array($tokens[$i]) && $tokens[$i][0] === T_CONST) {
        $nameIdx = next_sig($tokens, $i + 1);
        if ($nameIdx === null || !is_array($tokens[$nameIdx])) {
            continue;
        }
        $name = $tokens[$nameIdx][1];
        $eq = next_sig($tokens, $nameIdx + 1);
        if ($eq === null || $tokens[$eq] !== '=') {
            continue;
        }
        $expr = [];
        for ($j = $eq + 1; $j < $count; $j++) {
            $text = token_text($tokens[$j]);
            if ($text === ';' || $text === ',') {
                break;
            }
            $expr[] = $tokens[$j];
        }
        $resolved = resolve_scalar($expr, []);
        if ($resolved !== null && $resolved['value'] !== null) {
            $constants[$name] = $resolved['value'];
        }
        continue;
    }
    if (is_array($tokens[$i]) && $tokens[$i][0] === T_STRING && strtolower($tokens[$i][1]) === 'define') {
        $open = next_sig($tokens, $i + 1);
        if ($open === null || $tokens[$open] !== '(') {
            continue;
        }
        [$args] = collect_args($tokens, $open);
        if (count($args) < 2) {
            continue;
        }
        $nameValue = resolve_scalar($args[0], []);
        $value = resolve_scalar($args[1], []);
        if ($nameValue !== null && $nameValue['value'] !== null &&
            $value !== null && $value['value'] !== null) {
            $constants[$nameValue['value']] = $value['value'];
        }
    }
}
$GLOBALS['redos_constants'] = $constants;

// ---- pass 2: preg_* call sites ------------------------------------------
for ($i = 0; $i < $count; $i++) {
    if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_STRING) {
        continue;
    }
    $name = strtolower($tokens[$i][1]);
    if (!isset($sinks[$name])) {
        continue;
    }
    $previous = null;
    for ($k = $i - 1; $k >= 0; $k--) {
        if (!is_trivia($tokens[$k])) {
            $previous = $tokens[$k];
            break;
        }
    }
    if (is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NS_SEPARATOR], true)) {
        continue;
    }
    if (!is_array($previous) && ($previous === '>' || $previous === ':')) {
        continue;
    }
    $open = next_sig($tokens, $i + 1);
    if ($open === null || $tokens[$open] !== '(') {
        continue;
    }
    [$args, $end] = collect_args($tokens, $open);
    $patternIndex = $sinks[$name][0];
    $dataIndex = $sinks[$name][1];
    if (!isset($args[$patternIndex])) {
        continue;
    }
    $resolvedPatterns = resolve_patterns($args[$patternIndex], $literal_vars);
    $inputExpr = isset($args[$dataIndex]) ? render($args[$dataIndex]) : '';
    $line = $tokens[$i][2];
    foreach ($resolvedPatterns as $resolved) {
        $value = $resolved['value'];
        $notes = $resolved['notes'];
        $raw = null;
        $body = null;
        $flags = '';
        if ($value !== null) {
            [$body, $modifiers, $delimited] = parse_delimited($value);
            $raw = $value;
            if (!$delimited) {
                $notes[] = 'pattern does not start with a PCRE delimiter';
                $body = $value;
            } else {
                $flags = $modifiers;
                $extra = trim($flags, 'imsxuADUJSXn');
                if ($extra !== '') {
                    $notes[] = 'unusual PCRE modifiers: ' . $extra;
                }
            }
        } else {
            $notes[] = 'pattern value could not be resolved statically';
        }
        $key = $line . '|' . ($body ?? '') . '|' . $name;
        if (isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $results[] = [
            'line' => $line,
            'function' => $name,
            'pattern' => $body,
            'raw_pattern' => $raw,
            'flags' => $flags,
            'source_type' => $resolved['source_type'],
            'input_expr' => $inputExpr,
            'notes' => $notes,
        ];
    }
}

echo json_encode(['ok' => true, 'regexes' => $results]), "\n";
