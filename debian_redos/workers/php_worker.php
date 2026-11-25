<?php
// PCRE2 measurement worker for the Debian ReDoS scanner.
//
// Protocol: one JSON object per line on stdin, one JSON object per line on
// stdout.  The parent enforces the wall-clock timeout.  PCRE backtracking and
// recursion limits are raised on purpose (configurable for the parent) so that
// the measurement shows the underlying cost instead of PCRE's fast failure;
// the effective limits are reported back with every result.

$cache = [];
$backtrackLimit = (int) (getenv('REDOS_PCRE_BACKTRACK_LIMIT') ?: 100000000);
$recursionLimit = (int) (getenv('REDOS_PCRE_RECURSION_LIMIT') ?: 1000000);
ini_set('pcre.backtrack_limit', (string) $backtrackLimit);
ini_set('pcre.recursion_limit', (string) $recursionLimit);
ini_set('pcre.jit', '0');

function redos_error_name(int $code): string
{
    switch ($code) {
        case PREG_NO_ERROR:
            return 'PREG_NO_ERROR';
        case PREG_INTERNAL_ERROR:
            return 'PREG_INTERNAL_ERROR';
        case PREG_BACKTRACK_LIMIT_ERROR:
            return 'PREG_BACKTRACK_LIMIT_ERROR';
        case PREG_RECURSION_LIMIT_ERROR:
            return 'PREG_RECURSION_LIMIT_ERROR';
        case PREG_BAD_UTF8_ERROR:
            return 'PREG_BAD_UTF8_ERROR';
        case PREG_BAD_UTF8_OFFSET_ERROR:
            return 'PREG_BAD_UTF8_OFFSET_ERROR';
        case PREG_JIT_STACKLIMIT_ERROR:
            return 'PREG_JIT_STACKLIMIT_ERROR';
        default:
            return 'PREG_UNKNOWN_ERROR';
    }
}

$engineVersion = PHP_VERSION;
$pcreVersion = defined('PCRE_VERSION') ? PCRE_VERSION : 'unknown';

while (($line = fgets(STDIN)) !== false) {
    $line = trim($line);
    if ($line === '') {
        continue;
    }
    $request = json_decode($line, true);
    if (!is_array($request)) {
        echo json_encode(['status' => 'error', 'error' => 'bad request']), "\n";
        continue;
    }
    $pattern = isset($request['pattern']) ? $request['pattern'] : '';
    $response = [
        'engine' => 'php-pcre2',
        'engine_version' => $engineVersion,
        'pcre_version' => $pcreVersion,
        'backtrack_limit' => $backtrackLimit,
        'recursion_limit' => $recursionLimit,
    ];
    if (!array_key_exists($pattern, $cache)) {
        $compiled = @preg_match($pattern, '');
        if ($compiled === false) {
            $response['status'] = 'error';
            $response['error'] = 'preg_error: ' . redos_error_name(preg_last_error());
            echo json_encode($response), "\n";
            unset($cache[$pattern]);
            continue;
        }
        if (count($cache) < 128) {
            $cache[$pattern] = true;
        }
    }
    if (!empty($request['warmup'])) {
        $response['status'] = 'ok';
        echo json_encode($response), "\n";
        continue;
    }
    $text = isset($request['text']) ? $request['text'] : '';
    $started = hrtime(true);
    $result = @preg_match($pattern, $text);
    $elapsed = (hrtime(true) - $started) / 1e6;
    $error = preg_last_error();
    if ($result === false) {
        $response['status'] = 'error';
        $response['error'] = redos_error_name($error);
        $response['elapsed_ms'] = $elapsed;
    } else {
        $response['status'] = 'completed';
        $response['elapsed_ms'] = $elapsed;
        $response['matched'] = (bool) $result;
        if ($error !== PREG_NO_ERROR) {
            $response['pcre_error'] = redos_error_name($error);
        }
    }
    echo json_encode($response), "\n";
}
