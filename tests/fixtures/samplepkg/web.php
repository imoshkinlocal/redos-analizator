<?php
// Fixture: PHP PCRE2 use-site with request data.
$vuln = '/^(a+)+$/';
if (preg_match($vuln, $_GET['q'])) {
    echo "match";
}
$safe = '/^[a-z]+$/';
preg_match($safe, 'abc');
