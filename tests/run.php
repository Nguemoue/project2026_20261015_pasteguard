<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/src/bootstrap.php';

use PasteGuard\Cli;
use PasteGuard\Redactor;
use PasteGuard\Web;

$failed = 0;
$passed = 0;

function check(bool $ok, string $message): void
{
    global $failed, $passed;
    if ($ok) {
        $passed++;
        echo "ok   {$message}\n";
        return;
    }
    $failed++;
    echo "FAIL {$message}\n";
}

function secret(string ...$parts): string
{
    return implode('', $parts);
}

function kindOf(array $report, string $kind): int
{
    return $report['counts'][$kind] ?? 0;
}

function leaks(string $haystack, string $needle): bool
{
    return $needle !== '' && str_contains($haystack, $needle);
}

$bin = $root . '/bin/pasteguard';
$php = PHP_BINARY;

function runCli(array $args, ?string $stdin = null): array
{
    global $bin, $php;
    $cmd = array_merge([$php, $bin], $args);
    $input = null;
    $spec = [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    if ($stdin === null) {
        $spec[0] = ['pipe', 'r'];
    } else {
        $input = tempnam(sys_get_temp_dir(), 'pgin');
        file_put_contents((string) $input, $stdin);
        $spec[0] = ['file', $input, 'r'];
    }
    $proc = proc_open($cmd, $spec, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('proc_open failed');
    }
    if (isset($pipes[0]) && is_resource($pipes[0])) {
        fclose($pipes[0]);
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    if ($input !== null) {
        @unlink($input);
    }

    return [$code, $stdout === false ? '' : $stdout, $stderr === false ? '' : $stderr];
}

// --- known prefixes, built so this file itself contains no full token ---

$cases = [
    'github_token' => secret('gh', 'p_', str_repeat('a', 36)),
    'github_pat' => secret('github_pat_', str_repeat('b', 82)),
    'gitlab_pat' => secret('gl', 'pat-', str_repeat('c', 20)),
    'slack_token' => secret('xo', 'xb-', str_repeat('1', 12), '-', str_repeat('d', 12)),
    'stripe_secret' => secret('sk', '_live_', str_repeat('e', 24)),
    'stripe_webhook' => secret('wh', 'sec_', str_repeat('f', 32)),
    'anthropic' => secret('sk-', 'ant-', str_repeat('g', 24)),
    'openai' => secret('sk-', 'proj-', str_repeat('h', 24)),
    'xai_key' => secret('xa', 'i-', str_repeat('j', 24)),
    'google_api' => secret('AI', 'za', str_repeat('k', 35)),
    'sendgrid' => secret('SG.', str_repeat('m', 22), '.', str_repeat('n', 43)),
    'npm_token' => secret('np', 'm_', str_repeat('p', 36)),
    'shopify_token' => secret('shp', 'at_', str_repeat('ab', 16)),
    'huggingface' => secret('h', 'f_', str_repeat('q', 34)),
    'pypi_token' => secret('pypi-', 'AgEIcHlwaS5vcmc', str_repeat('r', 20)),
    'digitalocean' => secret('dop_', 'v1_', str_repeat('ab', 32)),
    'aws_access_key' => secret('AK', 'IA', 'IOSFODNN7EXAMPLE'),
    'jwt' => secret('eyJhbGciOiJIUzI1NiJ9', '.', str_repeat('A', 16), '.', str_repeat('B', 16)),
];

foreach ($cases as $kind => $token) {
    $report = Redactor::redact("before {$token} after");
    check(kindOf($report, $kind) === 1, "detects {$kind}");
    check(!leaks($report['text'], $token), "removes {$kind} from output");
    check(str_contains($report['text'], '[REDACTED:' . $kind . ':'), "labels {$kind}");
    check($report['text'] !== '' && !str_contains($report['text'], '[[[['), "one placeholder for {$kind}");
}

$openaiPlain = secret('sk-', str_repeat('z', 32));
$openaiReport = Redactor::redact($openaiPlain);
check(kindOf($openaiReport, 'openai') === 1, 'plain sk- key is openai, not anthropic');
check(kindOf($openaiReport, 'anthropic') === 0, 'plain sk- key is not anthropic');

$anth = $cases['anthropic'];
$anthReport = Redactor::redact($anth);
check(kindOf($anthReport, 'anthropic') === 1 && kindOf($anthReport, 'openai') === 0, 'sk-ant wins over generic openai');

$pk = secret('pk', '_live_', str_repeat('d', 24));
check(Redactor::redact("key {$pk}")['text'] === "key {$pk}", 'publishable stripe key is kept');

$short = secret('gh', 'p_', str_repeat('a', 10));
check(Redactor::redact($short)['total'] === 0, 'short ghp_ fragment is not a token');

$longGithub = secret('gh', 'p_', str_repeat('b', 50));
$longReport = Redactor::redact("x {$longGithub} y");
check(!leaks($longReport['text'], 'bbb'), 'long github token leaves no suffix');

$sha = str_repeat('ab', 20);
$uuid = '550e8400-e29b-41d4-a716-446655440000';
check(Redactor::redact("commit {$sha} id {$uuid}")['total'] === 0, 'git sha and uuid are not secrets');

$bearerJwt = 'Authorization: Bearer ' . $cases['jwt'];
$bearerReport = Redactor::redact($bearerJwt . '.');
check(kindOf($bearerReport, 'jwt') === 1, 'bearer jwt is labelled jwt');
check(kindOf($bearerReport, 'bearer') === 0, 'bearer jwt is not double counted');
check(str_contains($bearerReport['text'], 'Authorization: Bearer [REDACTED:jwt:'), 'bearer word stays, token goes');
check(!str_contains($bearerReport['text'], $cases['jwt']), 'jwt bytes are gone');
check(str_ends_with($bearerReport['text'], '.'), 'sentence period stays');

$opaque = 'Bearer ' . str_repeat('Q', 24) . '.';
$opaqueReport = Redactor::redact($opaque);
check(kindOf($opaqueReport, 'bearer') === 1, 'opaque bearer token');
check(str_ends_with($opaqueReport['text'], '.'), 'opaque bearer keeps the period');
check(!str_contains($opaqueReport['text'], str_repeat('Q', 24)), 'opaque bearer value is gone');

$basic = "Authorization: Basic " . secret('dXNlcjp', 'wYXNz');
$basicReport = Redactor::redact($basic);
check(kindOf($basicReport, 'basic_auth') === 1, 'basic auth credential');
check(str_starts_with($basicReport['text'], 'Authorization: Basic '), 'basic scheme stays');
check(!leaks($basicReport['text'], 'dXNlcjp'), 'basic blob is gone');

$url = 'mysql://billing:s3cret-db-pass@10.0.0.8:3306/billing';
$urlReport = Redactor::redact($url);
check(kindOf($urlReport, 'url_userinfo') === 1, 'dsn userinfo');
check(str_contains($urlReport['text'], 'mysql://[REDACTED:url_userinfo:'), 'dsn scheme stays');
check(str_contains($urlReport['text'], '@10.0.0.8:3306/billing'), 'dsn host stays');
check(!str_contains($urlReport['text'], 's3cret-db-pass'), 'dsn password is gone');
check(Redactor::redact('mysql://root:password@db/app')['total'] === 0, 'placeholder dsn password is kept');

$hook = secret('https://hooks.slack.com/services/T', str_repeat('A', 8), '/B', str_repeat('B', 8), '/', str_repeat('C', 16));
$hookReport = Redactor::redact("ping {$hook}");
check(kindOf($hookReport, 'slack_webhook') === 1, 'slack webhook');
check(!leaks($hookReport['text'], $hook), 'webhook url removed');

$pem = "-----BEGIN " . "RSA PRIVATE KEY-----\n" . str_repeat('A', 64) . "\n-----END " . "RSA PRIVATE KEY-----\n";
$pemReport = Redactor::redact("key follows\n{$pem}done\n");
check(kindOf($pemReport, 'private_key') === 1, 'pem private key');
check(!str_contains($pemReport['text'], 'BEGIN'), 'pem header is gone');
check(str_contains($pemReport['text'], 'key follows'), 'text around pem stays');
check(str_contains($pemReport['text'], 'done'), 'text after pem stays');

$escapedPem = "-----BEGIN " . "PRIVATE KEY-----\\n" . str_repeat('B', 40) . "\\n-----END " . "PRIVATE KEY-----";
$escapedReport = Redactor::redact($escapedPem);
check(kindOf($escapedReport, 'private_key') === 1, 'one-line escaped pem');

$app = 'base64:pasteguard-demo-key-not-a-real-laravel-key';
$assign = Redactor::redact("APP_KEY={$app}\nAPP_KEY={$app}\nDB_PASSWORD=changeme\npassword=secret\n");
check(kindOf($assign, 'assignment') === 2, 'two app keys, placeholders ignored');
check($assign['findings'][0]['fingerprint'] === $assign['findings'][1]['fingerprint'], 'same secret, same fingerprint');
check(str_contains($assign['text'], 'DB_PASSWORD=changeme'), 'changeme stays');
check(str_contains($assign['text'], 'password=secret'), 'password=secret stays');
check(!str_contains($assign['text'], $app), 'app key value is gone');

$again = Redactor::redact($assign['text']);
check($again['text'] === $assign['text'] && $again['total'] === 0, 'redaction is idempotent');

$line = Redactor::redact("ok\nnope\nAPI_KEY=" . $cases['github_token'] . "\n");
check($line['findings'][0]['line'] === 3, 'line number is 3');
check(kindOf($line, 'github_token') === 1, 'token wins over assignment label');
check(kindOf($line, 'assignment') === 0, 'assignment does not also fire');

$utf = "échec avant SECRET=valeur-secrète-99 après";
$utfReport = Redactor::redact($utf);
check(str_starts_with($utfReport['text'], 'échec avant SECRET='), 'utf-8 around the value stays');
check(!str_contains($utfReport['text'], 'valeur-secrète-99'), 'utf-8 secret value is gone');

$sentence = 'note: the user token expired after logout.';
check(Redactor::redact($sentence)['text'] === $sentence, 'prose about a token is untouched');

$noFp = Redactor::redact('MAIL_PASSWORD=correct-horse-battery', false, false);
check(str_contains($noFp['text'], '[REDACTED:assignment]'), 'fingerprint can be disabled');
check(!str_contains($noFp['text'], '[REDACTED:assignment:'), 'no hash when disabled');

$email = 'customer support@client.example asked, not user@example.com';
check(Redactor::redact($email)['total'] === 0, 'emails stay off by default');
$pii = Redactor::redact($email, true);
check(kindOf($pii, 'email') === 1, 'pii mode redacts a real-looking email');
check(str_contains($pii['text'], 'user@example.com'), 'example.com mailbox stays');
check(!str_contains($pii['text'], 'support@client.example'), 'other mailbox goes');

$example = file_get_contents($root . '/examples/leaky.txt');
check(is_string($example) && $example !== '', 'example file loads');
$demo = Redactor::redact((string) $example);
check($demo['total'] >= 4, 'example has several secrets');
foreach (['changeme', 'password=secret', 'the user token expired', 'support@client.example', '10.0.0.8'] as $keep) {
    check(str_contains($demo['text'], $keep), "example keeps {$keep}");
}
check(!str_contains($demo['text'], 's3cret-db-pass'), 'example drops the db password');
check(!str_contains($demo['text'], 'correct-horse-battery'), 'example drops the mail password');
check(!str_contains($demo['text'], 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), 'example drops the jwt');
check(!str_contains($demo['text'], 'AKIAIOSFODNN7EXAMPLE'), 'example drops the aws key');

$clean = $root . '/examples/leaky.txt';
[$code, $out, $err] = runCli(['--check', $clean]);
check($code === 1, 'check exits 1');
check(!str_contains($out . $err, 's3cret-db-pass'), 'check output hides the password');
check(!str_contains($out . $err, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), 'check output hides the jwt');
check(str_contains($err, 'not safe to paste'), 'check explains the exit');

$tmpIn = tempnam(sys_get_temp_dir(), 'pg');
$tmpOut = tempnam(sys_get_temp_dir(), 'pg');
file_put_contents((string) $tmpIn, "hello\n");
[$code, $out, $err] = runCli(['--check', (string) $tmpIn]);
check($code === 0 && str_contains($err, 'nothing to redact'), 'clean file exits 0');

[$code, $out, $err] = runCli(['-o', (string) $tmpOut, (string) $clean]);
check($code === 0, 'write mode exits 0');
$written = (string) file_get_contents((string) $tmpOut);
check(!str_contains($written, 's3cret-db-pass') && str_contains($written, '[REDACTED:'), 'output file is redacted');
check(str_contains($err, 'that file is the paste-safe copy'), 'stderr points at the file');

[$code, $out, $err] = runCli(['--json', '--check', (string) $clean]);
check($code === 1, 'json check exits 1');
$json = json_decode($out, true);
check(is_array($json) && !array_key_exists('text', $json), 'json check omits the log');
check(!str_contains($out, 's3cret-db-pass'), 'json check has no secret');
check(($json['total'] ?? 0) >= 4, 'json check counts findings');

[$code, $out, $err] = runCli(['--json', (string) $tmpIn]);
$json = json_decode($out, true);
check($code === 0 && ($json['text'] ?? null) === "hello\n", 'json mode can return clean text');

[$code, $out, $err] = runCli(['--no-fingerprint'], "MAIL_PASSWORD=correct-horse-battery\n");
check($code === 0 && str_contains($out, 'MAIL_PASSWORD=[REDACTED:assignment]'), 'stdin redact');
check(!str_contains($out, 'correct-horse-battery'), 'stdin dropped the password');

[$code, $out, $err] = runCli(['--help']);
check($code === 0 && str_contains($out, 'Usage:'), 'help exits 0');

[$code, $out, $err] = runCli(['missing-file-pasteguard.txt']);
check($code === 2 && str_contains($err, 'file not found'), 'missing file exits 2');

[$code, $out, $err] = runCli(['--nope']);
check($code === 2 && str_contains($err, 'unknown option'), 'unknown option exits 2');

$binFile = tempnam(sys_get_temp_dir(), 'pg');
file_put_contents((string) $binFile, "ok\0secret");
[$code, $out, $err] = runCli([(string) $binFile]);
check($code === 2 && str_contains($err, 'binary'), 'binary input exits 2');

$html = Web::handle([], []);
check(str_contains($html, 'PasteGuard') && !str_contains($html, 'AKIAIOSFODNN7EXAMPLE'), 'form does not embed the example');

$xss = "<script>alert(1)</script>\nAPP_KEY={$app}";
$page = Web::handle([], ['log' => $xss]);
check(!str_contains($page, '<script>alert'), 'page escapes html');
check(str_contains($page, '<script>'), 'page shows the escaped tag');
check(preg_match('#<pre id="out">(.*?)</pre>#s', $page, $preXss) === 1, 'xss page has a result');
check(!str_contains(html_entity_decode($preXss[1] ?? '', ENT_QUOTES, 'UTF-8'), $app), 'result pre hides the app key');
check(str_contains($preXss[1] ?? '', '[REDACTED:assignment:'), 'page shows the placeholder');

$samplePage = Web::handle([], ['example' => '1']);
check(str_contains($samplePage, 'Version collable'), 'example button redacts');
check(preg_match('#<pre id="out">(.*?)</pre>#s', $samplePage, $preSample) === 1, 'example page has a result');
$sampleOut = html_entity_decode($preSample[1] ?? '', ENT_QUOTES, 'UTF-8');
check(!str_contains($sampleOut, 's3cret-db-pass'), 'example result hides the password');
check(str_contains($sampleOut, 'the user token expired'), 'example result keeps the prose');

@unlink((string) $tmpIn);
@unlink((string) $tmpOut);
@unlink((string) $binFile);

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
