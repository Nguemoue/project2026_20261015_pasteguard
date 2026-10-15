<?php

declare(strict_types=1);

namespace PasteGuard;

final class Cli
{
    /** @param list<string> $argv */
    public static function run(array $argv): int
    {
        $opts = self::parse(array_slice($argv, 1));
        if ($opts['help']) {
            self::help(STDOUT);
            return 0;
        }
        if ($opts['error'] !== null) {
            fwrite(STDERR, "pasteguard: {$opts['error']}\n");
            self::help(STDERR);
            return 2;
        }

        if ($opts['file'] === null) {
            if (function_exists('stream_isatty') && stream_isatty(STDIN)) {
                self::help(STDERR);
                return 2;
            }
            $raw = stream_get_contents(STDIN);
            $label = 'stdin';
        } else {
            if (!is_file($opts['file'])) {
                fwrite(STDERR, "pasteguard: file not found: {$opts['file']}\n");
                return 2;
            }
            $size = filesize($opts['file']);
            if ($size !== false && $size > Redactor::MAX_BYTES) {
                fwrite(STDERR, "pasteguard: file exceeds 8MB\n");
                return 2;
            }
            $raw = file_get_contents($opts['file']);
            $label = $opts['file'];
        }

        if ($raw === false) {
            fwrite(STDERR, "pasteguard: could not read input\n");
            return 2;
        }
        if (strlen($raw) > Redactor::MAX_BYTES) {
            fwrite(STDERR, "pasteguard: input exceeds 8MB\n");
            return 2;
        }
        if (str_contains($raw, "\0")) {
            fwrite(STDERR, "pasteguard: input looks binary, refused\n");
            return 2;
        }

        $report = Redactor::redact($raw, $opts['pii'], $opts['fingerprint']);

        if ($opts['json']) {
            $payload = [
                'tool' => 'pasteguard',
                'version' => 1,
                'input' => $label,
                'total' => $report['total'],
                'counts' => $report['counts'],
                'findings' => $report['findings'],
            ];
            if (!$opts['check']) {
                $payload['text'] = $report['text'];
            }
            $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($json === false) {
                fwrite(STDERR, "pasteguard: could not encode json\n");
                return 2;
            }
            $json .= "\n";
            if ($opts['output'] !== null) {
                if (file_put_contents($opts['output'], $json) === false) {
                    fwrite(STDERR, "pasteguard: could not write {$opts['output']}\n");
                    return 2;
                }
            } else {
                fwrite(STDOUT, $json);
            }
        } elseif ($opts['check']) {
            foreach ($report['findings'] as $finding) {
                $fp = $finding['fingerprint'] === '' ? '' : ':' . $finding['fingerprint'];
                fwrite(STDOUT, $label . ':' . $finding['line'] . ': ' . $finding['kind'] . $fp . "\n");
            }
            if ($report['total'] === 0) {
                fwrite(STDERR, "pasteguard: nothing to redact\n");
            } else {
                fwrite(STDERR, "pasteguard: {$report['total']} secret(s) — not safe to paste\n");
            }
        } else {
            if ($opts['output'] === null) {
                fwrite(STDOUT, $report['text']);
            } elseif (file_put_contents($opts['output'], $report['text']) === false) {
                fwrite(STDERR, "pasteguard: could not write {$opts['output']}\n");
                return 2;
            }
            fwrite(STDERR, self::summary($label, $report, $opts['output']));
        }

        if ($opts['check'] && $report['total'] > 0) {
            return 1;
        }

        return 0;
    }

    /**
     * @param list<string> $args
     * @return array{help:bool,check:bool,json:bool,pii:bool,fingerprint:bool,output:?string,file:?string,error:?string}
     */
    private static function parse(array $args): array
    {
        $opts = [
            'help' => false,
            'check' => false,
            'json' => false,
            'pii' => false,
            'fingerprint' => true,
            'output' => null,
            'file' => null,
            'error' => null,
        ];

        $count = count($args);
        for ($i = 0; $i < $count; $i++) {
            $arg = $args[$i];
            if ($arg === '--') {
                if ($i + 1 < $count) {
                    if ($opts['file'] !== null) {
                        $opts['error'] = 'too many files';
                        return $opts;
                    }
                    $opts['file'] = $args[$i + 1];
                }
                break;
            }
            if ($arg === '-h' || $arg === '--help') {
                $opts['help'] = true;
                continue;
            }
            if ($arg === '--check') {
                $opts['check'] = true;
                continue;
            }
            if ($arg === '--json') {
                $opts['json'] = true;
                continue;
            }
            if ($arg === '--pii') {
                $opts['pii'] = true;
                continue;
            }
            if ($arg === '--no-fingerprint') {
                $opts['fingerprint'] = false;
                continue;
            }
            if ($arg === '-o' || $arg === '--output') {
                if ($i + 1 >= $count) {
                    $opts['error'] = 'missing path after ' . $arg;
                    return $opts;
                }
                $opts['output'] = $args[++$i];
                continue;
            }
            if (str_starts_with($arg, '-')) {
                $opts['error'] = 'unknown option ' . $arg;
                return $opts;
            }
            if ($opts['file'] !== null) {
                $opts['error'] = 'too many files';
                return $opts;
            }
            $opts['file'] = $arg;
        }

        return $opts;
    }

    /** @param array{total:int,counts:array<string,int>,findings:list<array{kind:string,line:int,fingerprint:string}>,text:string} $report */
    private static function summary(string $label, array $report, ?string $output): string
    {
        $lines = [];
        if ($output !== null) {
            $lines[] = "pasteguard: wrote {$output}";
        }
        $lines[] = "pasteguard: {$label}";
        if ($report['total'] === 0) {
            $lines[] = 'nothing to redact';
        } else {
            $lines[] = $report['total'] . ' secret(s) redacted';
            $counts = $report['counts'];
            ksort($counts);
            foreach ($counts as $kind => $count) {
                $lines[] = sprintf('  %-16s %d', $kind, $count);
            }
            $lines[] = $output === null
                ? 'stdout is the paste-safe copy. nothing was uploaded.'
                : 'that file is the paste-safe copy. nothing was uploaded.';
        }

        return implode("\n", $lines) . "\n";
    }

    /** @param resource $stream */
    private static function help($stream): void
    {
        fwrite($stream, <<<TXT
PasteGuard — redact secrets before you paste a log.

Usage:
  php bin/pasteguard [options] [file]
  php bin/pasteguard --check [file]

Options:
  -o, --output FILE     Write the redacted text to FILE
  --check               Print file:line:kind only. Exit 1 if a secret was found
  --json                JSON report (redacted text included unless --check)
  --pii                 Also redact email addresses
  --no-fingerprint      Placeholder is [REDACTED:kind], without the short hash
  -h, --help

With no file, read stdin unless it is a terminal.
Nothing is uploaded. Exit 0 when the text is clean or was redacted.
Exit 1 when --check finds a secret. Exit 2 on usage or IO errors.

TXT);
    }
}
