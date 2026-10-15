<?php

declare(strict_types=1);

namespace PasteGuard;

final class Redactor
{
    public const MAX_BYTES = 8000000;

    /**
     * @return array{
     *   text: string,
     *   total: int,
     *   counts: array<string, int>,
     *   findings: list<array{kind: string, line: int, fingerprint: string}>
     * }
     */
    public static function redact(string $text, bool $pii = false, bool $fingerprint = true): array
    {
        $found = [];
        foreach (Rules::tokenRules($pii) as $rule) {
            $matched = preg_match_all($rule['regex'], $text, $groups, PREG_OFFSET_CAPTURE);
            if ($matched === false) {
                throw new \RuntimeException('pattern failed: ' . $rule['kind'] . ' (' . preg_last_error_msg() . ')');
            }
            if ($matched === 0) {
                continue;
            }

            $group = $rule['group'];
            $hits = count($groups[0]);
            for ($i = 0; $i < $hits; $i++) {
                $chunk = $groups[$group][$i][0] ?? '';
                $start = $groups[$group][$i][1] ?? -1;
                if ($chunk === '' || $start < 0) {
                    continue;
                }
                $end = $start + strlen($chunk);
                if ($rule['trim']) {
                    $trimmed = rtrim($chunk, ".,;)]>");
                    if ($trimmed === '') {
                        continue;
                    }
                    $end = $start + strlen($trimmed);
                    $chunk = $trimmed;
                }
                if (strlen($chunk) < $rule['min']) {
                    continue;
                }
                if ($rule['kind'] === 'email' && Rules::ignoredEmail($chunk)) {
                    continue;
                }
                if ($rule['kind'] === 'url_userinfo' && self::urlSecretIsBenign($chunk)) {
                    continue;
                }
                $found[] = self::span($rule['kind'], $start, $end, $rule['priority'], $chunk, $fingerprint);
            }
        }

        foreach (self::assignments($text, $fingerprint) as $span) {
            $found[] = $span;
        }

        $chosen = self::resolve($found);
        $textOut = self::splice($text, $chosen);

        $findings = [];
        $counts = [];
        foreach ($chosen as $span) {
            $line = 1 + substr_count(substr($text, 0, $span['start']), "\n");
            $findings[] = [
                'kind' => $span['kind'],
                'line' => $line,
                'fingerprint' => $span['fingerprint'],
            ];
            $counts[$span['kind']] = ($counts[$span['kind']] ?? 0) + 1;
        }

        return [
            'text' => $textOut,
            'total' => count($findings),
            'counts' => $counts,
            'findings' => $findings,
        ];
    }

    /**
     * @return list<array{kind:string,start:int,end:int,priority:int,fingerprint:string,placeholder:string}>
     */
    private static function assignments(string $text, bool $fingerprint): array
    {
        $matched = preg_match_all(Rules::assignmentRegex(), $text, $groups, PREG_OFFSET_CAPTURE);
        if ($matched === false) {
            throw new \RuntimeException('assignment pattern failed (' . preg_last_error_msg() . ')');
        }
        if ($matched === 0) {
            return [];
        }

        $spans = [];
        $hits = count($groups[0]);
        for ($i = 0; $i < $hits; $i++) {
            $name = $groups[1][$i][0];
            $value = '';
            $start = -1;
            foreach ([3, 4, 5] as $group) {
                if (($groups[$group][$i][1] ?? -1) >= 0 && $groups[$group][$i][0] !== '') {
                    $value = $groups[$group][$i][0];
                    $start = $groups[$group][$i][1];
                    break;
                }
            }
            if ($start < 0 || $value === '') {
                continue;
            }
            if (!Rules::assignmentValueIsSecret($name, $value)) {
                continue;
            }
            $spans[] = self::span('assignment', $start, $start + strlen($value), 40, $value, $fingerprint);
        }

        return $spans;
    }

    /**
     * @param list<array{kind:string,start:int,end:int,priority:int,fingerprint:string,placeholder:string}> $found
     * @return list<array{kind:string,start:int,end:int,priority:int,fingerprint:string,placeholder:string}>
     */
    private static function resolve(array $found): array
    {
        usort($found, static function (array $a, array $b): int {
            if ($a['start'] !== $b['start']) {
                return $a['start'] <=> $b['start'];
            }
            $length = ($b['end'] - $b['start']) <=> ($a['end'] - $a['start']);
            if ($length !== 0) {
                return $length;
            }

            return $b['priority'] <=> $a['priority'];
        });

        $chosen = [];
        foreach ($found as $span) {
            $overlaps = false;
            foreach ($chosen as $kept) {
                if ($span['start'] < $kept['end'] && $span['end'] > $kept['start']) {
                    $overlaps = true;
                    break;
                }
            }
            if (!$overlaps) {
                $chosen[] = $span;
            }
        }

        usort($chosen, static fn (array $a, array $b): int => $a['start'] <=> $b['start']);

        return $chosen;
    }

    /**
     * @param list<array{kind:string,start:int,end:int,priority:int,fingerprint:string,placeholder:string}> $chosen
     */
    private static function splice(string $text, array $chosen): string
    {
        $out = '';
        $cursor = 0;
        foreach ($chosen as $span) {
            $out .= substr($text, $cursor, $span['start'] - $cursor);
            $out .= $span['placeholder'];
            $cursor = $span['end'];
        }
        $out .= substr($text, $cursor);

        return $out;
    }

    /**
     * @return array{kind:string,start:int,end:int,priority:int,fingerprint:string,placeholder:string}
     */
    private static function span(string $kind, int $start, int $end, int $priority, string $secret, bool $withFingerprint): array
    {
        $fingerprint = $withFingerprint ? substr(hash('sha256', $kind . "\0" . $secret), 0, 4) : '';
        $placeholder = $withFingerprint
            ? '[REDACTED:' . $kind . ':' . $fingerprint . ']'
            : '[REDACTED:' . $kind . ']';

        return [
            'kind' => $kind,
            'start' => $start,
            'end' => $end,
            'priority' => $priority,
            'fingerprint' => $fingerprint,
            'placeholder' => $placeholder,
        ];
    }

    private static function urlSecretIsBenign(string $userinfo): bool
    {
        $parts = explode(':', $userinfo, 2);
        $password = $parts[1] ?? '';

        return Rules::isPlaceholder($password);
    }
}
