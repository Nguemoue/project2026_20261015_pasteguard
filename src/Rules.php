<?php

declare(strict_types=1);

namespace PasteGuard;

/**
 * High-precision patterns for credentials that show up in logs.
 * A match is a reason to rotate the real credential, not a guarantee
 * that every secret in the world was found.
 */
final class Rules
{
    /**
     * @return list<array{kind:string,regex:string,group:int,priority:int,trim:bool,min:int}>
     */
    public static function tokenRules(bool $pii): array
    {
        $rules = [
            [
                'kind' => 'private_key',
                'regex' => '~-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\\\n|\r?\n)[\s\S]{0,20000}?-----END [A-Z0-9 ]*PRIVATE KEY-----~',
                'group' => 0,
                'priority' => 100,
                'trim' => false,
                'min' => 40,
            ],
            [
                'kind' => 'slack_webhook',
                'regex' => '~https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{8,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'github_pat',
                'regex' => '~github_pat_[A-Za-z0-9_]{82,}(?![A-Za-z0-9_])~',
                'group' => 0,
                'priority' => 92,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'github_token',
                'regex' => '~gh[pousr]_[A-Za-z0-9]{36,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'gitlab_pat',
                'regex' => '~glpat-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'slack_token',
                'regex' => '~xox[baprs]-[A-Za-z0-9\-]{10,}(?![A-Za-z0-9\-])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 14,
            ],
            [
                'kind' => 'stripe_webhook',
                'regex' => '~whsec_[A-Za-z0-9]{16,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 16,
            ],
            [
                'kind' => 'stripe_secret',
                'regex' => '~[rs]k_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 16,
            ],
            [
                'kind' => 'anthropic',
                'regex' => '~sk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 95,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'openai',
                'regex' => '~sk-(?:proj-)?[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 80,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'xai_key',
                'regex' => '~xai-[A-Za-z0-9]{20,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'google_api',
                'regex' => '~AIza[0-9A-Za-z_\-]{35,}(?![0-9A-Za-z_\-])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'sendgrid',
                'regex' => '~SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'npm_token',
                'regex' => '~npm_[A-Za-z0-9]{36,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'shopify_token',
                'regex' => '~shpat_[a-fA-F0-9]{32,}(?![a-fA-F0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'huggingface',
                'regex' => '~hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'pypi_token',
                'regex' => '~pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'digitalocean',
                'regex' => '~dop_v1_[a-f0-9]{64}(?![a-f0-9])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'aws_access_key',
                'regex' => '~AKIA[0-9A-Z]{16,}(?![0-9A-Z])~',
                'group' => 0,
                'priority' => 90,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'jwt',
                'regex' => '~eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?![A-Za-z0-9_\-])~',
                'group' => 0,
                'priority' => 70,
                'trim' => false,
                'min' => 20,
            ],
            [
                'kind' => 'bearer',
                'regex' => '~Bearer\s+([A-Za-z0-9\-._\~+/=]{16,})~i',
                'group' => 1,
                'priority' => 50,
                'trim' => true,
                'min' => 16,
            ],
            [
                'kind' => 'basic_auth',
                'regex' => '~Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})~i',
                'group' => 1,
                'priority' => 88,
                'trim' => true,
                'min' => 8,
            ],
            [
                'kind' => 'url_userinfo',
                'regex' => '~\b(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://([^\s/:@]*:[^\s/@]+)@~i',
                'group' => 1,
                'priority' => 85,
                'trim' => false,
                'min' => 3,
            ],
        ];

        if ($pii) {
            $rules[] = [
                'kind' => 'email',
                'regex' => '~\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b~i',
                'group' => 0,
                'priority' => 30,
                'trim' => false,
                'min' => 6,
            ];
        }

        return $rules;
    }

    public static function assignmentRegex(): string
    {
        $name = '[A-Za-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|app_key|token)(?:_(?:id|key))?';

        return '~(?i)\b(' . $name . ')(\s*[=:]\s*)(?:"([^"]{6,})"|\'([^\']{6,})\'|([^\s"\'#,;]{6,}))~';
    }

    public static function isPlaceholder(string $value): bool
    {
        $v = strtolower(trim($value));
        if ($v === '' || str_starts_with($v, '[redacted:')) {
            return true;
        }

        static $exact = [
            'changeme', 'change_me', 'change-me', 'password', 'passwd', 'secret', 'token',
            'null', 'none', 'false', 'true', 'undefined', 'default', 'example', 'test',
            'testing', 'todo', 'fixme', 'xxx', 'xxxx', 'xxxxx', 'placeholder', 'redacted',
            'your_token', 'your-token', 'your_password', 'your-password', 'your_api_key',
            'insert_token', 'replace_me', 'dummy', 'dummy_value', 'required', 'optional',
            '<secret>', '<token>', '<password>', 'xxx-xxx', 'na', 'n/a',
        ];
        if (in_array($v, $exact, true)) {
            return true;
        }
        if (preg_match('/^\*+$/', $v) === 1 || preg_match('/^x+$/', $v) === 1) {
            return true;
        }
        if (preg_match('/^<[^>\s]+>$/', $v) === 1) {
            return true;
        }
        if (preg_match('/^\$\{[^}]+\}$/', $v) === 1 || preg_match('/^\$[A-Za-z_][A-Za-z0-9_]*$/', $v) === 1) {
            return true;
        }
        if (preg_match('/^%[A-Za-z0-9_]+%$/', $v) === 1) {
            return true;
        }
        if (preg_match('/^(your|replace|insert|dummy)[-_]/', $v) === 1) {
            return true;
        }
        if (str_starts_with($v, '/') || str_starts_with($v, './') || str_starts_with($v, '../')) {
            return true;
        }

        return false;
    }

    public static function ignoredEmail(string $email): bool
    {
        return preg_match('/@(example\.(com|org|net)|localhost|email\.com|domain\.com)$/i', $email) === 1;
    }

    public static function assignmentValueIsSecret(string $name, string $value): bool
    {
        if (self::isPlaceholder($value)) {
            return false;
        }

        $passwordLike = preg_match('/password|passwd|pwd|secret/i', $name) === 1;
        if ($passwordLike) {
            return strlen($value) >= 6;
        }
        if (strlen($value) >= 24) {
            return true;
        }

        return strlen($value) >= 12
            && preg_match('/[A-Za-z]/', $value) === 1
            && preg_match('/\d/', $value) === 1;
    }
}
