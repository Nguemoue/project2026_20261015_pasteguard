<?php

declare(strict_types=1);

namespace PasteGuard;

final class Web
{
    private const MAX_CHARS = 200000;

    /** @param array<string, mixed> $query @param array<string, mixed> $post */
    public static function handle(array $query, array $post): string
    {
        unset($query);

        $submitted = isset($post['example']) || array_key_exists('log', $post);
        if (!$submitted) {
            return self::page('', null, null, false);
        }

        $pii = isset($post['pii']);
        $error = null;
        $report = null;
        $input = '';

        if (isset($post['example'])) {
            $path = dirname(__DIR__) . '/examples/leaky.txt';
            $loaded = is_file($path) ? file_get_contents($path) : false;
            $input = $loaded === false ? '' : $loaded;
            if ($input === '') {
                $error = 'Exemple introuvable.';
            }
        } else {
            $input = (string) $post['log'];
        }

        if ($error === null) {
            if (strlen($input) > self::MAX_CHARS) {
                $error = 'Texte trop long pour la page (200 Ko). Passe par le CLI.';
            } elseif (str_contains($input, "\0")) {
                $error = 'Ça ressemble à un fichier binaire.';
            } else {
                $report = Redactor::redact($input, $pii, true);
            }
        }

        return self::page($input, $report, $error, $pii);
    }

    /**
     * @param array{text:string,total:int,counts:array<string,int>,findings:list<array{kind:string,line:int,fingerprint:string}>}|null $report
     */
    private static function page(string $input, ?array $report, ?string $error, bool $pii): string
    {
        $e = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $checked = $pii ? ' checked' : '';
        $alert = '';
        if ($error !== null) {
            $alert = '<p class="alert">' . $e($error) . '</p>';
        }

        $result = '';
        if ($report !== null) {
            $bits = [];
            $counts = $report['counts'];
            ksort($counts);
            foreach ($counts as $kind => $count) {
                $bits[] = $e($kind) . ' ' . $count;
            }
            $meta = $report['total'] === 0
                ? 'Rien à retirer.'
                : $report['total'] . ' secret(s) retiré(s)' . ($bits === [] ? '' : ' · ' . implode(' · ', $bits));
            $stamp = $report['total'] === 0 ? 'clean' : 'redacted';
            $result = '<section class="out">'
                . '<div class="out-head"><h2>Version collable</h2><p>' . $meta . '</p></div>'
                . '<pre id="out">' . $e($report['text']) . '</pre>'
                . '<button type="button" class="ghost" id="copy">Copier</button>'
                . '<p class="stamp ' . $stamp . '">' . ($report['total'] === 0 ? 'Déjà collable' : 'Secrets retirés') . '</p>'
                . '</section>'
                . '<script>'
                . 'document.getElementById("copy").addEventListener("click",function(){'
                . 'var t=document.getElementById("out").textContent;'
                . 'var b=this;'
                . 'navigator.clipboard.writeText(t).then(function(){b.textContent="Copié";});'
                . '});'
                . '</script>';
        }

        return '<!DOCTYPE html>'
            . '<html lang="fr"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>PasteGuard</title>'
            . '<style>' . self::css() . '</style></head><body>'
            . '<main>'
            . '<p class="kicker">Avant de coller le log</p>'
            . '<h1>PasteGuard</h1>'
            . '<p class="lead">Un log de prod contient souvent une clé, un JWT, un mot de passe. Cette page en fait une version collable. Ça reste sur ta machine : rien n’est envoyé.</p>'
            . '<form method="post" autocomplete="off">'
            . '<label for="log">Log, .env, ou sortie de commande</label>'
            . '<textarea id="log" name="log" spellcheck="false" placeholder="Colle ici…">' . $e($input) . '</textarea>'
            . '<div class="row">'
            . '<label class="check"><input type="checkbox" name="pii" value="1"' . $checked . '> Masquer aussi les e-mails</label>'
            . '<div class="actions">'
            . '<button type="submit" name="example" value="1" class="ghost">Charger l’exemple</button>'
            . '<button type="submit">Rendre collable</button>'
            . '</div></div>'
            . $alert
            . '</form>'
            . $result
            . '<p class="foot">Ne déploie pas ce formulaire sur un serveur public : le texte passerait par cette machine. En CI : <code>php bin/pasteguard --check le.log</code></p>'
            . '</main></body></html>';
    }

    private static function css(): string
    {
        return <<<CSS
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #efe7d6;
  color: #211c16;
  font: 18px/1.45 Georgia, "Iowan Old Style", Palatino, serif;
}
main { max-width: 920px; margin: 0 auto; padding: 48px 20px 72px; }
.kicker {
  margin: 0 0 8px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  font: 12px/1 ui-sans-serif, system-ui, sans-serif;
  color: #8a3d28;
}
h1 { margin: 0 0 12px; font-size: 64px; font-weight: 500; letter-spacing: -0.03em; }
.lead { margin: 0 0 28px; max-width: 38em; font-size: 20px; }
form, .out {
  background: #f7f3ea;
  border: 1px solid #ddcbb3;
  padding: 18px;
}
label { display: block; font: 13px/1 ui-sans-serif, system-ui, sans-serif; margin-bottom: 8px; }
textarea {
  width: 100%;
  min-height: 220px;
  resize: vertical;
  border: 1px solid #ddcbb3;
  background: #fffdf8;
  color: #211c16;
  padding: 12px;
  font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.row { display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between; align-items: center; margin-top: 12px; }
.check { display: flex; gap: 8px; align-items: center; margin: 0; font: 14px/1.3 ui-sans-serif, system-ui, sans-serif; }
.actions { display: flex; gap: 8px; }
button, .ghost {
  border: 1px solid #211c16;
  background: #211c16;
  color: #f7f3ea;
  padding: 10px 14px;
  font: 14px/1 ui-sans-serif, system-ui, sans-serif;
  cursor: pointer;
}
.ghost { background: transparent; color: #211c16; }
button:hover { transform: translateY(-1px); }
.alert { color: #8a3d28; font: 14px/1.4 ui-sans-serif, system-ui, sans-serif; }
.out { margin-top: 18px; position: relative; }
.out-head h2 { margin: 0 0 4px; font-size: 28px; font-weight: 500; }
.out-head p { margin: 0 0 12px; font: 13px/1.4 ui-sans-serif, system-ui, sans-serif; color: #5e564c; }
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  background: #211c16;
  color: #f3ead8;
  padding: 14px;
  font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.stamp {
  position: absolute;
  top: 18px;
  right: 18px;
  margin: 0;
  border: 2px solid #b43324;
  color: #b43324;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font: 700 12px/1 ui-sans-serif, system-ui, sans-serif;
  padding: 6px 8px;
  transform: rotate(8deg);
}
.stamp.clean { border-color: #1f6b45; color: #1f6b45; }
.foot { margin: 18px 0 0; color: #5e564c; font: 14px/1.4 ui-sans-serif, system-ui, sans-serif; }
code { font: 13px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
@media (max-width: 640px) {
  h1 { font-size: 42px; }
  .stamp { position: static; display: inline-block; transform: none; margin-bottom: 8px; }
}
CSS;
    }
}
