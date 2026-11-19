<?php
/**
 * Nagybani Gastro – rendelés-visszaigazoló e-mail
 *
 * Feltöltés: ugyanoda, ahol az index.html van (cPanel → Fájlkezelő → public_html).
 * Az index.html-ben a MAIL_ENDPOINT = "send-order.php".
 *
 * A levél a saját domainről megy ki a cPanel levelezőn (PHP mail()).
 * Előfeltétel: a rendeles@nagybanigastro.hu cím létezik a cPanelben
 * (cPanel → Email Accounts), és a domainen be van állítva az SPF/DKIM
 * (cPanel → Email Deliverability: "Repair" gomb).
 */

// ---- Beállítások ----
const FROM_EMAIL    = 'rendeles@nagybanigastro.hu';
const FROM_NAME     = 'Nagybani Gastro Zrt.';
const NOTIFY_EMAIL  = '';   // később: ide jön az értesítő új rendelésről (pl. 'rendeles@nagybanigastro.hu')
const ALLOWED_ORIGINS = [   // honnan érkezhet kérés. Ugyanazon a domainen az Origin fejléc üres vagy egyezik.
    'https://nagybanigastro.hu',
    'https://www.nagybanigastro.hu',
    // 'https://FELHASZNALO.github.io',   // ha GitHub Pages-en fut az index.html
];
const MAX_ITEMS = 200;

header('Content-Type: application/json; charset=utf-8');

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

// ---- CORS ----
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    if (!in_array($origin, ALLOWED_ORIGINS, true)) fail(403, 'Nem engedélyezett eredet.');
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(204); exit; }
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST')     fail(405, 'Csak POST engedélyezett.');

// ---- Bemenet ----
$raw  = file_get_contents('php://input');
if ($raw === false || strlen($raw) > 100000) fail(413, 'Túl nagy kérés.');
$data = json_decode($raw, true);
if (!is_array($data)) fail(400, 'Hibás kérés.');

$company = trim((string)($data['company'] ?? ''));
$email   = trim((string)($data['email'] ?? ''));
$date    = (string)($data['deliveryDate'] ?? '');
$time    = (string)($data['arriveFrom'] ?? '');
$items   = $data['items'] ?? [];

if ($company === '' || mb_strlen($company) > 150)                       fail(422, 'Hibás cégnév.');
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) fail(422, 'Hibás e-mail cím.');
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date))                        fail(422, 'Hibás dátum.');
if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $time))                  fail(422, 'Hibás időpont.');
if (!is_array($items) || count($items) === 0 || count($items) > MAX_ITEMS) fail(422, 'Hibás tétellista.');

// ---- Egyszerű korlát: ugyanarra a címre percenként legfeljebb 1 levél ----
$lockFile = sys_get_temp_dir() . '/nb_mail_' . md5(strtolower($email));
if (is_file($lockFile) && time() - filemtime($lockFile) < 60) fail(429, 'Túl sok kérés, próbálja újra egy perc múlva.');
@touch($lockFile);

// ---- Tartalom ----
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fmtQty = fn($n) => rtrim(rtrim(number_format((float)$n, 1, ',', ''), '0'), ',');
[$y, $m, $d] = explode('-', $date);
$dateHu = "$y. $m. $d.";

$textLines = []; $rows = '';
foreach ($items as $it) {
    $name = trim((string)($it['name'] ?? ''));
    $unit = trim((string)($it['unit'] ?? ''));
    $qty  = (float)($it['qty'] ?? 0);
    if ($name === '' || $qty <= 0 || mb_strlen($name) > 120 || mb_strlen($unit) > 20) continue;
    $q = $fmtQty($qty);
    $textLines[] = "- $name: $q $unit";
    $rows .= '<tr><td style="padding:9px 12px;border-bottom:1px solid #e3e9d6">' . $h($name) . '</td>'
           . '<td style="padding:9px 12px;border-bottom:1px solid #e3e9d6;text-align:right;white-space:nowrap;font-weight:700;color:#61672c">'
           . $h("$q $unit") . '</td></tr>';
}
if (!$textLines) fail(422, 'Nincs érvényes tétel.');

$text = "Kedves Partnerünk!\n\nA megrendelését rögzítettük! Köszönjük!\n\n"
      . "Cég: $company\nSzállítás napja: $dateHu\nÉrkezés az áruval: $time-tól\n\n"
      . "Rendelt tételek:\n" . implode("\n", $textLines)
      . "\n\nÜdvözlettel,\nNagybani Gastro Zrt.\n";

$html = '<!DOCTYPE html><html lang="hu"><body style="margin:0;background:#f3f6ea;font-family:Arial,Helvetica,sans-serif;color:#1b2a10">'
  . '<div style="max-width:560px;margin:0 auto;padding:24px">'
  . '<div style="background:#244016;color:#f4f9e8;border-radius:16px 16px 0 0;padding:22px 24px">'
  . '<div style="font-size:22px;font-weight:700">Nagybani Gastro</div>'
  . '<div style="font-size:12px;margin-top:4px;opacity:.85">Frissesség • Minőség • Megbízhatóság</div></div>'
  . '<div style="height:6px;background:linear-gradient(90deg,#82a241,#f2c230,#f08a24,#d9412f)"></div>'
  . '<div style="background:#fff;padding:24px;border-radius:0 0 16px 16px">'
  . '<p style="margin:0 0 10px;font-size:16px">Kedves Partnerünk!</p>'
  . '<p style="margin:0 0 18px;font-size:16px"><b>A megrendelését rögzítettük! Köszönjük!</b></p>'
  . '<table style="width:100%;font-size:14px;margin-bottom:18px">'
  . '<tr><td style="padding:4px 0;color:#5d6a46">Cég</td><td style="text-align:right;font-weight:700">' . $h($company) . '</td></tr>'
  . '<tr><td style="padding:4px 0;color:#5d6a46">Szállítás napja</td><td style="text-align:right;font-weight:700">' . $h($dateHu) . '</td></tr>'
  . '<tr><td style="padding:4px 0;color:#5d6a46">Érkezés az áruval</td><td style="text-align:right;font-weight:700">' . $h($time) . '-tól</td></tr></table>'
  . '<p style="margin:0 0 6px;font-weight:700">Rendelt tételek</p>'
  . '<table style="width:100%;border-collapse:collapse;font-size:14px">' . $rows . '</table>'
  . '<p style="margin:24px 0 0;font-size:15px">Üdvözlettel,<br><b>Nagybani Gastro Zrt.</b></p>'
  . '</div></div></body></html>';

// ---- Küldés (multipart: szöveg + HTML) ----
function send_mail(string $to, string $subject, string $text, string $html, string $replyTo = FROM_EMAIL): bool {
    $boundary = 'nb_' . bin2hex(random_bytes(8));
    $from = '=?UTF-8?B?' . base64_encode(FROM_NAME) . '?= <' . FROM_EMAIL . '>';
    $headers  = "From: $from\r\n";
    $headers .= "Reply-To: $replyTo\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";
    $body  = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
           . chunk_split(base64_encode($text))
           . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
           . chunk_split(base64_encode($html))
           . "--$boundary--";
    $subj = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    return mail($to, $subj, $body, $headers, '-f' . FROM_EMAIL);
}

$sent = send_mail($email, 'Megrendelését rögzítettük – Nagybani Gastro', $text, $html);
if (!$sent) {
    @unlink($lockFile);
    error_log('send-order.php: mail() sikertelen: ' . $email);
    fail(500, 'Az e-mail küldése nem sikerült.');
}

// Később: értesítő a cégnek (alapból ki van kapcsolva, amíg a NOTIFY_EMAIL üres)
if (NOTIFY_EMAIL !== '') {
    send_mail(NOTIFY_EMAIL, "Új megrendelés – $company", "Új megrendelés érkezett.\n\n" . $text, $html, $email);
}

echo json_encode(['ok' => true]);
