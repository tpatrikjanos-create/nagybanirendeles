<?php
/**
 * Nagybani Gastro – rendelés fogadása és visszaigazoló e-mail
 *
 * Feltöltés: az index.html mellé (cPanel → Fájlkezelő → public_html).
 * A szkript első futáskor létrehozza a "rendelesek" mappát (rendelésszám-számláló,
 * napló, korlátozás), és lezárja a böngészős hozzáférés elől.
 *
 * Előfeltétel: a rendeles@nagybanigastro.hu cím létezik a cPanelben,
 * és az Email Deliverability menüben az SPF/DKIM rendben van ("Repair").
 */

// ================= Beállítások =================
const FROM_EMAIL   = 'rendeles@nagybanigastro.hu';
const FROM_NAME    = 'Nagybani Gastro Zrt.';
const NOTIFY_EMAIL = '';          // később: értesítő a cégnek új rendelésről, pl. 'rendeles@nagybanigastro.hu'
const ALLOWED_ORIGINS = [
    'https://nagybanigastro.hu',
    'https://www.nagybanigastro.hu',
    'https://tpatrikjanos-create.github.io',   // GitHub Pages
];
const TURNSTILE_SECRET = '';      // Cloudflare Turnstile titkos kulcs (ha az index.html-ben a site key ki van töltve)
const TZ           = 'Europe/Budapest';
const CUTOFF_HOUR  = 13;          // tisztított áru: 13:00-ig leadva másnapra, utána holnaputánra
const MAX_ITEMS    = 200;
const IP_LIMIT     = 5;           // ennyi rendelés ...
const IP_WINDOW    = 600;         // ... ennyi másodperc alatt egy IP-címről
const DATA_DIR     = __DIR__ . '/rendelesek';
// ==============================================

date_default_timezone_set(TZ);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

function out(int $code, array $body): void {
    http_response_code($code);
    echo json_encode($body, JSON_UNESCAPED_UNICODE);
    exit;
}
function fail(int $code, string $msg, string $field = ''): void {
    out($code, ['ok' => false, 'error' => $msg] + ($field ? ['field' => $field] : []));
}

// ---- CORS ----
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$sameOrigin = $origin !== '' && strcasecmp((string)parse_url($origin, PHP_URL_HOST) . (parse_url($origin, PHP_URL_PORT) ? ':' . parse_url($origin, PHP_URL_PORT) : ''), (string)($_SERVER['HTTP_HOST'] ?? '')) === 0;
if ($origin !== '') {
    if (!$sameOrigin && !in_array($origin, ALLOWED_ORIGINS, true)) fail(403, 'Nem engedélyezett eredet.');
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'OPTIONS') { http_response_code(204); exit; }
if ($method !== 'POST') fail(405, 'Csak POST engedélyezett.');

// ---- Adatmappa (védett) ----
if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0750, true);
if (!is_file(DATA_DIR . '/.htaccess')) @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");

// ---- Bemenet ----
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > 100000) fail(413, 'Túl nagy kérés.');
$data = json_decode($raw, true);
if (!is_array($data)) fail(400, 'Hibás kérés.');

// Csapdamező: ember nem tölti ki. Robotnak "sikert" mondunk, de nem csinálunk semmit.
if (trim((string)($data['website'] ?? '')) !== '') out(200, ['ok' => true, 'orderNo' => 'NB-0000']);

// ---- IP-korlát ----
$ip = $_SERVER['REMOTE_ADDR'] ?? 'x';
$rlFile = DATA_DIR . '/ratelimit.json';
$fh = fopen($rlFile, 'c+');
if ($fh && flock($fh, LOCK_EX)) {
    $rl = json_decode(stream_get_contents($fh) ?: '{}', true) ?: [];
    $now = time();
    foreach ($rl as $k => $ts) { $rl[$k] = array_values(array_filter($ts, fn($t) => $now - $t < IP_WINDOW)); if (!$rl[$k]) unset($rl[$k]); }
    $key = hash('sha256', $ip);
    if (count($rl[$key] ?? []) >= IP_LIMIT) { flock($fh, LOCK_UN); fclose($fh); fail(429, 'Túl sok rendelés rövid idő alatt. Próbálja újra pár perc múlva, vagy hívjon minket: +36 70 7729 373.'); }
    $rl[$key][] = $now;
    ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($rl));
    flock($fh, LOCK_UN); fclose($fh);
}

// ---- Turnstile (ha be van állítva) ----
if (TURNSTILE_SECRET !== '') {
    $ctx = stream_context_create(['http' => [
        'method' => 'POST', 'timeout' => 8,
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query(['secret' => TURNSTILE_SECRET, 'response' => (string)($data['turnstile'] ?? ''), 'remoteip' => $ip]),
    ]]);
    $v = json_decode((string)@file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false, $ctx), true);
    if (empty($v['success'])) fail(403, 'Az ellenőrzés nem sikerült. Frissítse az oldalt, és próbálja újra.');
}

// ---- Mezők ----
$company = trim((string)($data['company'] ?? ''));
$email   = trim((string)($data['email'] ?? ''));
$date    = (string)($data['deliveryDate'] ?? '');
$time    = (string)($data['arriveFrom'] ?? '');
$items   = $data['items'] ?? [];

if ($company === '' || mb_strlen($company) > 150 || preg_match('/[\r\n]/', $company)) fail(422, 'Adja meg a cég nevét.', 'company');
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email))   fail(422, 'Hibás e-mail cím.', 'email');
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) || !strtotime($date))               fail(422, 'Hibás dátum.', 'date');
if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $time))                              fail(422, 'Hibás időpont.', 'time');
if (!is_array($items) || !$items || count($items) > MAX_ITEMS)                      fail(422, 'Hibás tétellista.', 'cart');

$clean = []; $hasCleaned = false;
foreach ($items as $it) {
    $name = trim((string)($it['name'] ?? ''));
    $unit = trim((string)($it['unit'] ?? ''));
    $qty  = (float)($it['qty'] ?? 0);
    if ($name === '' || $qty <= 0 || $qty > 9999 || mb_strlen($name) > 120 || mb_strlen($unit) > 20) continue;
    $isCleaned = !empty($it['cleaned']);
    $hasCleaned = $hasCleaned || $isCleaned;
    $clean[] = ['name' => $name, 'unit' => $unit, 'qty' => $qty, 'cleaned' => $isCleaned];
}
if (!$clean) fail(422, 'Nincs érvényes tétel.', 'cart');

// ---- Szállítási nap ellenőrzése (budapesti idő) ----
$today = new DateTimeImmutable('today');
$hour  = (int)(new DateTimeImmutable('now'))->format('G');
$min   = $hasCleaned ? $today->modify($hour < CUTOFF_HOUR ? '+1 day' : '+2 days') : $today;
while ($min->format('w') === '0') $min = $min->modify('+1 day');
$req = DateTimeImmutable::createFromFormat('!Y-m-d', $date);
if ($req->format('w') === '0') fail(422, 'Vasárnap nem szállítunk. Válasszon másik napot.', 'date');
if ($req < $min) {
    $msg = $hasCleaned
        ? 'A tisztított áru 13:00 után legkorábban holnaputánra kérhető. Válasszon későbbi napot.'
        : 'Ez a nap már nem választható.';
    fail(422, $msg, 'date');
}
if ($req > $today->modify('+60 days')) fail(422, 'Legfeljebb 60 nappal előre lehet rendelni.', 'date');

// ---- Rendelésszám ----
$orderNo = 'NB-' . date('ymd-His');
$cf = fopen(DATA_DIR . '/counter.txt', 'c+');
if ($cf && flock($cf, LOCK_EX)) {
    $n = (int)stream_get_contents($cf) + 1;
    ftruncate($cf, 0); rewind($cf); fwrite($cf, (string)$n);
    flock($cf, LOCK_UN); fclose($cf);
    $orderNo = 'NB-' . str_pad((string)$n, 4, '0', STR_PAD_LEFT);
}

// ---- Napló (biztonsági másolat a Firebase mellé) ----
@file_put_contents(DATA_DIR . '/orders.jsonl', json_encode([
    'orderNo' => $orderNo, 'at' => date('c'), 'company' => $company, 'email' => $email,
    'deliveryDate' => $date, 'arriveFrom' => $time, 'items' => $clean, 'ip' => hash('sha256', $ip),
], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);

// ---- E-mail tartalom ----
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fmtQty = fn($n) => rtrim(rtrim(number_format((float)$n, 2, ',', ''), '0'), ',');
$napok = ['vasárnap','hétfő','kedd','szerda','csütörtök','péntek','szombat'];
$dateHu = $req->format('Y. m. d.') . ', ' . $napok[(int)$req->format('w')];

$textLines = []; $rows = '';
foreach ($clean as $it) {
    $q = $fmtQty($it['qty']);
    $textLines[] = "- {$it['name']}: $q {$it['unit']}";
    $rows .= '<tr><td style="padding:9px 12px;border-bottom:1px solid #e3e9d6">' . $h($it['name']) . '</td>'
           . '<td style="padding:9px 12px;border-bottom:1px solid #e3e9d6;text-align:right;white-space:nowrap;font-weight:700;color:#4f8a27">'
           . $h("$q {$it['unit']}") . '</td></tr>';
}

$text = "Kedves Partnerünk!\n\nA megrendelését rögzítettük! Köszönjük!\n\n"
      . "Rendelésszám: $orderNo\nCég: $company\nSzállítás napja: $dateHu\nÉrkezés az áruval: $time órától\n\n"
      . "Rendelt tételek:\n" . implode("\n", $textLines)
      . "\n\nÜdvözlettel,\nNagybani Gastro Zrt.\n";

$html = '<!DOCTYPE html><html lang="hu"><body style="margin:0;background:#f5f8ef;font-family:Arial,Helvetica,sans-serif;color:#16381b">'
  . '<div style="max-width:560px;margin:0 auto;padding:24px">'
  . '<div style="background:#16381b;color:#fff;border-radius:16px 16px 0 0;padding:22px 24px">'
  . '<div style="font-size:22px;font-weight:700">Nagybani Gastro</div>'
  . '<div style="font-size:12px;margin-top:4px;color:#b9d79a">Frissesség • Minőség • Megbízhatóság</div></div>'
  . '<div style="height:6px;background:#6fa838;background:linear-gradient(90deg,#6fa838,#f5c22c,#f0882a,#e0442f)"></div>'
  . '<div style="background:#fff;padding:24px;border-radius:0 0 16px 16px">'
  . '<p style="margin:0 0 10px;font-size:16px">Kedves Partnerünk!</p>'
  . '<p style="margin:0 0 18px;font-size:16px"><b>A megrendelését rögzítettük! Köszönjük!</b></p>'
  . '<table style="width:100%;font-size:14px;margin-bottom:18px">'
  . '<tr><td style="padding:4px 0;color:#5f6d55">Rendelésszám</td><td style="text-align:right;font-weight:700">' . $h($orderNo) . '</td></tr>'
  . '<tr><td style="padding:4px 0;color:#5f6d55">Cég</td><td style="text-align:right;font-weight:700">' . $h($company) . '</td></tr>'
  . '<tr><td style="padding:4px 0;color:#5f6d55">Szállítás napja</td><td style="text-align:right;font-weight:700">' . $h($dateHu) . '</td></tr>'
  . '<tr><td style="padding:4px 0;color:#5f6d55">Érkezés az áruval</td><td style="text-align:right;font-weight:700">' . $h($time) . ' órától</td></tr></table>'
  . '<p style="margin:0 0 6px;font-weight:700">Rendelt tételek</p>'
  . '<table style="width:100%;border-collapse:collapse;font-size:14px">' . $rows . '</table>'
  . '<p style="margin:24px 0 0;font-size:15px">Üdvözlettel,<br><b>Nagybani Gastro Zrt.</b></p>'
  . '</div></div></body></html>';

function send_mail(string $to, string $subject, string $text, string $html, string $replyTo = FROM_EMAIL): bool {
    $b = 'nb_' . bin2hex(random_bytes(8));
    $headers  = 'From: =?UTF-8?B?' . base64_encode(FROM_NAME) . '?= <' . FROM_EMAIL . ">\r\n";
    $headers .= "Reply-To: $replyTo\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"$b\"\r\n";
    $body  = "--$b\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($text))
           . "--$b\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($html))
           . "--$b--";
    return mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers, '-f' . FROM_EMAIL);
}

$sent = send_mail($email, "Megrendelését rögzítettük ($orderNo) – Nagybani Gastro", $text, $html);
if (NOTIFY_EMAIL !== '') {
    send_mail(NOTIFY_EMAIL, "Új megrendelés $orderNo – $company", "Új megrendelés érkezett.\n\n" . $text, $html, $email);
}
if (!$sent) {
    error_log("send-order.php: mail() sikertelen ($orderNo, $email)");
    // A rendelés a naplóban rögzítve van, csak a levél nem ment ki.
    out(200, ['ok' => false, 'orderNo' => $orderNo, 'error' => 'Az e-mail küldése nem sikerült.']);
}
out(200, ['ok' => true, 'orderNo' => $orderNo]);
