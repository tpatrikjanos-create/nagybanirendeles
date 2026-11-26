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
const NOTIFY_EMAIL = 'info@nagybanigastro.hu';  // értesítő a cégnek minden új rendelésről
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
$PAY = ['kártya' => 'Kártya', 'készpénz' => 'Készpénz', 'átutalás' => 'Átutalás'];
$payment = (string)($data['payment'] ?? '');
if (!isset($PAY[$payment])) $payment = '';
$source = in_array($data['source'] ?? '', ['web', 'email', 'photo', 'chat', 'voice', 'admin'], true) ? $data['source'] : 'web';

$clean = []; $hasCleaned = false;
foreach ($items as $it) {
    $name = trim((string)($it['name'] ?? ''));
    $unit = trim((string)($it['unit'] ?? ''));
    $qty  = (float)($it['qty'] ?? 0);
    if ($name === '' || $qty <= 0 || $qty > 9999 || mb_strlen($name) > 160 || mb_strlen($unit) > 20) continue;
    $isCleaned = !empty($it['cleaned']);
    $hasCleaned = $hasCleaned || $isCleaned;
    $one = fn($k, $n) => preg_replace('/\s+/u', ' ', mb_substr(trim((string)($it[$k] ?? '')), 0, $n));
    $clean[] = [
        'name' => $name, 'product' => $one('product', 120) ?: $name, 'variant' => $one('variant', 40),
        'category' => $one('category', 60) ?: 'Egyéb', 'unit' => $unit, 'qty' => $qty,
        'cleaned' => $isCleaned, 'note' => $one('note', 120), 'custom' => !empty($it['custom']),
    ];
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
    'deliveryDate' => $date, 'arriveFrom' => $time, 'payment' => $payment, 'source' => $source,
    'items' => $clean, 'ip' => hash('sha256', $ip),
], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);

// =====================================================================
//  E-MAILEK – az oldal mattüveg dizájnjához igazítva.
//  A levelezők nem ismerik az elmosást, ezért halvány zöldes háttér
//  + fehér, lekerekített kártyák adják az üveg hatását.
//  Logó és teherautó beágyazott képként (cid), így a Gmail sem tiltja le.
// =====================================================================
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fmtQty = fn($n) => rtrim(rtrim(number_format((float)$n, 2, ',', ''), '0'), ',');
$napok = ['vasárnap','hétfő','kedd','szerda','csütörtök','péntek','szombat'];
$honapok = ['január','február','március','április','május','június','július','augusztus','szeptember','október','november','december'];
$honapR = ['jan.','febr.','márc.','ápr.','máj.','jún.','júl.','aug.','szept.','okt.','nov.','dec.'];
$wd = $napok[(int)$req->format('w')];
$dateLong  = ucfirst($wd) . ', ' . $honapok[(int)$req->format('n') - 1] . ' ' . $req->format('j') . '.';
$dateShort = $wd . ', ' . $honapR[(int)$req->format('n') - 1] . ' ' . $req->format('j') . '.';
$placedAt  = $honapR[(int)date('n') - 1] . ' ' . date('j') . '. ' . date('H:i');
$payLabel  = $payment !== '' ? $PAY[$payment] : '';
$SOURCE = ['web' => 'Webes rendelés', 'email' => 'E-mailes rendelés', 'photo' => 'Fotóról kiolvasott rendelés',
           'chat' => 'AI-csevegős rendelés', 'voice' => 'Szóban leadott rendelés', 'admin' => 'Admin rögzítette'];

$CAT_COLOR = [
    'Zöldségek' => '#f0882a', 'Paprika, paradicsom, padlizsán' => '#e0442f', 'Burgonya, hagyma' => '#c98f4e',
    'Káposzta, saláta' => '#6fa838', 'Uborka, cukkini, tök' => '#3f7d2a', 'Gomba' => '#9a7b63',
    'Fűszernövények' => '#3b8a4a', 'Gyümölcs' => '#e0442f', 'Egzotikus gyümölcsök' => '#e8a910',
    'Száraz áru' => '#a8683a', 'Tojások' => '#d9a066', 'Csíra' => '#6fa838', 'Savanyúságok' => '#8a4fb0',
    'Konyhakész, tisztított termékek' => '#3b8ea5', 'Egyéb' => '#56614f',
];
// Kategóriák a vevő sorrendjében
$groups = [];
foreach ($clean as $it) $groups[$it['category']][] = $it;

$cleanedCount = count(array_filter($clean, fn($i) => $i['cleaned']));
$customCount  = count(array_filter($clean, fn($i) => $i['custom']));
$noteCount    = count(array_filter($clean, fn($i) => $i['note'] !== ''));

$LOGO  = is_file(__DIR__ . '/logo-mail.png')  ? __DIR__ . '/logo-mail.png'  : '';
$TRUCK = is_file(__DIR__ . '/truck-mail.png') ? __DIR__ . '/truck-mail.png' : '';

$INK = '#17210f'; $MUTED = '#56614f'; $GREEN = '#2f8a3c'; $GREEN_D = '#256f30'; $MINT = '#e8f2e4'; $LINE = '#e6ebe2';
$FONT = "font-family:'Manrope','Segoe UI',Helvetica,Arial,sans-serif";
$card = fn($inner, $pad = '22px 24px', $extra = '') =>
    '<tr><td style="padding:0 0 12px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:separate;background:#ffffff;border:1px solid #ffffff;border-radius:22px;' . $extra . '">'
  . '<tr><td style="padding:' . $pad . '">' . $inner . '</td></tr></table></td></tr>';
$pill = fn($t, $bg, $fg) => '<span style="display:inline-block;padding:3px 9px;border-radius:999px;background:' . $bg . ';color:' . $fg . ';font-size:11.5px;font-weight:800;line-height:1.4;white-space:nowrap">' . $t . '</span>';

$headerCard = function (string $badge) use ($h, $LOGO, $INK, $MUTED, $GREEN, $card) {
    $logo = $LOGO ? '<img src="cid:logo@nagybani" width="56" height="56" alt="Nagybani Gastro" style="display:block;border:0;border-radius:50%">' : '';
    return $card(
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>'
      . ($logo ? '<td width="64" style="vertical-align:middle">' . $logo . '</td>' : '')
      . '<td style="vertical-align:middle"><div style="font-size:19px;font-weight:800;letter-spacing:-.3px;color:' . $INK . '">Nagybani Gastro</div>'
      . '<div style="font-size:12px;color:' . $MUTED . ';margin-top:2px">Frissesség · Minőség · Megbízhatóság</div></td>'
      . '<td align="right" style="vertical-align:middle">' . $badge . '</td></tr></table>',
        '16px 20px', 'border-top:4px solid ' . $GREEN . ';');
};
$summaryCell = fn($label, $value, $bg = '#f4f7f2', $fg = '#17210f') =>
    '<td width="50%" style="padding:5px;vertical-align:top"><div style="background:' . $bg . ';border-radius:16px;padding:12px 14px">'
  . '<div style="font-size:12px;font-weight:700;color:' . ($fg === '#17210f' ? '#56614f' : $fg) . ';opacity:.85">' . $label . '</div>'
  . '<div style="font-size:16.5px;font-weight:800;color:' . $fg . ';margin-top:3px">' . $value . '</div></div></td>';

// ---------- Tételsorok kategóriánként ----------
$itemRows = function (bool $internal) use ($groups, $CAT_COLOR, $h, $fmtQty, $pill, $INK, $MUTED, $GREEN_D, $MINT, $LINE) {
    $out = '';
    foreach ($groups as $cat => $list) {
        $col = $CAT_COLOR[$cat] ?? '#56614f';
        $out .= '<tr><td colspan="' . ($internal ? 3 : 2) . '" style="padding:16px 0 6px">'
              . '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' . $col . ';margin-right:8px;vertical-align:middle"></span>'
              . '<span style="font-size:13px;font-weight:800;color:' . $MUTED . ';vertical-align:middle">' . $h($cat) . ' · ' . count($list) . '</span></td></tr>';
        foreach ($list as $it) {
            $q = $fmtQty($it['qty']) . ' ' . $it['unit'];
            $title = $it['custom'] ? $it['name'] : $it['product'];
            $sub = [];
            if ($it['variant'] !== '') $sub[] = $h($it['variant']);
            $tags = ($it['cleaned'] ? ' ' . $pill('tisztított', '#e3f1f5', '#2b6f85') : '')
                  . ($it['custom'] ? ' ' . $pill($internal ? 'nincs a listában' : 'egyeztetjük', '#fdeedd', '#9a5a1c') : '');
            $note = $it['note'] !== ''
                ? '<div style="margin-top:4px;font-size:13px;' . ($internal ? 'font-weight:800;color:#9a5a1c' : 'font-style:italic;color:' . $MUTED) . '">' . ($internal ? 'Megjegyzés: ' : '„') . $h($it['note']) . ($internal ? '' : '”') . '</div>'
                : '';
            $out .= '<tr>'
                . ($internal ? '<td width="30" style="padding:11px 0;border-top:1px solid ' . $LINE . ';vertical-align:top"><div style="width:18px;height:18px;border:2px solid #b9c4b2;border-radius:6px"></div></td>' : '')
                . '<td style="padding:11px 0;border-top:1px solid ' . $LINE . ';vertical-align:top">'
                . '<div style="font-size:' . ($internal ? '16.5' : '15.5') . 'px;font-weight:700;color:' . $INK . '">' . $h($title) . $tags . '</div>'
                . ($sub ? '<div style="font-size:13px;color:' . $MUTED . ';margin-top:2px">' . implode(' · ', $sub) . '</div>' : '')
                . $note . '</td>'
                . '<td align="right" style="padding:11px 0 11px 12px;border-top:1px solid ' . $LINE . ';vertical-align:top;white-space:nowrap">'
                . '<span style="display:inline-block;padding:6px 12px;border-radius:999px;background:' . ($internal ? $INK : $MINT) . ';color:' . ($internal ? '#ffffff' : $GREEN_D) . ';font-size:' . ($internal ? '16' : '14.5') . 'px;font-weight:800">' . $h($q) . '</span></td></tr>';
        }
    }
    return '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">' . $out . '</table>';
};

$wrap = fn($preheader, $rows) => '<!DOCTYPE html><html lang="hu"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light only"></head>'
  . '<body style="margin:0;padding:0;background:#eef1ec;' . $FONT . ';color:#17210f">'
  . '<div style="display:none;max-height:0;overflow:hidden;opacity:0">' . $h($preheader) . '</div>'
  . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#eef1ec;background-image:linear-gradient(160deg,#e3f0dc 0%,#f4f6f1 45%,#fbe9d9 100%)"><tr><td align="center" style="padding:22px 12px">'
  . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px">' . $rows . '</table>'
  . '</td></tr></table></body></html>';

// ---------- 1) Vevő levele ----------
$truckImg = $TRUCK ? '<img src="cid:truck@nagybani" width="200" alt="" style="display:block;border:0;width:200px;max-width:100%;height:auto">' : '';
$heroInner = '<div style="font-size:15px;color:' . $MUTED . '">Kedves Partnerünk!</div>'
  . '<div style="font-size:26px;line-height:1.15;font-weight:800;letter-spacing:-.5px;color:' . $INK . ';margin:6px 0 8px">A megrendelését rögzítettük! Köszönjük!</div>'
  . '<div style="font-size:14.5px;line-height:1.5;color:' . $MUTED . '">Az alábbiakban összefoglaltuk, mit és mikorra kért. Ha valamit módosítana, válaszoljon erre a levélre, vagy hívjon minket.</div>'
  . ($truckImg ? '<div style="margin-top:14px">' . $truckImg . '</div>' : '');
$summary = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:-5px">'
  . '<tr>' . $summaryCell('Konyha', $h($company)) . $summaryCell('Rendelésszám', $h($orderNo)) . '</tr>'
  . '<tr>' . $summaryCell('Szállítás napja', $h($dateLong), $GREEN, '#ffffff') . $summaryCell('Érkezés az áruval', $h($time) . ' órától', '#fde9b0', '#5c4300') . '</tr>'
  . '<tr>' . $summaryCell('Fizetés', $payLabel !== '' ? $h($payLabel) : '<span style="font-weight:600;color:' . $MUTED . '">Nem adta meg</span>') . $summaryCell('Leadva', $h($placedAt)) . '</tr></table>';
$tips = '<div style="font-size:15px;font-weight:800;color:' . $INK . ';margin-bottom:8px">Jó tudni</div>'
  . '<table role="presentation" cellspacing="0" cellpadding="0" style="font-size:14px;line-height:1.5;color:' . $MUTED . '">'
  . '<tr><td style="padding:3px 10px 3px 0;vertical-align:top;color:' . $GREEN . ';font-weight:800">✓</td><td style="padding:3px 0">Módosítás vagy kérdés esetén válaszoljon erre a levélre, vagy hívja a <a href="tel:+36707729373" style="color:' . $GREEN_D . ';font-weight:800;text-decoration:none">+36 70 7729 373</a> számot.</td></tr>'
  . ($cleanedCount ? '<tr><td style="padding:3px 10px 3px 0;vertical-align:top;color:' . $GREEN . ';font-weight:800">✓</td><td style="padding:3px 0">A tisztított, konyhakész árut 13:00-ig leadva másnapra, utána holnaputánra tudjuk szállítani.</td></tr>' : '')
  . ($customCount ? '<tr><td style="padding:3px 10px 3px 0;vertical-align:top;color:' . $GREEN . ';font-weight:800">✓</td><td style="padding:3px 0">A listában nem szereplő tételekkel kapcsolatban hamarosan keressük.</td></tr>' : '')
  . '<tr><td style="padding:3px 10px 3px 0;vertical-align:top;color:' . $GREEN . ';font-weight:800">✓</td><td style="padding:3px 0">Vasárnap nem szállítunk.</td></tr></table>';
$sign = '<div style="font-size:15px;color:' . $INK . '">Üdvözlettel,<br><b>Nagybani Gastro Zrt.</b></div>'
  . '<div style="font-size:13px;color:' . $MUTED . ';margin-top:8px"><a href="tel:+36707729373" style="color:' . $GREEN_D . ';text-decoration:none;font-weight:700">+36 70 7729 373</a> · <a href="mailto:' . FROM_EMAIL . '" style="color:' . $GREEN_D . ';text-decoration:none;font-weight:700">' . FROM_EMAIL . '</a></div>';

$html = $wrap("Rendelés rögzítve: $company, $dateShort, $time órától. Rendelésszám: $orderNo",
    $headerCard($pill($h($orderNo), '#e8f2e4', $GREEN_D))
  . $card($heroInner, '24px', 'background:#f7fbf5;')
  . $card($summary, '17px')
  . $card('<div style="font-size:17px;font-weight:800;color:' . $INK . '">Rendelt tételek <span style="color:' . $MUTED . ';font-weight:700">(' . count($clean) . ')</span></div>' . $itemRows(false), '20px 22px 12px')
  . $card($tips)
  . $card($sign)
  . '<tr><td align="center" style="padding:6px 10px 0;font-size:12px;color:#7a8473">Ezt a levelet azért kapta, mert rendelést adott le a Nagybani Gastro rendelési felületén.</td></tr>');

$text = "Kedves Partnerünk!\n\nA megrendelését rögzítettük! Köszönjük!\n\n"
      . "Rendelésszám: $orderNo\nKonyha: $company\nSzállítás napja: $dateLong\nÉrkezés az áruval: $time órától\n"
      . 'Fizetés: ' . ($payLabel !== '' ? $payLabel : 'nem adta meg') . "\nLeadva: $placedAt\n\nRendelt tételek:\n";
foreach ($groups as $cat => $list) {
    $text .= "\n$cat\n";
    foreach ($list as $it) $text .= '- ' . $it['name'] . ': ' . $fmtQty($it['qty']) . ' ' . $it['unit']
        . ($it['custom'] ? ' (egyeztetjük)' : '') . ($it['note'] !== '' ? " – „{$it['note']}”" : '') . "\n";
}
$text .= "\nMódosítás vagy kérdés esetén válaszoljon erre a levélre, vagy hívja a +36 70 7729 373 számot.\nVasárnap nem szállítunk.\n\nÜdvözlettel,\nNagybani Gastro Zrt.\n";

// ---------- 2) Belső értesítő (info@) ----------
$alerts = '';
$alert = fn($t, $bg, $fg) => '<div style="margin:0 0 8px;padding:11px 14px;border-radius:14px;background:' . $bg . ';color:' . $fg . ';font-size:14px;font-weight:800">' . $t . '</div>';
if ($cleanedCount) $alerts .= $alert($cleanedCount . ' tisztított tétel – előkészítendő.', '#e3f1f5', '#2b6f85');
if ($customCount)  $alerts .= $alert($customCount . ' tétel nincs a listában – egyeztetni kell a vevővel.', '#fdeedd', '#9a5a1c');
if ($noteCount)    $alerts .= $alert($noteCount . ' tételhez megjegyzést írt.', '#fff4d6', '#7a5a00');
$topInner = '<div style="font-size:12.5px;font-weight:800;color:#a9d79b">' . $h($SOURCE[$source]) . ' · ' . $h($orderNo) . '</div>'
  . '<div style="font-size:30px;line-height:1.1;font-weight:800;letter-spacing:-.6px;color:#ffffff;margin:6px 0 14px">' . $h($company) . '</div>'
  . '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:-4px"><tr>'
  . '<td style="padding:4px"><div style="background:' . $GREEN . ';border-radius:14px;padding:10px 12px"><div style="font-size:11.5px;font-weight:800;color:#d9f0d2">Szállítás</div><div style="font-size:17px;font-weight:800;color:#fff;margin-top:2px">' . $h($dateShort) . '</div></div></td>'
  . '<td style="padding:4px"><div style="background:#f5c22c;border-radius:14px;padding:10px 12px"><div style="font-size:11.5px;font-weight:800;color:#5c4300">Érkezés</div><div style="font-size:17px;font-weight:800;color:#17210f;margin-top:2px">' . $h($time) . ' órától</div></div></td>'
  . '<td style="padding:4px"><div style="background:#ffffff;border-radius:14px;padding:10px 12px"><div style="font-size:11.5px;font-weight:800;color:' . $MUTED . '">Fizetés</div><div style="font-size:17px;font-weight:800;color:#17210f;margin-top:2px">' . ($payLabel !== '' ? $h($payLabel) : '–') . '</div></div></td>'
  . '</tr></table>';
$meta = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="font-size:14px;color:' . $MUTED . '">'
  . '<tr><td style="padding:4px 0">Vevő e-mail</td><td align="right"><a href="mailto:' . $h($email) . '?subject=' . rawurlencode("Rendelés $orderNo") . '" style="color:' . $GREEN_D . ';font-weight:800;text-decoration:none">' . $h($email) . '</a></td></tr>'
  . '<tr><td style="padding:4px 0">Leadva</td><td align="right" style="color:#17210f;font-weight:700">' . $h($placedAt) . '</td></tr>'
  . '<tr><td style="padding:4px 0">Tételek</td><td align="right" style="color:#17210f;font-weight:800">' . count($clean) . ' tétel, ' . count($groups) . ' kategória</td></tr></table>';

$htmlInternal = $wrap("$company · $dateShort $time · " . count($clean) . ' tétel',
    $headerCard($pill('ÚJ RENDELÉS', $GREEN, '#ffffff'))
  . $card($topInner, '22px', 'background:#17210f;border-color:#17210f;')
  . $card($meta . ($alerts ? '<div style="height:12px"></div>' . $alerts : ''), '16px 22px')
  . $card('<div style="font-size:17px;font-weight:800;color:' . $INK . '">Összekészítendő</div>' . $itemRows(true), '18px 22px 10px')
  . '<tr><td align="center" style="padding:6px 10px 0;font-size:12.5px;color:#7a8473">A „Válasz” gombbal közvetlenül a vevőnek ír.</td></tr>');

$textInternal = "ÚJ RENDELÉS – $orderNo (" . $SOURCE[$source] . ")\n\n$company\nSzállítás: $dateShort\nÉrkezés: $time órától\n"
  . 'Fizetés: ' . ($payLabel !== '' ? $payLabel : '–') . "\nVevő e-mail: $email\nLeadva: $placedAt\n"
  . ($cleanedCount ? "\n$cleanedCount tisztított tétel – előkészítendő!\n" : '')
  . ($customCount ? "$customCount tétel nincs a listában – egyeztetni kell!\n" : '');
foreach ($groups as $cat => $list) {
    $textInternal .= "\n$cat\n";
    foreach ($list as $it) $textInternal .= '[ ] ' . $it['name'] . ': ' . $fmtQty($it['qty']) . ' ' . $it['unit']
        . ($it['cleaned'] ? ' (tisztított)' : '') . ($it['custom'] ? ' (NINCS A LISTÁBAN)' : '')
        . ($it['note'] !== '' ? "\n    megjegyzés: {$it['note']}" : '') . "\n";
}

// ---------- Küldés: szöveg + HTML + beágyazott képek ----------
function send_mail(string $to, string $subject, string $text, string $html, string $replyTo = FROM_EMAIL, array $inline = []): bool {
    $alt = 'nba_' . bin2hex(random_bytes(8));
    $rel = 'nbr_' . bin2hex(random_bytes(8));
    $altPart = "--$alt\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($text))
             . "--$alt\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($html))
             . "--$alt--\r\n";
    $headers  = 'From: =?UTF-8?B?' . base64_encode(FROM_NAME) . '?= <' . FROM_EMAIL . ">\r\n";
    $headers .= "Reply-To: $replyTo\r\nMIME-Version: 1.0\r\n";
    $files = array_filter($inline, fn($p) => $p !== '' && is_readable($p));
    if (!$files) {
        $headers .= "Content-Type: multipart/alternative; boundary=\"$alt\"\r\n";
        $body = $altPart;
    } else {
        $headers .= "Content-Type: multipart/related; boundary=\"$rel\"; type=\"multipart/alternative\"\r\n";
        $body = "--$rel\r\nContent-Type: multipart/alternative; boundary=\"$alt\"\r\n\r\n" . $altPart;
        foreach ($files as $cid => $path) {
            $fn = basename($path);
            $body .= "--$rel\r\nContent-Type: image/png; name=\"$fn\"\r\nContent-Transfer-Encoding: base64\r\n"
                   . "Content-ID: <$cid>\r\nContent-Disposition: inline; filename=\"$fn\"\r\n\r\n" . chunk_split(base64_encode((string)file_get_contents($path)));
        }
        $body .= "--$rel--";
    }
    return mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers, '-f' . FROM_EMAIL);
}

$imgs = ['logo@nagybani' => $LOGO, 'truck@nagybani' => $TRUCK];
$sent = send_mail($email, "Megrendelését rögzítettük ($orderNo) – Nagybani Gastro", $text, $html, FROM_EMAIL, $imgs);
if (NOTIFY_EMAIL !== '') {
    send_mail(NOTIFY_EMAIL, "Új rendelés · $company · $dateShort $time · $orderNo", $textInternal, $htmlInternal, $email, ['logo@nagybani' => $LOGO]);
}
if (!$sent) {
    error_log("send-order.php: mail() sikertelen ($orderNo, $email)");
    // A rendelés a naplóban rögzítve van, csak a levél nem ment ki.
    out(200, ['ok' => false, 'orderNo' => $orderNo, 'error' => 'Az e-mail küldése nem sikerült.']);
}
out(200, ['ok' => true, 'orderNo' => $orderNo]);
