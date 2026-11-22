<?php
/**
 * Nagybani Gastro – fejlesztői mód szerveroldala
 *
 * Műveletek (POST):
 *   status         – van-e már jelszó beállítva
 *   setup          – első belépéskor a jelszó beállítása (csak ha még nincs)
 *   login          – belépés jelszóval, visszaad egy 12 órás belépési kulcsot
 *   save           – a terméklista mentése (catalog.json), előtte biztonsági másolat
 *   upload         – termékkép feltöltése (a "kepek" mappába, átméretezve)
 *
 * A jelszó a "rendelesek/admin.json" fájlban van, titkosítva (hash).
 * Elfelejtett jelszó: a cPanel Fájlkezelőben töröld a rendelesek/admin.json fájlt,
 * és a következő megnyitáskor új jelszót állíthatsz be.
 */

const DATA_DIR    = __DIR__ . '/rendelesek';
const IMG_DIR     = __DIR__ . '/kepek';
const CATALOG     = __DIR__ . '/catalog.json';
const TOKEN_TTL   = 12 * 3600;
const MAX_UPLOAD  = 8 * 1024 * 1024;   // 8 MB
const IMG_MAX_PX  = 900;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function out(int $code, array $body): void { http_response_code($code); echo json_encode($body, JSON_UNESCAPED_UNICODE); exit; }
function fail(int $code, string $msg): void { out($code, ['ok' => false, 'error' => $msg]); }

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail(405, 'Csak POST engedélyezett.');

// Csak saját domainről
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    $host = parse_url($origin, PHP_URL_HOST) . (parse_url($origin, PHP_URL_PORT) ? ':' . parse_url($origin, PHP_URL_PORT) : '');
    if (strcasecmp($host, (string)($_SERVER['HTTP_HOST'] ?? '')) !== 0) fail(403, 'Nem engedélyezett eredet.');
}

if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0750, true);
if (!is_file(DATA_DIR . '/.htaccess')) @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");
if (!is_dir(IMG_DIR)) @mkdir(IMG_DIR, 0755, true);

$cfgFile = DATA_DIR . '/admin.json';
$cfg = is_file($cfgFile) ? (json_decode((string)file_get_contents($cfgFile), true) ?: []) : [];
function save_cfg(array $c): void { global $cfgFile; file_put_contents($cfgFile, json_encode($c), LOCK_EX); @chmod($cfgFile, 0600); }

function make_token(array $cfg): string {
    $exp = time() + TOKEN_TTL;
    return $exp . '.' . hash_hmac('sha256', (string)$exp, $cfg['secret']);
}
function check_token(array $cfg, string $t): bool {
    if (empty($cfg['secret']) || strpos($t, '.') === false) return false;
    [$exp, $sig] = explode('.', $t, 2);
    return ctype_digit($exp) && (int)$exp > time() && hash_equals(hash_hmac('sha256', $exp, $cfg['secret']), $sig);
}
function throttle(string $bucket, int $max, int $window): void {
    $f = DATA_DIR . '/admin-throttle.json';
    $fh = fopen($f, 'c+'); if (!$fh || !flock($fh, LOCK_EX)) return;
    $d = json_decode(stream_get_contents($fh) ?: '{}', true) ?: [];
    $now = time(); $k = hash('sha256', $bucket . ($_SERVER['REMOTE_ADDR'] ?? ''));
    $d[$k] = array_values(array_filter($d[$k] ?? [], fn($t) => $now - $t < $window));
    $over = count($d[$k]) >= $max;
    if (!$over) $d[$k][] = $now;
    ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($d)); flock($fh, LOCK_UN); fclose($fh);
    if ($over) fail(429, 'Túl sok próbálkozás. Várj 10 percet.');
}

// Képfeltöltésnél multipart, minden másnál JSON
$isUpload = isset($_POST['action']) && $_POST['action'] === 'upload';
$in = $isUpload ? $_POST : (json_decode((string)file_get_contents('php://input'), true) ?: []);
$action = (string)($in['action'] ?? '');

switch ($action) {
case 'status':
    out(200, ['ok' => true, 'hasPassword' => !empty($cfg['hash'])]);

case 'setup':
    if (!empty($cfg['hash'])) fail(409, 'A jelszó már be van állítva. Lépj be.');
    $pw = (string)($in['password'] ?? '');
    if (mb_strlen($pw) < 8) fail(422, 'A jelszó legalább 8 karakter legyen.');
    $cfg = ['hash' => password_hash($pw, PASSWORD_DEFAULT), 'secret' => bin2hex(random_bytes(32))];
    save_cfg($cfg);
    out(200, ['ok' => true, 'token' => make_token($cfg)]);

case 'login':
    if (empty($cfg['hash'])) fail(409, 'Még nincs jelszó beállítva.');
    throttle('login', 6, 600);
    if (!password_verify((string)($in['password'] ?? ''), $cfg['hash'])) fail(401, 'Hibás jelszó.');
    out(200, ['ok' => true, 'token' => make_token($cfg)]);
}

// Innentől belépés kell
if (!check_token($cfg, (string)($in['token'] ?? ''))) fail(401, 'Lejárt a belépés. Lépj be újra.');

switch ($action) {
case 'save':
    $c = $in['catalog'] ?? null;
    if (!is_array($c) || !isset($c['products']) || !is_array($c['products']) || !$c['products']) fail(422, 'Hibás terméklista.');
    if (count($c['products']) > 2000) fail(422, 'Túl sok termék.');
    $str = fn($v, $max) => mb_substr(trim((string)$v), 0, $max);
    $units = array_values(array_unique(array_filter(array_map(fn($u) => $str($u, 20), (array)($c['units'] ?? [])))));
    $ids = []; $products = [];
    foreach ($c['products'] as $p) {
        $id = preg_replace('/[^a-z0-9-]/', '', strtolower((string)($p['id'] ?? '')));
        $name = $str($p['name'] ?? '', 80);
        $cat  = $str($p['cat'] ?? '', 60);
        if ($id === '' || $name === '' || $cat === '' || isset($ids[$id])) fail(422, "Hibás vagy duplikált termék: $name");
        $ids[$id] = true;
        $pu = array_values(array_unique(array_filter(array_map(fn($u) => $str($u, 20), (array)($p['units'] ?? [])))));
        if (!$pu) fail(422, "Nincs mértékegység: $name");
        $variants = null;
        if (!empty($p['variants']['options'])) {
            $opts = array_values(array_unique(array_filter(array_map(fn($o) => $str($o, 30), (array)$p['variants']['options']))));
            if ($opts) $variants = ['label' => $str($p['variants']['label'] ?? 'Változat', 30) ?: 'Változat', 'options' => $opts];
        }
        $img = (string)($p['image'] ?? '');
        if ($img !== '' && !preg_match('#^kepek/[a-z0-9-]+\.(jpg|webp)$#', $img)) $img = '';
        $products[] = [
            'id' => $id, 'name' => $name, 'cat' => $cat, 'units' => $pu, 'variants' => $variants,
            'orderable' => !empty($p['orderable']), 'cleaned' => !empty($p['cleaned']),
            'hidden' => !empty($p['hidden']), 'image' => $img,
        ];
    }
    $catalog = ['version' => (int)($c['version'] ?? 1), 'updatedAt' => gmdate('c'), 'units' => $units, 'products' => $products];
    $bdir = DATA_DIR . '/catalog-mentesek';
    if (!is_dir($bdir)) @mkdir($bdir, 0750, true);
    if (is_file(CATALOG)) @copy(CATALOG, $bdir . '/catalog-' . date('Ymd-His') . '.json');
    $tmp = CATALOG . '.tmp';
    if (file_put_contents($tmp, json_encode($catalog, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX) === false || !rename($tmp, CATALOG))
        fail(500, 'Nem sikerült menteni. Ellenőrizd a mappa írási jogát.');
    out(200, ['ok' => true, 'updatedAt' => $catalog['updatedAt'], 'count' => count($products)]);

case 'upload':
    $id = preg_replace('/[^a-z0-9-]/', '', strtolower((string)($in['id'] ?? '')));
    if ($id === '') fail(422, 'Hiányzó termékazonosító.');
    $f = $_FILES['file'] ?? null;
    if (!$f || $f['error'] !== UPLOAD_ERR_OK) fail(422, 'A feltöltés nem sikerült.');
    if ($f['size'] > MAX_UPLOAD) fail(413, 'A kép legfeljebb 8 MB lehet.');
    $info = @getimagesize($f['tmp_name']);
    if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF], true)) fail(415, 'Csak JPG, PNG, WEBP vagy GIF kép tölthető fel.');
    $src = @imagecreatefromstring((string)file_get_contents($f['tmp_name']));
    if (!$src) fail(415, 'A képet nem sikerült beolvasni.');
    // Négyzetes kivágás középről, majd átméretezés
    $w = imagesx($src); $h = imagesy($src); $side = min($w, $h);
    $size = min(IMG_MAX_PX, $side);
    $dst = imagecreatetruecolor($size, $size);
    imagefill($dst, 0, 0, imagecolorallocate($dst, 255, 255, 255));
    imagecopyresampled($dst, $src, 0, 0, (int)(($w - $side) / 2), (int)(($h - $side) / 2), $size, $size, $side, $side);
    $name = $id . '-' . substr(bin2hex(random_bytes(4)), 0, 6);
    $useWebp = function_exists('imagewebp');
    $path = 'kepek/' . $name . ($useWebp ? '.webp' : '.jpg');
    $ok = $useWebp ? imagewebp($dst, __DIR__ . '/' . $path, 82) : imagejpeg($dst, __DIR__ . '/' . $path, 85);
    imagedestroy($src); imagedestroy($dst);
    if (!$ok) fail(500, 'A képet nem sikerült menteni.');
    out(200, ['ok' => true, 'image' => $path]);

default:
    fail(400, 'Ismeretlen művelet.');
}
