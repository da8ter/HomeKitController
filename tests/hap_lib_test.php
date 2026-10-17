<?php

declare(strict_types=1);

/** Prüfung der reinen HomeKit-Bausteine ohne Symcon: php tests/hap_lib_test.php */
require __DIR__ . '/../libs/HapTlv8.php';
require __DIR__ . '/../libs/HapSrp.php';
require __DIR__ . '/../libs/HapCrypto.php';
require __DIR__ . '/../libs/HapSession.php';
require __DIR__ . '/../libs/HapHttp.php';
require __DIR__ . '/../libs/HapPairing.php';

$n = 0;
$fail = 0;
function check(bool $ok, string $label): void
{
    global $n, $fail;
    $n++;
    if (!$ok) {
        $fail++;
        echo "FAIL: $label\n";
    } else {
        echo "ok   $label\n";
    }
}
function section(string $t): void { echo "== $t\n"; }
function hx(string $s): string { return strtolower(preg_replace('/\s+/', '', $s)); }

section('TLV8');
$long = str_repeat('A', 300);
$enc = HapTlv8::encode([[HapTlv8::STATE, "\x01"], [HapTlv8::PUBLIC_KEY, $long], [HapTlv8::ERROR, '']]);
check(strlen($enc) === 3 + (2 + 255) + (2 + 45) + 2, 'Wert über 255 Byte wird in zwei Einträge zerlegt, leerer Wert bleibt erhalten');
$dec = HapTlv8::decode($enc);
check(count($dec) === 3 && $dec[1][1] === $long && $dec[2] === [HapTlv8::ERROR, ''], 'Fragmente werden zusammengesetzt');
$exact = str_repeat('B', 255);
$two = HapTlv8::decode(HapTlv8::encode([[HapTlv8::IDENTIFIER, 'x'], [HapTlv8::SEPARATOR, ''], [HapTlv8::IDENTIFIER, 'y']]));
check(count($two) === 3 && $two[0][1] === 'x' && $two[2][1] === 'y', 'Trenner hält gleichartige Einträge auseinander');
check(HapTlv8::decode(HapTlv8::encode([[1, $exact], [1, 'z']]))[0][1] === $exact . 'z', 'genau 255 Byte + gleicher Typ = Fortsetzung (so verlangt es TLV8)');
$threw = false;
try { HapTlv8::decode("\x06\x05ab"); } catch (InvalidArgumentException $e) { $threw = true; }
check($threw, 'abgeschnittene Daten werden abgewiesen');
$threw = '';
try { HapTlv8::assertNoError(HapTlv8::map(HapTlv8::encode([[HapTlv8::STATE, "\x04"], [HapTlv8::ERROR, "\x02"]])), 'M4'); } catch (RuntimeException $e) { $threw = $e->getMessage(); }
check(str_contains($threw, 'HomeKit-Code'), 'Fehler 2 wird als falscher Code gemeldet');
check(HapTlv8::uint("\x2c\x01") === 300, 'Ganzzahl little-endian');

section('SRP-6a gegen RFC 5054 Anhang B (1024 Bit, SHA-1)');
$n1024 = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3';
$r = new HapSrp($n1024, 2, 'sha1');
$salt = hex2bin('BEB25379D1A8581EB5A727673A2441EE');
$x = $r->x($salt, 'alice', 'password123');
check(gmp_strval($r->k(), 16) === hx('7556AA045AEF2CDD07ABAF0F665C3E818913186F'), 'k');
check(gmp_strval($x, 16) === hx('94B7555AABE9127CC58CCF4993DB6CF84D16C124'), 'x');
$v = $r->verifier($x);
check(gmp_strval($v, 16) === hx('7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB'), 'Verifier v');
$a = gmp_init('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393', 16);
$b = gmp_init('E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20', 16);
$A = $r->publicA($a);
$B = $r->publicB($b, $v);
check(gmp_strval($A, 16) === hx('61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B'), 'A');
check(gmp_strval($B, 16) === hx('BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58'), 'B');
$u = $r->u($A, $B);
check(gmp_strval($u, 16) === hx('CE38B9593487DA98554ED47D70A7AE5F462EF019'), 'u');
$S = $r->clientS($B, $a, $x, $u);
check(gmp_strval($S, 16) === hx('B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A'), 'gemeinsames Geheimnis S (Client)');
check(gmp_cmp($S, $r->serverS($A, $b, $v, $u)) === 0, 'Server kommt auf dasselbe S');

section('HomeKit-Gruppe');
$hap = HapSrp::hap();
check(gmp_prob_prime($hap->N(), 25) > 0 && gmp_prob_prime(gmp_div_q(gmp_sub($hap->N(), 1), 2), 25) > 0, '3072-Bit-N ist eine sichere Primzahl (Tippfehler ausgeschlossen)');
check(strlen($hap->pad(gmp_init(5))) === 384, 'Auffüllen auf 384 Byte');

/** Simuliertes HomeKit-Gerät: Gegenstück zu /pair-setup und /pair-verify nach Spezifikation. */
final class FakeAccessory
{
    public string $id = 'A4:FA:0D:00:00:01';
    public string $code = '031-45-154';
    public array $ltk;
    public ?array $controller = null;
    private HapSrp $srp;
    private GMP $b;
    private GMP $v;
    private string $salt;
    private string $K = '';
    private array $eph = [];
    private string $shared = '';
    private string $ctrlEph = '';

    public function __construct()
    {
        $this->ltk = HapCrypto::ed25519Keypair();
        $this->srp = HapSrp::hap();
    }

    public function pairSetup(string $body): string
    {
        $m = HapTlv8::map($body);
        switch (ord($m[HapTlv8::STATE])) {
            case 1:
                $this->salt = random_bytes(16);
                $this->v = $this->srp->verifier($this->srp->x($this->salt, 'Pair-Setup', $this->code));
                $this->b = $this->srp->int(random_bytes(32));
                $B = $this->srp->publicB($this->b, $this->v);
                return HapTlv8::encode([[HapTlv8::STATE, "\x02"], [HapTlv8::SALT, $this->salt], [HapTlv8::PUBLIC_KEY, $this->srp->bytes($B)]]);
            case 3:
                $A = $this->srp->int($m[HapTlv8::PUBLIC_KEY]);
                $B = $this->srp->publicB($this->b, $this->v);
                $u = $this->srp->u($A, $B);
                $this->K = $this->srp->h($this->srp->bytes($this->srp->serverS($A, $this->b, $this->v, $u)));
                $m1 = $this->srp->m1('Pair-Setup', $this->salt, $A, $B, $this->K);
                if (!hash_equals($m1, $m[HapTlv8::PROOF])) {
                    return HapTlv8::encode([[HapTlv8::STATE, "\x04"], [HapTlv8::ERROR, "\x02"]]);
                }
                return HapTlv8::encode([[HapTlv8::STATE, "\x04"], [HapTlv8::PROOF, $this->srp->m2($A, $m1, $this->K)]]);
            case 5:
                $encKey = HapCrypto::hkdf($this->K, 'Pair-Setup-Encrypt-Salt', 'Pair-Setup-Encrypt-Info');
                $sub = HapTlv8::map(HapCrypto::open($m[HapTlv8::ENCRYPTED_DATA], $encKey, HapCrypto::nonceText('PS-Msg05')));
                $x = HapCrypto::hkdf($this->K, 'Pair-Setup-Controller-Sign-Salt', 'Pair-Setup-Controller-Sign-Info');
                if (!HapCrypto::verify($sub[HapTlv8::SIGNATURE], $x . $sub[HapTlv8::IDENTIFIER] . $sub[HapTlv8::PUBLIC_KEY], $sub[HapTlv8::PUBLIC_KEY])) {
                    return HapTlv8::encode([[HapTlv8::STATE, "\x06"], [HapTlv8::ERROR, "\x02"]]);
                }
                $this->controller = ['id' => $sub[HapTlv8::IDENTIFIER], 'ltpk' => $sub[HapTlv8::PUBLIC_KEY]];
                $ax = HapCrypto::hkdf($this->K, 'Pair-Setup-Accessory-Sign-Salt', 'Pair-Setup-Accessory-Sign-Info');
                $sig = HapCrypto::sign($ax . $this->id . $this->ltk['public'], $this->ltk['secret']);
                $inner = HapTlv8::encode([[HapTlv8::IDENTIFIER, $this->id], [HapTlv8::PUBLIC_KEY, $this->ltk['public']], [HapTlv8::SIGNATURE, $sig]]);
                return HapTlv8::encode([[HapTlv8::STATE, "\x06"], [HapTlv8::ENCRYPTED_DATA, HapCrypto::seal($inner, $encKey, HapCrypto::nonceText('PS-Msg06'))]]);
        }
        return '';
    }

    public function pairVerify(string $body): string
    {
        $m = HapTlv8::map($body);
        $key = fn() => HapCrypto::hkdf($this->shared, 'Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info');
        if (ord($m[HapTlv8::STATE]) === 1) {
            $this->ctrlEph = $m[HapTlv8::PUBLIC_KEY];
            $this->eph = HapCrypto::x25519Keypair();
            $this->shared = HapCrypto::x25519($this->eph['secret'], $this->ctrlEph);
            $sig = HapCrypto::sign($this->eph['public'] . $this->id . $this->ctrlEph, $this->ltk['secret']);
            $inner = HapTlv8::encode([[HapTlv8::IDENTIFIER, $this->id], [HapTlv8::SIGNATURE, $sig]]);
            return HapTlv8::encode([[HapTlv8::STATE, "\x02"], [HapTlv8::PUBLIC_KEY, $this->eph['public']], [HapTlv8::ENCRYPTED_DATA, HapCrypto::seal($inner, $key(), HapCrypto::nonceText('PV-Msg02'))]]);
        }
        $sub = HapTlv8::map(HapCrypto::open($m[HapTlv8::ENCRYPTED_DATA], $key(), HapCrypto::nonceText('PV-Msg03')));
        $ok = $this->controller !== null && $sub[HapTlv8::IDENTIFIER] === $this->controller['id']
            && HapCrypto::verify($sub[HapTlv8::SIGNATURE], $this->ctrlEph . $sub[HapTlv8::IDENTIFIER] . $this->eph['public'], $this->controller['ltpk']);
        return HapTlv8::encode($ok ? [[HapTlv8::STATE, "\x04"]] : [[HapTlv8::STATE, "\x04"], [HapTlv8::ERROR, "\x02"]]);
    }

    public function sessionKeys(): array
    {
        return [
            'read'  => HapCrypto::hkdf($this->shared, 'Control-Salt', 'Control-Write-Encryption-Key'),
            'write' => HapCrypto::hkdf($this->shared, 'Control-Salt', 'Control-Read-Encryption-Key'),
        ];
    }
}

section('Kopplung gegen simuliertes Gerät');
$acc = new FakeAccessory();
$ctrlId = HapPairing::newControllerId();
$ltk = HapCrypto::ed25519Keypair();
check(preg_match('/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/', $ctrlId) === 1, 'Controller-ID ist eine UUID v4');
[$m3, $st] = HapPairing::setupM3($acc->pairSetup(HapPairing::setupM1()), '03145154');
[$m5, $st] = HapPairing::setupM5($acc->pairSetup($m3), $st, $ctrlId, $ltk['secret'], $ltk['public']);
$pair = HapPairing::setupFinish($acc->pairSetup($m5), $st);
check($pair['id'] === $acc->id && $pair['ltpk'] === $acc->ltk['public'], 'M1–M6: Gerätekennung und Langzeitschlüssel übernommen');
check($acc->controller['id'] === $ctrlId, 'Gerät kennt den Controller');

$acc2 = new FakeAccessory();
[$m3b, $stb] = HapPairing::setupM3($acc2->pairSetup(HapPairing::setupM1()), '111-22-333');
$err = '';
try { HapPairing::setupM5($acc2->pairSetup($m3b), $stb, $ctrlId, $ltk['secret'], $ltk['public']); } catch (RuntimeException $e) { $err = $e->getMessage(); }
check(str_contains($err, 'HomeKit-Code'), 'falscher Code: Gerät lehnt M3 ab, Klartext-Fehler');
$threw = false;
try { HapPairing::normalizeCode('1234'); } catch (InvalidArgumentException $e) { $threw = true; }
check($threw && HapPairing::normalizeCode('031 45 154') === '031-45-154', 'Code wird geprüft und normalisiert');

section('Sitzungsaufbau gegen simuliertes Gerät');
[$v1, $vs] = HapPairing::verifyM1();
[$v3, $vs] = HapPairing::verifyM3($acc->pairVerify($v1), $vs, $ctrlId, $ltk['secret'], $pair['id'], $pair['ltpk']);
$keys = HapPairing::verifyFinish($acc->pairVerify($v3), $vs);
$accKeys = $acc->sessionKeys();
check($keys['write'] === $accKeys['read'] && $keys['read'] === $accKeys['write'], 'beide Seiten haben dieselben Sitzungsschlüssel');
$err = '';
[$neg1, $negState] = HapPairing::verifyM1();
try { HapPairing::verifyM3($acc->pairVerify($neg1), $negState, $ctrlId, $ltk['secret'], 'XX:XX', $pair['ltpk']); } catch (RuntimeException $e) { $err = $e->getMessage(); }
check(str_contains($err, 'anderes Gerät'), 'falsche Gerätekennung wird abgewiesen');
$err = '';
$other = HapCrypto::ed25519Keypair();
[$neg2, $negState2] = HapPairing::verifyM1();
try { HapPairing::verifyM3($acc->pairVerify($neg2), $negState2, $ctrlId, $ltk['secret'], $pair['id'], $other['public']); } catch (RuntimeException $e) { $err = $e->getMessage(); }
check(str_contains($err, 'Signatur'), 'fremder Langzeitschlüssel: Signatur fällt durch');

section('Verschlüsselte Rahmen');
$msg = str_repeat('0123456789', 250); // 2500 Byte -> 3 Rahmen
[$wire, $c1] = HapSession::encrypt($msg, $keys['write'], 0);
check($c1 === 3 && strlen($wire) === 2500 + 3 * 18, 'Zerlegung in Rahmen zu höchstens 1024 Byte');
[$plain, $rest, $c2] = HapSession::decrypt(substr($wire, 0, 1100), $accKeys['read'], 0);
check($plain === substr($msg, 0, 1024) && $c2 === 1, 'unvollständiger zweiter Rahmen bleibt im Rest');
[$plain2, $rest2, $c3] = HapSession::decrypt($rest . substr($wire, 1100), $accKeys['read'], $c2);
check($plain . $plain2 === $msg && $rest2 === '' && $c3 === 3, 'Fortsetzung mit Rest und Zähler');
$bad = $wire; $bad[10] = chr(ord($bad[10]) ^ 1);
$threw = false;
try { HapSession::decrypt($bad, $accKeys['read'], 0); } catch (RuntimeException $e) { $threw = true; }
check($threw, 'manipulierter Rahmen fällt auf');
$threw = false;
try { HapSession::decrypt($wire, $accKeys['read'], 1); } catch (RuntimeException $e) { $threw = true; }
check($threw, 'falscher Zähler fällt auf');

section('HTTP und Ereignisse');
$req = HapHttp::request('POST', '/pair-setup', 'fp2.local', "\x06\x01\x01", HapHttp::TLV);
check(str_starts_with($req, "POST /pair-setup HTTP/1.1\r\nHost: fp2.local\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: 3\r\n\r\n"), 'Anfrage mit Länge und Typ');
check(HapHttp::request('GET', '/accessories', 'x') === "GET /accessories HTTP/1.1\r\nHost: x\r\n\r\n", 'GET ohne Inhalt');
$ev = '{"characteristics":[{"aid":1,"iid":10,"value":1}]}';
$resp = "HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: 2\r\n\r\n{}EVENT/1.0 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: " . strlen($ev) . "\r\n\r\n" . $ev;
$p1 = HapHttp::parse($resp);
check($p1 !== null && !$p1['event'] && $p1['status'] === 200 && $p1['body'] === '{}', 'Antwort mit Content-Length');
$p2 = HapHttp::parse($p1['rest']);
check($p2 !== null && $p2['event'] && json_decode($p2['body'], true)['characteristics'][0]['value'] === 1 && $p2['rest'] === '', 'Ereignis direkt dahinter');
check(HapHttp::parse(substr($resp, 0, 60)) === null && HapHttp::parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab") === null, 'unvollständig: noch nichts');
$chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nX";
$p3 = HapHttp::parse($chunked);
check($p3 !== null && $p3['body'] === 'Wikipedia' && $p3['rest'] === 'X', 'chunked mit Rest');
check(HapHttp::parse(substr($chunked, 0, -4)) === null, 'chunked ohne Schlussblock: noch nichts');
check(HapHttp::parse("HTTP/1.1 204 No Content\r\n\r\n")['status'] === 204, '204 ohne Inhalt');

echo "\n" . ($fail === 0 ? "Alle $n Prüfungen bestanden.\n" : "$fail von $n Prüfungen fehlgeschlagen.\n");
exit($fail === 0 ? 0 : 1);
