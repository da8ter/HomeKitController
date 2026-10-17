<?php

declare(strict_types=1);

/**
 * Diagnose ohne Symcon: koppelt mit einem HomeKit-Gerät, baut die Sitzung auf, liest /accessories
 * und hört auf Ereignisse. Die Kopplung (inkl. privatem Schlüssel) landet in der angegebenen Datei –
 * eine Datei außerhalb des Repos wählen.
 *
 *   php tools/hap_cli.php pair    <host> <port> <code> <kopplungsdatei>
 *   php tools/hap_cli.php listen  <host> <port> <kopplungsdatei> [sekunden]
 *   php tools/hap_cli.php unpair  <host> <port> <kopplungsdatei>
 */
require __DIR__ . '/../libs/HapTlv8.php';
require __DIR__ . '/../libs/HapSrp.php';
require __DIR__ . '/../libs/HapCrypto.php';
require __DIR__ . '/../libs/HapSession.php';
require __DIR__ . '/../libs/HapHttp.php';
require __DIR__ . '/../libs/HapPairing.php';

final class Conn
{
    private $s;
    private string $buf = '';
    private ?array $keys = null;
    private int $wc = 0;
    private int $rc = 0;
    private string $raw = '';

    public function __construct(private string $host, int $port)
    {
        $this->s = stream_socket_client("tcp://$host:$port", $errno, $err, 5);
        if (!$this->s) {
            throw new RuntimeException("Verbindung fehlgeschlagen: $err");
        }
        stream_set_timeout($this->s, 5);
    }

    public function secure(array $keys): void { $this->keys = $keys; }

    public function send(string $method, string $path, string $body = '', string $type = ''): void
    {
        $req = HapHttp::request($method, $path, $this->host, $body, $type);
        if ($this->keys !== null) {
            [$req, $this->wc] = HapSession::encrypt($req, $this->keys['write'], $this->wc);
        }
        fwrite($this->s, $req);
    }

    /** Nächste Nachricht (Antwort oder Ereignis) oder null nach Zeitablauf. */
    public function next(float $timeout = 5.0): ?array
    {
        $end = microtime(true) + $timeout;
        while (true) {
            $msg = HapHttp::parse($this->buf);
            if ($msg !== null) {
                $this->buf = $msg['rest'];
                return $msg;
            }
            if (microtime(true) > $end) {
                return null;
            }
            $r = [$this->s]; $w = $e = null;
            if (stream_select($r, $w, $e, 0, 200000) > 0) {
                $chunk = fread($this->s, 65536);
                if ($chunk === '' || $chunk === false) {
                    if (feof($this->s)) throw new RuntimeException('Gerät hat die Verbindung geschlossen');
                    continue;
                }
                if ($this->keys !== null) {
                    $this->raw .= $chunk;
                    [$plain, $this->raw, $this->rc] = HapSession::decrypt($this->raw, $this->keys['read'], $this->rc);
                    $this->buf .= $plain;
                } else {
                    $this->buf .= $chunk;
                }
            }
        }
    }

    public function call(string $method, string $path, string $body = '', string $type = ''): array
    {
        $this->send($method, $path, $body, $type);
        while (true) {
            $m = $this->next();
            if ($m === null) throw new RuntimeException("keine Antwort auf $method $path");
            if (!$m['event']) return $m;
            echo 'EREIGNIS ' . $m['body'] . "\n";
        }
    }
}

function verify(Conn $c, array $p): void
{
    [$m1, $st] = HapPairing::verifyM1();
    [$m3, $st] = HapPairing::verifyM3($c->call('POST', '/pair-verify', $m1, HapHttp::TLV)['body'], $st, $p['ctrlId'], base64_decode($p['ltsk']), $p['accId'], base64_decode($p['accLtpk']));
    $c->secure(HapPairing::verifyFinish($c->call('POST', '/pair-verify', $m3, HapHttp::TLV)['body'], $st));
}

[$self, $cmd, $host, $port] = array_pad($argv, 4, '');
try {
    if ($cmd === 'pair') {
        [, , , , $code, $file] = $argv;
        $c = new Conn($host, (int)$port);
        $t = microtime(true);
        [$m3, $st] = HapPairing::setupM3($c->call('POST', '/pair-setup', HapPairing::setupM1(), HapHttp::TLV)['body'], $code);
        printf("M2 erhalten, SRP gerechnet (%.2f s)\n", microtime(true) - $t);
        $ctrlId = HapPairing::newControllerId();
        $ltk = HapCrypto::ed25519Keypair();
        [$m5, $st] = HapPairing::setupM5($c->call('POST', '/pair-setup', $m3, HapHttp::TLV)['body'], $st, $ctrlId, $ltk['secret'], $ltk['public']);
        $acc = HapPairing::setupFinish($c->call('POST', '/pair-setup', $m5, HapHttp::TLV)['body'], $st);
        file_put_contents($file, json_encode(['ctrlId' => $ctrlId, 'ltsk' => base64_encode($ltk['secret']), 'ltpk' => base64_encode($ltk['public']), 'accId' => $acc['id'], 'accLtpk' => base64_encode($acc['ltpk'])]));
        chmod($file, 0600);
        echo "Gekoppelt mit {$acc['id']}, Kopplung in $file\n";
    } elseif ($cmd === 'listen') {
        [, , , , $file] = $argv;
        $secs = (int)($argv[5] ?? 20);
        $p = json_decode((string)file_get_contents($file), true);
        $c = new Conn($host, (int)$port);
        verify($c, $p);
        echo "Sitzung steht\n";
        $acc = json_decode($c->call('GET', '/accessories')['body'], true);
        $ev = [];
        foreach ($acc['accessories'] as $a) {
            foreach ($a['services'] as $s) {
                $name = '';
                foreach ($s['characteristics'] as $ch) if (strtoupper($ch['type']) === '23' || str_starts_with(strtoupper($ch['type']), '00000023')) $name = (string)($ch['value'] ?? '');
                foreach ($s['characteristics'] as $ch) {
                    printf("  %d.%-4d Dienst %-6s %-22s Merkmal %-6s %-14s = %s\n", $a['aid'], $ch['iid'], $s['type'], $name, $ch['type'], implode(',', $ch['perms']), json_encode($ch['value'] ?? null));
                    if (in_array('ev', $ch['perms'], true)) $ev[] = ['aid' => $a['aid'], 'iid' => $ch['iid'], 'ev' => true];
                }
            }
        }
        $r = $c->call('PUT', '/characteristics', json_encode(['characteristics' => $ev]), HapHttp::JSON);
        echo "Ereignisse abonniert: " . count($ev) . " (Status {$r['status']})\n";
        $end = time() + $secs;
        while (time() < $end) {
            $m = $c->next(1.0);
            if ($m !== null) echo date('H:i:s') . ' ' . ($m['event'] ? 'EREIGNIS ' : 'ANTWORT ') . $m['body'] . "\n";
        }
    } elseif ($cmd === 'unpair') {
        [, , , , $file] = $argv;
        $p = json_decode((string)file_get_contents($file), true);
        $c = new Conn($host, (int)$port);
        verify($c, $p);
        $r = $c->call('POST', '/pairings', HapPairing::removePairing($p['ctrlId']), HapHttp::TLV);
        HapTlv8::assertNoError(HapTlv8::map($r['body']), 'Entkoppeln');
        echo "Entkoppelt\n";
    } else {
        fwrite(STDERR, "Aufruf: pair|listen|unpair – siehe Kopf der Datei\n");
        exit(2);
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'Fehler: ' . $e->getMessage() . "\n");
    exit(1);
}
