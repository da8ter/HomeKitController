<?php

declare(strict_types=1);

/**
 * Direkte mDNS-Anfrage an ein bekanntes Gerät (RFC 6762, Abschnitt 6.7): Eine Anfrage an Port 5353 von einem anderen
 * Absenderport beantwortet das Gerät per Unicast an den Absender. So findet sich der neue Port nach einem Neustart auch
 * dann, wenn die Bonjour-Suche von Symcon das Gerät nicht sieht (Multicast kommt nicht überall an).
 */
final class HapMdns
{
    public const PORT = 5353;
    private const PTR = 12;
    private const TXT = 16;
    private const SRV = 33;

    /** Anfrage nach allen HomeKit-Diensten des Geräts (PTR _hap._tcp.local); die Antwort bringt SRV und TXT mit. */
    public static function query(): string
    {
        $name = '';
        foreach (['_hap', '_tcp', 'local'] as $label) {
            $name .= chr(strlen($label)) . $label;
        }
        return pack('n6', random_int(1, 0xFFFF), 0, 1, 0, 0, 0) . $name . "\0" . pack('n2', self::PTR, 1);
    }

    /**
     * HomeKit-Dienste aus einer Antwort: Instanzname (ohne „._hap._tcp.local“) => ['port' => int, 'id' => string].
     * `id` ist die HomeKit-ID aus dem TXT-Eintrag in Großbuchstaben, '' ohne TXT. Kaputte Pakete ergeben [].
     */
    public static function parse(string $packet): array
    {
        if (strlen($packet) < 12) {
            return [];
        }
        $counts = unpack('n4', substr($packet, 4, 8));
        $pos = 12;
        try {
            for ($i = 0; $i < $counts[1]; $i++) {
                self::name($packet, $pos);
                $pos += 4;
            }
            $srv = $txt = [];
            for ($i = 0, $records = $counts[2] + $counts[3] + $counts[4]; $i < $records; $i++) {
                $owner = self::name($packet, $pos);
                $head = unpack('ntype/nclass/Nttl/nlen', self::take($packet, $pos, 10));
                $start = $pos;
                $data = self::take($packet, $pos, $head['len']);
                if ($head['type'] === self::SRV && $head['len'] >= 6) {
                    $srv[$owner] = unpack('n', substr($data, 4, 2))[1];
                } elseif ($head['type'] === self::TXT) {
                    for ($o = 0; $o < strlen($data); $o += 1 + ord($data[$o])) {
                        $entry = substr($data, $o + 1, ord($data[$o]));
                        if (strncasecmp($entry, 'id=', 3) === 0) {
                            $txt[$owner] = strtoupper(substr($entry, 3));
                        }
                    }
                }
                $pos = $start + $head['len'];
            }
        } catch (UnexpectedValueException) {
            return [];
        }
        $out = [];
        foreach ($srv as $owner => $port) {
            if (preg_match('/^(.+)\._hap\._tcp\.local$/i', $owner, $m)) {
                $out[$m[1]] = ['port' => $port, 'id' => $txt[$owner] ?? ''];
            }
        }
        return $out;
    }

    /** Name ab $pos lesen (mit Kompressionszeigern); $pos steht danach hinter dem Namen. */
    private static function name(string $p, int &$pos): string
    {
        $labels = [];
        $at = $pos;
        $jumped = false;
        for ($hops = 0; $hops < 64; $hops++) {
            $len = ord(self::take($p, $at, 1));
            if ($len === 0) {
                break;
            }
            if (($len & 0xC0) === 0xC0) {
                $target = (($len & 0x3F) << 8) | ord(self::take($p, $at, 1));
                if (!$jumped) {
                    $pos = $at;
                    $jumped = true;
                }
                $at = $target;
                continue;
            }
            $labels[] = self::take($p, $at, $len);
        }
        if ($hops === 64) {
            throw new UnexpectedValueException('name loop');
        }
        if (!$jumped) {
            $pos = $at;
        }
        return implode('.', $labels);
    }

    private static function take(string $p, int &$pos, int $len): string
    {
        if ($pos < 0 || $pos + $len > strlen($p)) {
            throw new UnexpectedValueException('truncated');
        }
        $s = substr($p, $pos, $len);
        $pos += $len;
        return $s;
    }
}
