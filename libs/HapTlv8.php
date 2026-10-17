<?php

declare(strict_types=1);

/**
 * TLV8 nach HomeKit-Spezifikation: Typ (1 Byte), Länge (1 Byte), Wert. Werte über 255 Byte werden
 * in aufeinanderfolgende Einträge desselben Typs zerlegt; der Empfänger setzt sie wieder zusammen.
 * Mehrere gleichartige Einträge (z. B. Listen bei /pairings) trennt ein leerer Eintrag vom Typ 0xFF.
 */
final class HapTlv8
{
    public const METHOD = 0x00;
    public const IDENTIFIER = 0x01;
    public const SALT = 0x02;
    public const PUBLIC_KEY = 0x03;
    public const PROOF = 0x04;
    public const ENCRYPTED_DATA = 0x05;
    public const STATE = 0x06;
    public const ERROR = 0x07;
    public const RETRY_DELAY = 0x08;
    public const CERTIFICATE = 0x09;
    public const SIGNATURE = 0x0A;
    public const PERMISSIONS = 0x0B;
    public const FRAGMENT_DATA = 0x0C;
    public const FRAGMENT_LAST = 0x0D;
    public const FLAGS = 0x13;
    public const SEPARATOR = 0xFF;

    /** Fehlercodes der Gegenstelle (kTLVError_*). */
    public const ERRORS = [
        1 => 'Unbekannter Fehler',
        2 => 'Falscher HomeKit-Code oder Signatur ungültig',
        3 => 'Zu viele Versuche, Gerät wartet (Backoff)',
        4 => 'Gerät nimmt keine weitere Kopplung an',
        5 => 'Gerät hat die maximale Zahl an Versuchen erreicht und sperrt die Kopplung',
        6 => 'Gerät ist gerade mit einer anderen Kopplung beschäftigt',
    ];

    /**
     * @param array<int, array{0:int, 1:string}> $items Liste aus [Typ, Wert], Reihenfolge bleibt erhalten
     */
    public static function encode(array $items): string
    {
        $out = '';
        foreach ($items as [$type, $value]) {
            $value = (string)$value;
            if ($value === '') {
                $out .= chr($type) . "\x00";
                continue;
            }
            foreach (str_split($value, 255) as $part) {
                $out .= chr($type) . chr(strlen($part)) . $part;
            }
        }
        return $out;
    }

    /**
     * @return array<int, array{0:int, 1:string}> Liste aus [Typ, Wert], Fragmente zusammengesetzt
     */
    public static function decode(string $data): array
    {
        $items = [];
        $pos = 0;
        $len = strlen($data);
        $lastFull = false; // vorheriger Eintrag hatte genau 255 Byte: ein gleicher Typ setzt ihn fort
        while ($pos < $len) {
            if ($pos + 2 > $len) {
                throw new InvalidArgumentException('TLV8 abgeschnitten (Kopf)');
            }
            $type = ord($data[$pos]);
            $size = ord($data[$pos + 1]);
            if ($pos + 2 + $size > $len) {
                throw new InvalidArgumentException('TLV8 abgeschnitten (Wert)');
            }
            $value = substr($data, $pos + 2, $size);
            $pos += 2 + $size;
            $n = count($items);
            if ($lastFull && $n > 0 && $items[$n - 1][0] === $type) {
                $items[$n - 1][1] .= $value;
            } else {
                $items[] = [$type, $value];
            }
            $lastFull = $size === 255;
        }
        return $items;
    }

    /** Erster Wert je Typ als Map, für Antworten ohne Listen. */
    public static function map(string $data): array
    {
        $map = [];
        foreach (self::decode($data) as [$type, $value]) {
            if (!array_key_exists($type, $map)) {
                $map[$type] = $value;
            }
        }
        return $map;
    }

    /** Wirft bei einem Fehler-Eintrag der Gegenstelle eine Ausnahme mit Klartext. */
    public static function assertNoError(array $map, string $step): void
    {
        if (isset($map[self::ERROR])) {
            $code = ord($map[self::ERROR]);
            $text = self::ERRORS[$code] ?? ('Fehlercode ' . $code);
            if ($code === 3 && isset($map[self::RETRY_DELAY])) {
                $text .= ' (' . self::uint($map[self::RETRY_DELAY]) . ' s)';
            }
            throw new RuntimeException($step . ': ' . $text, $code);
        }
    }

    /** Ganzzahl little-endian, wie HomeKit sie in TLV8 überträgt. */
    public static function uint(string $bytes): int
    {
        $v = 0;
        for ($i = strlen($bytes) - 1; $i >= 0; $i--) {
            $v = ($v << 8) | ord($bytes[$i]);
        }
        return $v;
    }
}
