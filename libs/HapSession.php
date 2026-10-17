<?php

declare(strict_types=1);

require_once __DIR__ . '/HapCrypto.php';

/**
 * Verschlüsselte HomeKit-Sitzung nach /pair-verify: Rahmen aus Länge (2 Byte little-endian, zugleich
 * AAD), höchstens 1024 Byte verschlüsselter Nutzlast und 16 Byte Tag. Jede Richtung hat ihren eigenen
 * Schlüssel und Zähler; der Zähler bildet die Nonce. Zustandslos geschrieben: Zähler und Restpuffer
 * kommen von außen herein und gehen zurück, weil Symcon jeden Aufruf auf einem neuen Objekt ausführt.
 */
final class HapSession
{
    public const MAX_FRAME = 1024;

    /**
     * Leitet die Sitzungsschlüssel aus dem gemeinsamen Geheimnis von /pair-verify ab (Sicht des Controllers).
     * @return array{write:string, read:string} write = Controller -> Gerät, read = Gerät -> Controller
     */
    public static function keys(string $sharedSecret): array
    {
        return [
            'write' => HapCrypto::hkdf($sharedSecret, 'Control-Salt', 'Control-Write-Encryption-Key'),
            'read'  => HapCrypto::hkdf($sharedSecret, 'Control-Salt', 'Control-Read-Encryption-Key'),
        ];
    }

    /** @return array{0:string, 1:int} [Rahmen, neuer Zähler] */
    public static function encrypt(string $plain, string $key, int $counter): array
    {
        $out = '';
        foreach ($plain === '' ? [] : str_split($plain, self::MAX_FRAME) as $chunk) {
            $aad = pack('v', strlen($chunk));
            $out .= $aad . HapCrypto::seal($chunk, $key, HapCrypto::nonceCounter($counter), $aad);
            $counter++;
        }
        return [$out, $counter];
    }

    /**
     * Entschlüsselt alle vollständigen Rahmen im Puffer.
     * @return array{0:string, 1:string, 2:int} [Klartext, Rest (unvollständiger Rahmen), neuer Zähler]
     */
    public static function decrypt(string $buffer, string $key, int $counter): array
    {
        $plain = '';
        while (strlen($buffer) >= 2) {
            $size = unpack('v', substr($buffer, 0, 2))[1];
            if ($size > self::MAX_FRAME) {
                throw new RuntimeException('HomeKit frame too large: ' . $size);
            }
            if (strlen($buffer) < 2 + $size + 16) {
                break;
            }
            $aad = substr($buffer, 0, 2);
            $plain .= HapCrypto::open(substr($buffer, 2, $size + 16), $key, HapCrypto::nonceCounter($counter), $aad);
            $buffer = (string)substr($buffer, 2 + $size + 16);
            $counter++;
        }
        return [$plain, $buffer, $counter];
    }
}
