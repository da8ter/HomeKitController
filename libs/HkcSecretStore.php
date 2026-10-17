<?php

declare(strict_types=1);

/**
 * Verschlüsselt Geheimnisse (HomeKit-Langzeitschlüssel der Kopplung), bevor sie in einem Attribut
 * und damit in settings.json landen. Schlüsseldatei mit Modus 0600 im Kernel-Verzeichnis;
 * die Zusatzdaten "InstanzID|Feld" verhindern, dass vertauschte Felder entschlüsseln.
 * Grenze: Wer die Schlüsseldatei lesen kann, kann entschlüsseln. Es schützt lesbare
 * settings.json, Sicherungen und Support-Exporte.
 */
final class HkcSecretStore
{
    private const PREFIX = 'v1:';

    public function __construct(private readonly string $KeyFile)
    {
    }

    public function Encrypt(string $Plain, string $Context): string
    {
        if ($Plain === '') {
            return '';
        }
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($Plain, $Context, $nonce, $this->Key(true));
        return self::PREFIX . base64_encode($nonce . $cipher);
    }

    /** Liefert null, wenn der Wert fehlt, beschädigt ist oder zu einem anderen Kontext gehört. */
    public function Decrypt(string $Stored, string $Context): ?string
    {
        if (!str_starts_with($Stored, self::PREFIX)) {
            return null;
        }
        $raw = base64_decode(substr($Stored, strlen(self::PREFIX)), true);
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        $key = $this->Key(false);
        if ($raw === false || strlen($raw) <= $nonceLength || $key === null) {
            return null;
        }
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($raw, $nonceLength), $Context, substr($raw, 0, $nonceLength), $key);
        return $plain === false ? null : $plain;
    }

    private function Key(bool $Create): ?string
    {
        $length = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
        if (is_file($this->KeyFile)) {
            $key = (string) file_get_contents($this->KeyFile);
            if (strlen($key) === $length) {
                return $key;
            }
            // Beschädigte Datei: Lesen liefert „kein Geheimnis“ (Formular und Kachel laufen weiter),
            // nur das Speichern meldet den Fehler, damit niemand unbemerkt mit falschem Schlüssel schreibt.
            if (!$Create) {
                return null;
            }
            throw new RuntimeException('Key file is damaged: ' . $this->KeyFile);
        }
        if (!$Create) {
            return null;
        }
        $key = random_bytes($length);
        $previous = umask(0077);
        try {
            // x: niemals eine fremde oder gleichzeitig angelegte Datei überschreiben
            $handle = @fopen($this->KeyFile, 'x');
            if ($handle === false) {
                return $this->Key(false) ?? throw new RuntimeException('Key file cannot be created');
            }
            fwrite($handle, $key);
            fclose($handle);
            chmod($this->KeyFile, 0600);
        } finally {
            umask($previous);
        }
        return $key;
    }
}
