<?php

declare(strict_types=1);

/**
 * Kryptobausteine von HomeKit über libsodium: HKDF-SHA512, ChaCha20-Poly1305 (IETF, 96-Bit-Nonce),
 * Ed25519 und X25519. Nonces sind immer 4 Nullbytes + 8 Byte (Text wie "PS-Msg05" oder ein
 * 64-Bit-Zähler little-endian).
 */
final class HapCrypto
{
    public static function hkdf(string $ikm, string $salt, string $info, int $len = 32): string
    {
        return hash_hkdf('sha512', $ikm, $len, $info, $salt);
    }

    public static function nonceText(string $label): string
    {
        return "\x00\x00\x00\x00" . str_pad($label, 8, "\x00");
    }

    public static function nonceCounter(int $counter): string
    {
        return "\x00\x00\x00\x00" . pack('P', $counter);
    }

    public static function seal(string $plain, string $key, string $nonce, string $aad = ''): string
    {
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plain, $aad, $nonce, $key);
    }

    /** Entschlüsselt und prüft; wirft bei falschem Schlüssel oder manipulierten Daten. */
    public static function open(string $cipher, string $key, string $nonce, string $aad = ''): string
    {
        $plain = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($cipher, $aad, $nonce, $key);
        if ($plain === false) {
            throw new RuntimeException('Decryption failed (wrong key or corrupted data)');
        }
        return $plain;
    }

    /** @return array{secret:string, public:string} Ed25519, secret = 64 Byte (sodium-Format) */
    public static function ed25519Keypair(): array
    {
        $pair = sodium_crypto_sign_keypair();
        return ['secret' => sodium_crypto_sign_secretkey($pair), 'public' => sodium_crypto_sign_publickey($pair)];
    }

    public static function sign(string $message, string $secret): string
    {
        return sodium_crypto_sign_detached($message, $secret);
    }

    public static function verify(string $signature, string $message, string $public): bool
    {
        return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES && strlen($public) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && sodium_crypto_sign_verify_detached($signature, $message, $public);
    }

    /** @return array{secret:string, public:string} X25519 */
    public static function x25519Keypair(): array
    {
        $secret = random_bytes(32);
        return ['secret' => $secret, 'public' => sodium_crypto_scalarmult_base($secret)];
    }

    public static function x25519(string $secret, string $public): string
    {
        return sodium_crypto_scalarmult($secret, $public);
    }
}
