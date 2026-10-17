<?php

declare(strict_types=1);

require_once __DIR__ . '/HapTlv8.php';
require_once __DIR__ . '/HapSrp.php';
require_once __DIR__ . '/HapCrypto.php';
require_once __DIR__ . '/HapSession.php';

/**
 * Kopplung (/pair-setup, M1–M6) und Sitzungsaufbau (/pair-verify, M1–M4) aus Sicht des Controllers.
 * Jeder Schritt nimmt die Antwort der Gegenstelle und einen Zustand entgegen und liefert den nächsten
 * Anfrage-Inhalt und den neuen Zustand. Der Zustand ist ein Array aus Binärstrings, damit das Modul ihn
 * zwischen zwei ReceiveData-Aufrufen in einem Puffer ablegen kann (base64).
 */
final class HapPairing
{
    public const METHOD_PAIR_SETUP = 0;
    public const METHOD_ADD_PAIRING = 3;
    public const METHOD_REMOVE_PAIRING = 4;
    public const METHOD_LIST_PAIRINGS = 5;

    // ---------- /pair-setup ----------

    public static function setupM1(): string
    {
        return HapTlv8::encode([[HapTlv8::STATE, "\x01"], [HapTlv8::METHOD, chr(self::METHOD_PAIR_SETUP)]]);
    }

    /** @return array{0:string, 1:array} [Inhalt M3, Zustand] */
    public static function setupM3(string $m2, string $code, ?GMP $a = null): array
    {
        $map = HapTlv8::map($m2);
        HapTlv8::assertNoError($map, 'Kopplung M2');
        if (($map[HapTlv8::STATE] ?? '') !== "\x02" || !isset($map[HapTlv8::SALT], $map[HapTlv8::PUBLIC_KEY])) {
            throw new RuntimeException('Kopplung M2: unerwartete Antwort');
        }
        $srp = HapSrp::hap()->client('Pair-Setup', self::normalizeCode($code), $map[HapTlv8::SALT], $map[HapTlv8::PUBLIC_KEY], $a);
        $body = HapTlv8::encode([[HapTlv8::STATE, "\x03"], [HapTlv8::PUBLIC_KEY, $srp['A']], [HapTlv8::PROOF, $srp['M1']]]);
        return [$body, ['K' => $srp['K'], 'M2' => $srp['expectM2']]];
    }

    /** @return array{0:string, 1:array} [Inhalt M5, Zustand] */
    public static function setupM5(string $m4, array $state, string $controllerId, string $ltsk, string $ltpk): array
    {
        $map = HapTlv8::map($m4);
        HapTlv8::assertNoError($map, 'Kopplung M4');
        if (($map[HapTlv8::STATE] ?? '') !== "\x04" || !hash_equals($state['M2'], (string)($map[HapTlv8::PROOF] ?? ''))) {
            throw new RuntimeException('Kopplung M4: Gerät hat sich nicht ausgewiesen');
        }
        $K = $state['K'];
        $x = HapCrypto::hkdf($K, 'Pair-Setup-Controller-Sign-Salt', 'Pair-Setup-Controller-Sign-Info');
        $sig = HapCrypto::sign($x . $controllerId . $ltpk, $ltsk);
        $sub = HapTlv8::encode([[HapTlv8::IDENTIFIER, $controllerId], [HapTlv8::PUBLIC_KEY, $ltpk], [HapTlv8::SIGNATURE, $sig]]);
        $encKey = HapCrypto::hkdf($K, 'Pair-Setup-Encrypt-Salt', 'Pair-Setup-Encrypt-Info');
        $body = HapTlv8::encode([[HapTlv8::STATE, "\x05"], [HapTlv8::ENCRYPTED_DATA, HapCrypto::seal($sub, $encKey, HapCrypto::nonceText('PS-Msg05'))]]);
        return [$body, ['K' => $K, 'encKey' => $encKey]];
    }

    /** @return array{id:string, ltpk:string} Kennung und Langzeitschlüssel des Geräts */
    public static function setupFinish(string $m6, array $state): array
    {
        $map = HapTlv8::map($m6);
        HapTlv8::assertNoError($map, 'Kopplung M6');
        if (($map[HapTlv8::STATE] ?? '') !== "\x06" || !isset($map[HapTlv8::ENCRYPTED_DATA])) {
            throw new RuntimeException('Kopplung M6: unerwartete Antwort');
        }
        $sub = HapTlv8::map(HapCrypto::open($map[HapTlv8::ENCRYPTED_DATA], $state['encKey'], HapCrypto::nonceText('PS-Msg06')));
        $id = (string)($sub[HapTlv8::IDENTIFIER] ?? '');
        $ltpk = (string)($sub[HapTlv8::PUBLIC_KEY] ?? '');
        $x = HapCrypto::hkdf($state['K'], 'Pair-Setup-Accessory-Sign-Salt', 'Pair-Setup-Accessory-Sign-Info');
        if ($id === '' || !HapCrypto::verify((string)($sub[HapTlv8::SIGNATURE] ?? ''), $x . $id . $ltpk, $ltpk)) {
            throw new RuntimeException('Kopplung M6: Signatur des Geräts ungültig');
        }
        return ['id' => $id, 'ltpk' => $ltpk];
    }

    // ---------- /pair-verify ----------

    /** @return array{0:string, 1:array} [Inhalt M1, Zustand] */
    public static function verifyM1(): array
    {
        $eph = HapCrypto::x25519Keypair();
        return [HapTlv8::encode([[HapTlv8::STATE, "\x01"], [HapTlv8::PUBLIC_KEY, $eph['public']]]), $eph];
    }

    /** @return array{0:string, 1:array} [Inhalt M3, Zustand mit dem gemeinsamen Geheimnis] */
    public static function verifyM3(string $m2, array $state, string $controllerId, string $ltsk, string $accessoryId, string $accessoryLtpk): array
    {
        $map = HapTlv8::map($m2);
        HapTlv8::assertNoError($map, 'Sitzung M2');
        $bPub = (string)($map[HapTlv8::PUBLIC_KEY] ?? '');
        if (($map[HapTlv8::STATE] ?? '') !== "\x02" || strlen($bPub) !== 32 || !isset($map[HapTlv8::ENCRYPTED_DATA])) {
            throw new RuntimeException('Sitzung M2: unerwartete Antwort');
        }
        $shared = HapCrypto::x25519($state['secret'], $bPub);
        $key = HapCrypto::hkdf($shared, 'Pair-Verify-Encrypt-Salt', 'Pair-Verify-Encrypt-Info');
        $sub = HapTlv8::map(HapCrypto::open($map[HapTlv8::ENCRYPTED_DATA], $key, HapCrypto::nonceText('PV-Msg02')));
        $id = (string)($sub[HapTlv8::IDENTIFIER] ?? '');
        if (!hash_equals($accessoryId, $id)) {
            throw new RuntimeException('Sitzung M2: anderes Gerät (' . $id . ') meldet sich');
        }
        if (!HapCrypto::verify((string)($sub[HapTlv8::SIGNATURE] ?? ''), $bPub . $id . $state['public'], $accessoryLtpk)) {
            throw new RuntimeException('Sitzung M2: Signatur des Geräts ungültig');
        }
        $sig = HapCrypto::sign($state['public'] . $controllerId . $bPub, $ltsk);
        $inner = HapTlv8::encode([[HapTlv8::IDENTIFIER, $controllerId], [HapTlv8::SIGNATURE, $sig]]);
        $body = HapTlv8::encode([[HapTlv8::STATE, "\x03"], [HapTlv8::ENCRYPTED_DATA, HapCrypto::seal($inner, $key, HapCrypto::nonceText('PV-Msg03'))]]);
        return [$body, ['shared' => $shared]];
    }

    /** @return array{write:string, read:string} Sitzungsschlüssel */
    public static function verifyFinish(string $m4, array $state): array
    {
        $map = HapTlv8::map($m4);
        HapTlv8::assertNoError($map, 'Sitzung M4');
        if (($map[HapTlv8::STATE] ?? '') !== "\x04") {
            throw new RuntimeException('Sitzung M4: unerwartete Antwort');
        }
        return HapSession::keys($state['shared']);
    }

    // ---------- /pairings ----------

    public static function removePairing(string $controllerId): string
    {
        return HapTlv8::encode([[HapTlv8::STATE, "\x01"], [HapTlv8::METHOD, chr(self::METHOD_REMOVE_PAIRING)], [HapTlv8::IDENTIFIER, $controllerId]]);
    }

    /** HomeKit-Code in die Form "123-45-678" bringen; Leerzeichen und fehlende Striche sind erlaubt. */
    public static function normalizeCode(string $code): string
    {
        $digits = preg_replace('/\D/', '', $code) ?? '';
        if (strlen($digits) !== 8) {
            throw new InvalidArgumentException('Der HomeKit-Code hat 8 Ziffern (z. B. 123-45-678).');
        }
        return substr($digits, 0, 3) . '-' . substr($digits, 3, 2) . '-' . substr($digits, 5, 3);
    }

    public static function newControllerId(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0F) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3F) | 0x80);
        return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4)));
    }
}
