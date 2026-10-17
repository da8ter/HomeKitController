<?php

declare(strict_types=1);

/**
 * SRP-6a, Client-Seite, wie HomeKit sie für /pair-setup verlangt: 3072-Bit-Gruppe aus RFC 5054
 * (Generator 5), SHA-512, Benutzername "Pair-Setup", Passwort = HomeKit-Code "123-45-678".
 *
 * Formeln (wie Apples HomeKit-ADK und aiohomekit):
 *   k  = H(N | PAD(g))           u  = H(PAD(A) | PAD(B))       x = H(s | H(I ":" P))
 *   S  = (B - k*g^x)^(a + u*x)   K  = H(S)
 *   M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)              M2 = H(A | M1 | K)
 * PAD = linksbündig mit Nullen auf die Länge von N; A, B, S in M1/K ohne Auffüllen.
 * Die Gruppe und die Hashfunktion sind einstellbar, damit der Test die Vektoren aus RFC 5054
 * (1024 Bit, SHA-1) gegen dieselbe Rechnung prüfen kann.
 */
final class HapSrp
{
    public const N_3072 =
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        . 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        . 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
        . '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        . 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
        . '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
        . 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
        . 'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

    private GMP $n;
    private GMP $g;
    private int $len;
    private string $hash;

    public function __construct(string $nHex = self::N_3072, int $g = 5, string $hash = 'sha512')
    {
        $this->n = gmp_init($nHex, 16);
        $this->g = gmp_init($g);
        $this->len = intdiv(strlen(ltrim($nHex, '0')) + 1, 2);
        $this->hash = $hash;
    }

    public static function hap(): self
    {
        return new self();
    }

    public function N(): GMP { return $this->n; }

    public function bytes(GMP $v): string
    {
        return gmp_cmp($v, 0) === 0 ? "\x00" : gmp_export($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    public function pad(GMP $v): string
    {
        return str_pad($this->bytes($v), $this->len, "\x00", STR_PAD_LEFT);
    }

    public function int(string $bytes): GMP
    {
        return $bytes === '' ? gmp_init(0) : gmp_import($bytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    public function h(string ...$parts): string
    {
        return hash($this->hash, implode('', $parts), true);
    }

    public function k(): GMP
    {
        return $this->int($this->h($this->bytes($this->n), $this->pad($this->g)));
    }

    public function x(string $salt, string $user, string $password): GMP
    {
        return $this->int($this->h($salt, $this->h($user . ':' . $password)));
    }

    public function u(GMP $A, GMP $B): GMP
    {
        return $this->int($this->h($this->pad($A), $this->pad($B)));
    }

    public function publicA(GMP $a): GMP
    {
        return gmp_powm($this->g, $a, $this->n);
    }

    /** Gemeinsames Geheimnis S aus Sicht des Clients. */
    public function clientS(GMP $B, GMP $a, GMP $x, GMP $u): GMP
    {
        if (gmp_cmp(gmp_mod($B, $this->n), 0) === 0) {
            throw new RuntimeException('SRP: ungültiger öffentlicher Schlüssel der Gegenstelle');
        }
        $base = gmp_mod(gmp_sub($B, gmp_mul($this->k(), gmp_powm($this->g, $x, $this->n))), $this->n);
        $exp = gmp_add($a, gmp_mul($u, $x));
        return gmp_powm($base, $exp, $this->n);
    }

    /** Für Tests: S aus Sicht des Servers (Verifier v, geheimes b). */
    public function serverS(GMP $A, GMP $b, GMP $v, GMP $u): GMP
    {
        return gmp_powm(gmp_mod(gmp_mul($A, gmp_powm($v, $u, $this->n)), $this->n), $b, $this->n);
    }

    /** Für Tests: B = k*v + g^b. */
    public function publicB(GMP $b, GMP $v): GMP
    {
        return gmp_mod(gmp_add(gmp_mul($this->k(), $v), gmp_powm($this->g, $b, $this->n)), $this->n);
    }

    public function verifier(GMP $x): GMP
    {
        return gmp_powm($this->g, $x, $this->n);
    }

    public function m1(string $user, string $salt, GMP $A, GMP $B, string $K): string
    {
        $hn = $this->h($this->bytes($this->n));
        $hg = $this->h($this->bytes($this->g));
        return $this->h($hn ^ $hg, $this->h($user), $salt, $this->bytes($A), $this->bytes($B), $K);
    }

    public function m2(GMP $A, string $m1, string $K): string
    {
        return $this->h($this->bytes($A), $m1, $K);
    }

    /**
     * Kompletter Client-Schritt für HomeKit: aus Salz und B der Gegenstelle A, M1 und den Sitzungsschlüssel K.
     * @return array{A:string, M1:string, K:string, expectM2:string}
     */
    public function client(string $user, string $password, string $salt, string $bBytes, ?GMP $a = null): array
    {
        $a ??= $this->int(random_bytes(32));
        $A = $this->publicA($a);
        $B = $this->int($bBytes);
        $u = $this->u($A, $B);
        if (gmp_cmp($u, 0) === 0) {
            throw new RuntimeException('SRP: u = 0');
        }
        $x = $this->x($salt, $user, $password);
        $K = $this->h($this->bytes($this->clientS($B, $a, $x, $u)));
        $m1 = $this->m1($user, $salt, $A, $B, $K);
        return ['A' => $this->bytes($A), 'M1' => $m1, 'K' => $K, 'expectM2' => $this->m2($A, $m1, $K)];
    }
}
