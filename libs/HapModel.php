<?php

declare(strict_types=1);

/**
 * Übersetzt die Antwort von GET /accessories in eine flache Liste der Merkmale, die als Symcon-Variable
 * taugen. Bekannte Merkmale bekommen eine Art (kind), aus der das Modul Typ und Darstellung ableitet;
 * unbekannte werden mit kind = '' geliefert und nur im Debug gezeigt. Rein, ohne Symcon.
 */
final class HapModel
{
    public const APPLE_SUFFIX = '-0000-1000-8000-0026BB765291';

    /** Kurzform eines Merkmal-/Diensttyps: "00000071-0000-1000-8000-0026BB765291" -> "71". */
    public static function shortType(string $type): string
    {
        $t = strtoupper(trim($type));
        if (str_ends_with($t, self::APPLE_SUFFIX)) {
            $t = substr($t, 0, 8);
        }
        $short = ltrim($t, '0');
        return $short === '' ? '0' : $short;
    }

    /** Bekannte Merkmale: Kurztyp => [Art, Variablentyp (0 bool, 1 int, 2 float, 3 string), Bezeichnung]. */
    private const KNOWN = [
        '71' => ['presence', 0, 'Presence'],
        '22' => ['motion', 0, 'Motion'],
        '6B' => ['lux', 2, 'Illuminance'],
        '11' => ['temperature', 2, 'Temperature'],
        '10' => ['humidity', 2, 'Humidity'],
        '25' => ['switch', 0, 'On'],
        '8'  => ['brightness', 1, 'Brightness'],
        '68' => ['battery', 1, 'Battery'],
        '79' => ['lowbattery', 0, 'Battery low'],
        '6A' => ['contact', 0, 'Contact'],
        '75' => ['active', 0, 'Active'],
    ];

    /** Dienste ohne eigene Variablen (Geräteinformation, Protokoll). */
    private const SKIP_SERVICES = ['3E', 'A2'];

    /**
     * @return array<int, array{ident:string, aid:int, iid:int, type:string, service:string, name:string, label:string,
     *                           kind:string, vartype:int, format:string, perms:array, writable:bool, events:bool, value:mixed,
     *                           min:?float, max:?float, step:?float}>
     */
    public static function characteristics(array $accessories): array
    {
        $out = [];
        $multi = count($accessories['accessories'] ?? []) > 1;
        foreach ($accessories['accessories'] ?? [] as $acc) {
            $aid = (int)($acc['aid'] ?? 0);
            $accName = self::accessoryName($acc);
            foreach ($acc['services'] ?? [] as $svc) {
                $svcType = self::shortType((string)($svc['type'] ?? ''));
                if (in_array($svcType, self::SKIP_SERVICES, true)) {
                    continue;
                }
                $svcName = '';
                foreach ($svc['characteristics'] ?? [] as $ch) {
                    if (self::shortType((string)($ch['type'] ?? '')) === '23') {
                        $svcName = trim((string)($ch['value'] ?? ''));
                    }
                }
                foreach ($svc['characteristics'] ?? [] as $ch) {
                    $type = self::shortType((string)($ch['type'] ?? ''));
                    $perms = array_values(array_map('strval', (array)($ch['perms'] ?? [])));
                    if ($type === '23' || !in_array('pr', $perms, true) && !in_array('pw', $perms, true)) {
                        continue;
                    }
                    [$kind, $vartype, $label] = self::KNOWN[$type] ?? ['', self::varTypeFor((string)($ch['format'] ?? '')), $type];
                    $base = $svcName !== '' ? $svcName : $label;
                    if ($multi && $accName !== '' && $svcName === '') {
                        $base = $accName . ' ' . $base;
                    }
                    $out[] = [
                        'ident' => 'A' . $aid . '_I' . (int)$ch['iid'],
                        'aid' => $aid,
                        'iid' => (int)$ch['iid'],
                        'type' => $type,
                        'service' => $svcType,
                        'name' => $base,
                        'label' => $label,
                        'kind' => $kind,
                        'vartype' => $vartype,
                        'format' => (string)($ch['format'] ?? ''),
                        'perms' => $perms,
                        'writable' => in_array('pw', $perms, true),
                        'events' => in_array('ev', $perms, true),
                        'value' => $ch['value'] ?? null,
                        'min' => isset($ch['minValue']) ? (float)$ch['minValue'] : null,
                        'max' => isset($ch['maxValue']) ? (float)$ch['maxValue'] : null,
                        'step' => isset($ch['minStep']) ? (float)$ch['minStep'] : null,
                    ];
                }
            }
        }
        // Mehrere Merkmale mit gleichem Namen (z. B. Präsenz und Helligkeit ohne Dienstnamen): Bezeichnung anhängen
        // nur unter den bekannten Merkmalen zählen: unbekannte (z. B. Herstellerfelder im selben Dienst) werden keine Variablen
        $count = array_count_values(array_column(array_filter($out, fn(array $c) => $c['kind'] !== ''), 'name'));
        foreach ($out as &$c) {
            if ($c['kind'] !== '' && $count[$c['name']] > 1 && $c['name'] !== $c['label']) {
                $c['name'] .= ' ' . $c['label'];
            }
        }
        unset($c);
        return $out;
    }

    /** Wert aus HomeKit in den Symcon-Variablentyp bringen. */
    public static function toSymcon(mixed $value, int $vartype): bool|int|float|string
    {
        return match ($vartype) {
            0 => is_string($value) ? in_array(strtolower($value), ['1', 'true'], true) : (bool)$value,
            1 => (int)round((float)$value),
            2 => (float)$value,
            default => is_scalar($value) ? (string)$value : (string)json_encode($value),
        };
    }

    /** Wert aus Symcon für PUT /characteristics. */
    public static function toHomeKit(mixed $value, string $format): bool|int|float|string
    {
        return match ($format) {
            'bool' => (bool)$value,
            'uint8', 'uint16', 'uint32', 'uint64', 'int' => (int)$value,
            'float' => (float)$value,
            default => (string)$value,
        };
    }

    private static function varTypeFor(string $format): int
    {
        return match ($format) {
            'bool' => 0,
            'uint8', 'uint16', 'uint32', 'uint64', 'int' => 1,
            'float' => 2,
            default => 3,
        };
    }

    private static function accessoryName(array $acc): string
    {
        foreach ($acc['services'] ?? [] as $svc) {
            if (self::shortType((string)($svc['type'] ?? '')) !== '3E') {
                continue;
            }
            foreach ($svc['characteristics'] ?? [] as $ch) {
                if (self::shortType((string)($ch['type'] ?? '')) === '23') {
                    return trim((string)($ch['value'] ?? ''));
                }
            }
        }
        return '';
    }
}
