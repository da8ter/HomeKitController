<?php

declare(strict_types=1);

/**
 * HTTP/1.1 für HomeKit: Anfragen bauen und Antworten sowie Ereignisse (EVENT/1.0) inkrementell zerlegen.
 * Die Gegenstelle schickt Antworten mit Content-Length oder chunked; Ereignisse sehen aus wie Antworten
 * mit der Startzeile "EVENT/1.0 200 OK". Rein, ohne Symcon.
 */
final class HapHttp
{
    public const TLV = 'application/pairing+tlv8';
    public const JSON = 'application/hap+json';
    private const MAX_HEADER = 8192;
    private const MAX_BODY = 4 * 1024 * 1024;

    public static function request(string $method, string $path, string $host, string $body = '', string $type = ''): string
    {
        $out = "$method $path HTTP/1.1\r\nHost: $host\r\n";
        if ($body !== '' || $method === 'POST' || $method === 'PUT') {
            if ($type !== '') {
                $out .= "Content-Type: $type\r\n";
            }
            $out .= 'Content-Length: ' . strlen($body) . "\r\n";
        }
        return $out . "\r\n" . $body;
    }

    /**
     * Zerlegt die nächste vollständige Nachricht am Anfang des Puffers.
     * @return array{event:bool, status:int, headers:array<string,string>, body:string, rest:string}|null null = noch unvollständig
     */
    public static function parse(string $buffer): ?array
    {
        $end = strpos($buffer, "\r\n\r\n");
        if ($end === false) {
            if (strlen($buffer) > self::MAX_HEADER) {
                throw new InvalidArgumentException('HTTP-Kopf zu groß');
            }
            return null;
        }
        $lines = explode("\r\n", substr($buffer, 0, $end));
        if (preg_match('#^(HTTP/1\.[01]|EVENT/1\.0) (\d{3})#', (string)array_shift($lines), $m) !== 1) {
            throw new InvalidArgumentException('keine HTTP-Antwort: ' . bin2hex(substr($buffer, 0, 16)));
        }
        $headers = [];
        foreach ($lines as $line) {
            $pos = strpos($line, ':');
            if ($pos !== false) {
                $headers[strtolower(trim(substr($line, 0, $pos)))] = trim(substr($line, $pos + 1));
            }
        }
        $rest = (string)substr($buffer, $end + 4);
        if (stripos($headers['transfer-encoding'] ?? '', 'chunked') !== false) {
            $decoded = self::dechunk($rest);
            if ($decoded === null) {
                return null;
            }
            [$body, $rest] = $decoded;
        } else {
            $len = (int)($headers['content-length'] ?? 0);
            if ($len < 0 || $len > self::MAX_BODY) {
                throw new InvalidArgumentException('ungültige Content-Length ' . $len);
            }
            if (strlen($rest) < $len) {
                return null;
            }
            $body = (string)substr($rest, 0, $len);
            $rest = (string)substr($rest, $len);
        }
        return ['event' => $m[1] === 'EVENT/1.0', 'status' => (int)$m[2], 'headers' => $headers, 'body' => $body, 'rest' => $rest];
    }

    /** @return array{0:string, 1:string}|null [Inhalt, Rest] oder null, solange der letzte Block fehlt */
    private static function dechunk(string $data): ?array
    {
        $body = '';
        $pos = 0;
        while (true) {
            $eol = strpos($data, "\r\n", $pos);
            if ($eol === false) {
                return null;
            }
            $sizeHex = trim(explode(';', substr($data, $pos, $eol - $pos))[0]);
            if ($sizeHex === '' || !ctype_xdigit($sizeHex)) {
                throw new InvalidArgumentException('ungültige Blockgröße');
            }
            $size = hexdec($sizeHex);
            if ($size > self::MAX_BODY || strlen($body) + $size > self::MAX_BODY) {
                throw new InvalidArgumentException('Inhalt zu groß');
            }
            $start = $eol + 2;
            if ($size === 0) {
                $trailerEnd = strpos($data, "\r\n", $start);
                if ($trailerEnd === false) {
                    return null;
                }
                return [$body, (string)substr($data, $trailerEnd + 2)];
            }
            if (strlen($data) < $start + $size + 2) {
                return null;
            }
            $body .= substr($data, $start, (int)$size);
            $pos = $start + (int)$size + 2;
        }
    }
}
