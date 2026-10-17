<?php

declare(strict_types=1);

/**
 * Verbindung zum HomeKit-Gerät über den Client Socket: Kopplung, Sitzungsaufbau, verschlüsselte
 * Anfragen, Antworten und Ereignisse. Der Sitzungszustand liegt im Puffer "S" (nicht in Objektfeldern:
 * Symcon führt jedes ReceiveData auf einem neuen Objekt aus) und wird nur unter dem Semaphor gelesen
 * und geschrieben. Antworten kommen in der Reihenfolge der Anfragen; die Warteschlange "q" sagt,
 * wozu die nächste Antwort gehört. Jede Sitzung trägt eine Nummer "gen": Ein Aufruf, der den Zustand
 * nach einer Pause zurückschreibt, prüft damit, ob die Sitzung inzwischen ersetzt wurde.
 */
trait HkcConnection
{
    private const SEM_MS = 5000;

    private function semaphore(): string
    {
        return 'HKC_' . $this->InstanceID;
    }

    /** Semaphor holen; false heißt: nicht halten, nichts anfassen, nicht freigeben. */
    private function lock(): bool
    {
        if (IPS_SemaphoreEnter($this->semaphore(), self::SEM_MS)) {
            return true;
        }
        $this->SendDebug('Semaphor', 'nicht bekommen, Aufruf übersprungen', 0);
        return false;
    }

    private function unlock(): void
    {
        IPS_SemaphoreLeave($this->semaphore());
    }

    /** @return array<string, mixed> */
    private function loadSession(): array
    {
        $s = json_decode($this->GetBuffer('S'), true);
        return is_array($s) ? $s : $this->blankSession('closed');
    }

    private function saveSession(array $s): void
    {
        $this->SetBuffer('S', (string)json_encode($s));
    }

    private function blankSession(string $phase): array
    {
        return ['phase' => $phase, 'gen' => (int)$this->GetBuffer('Gen') + 1, 'q' => [], 'raw' => '', 'buf' => '', 'wc' => 0, 'rc' => 0, 'since' => time()];
    }

    /** Neue Sitzung anlegen und als aktuelle Generation merken (nur unter dem Semaphor aufrufen). */
    private function resetSession(string $phase, array $extra = []): array
    {
        $s = $this->blankSession($phase) + $extra;
        $this->SetBuffer('Gen', (string)$s['gen']);
        $this->saveSession($s);
        return $s;
    }

    private function ioId(): int
    {
        return (int)(IPS_GetInstance($this->InstanceID)['ConnectionID'] ?? 0);
    }

    private function ioActive(): bool
    {
        $io = $this->ioId();
        return $io > 0 && (int)(IPS_GetInstance($io)['InstanceStatus'] ?? 0) === IS_ACTIVE;
    }

    /** Neue, leere Sitzung nach (Wieder-)Verbindung; bei vorhandener Kopplung gleich /pair-verify. */
    private function sessionOpened(): void
    {
        if (!$this->lock()) {
            return;
        }
        try {
            $s = $this->resetSession('open');
            if ($this->pairing() !== null && $this->GetBuffer('AuthFailed') !== '1') {
                $this->startVerify($s);
            }
            $this->saveSession($s);
        } catch (Throwable $e) {
            $this->failSession($e, $s ?? null);
        } finally {
            $this->unlock();
        }
        $this->updateState();
    }

    private function sessionClosed(): void
    {
        if ($this->lock()) {
            try {
                $this->resetSession('closed');
            } finally {
                $this->unlock();
            }
        }
        $this->updateState();
    }

    private function startVerify(array &$s): void
    {
        $p = $this->pairing();
        [$m1, $st] = HapPairing::verifyM1();
        $s['st'] = array_map('base64_encode', $st);
        $s['phase'] = 'verify2';
        $this->send($s, 'POST', '/pair-verify', $m1, HapHttp::TLV, 'verify2');
        $this->SendDebug('Sitzung', 'pair-verify M1 gesendet (Gerät ' . ($p['accId'] ?? '?') . ')', 0);
    }

    private function send(array &$s, string $method, string $path, string $body, string $type, string $purpose): void
    {
        $req = HapHttp::request($method, $path, $this->ReadPropertyString('Host') ?: 'homekit', $body, $type);
        if (isset($s['keys'])) {
            [$req, $s['wc']] = HapSession::encrypt($req, base64_decode($s['keys']['write']), (int)$s['wc']);
        }
        $s['q'][] = $purpose;
        $io = $this->ioId();
        if ($io <= 0 || !function_exists('CSCK_SendText')) {
            throw new RuntimeException('no client socket');
        }
        CSCK_SendText($io, $req);
    }

    /** Eingehende Bytes: entschlüsseln (falls Sitzung steht), Nachrichten zerlegen und verarbeiten. */
    private function receive(string $bytes): void
    {
        $events = [];
        if (!$this->lock()) {
            return;
        }
        try {
            $s = $this->loadSession();
            if (($s['phase'] ?? '') === 'closed' || ($s['phase'] ?? '') === 'error') {
                return; // Reste einer alten Verbindung
            }
            if (isset($s['keys'])) {
                [$plain, $rest, $s['rc']] = HapSession::decrypt(base64_decode($s['raw']) . $bytes, base64_decode($s['keys']['read']), (int)$s['rc']);
                $s['raw'] = base64_encode($rest);
                $buf = base64_decode($s['buf']) . $plain;
            } else {
                $buf = base64_decode($s['buf']) . $bytes;
            }
            while (($msg = HapHttp::parse($buf)) !== null) {
                $buf = $msg['rest'];
                if ($msg['event']) {
                    $events[] = $msg['body'];
                    continue;
                }
                $purpose = (string)array_shift($s['q']);
                $this->handleResponse($s, $purpose, $msg);
            }
            $s['buf'] = base64_encode($buf);
            $s['rx'] = time();
            $this->saveSession($s);
        } catch (Throwable $e) {
            $this->SendDebug('Fehler', $e->getMessage(), 0);
            $this->failSession($e, $s ?? null);
            return;
        } finally {
            $this->unlock();
        }
        // Variablen anlegen und Werte setzen erst nach dem Semaphor: das löst Nachrichten und Ereignisse aus
        if ($this->GetBuffer('Apply') === '1') {
            $this->SetBuffer('Apply', '');
            $this->afterAccessories();
        }
        $values = $this->GetBuffer('Values');
        if ($values !== '') {
            $this->SetBuffer('Values', '');
            $events[] = $values;
        }
        foreach ($events as $body) {
            $this->applyValues((array)(json_decode($body, true)['characteristics'] ?? []));
        }
        if ($this->GetBuffer('Reconnect') === '1') {
            $this->SetBuffer('Reconnect', '');
            $this->SetTimerInterval('Reconnect', 300);
        }
        $this->updateState();
    }

    private function handleResponse(array &$s, string $purpose, array $msg): void
    {
        $this->SendDebug('Antwort', $purpose . ' -> ' . $msg['status'] . ' (' . strlen($msg['body']) . ' Byte)', 0);
        switch ($purpose) {
            case 'setup2':
                [$m3, $st] = HapPairing::setupM3($msg['body'], (string)($s['code'] ?? ''));
                unset($s['code']);
                $s['st'] = array_map('base64_encode', $st);
                $this->send($s, 'POST', '/pair-setup', $m3, HapHttp::TLV, 'setup4');
                return;
            case 'setup4':
                $c = $s['ctrl'];
                [$m5, $st] = HapPairing::setupM5($msg['body'], array_map('base64_decode', $s['st']), $c['id'], base64_decode($c['ltsk']), base64_decode($c['ltpk']));
                $s['st'] = array_map('base64_encode', $st);
                $this->send($s, 'POST', '/pair-setup', $m5, HapHttp::TLV, 'setup6');
                return;
            case 'setup6':
                $acc = HapPairing::setupFinish($msg['body'], array_map('base64_decode', $s['st']));
                $c = $s['ctrl'];
                $this->storePairing(['ctrlId' => $c['id'], 'ltsk' => $c['ltsk'], 'ltpk' => $c['ltpk'], 'accId' => $acc['id'], 'accLtpk' => base64_encode($acc['ltpk'])]);
                unset($s['ctrl'], $s['st']);
                $this->LogMessage(sprintf($this->Translate('Paired with %s'), $acc['id']), KL_NOTIFY);
                $this->startVerify($s);
                return;
            case 'verify2':
                $p = $this->pairing() ?? throw new RuntimeException('no pairing stored');
                [$m3, $st] = HapPairing::verifyM3($msg['body'], array_map('base64_decode', $s['st']), $p['ctrlId'], base64_decode($p['ltsk']), $p['accId'], base64_decode($p['accLtpk']));
                $s['st'] = array_map('base64_encode', $st);
                $this->send($s, 'POST', '/pair-verify', $m3, HapHttp::TLV, 'verify4');
                return;
            case 'verify4':
                $keys = HapPairing::verifyFinish($msg['body'], array_map('base64_decode', $s['st']));
                unset($s['st']);
                $s['keys'] = array_map('base64_encode', $keys);
                $s['wc'] = 0;
                $s['rc'] = 0;
                $s['phase'] = 'ready';
                $s['since'] = time();
                $this->send($s, 'GET', '/accessories', '', '', 'accessories');
                return;
            case 'accessories':
                $list = json_decode($msg['body'], true);
                if ($msg['status'] >= 300 || !is_array($list) || !isset($list['accessories'])) {
                    throw new RuntimeException('GET /accessories failed: ' . $msg['status'] . ' ' . substr($msg['body'], 0, 120));
                }
                $this->SendDebug('Geräteliste', $msg['body'], 0);
                $this->WriteAttributeString('Accessories', $msg['body']);
                $this->SetBuffer('Apply', '1'); // Variablen außerhalb des Semaphors anlegen
                $ev = [];
                foreach (HapModel::characteristics($list) as $c) {
                    if ($c['events'] && $c['kind'] !== '') {
                        $ev[] = ['aid' => $c['aid'], 'iid' => $c['iid'], 'ev' => true];
                    }
                }
                if ($ev !== []) {
                    $this->send($s, 'PUT', '/characteristics', (string)json_encode(['characteristics' => $ev]), HapHttp::JSON, 'subscribe');
                }
                return;
            case 'read':
                if ($msg['status'] < 300) {
                    $this->SetBuffer('Values', $msg['body']);
                }
                return;
            case 'unpair':
                HapTlv8::assertNoError(HapTlv8::map($msg['body']), 'Unpair');
                $this->storePairing(null);
                $this->LogMessage($this->Translate('Pairing removed'), KL_NOTIFY);
                $this->SetBuffer('Reconnect', '1'); // ungekoppelt frisch verbinden, bereit für eine neue Kopplung
                return;
            default: // subscribe, write: nur Status prüfen
                if ($msg['status'] >= 300) {
                    $this->SendDebug('Warnung', $purpose . ': ' . $msg['status'] . ' ' . $msg['body'], 0);
                }
        }
    }

    /**
     * Fehler im Protokoll: Sitzung verwerfen, der Timer verbindet neu. Jeder Fehler während
     * /pair-verify gilt als ungültige Kopplung (zurückgesetztes oder getauschtes Gerät): dann kein
     * Dauerversuch, sondern Status 202 mit dem Hinweis, die Kopplung lokal zu löschen.
     */
    private function failSession(Throwable $e, ?array $s = null): void
    {
        $s ??= $this->loadSession();
        $authFailed = str_starts_with((string)($s['phase'] ?? ''), 'verify');
        $this->resetSession('error', ['error' => $e->getMessage()]);
        $this->LogMessage($this->translateError($e->getMessage()), KL_ERROR);
        if ($authFailed) {
            $this->SetBuffer('AuthFailed', '1');
        }
        $this->updateState();
    }

    /** @return array{ctrlId:string, ltsk:string, ltpk:string, accId:string, accLtpk:string}|null Schlüssel base64 */
    private function pairing(): ?array
    {
        $plain = $this->secrets()->Decrypt($this->ReadAttributeString('Pairing'), $this->InstanceID . '|Pairing');
        $p = $plain === null ? null : json_decode($plain, true);
        return is_array($p) && isset($p['ctrlId'], $p['ltsk'], $p['accId'], $p['accLtpk']) ? $p : null;
    }

    private function storePairing(?array $p): void
    {
        $this->WriteAttributeString('Pairing', $p === null ? '' : $this->secrets()->Encrypt((string)json_encode($p), $this->InstanceID . '|Pairing'));
    }

    private function secrets(): HkcSecretStore
    {
        return new HkcSecretStore(IPS_GetKernelDir() . 'HomeKitController.key');
    }
}
