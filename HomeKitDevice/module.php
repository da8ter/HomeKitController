<?php

declare(strict_types=1);

require_once __DIR__ . '/../libs/HapTlv8.php';
require_once __DIR__ . '/../libs/HapSrp.php';
require_once __DIR__ . '/../libs/HapCrypto.php';
require_once __DIR__ . '/../libs/HapSession.php';
require_once __DIR__ . '/../libs/HapHttp.php';
require_once __DIR__ . '/../libs/HapPairing.php';
require_once __DIR__ . '/../libs/HapModel.php';
require_once __DIR__ . '/../libs/HkcSecretStore.php';
require_once __DIR__ . '/../libs/HkcConnection.php';
require_once __DIR__ . '/../libs/HkcVariables.php';

/**
 * Ein HomeKit-Gerät (HAP over IP) an einem eigenen Client Socket. Symcon ist die Steuerzentrale:
 * Kopplung mit dem HomeKit-Code, verschlüsselte Dauerverbindung, Ereignisse in Echtzeit.
 */
class HomeKitDevice extends IPSModuleStrict
{
    use HkcConnection;
    use HkcVariables;

    private const CLIENT_SOCKET = '{3CFF0FD9-E306-41DB-9B5A-9D06D38576C3}';
    private const DNSSD = '{780B2D48-916C-4D59-AD35-5A429B2355A5}';
    private const WATCH_S = 60;
    private const RESYNC_S = 300;

    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyString('AccessoryId', ''); // HomeKit-ID aus Bonjour (TXT "id"), findet das Gerät nach Portwechsel wieder
        $this->RegisterPropertyString('Host', '');        // nur ohne AccessoryId nötig
        $this->RegisterPropertyInteger('Port', 0);
        $this->RegisterAttributeString('Pairing', '');    // verschlüsselt (HkcSecretStore)
        $this->RegisterAttributeString('Accessories', '{}');
        $this->RegisterAttributeString('Resolved', '{}'); // zuletzt per Bonjour gefundene Adresse
        $this->RegisterVariableBoolean('CONNECTED', $this->Translate('Connected'), [
            'PRESENTATION' => VARIABLE_PRESENTATION_VALUE_PRESENTATION,
            'ICON' => 'Network',
            'OPTIONS' => json_encode([
                ['Value' => false, 'Caption' => $this->Translate('Offline'), 'IconActive' => false, 'IconValue' => '', 'ColorActive' => true, 'ColorValue' => 0xC62828, 'ContentColorActive' => false, 'ContentColorValue' => -1],
                ['Value' => true, 'Caption' => $this->Translate('Online'), 'IconActive' => false, 'IconValue' => '', 'ColorActive' => true, 'ColorValue' => 0x2E7D32, 'ContentColorActive' => false, 'ContentColorValue' => -1],
            ], JSON_UNESCAPED_UNICODE),
        ], 1);
        $this->RegisterTimer('Watch', 0, 'HKC_Watch($_IPS[\'TARGET\']);');
        // Neu verbinden nie aus ReceiveData heraus: IPS_ApplyChanges am Client Socket in dessen eigenem
        // Empfangspfad ließ ihn mit Open=true im Zustand 104 stehen (Docker, 17.10.2026). Deshalb über diesen Timer.
        $this->RegisterTimer('Reconnect', 0, 'HKC_Reconnect($_IPS[\'TARGET\']);');
    }

    public function GetCompatibleParents(): string
    {
        return (string)json_encode(['type' => 'require', 'moduleIDs' => [self::CLIENT_SOCKET]]);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        if (IPS_GetKernelRunlevel() !== KR_READY) {
            $this->RegisterMessage(0, IPS_KERNELSTARTED);
            return;
        }
        $old = (int)$this->GetBuffer('IO');
        $io = $this->ioId();
        if ($old > 0 && $old !== $io) {
            $this->UnregisterMessage($old, IM_CHANGESTATUS);
        }
        if ($io > 0) {
            $this->RegisterMessage($io, IM_CHANGESTATUS);
        }
        $this->SetBuffer('IO', (string)$io);
        $moved = $this->ReadPropertyString('AccessoryId') !== '' && $this->ReadPropertyString('Host') === '' && $this->Resolve();
        $this->afterAccessories();
        $this->SetTimerInterval('Watch', self::WATCH_S * 1000);
        $phase = (string)($this->loadSession()['phase'] ?? 'closed');
        // Socket nicht aktiv, aber auf Öffnen gestellt (z. B. Fehler 200 nach Reload): ebenfalls frisch verbinden
        $ioStuck = !$this->ioActive() && (bool)(json_decode($this->GetConfigurationForParent(), true)['Open'] ?? false);
        if ($moved || $this->addressChanged() || $ioStuck || ($this->ioActive() && $phase === 'closed')) {
            // Neue Adresse, oder Sitzungszustand verloren (Reload, Kernelstart) bei offener Verbindung:
            // Das Gerät erwartet darauf noch verschlüsselte Rahmen. Nur eine frische Verbindung erlaubt /pair-verify.
            $this->Reconnect();
        } else {
            $this->configureIo(true);
        }
        $this->updateState();
    }

    public function MessageSink(int $TimeStamp, int $SenderID, int $Message, array $Data): void
    {
        if ($Message === IPS_KERNELSTARTED) {
            $this->ApplyChanges();
            return;
        }
        if ($Message === IM_CHANGESTATUS && $SenderID === $this->ioId()) {
            $status = (int)($Data[0] ?? 0);
            if ($status === IS_ACTIVE) {
                $this->SetBuffer('Retry', '');
                $this->sessionOpened();
            } else {
                $this->sessionClosed();
                if ($status >= IS_EBASE) {
                    $this->scheduleReconnect();
                }
            }
        }
    }

    /**
     * Der Socket steht im Fehler (Gerät hat die Verbindung gekappt, meist Neustart mit neuem Port): bald selbst neu
     * verbinden, bevor der Client Socket nach 60 s auf der alten Adresse scheitert und das als Fehler ins Log schreibt.
     * Nicht direkt hier verbinden (Nachrichtenpfad des Sockets), sondern über den Timer; Abstand wächst 5/10/20/30 s.
     */
    private function scheduleReconnect(): void
    {
        if ($this->GetBuffer('AuthFailed') === '1') {
            return;
        }
        $n = (int)$this->GetBuffer('Retry');
        $this->SetBuffer('Retry', (string)($n + 1));
        $moved = $this->ReadPropertyString('Host') === '' && $this->Resolve();
        $delay = $moved ? 1 : ([5, 10, 20][$n] ?? 30);
        $this->SendDebug('Verbindung', 'Socket im Fehler, neuer Versuch in ' . $delay . ' s' . ($moved ? ' (neue Adresse)' : ''), 0);
        $this->SetTimerInterval('Reconnect', $delay * 1000);
    }

    public function GetConfigurationForParent(): string
    {
        [$host, $port] = $this->address();
        return (string)json_encode(['Host' => $host, 'Port' => $port, 'Open' => $host !== '' && $port > 0]);
    }

    public function ReceiveData(string $JSONString): string
    {
        $data = json_decode($JSONString, true);
        $raw = (string)($data['Buffer'] ?? '');
        // IPSModuleStrict: der Client Socket liefert HEX (List/.claude/docs/plattform/module-strict-und-php.md)
        $bytes = ctype_xdigit($raw) && strlen($raw) % 2 === 0 ? (string)hex2bin($raw) : $raw;
        if ($bytes !== '') {
            $this->receive($bytes);
        }
        return '';
    }

    public function RequestAction(string $Ident, mixed $Value): void
    {
        $model = $this->model();
        if (!isset($model[$Ident]) || !$model[$Ident]['writable']) {
            throw new InvalidArgumentException(sprintf($this->Translate('Unknown ident %s'), $Ident));
        }
        $c = $model[$Ident];
        $body = (string)json_encode(['characteristics' => [['aid' => $c['aid'], 'iid' => $c['iid'], 'value' => HapModel::toHomeKit($Value, $c['format'])]]]);
        $this->withReadySession(fn(array &$s) => $this->send($s, 'PUT', '/characteristics', $body, HapHttp::JSON, 'write'));
        $this->SetValue($Ident, $Value);
    }

    // ---------------------------------------------------------------- öffentliche Funktionen

    /** Koppelt mit dem HomeKit-Code (Aufkleber am Gerät oder Aqara-App). Läuft im Hintergrund weiter. */
    public function Pair(string $Code): string
    {
        if ($this->pairing() !== null) {
            return $this->Translate('Already paired. Unpair first.');
        }
        try {
            $code = HapPairing::normalizeCode($Code);
        } catch (InvalidArgumentException $e) {
            return $this->Translate($e->getMessage());
        }
        if (!$this->ioActive()) {
            return $this->Translate('No connection to the device. Check address and that it is in the same network.');
        }
        $this->SetBuffer('AuthFailed', '');
        if (!$this->lock()) {
            return $this->Translate('Connection is busy, try again in a moment.');
        }
        try {
            $s = $this->loadSession();
            $retry = ($s['phase'] ?? '') !== 'open';
            if (!$retry) {
                $ltk = HapCrypto::ed25519Keypair();
                $s += ['code' => $code, 'ctrl' => ['id' => HapPairing::newControllerId(), 'ltsk' => base64_encode($ltk['secret']), 'ltpk' => base64_encode($ltk['public'])]];
                $s['phase'] = 'setup2';
                $this->send($s, 'POST', '/pair-setup', HapPairing::setupM1(), HapHttp::TLV, 'setup2');
                $this->saveSession($s);
            }
        } finally {
            $this->unlock();
        }
        if ($retry) {
            $this->Reconnect(); // Kopplung nur auf einer frischen Verbindung
            return $this->Translate('Connection is being re-established. Please press Pair again in a few seconds.');
        }
        return $this->Translate('Pairing started. The status shows the result in a few seconds.');
    }

    /** Hebt die Kopplung beim Gerät auf und löscht sie hier. */
    public function Unpair(): string
    {
        if ($this->pairing() === null) {
            return $this->Translate('Not paired.');
        }
        $p = $this->pairing();
        try {
            $this->withReadySession(fn(array &$s) => $this->send($s, 'POST', '/pairings', HapPairing::removePairing($p['ctrlId']), HapHttp::TLV, 'unpair'));
        } catch (RuntimeException $e) {
            return $e->getMessage() . ' ' . $this->Translate('If the device was reset, use "Delete pairing locally".');
        }
        return $this->Translate('Unpairing sent.');
    }

    /** Löscht die Kopplung nur hier, z. B. wenn das Gerät zurückgesetzt wurde. */
    public function ForgetPairing(): string
    {
        $this->storePairing(null);
        $this->SetBuffer('AuthFailed', '');
        $this->Reconnect();
        return $this->Translate('Pairing deleted locally.');
    }

    public function Reconnect(): void
    {
        $this->SetTimerInterval('Reconnect', 0);
        // Nach einem Verbindungsverlust zuerst die Adresse nachführen: nach einem Neustart meldet das Gerät einen neuen Port
        if (!$this->ioActive() && $this->ReadPropertyString('Host') === '') {
            $this->Resolve();
        }
        $this->configureIo(false);
        $this->sessionClosed();
        $this->configureIo(true);
    }

    /** Sucht das Gerät per Bonjour über seine HomeKit-ID und übernimmt Adresse und Port. */
    public function Resolve(): bool
    {
        $id = strtoupper($this->ReadPropertyString('AccessoryId'));
        $control = IPS_GetInstanceListByModuleID(self::DNSSD)[0] ?? 0;
        if ($id === '' || $control === 0 || !function_exists('ZC_QueryServiceType')) {
            return false;
        }
        foreach (@ZC_QueryServiceType($control, '_hap._tcp', '') ?: [] as $svc) {
            foreach (@ZC_QueryService($control, (string)$svc['Name'], '_hap._tcp', (string)($svc['Domain'] ?? 'local.')) ?: [] as $d) {
                if (in_array('ID=' . $id, array_map('strtoupper', (array)($d['TXTRecords'] ?? [])), true) && isset($d['IPv4'][0])) {
                    $new = ['host' => (string)$d['IPv4'][0], 'port' => (int)$d['Port'], 'name' => (string)$svc['Name']];
                    if ($new !== json_decode($this->ReadAttributeString('Resolved'), true)) {
                        $this->WriteAttributeString('Resolved', (string)json_encode($new));
                        $this->SendDebug('Bonjour', 'Gerät ' . $id . ' unter ' . $new['host'] . ':' . $new['port'], 0);
                        return true;
                    }
                    return false;
                }
            }
        }
        $this->SendDebug('Bonjour', 'Gerät ' . $id . ' nicht gefunden', 0);
        return false;
    }

    /** Timer: Wiederverbinden, Adresse nachführen, regelmäßig Werte nachlesen. */
    public function Watch(): void
    {
        $s = $this->loadSession();
        $phase = (string)($s['phase'] ?? 'closed');
        $age = time() - (int)($s['since'] ?? 0);
        $quiet = time() - (int)($s['rx'] ?? $s['since'] ?? 0);
        if ($phase === 'ready') {
            if ($quiet > 2 * self::RESYNC_S) {
                $this->SendDebug('Watch', 'keine Antwort seit ' . $quiet . ' s, verbinde neu', 0);
                if ($this->ReadPropertyString('Host') === '') {
                    $this->Resolve();
                }
                $this->Reconnect();
            } elseif ($quiet > self::RESYNC_S) {
                $ids = implode(',', array_map(fn(array $c) => $c['aid'] . '.' . $c['iid'], array_filter($this->model(), fn(array $c) => in_array('pr', $c['perms'], true))));
                if ($ids !== '') {
                    $this->withReadySession(fn(array &$x) => $this->send($x, 'GET', '/characteristics?id=' . $ids, '', '', 'read'));
                }
            }
            return;
        }
        $bonjour = $this->ReadPropertyString('Host') === '';
        if ($this->GetBuffer('AuthFailed') === '1' || $this->address()[0] === '') {
            if ($bonjour) {
                $this->Resolve();
            }
            return;
        }
        if (!$this->ioActive() || $phase === 'error' || $age > 60 && $phase !== 'open') {
            if ($bonjour) {
                $this->Resolve();
            }
            $this->Reconnect();
        }
    }

    public function GetConfigurationForm(): string
    {
        $form = json_decode((string)file_get_contents(__DIR__ . '/form.json'), true);
        $p = $this->pairing();
        $s = $this->loadSession();
        [$host, $port] = $this->address();
        $state = sprintf($this->Translate('Address: %s | Paired: %s | Session: %s'), $host !== '' ? $host . ':' . $port : '-', $p !== null ? $p['accId'] : $this->Translate('no'), (string)($s['phase'] ?? '-'));
        if (($s['error'] ?? '') !== '') {
            $state .= ' | ' . $this->translateError((string)$s['error']);
        }
        $form['actions'][0]['caption'] = $state;
        return (string)json_encode($form);
    }

    // ---------------------------------------------------------------- intern

    /** @return array{0:string, 1:int} */
    private function address(): array
    {
        if ($this->ReadPropertyString('Host') !== '') {
            return [$this->ReadPropertyString('Host'), $this->ReadPropertyInteger('Port')];
        }
        $r = json_decode($this->ReadAttributeString('Resolved'), true);
        return [(string)($r['host'] ?? ''), (int)($r['port'] ?? 0)];
    }

    private function configureIo(bool $open): void
    {
        $io = $this->ioId();
        if ($io <= 0) {
            return;
        }
        $cfg = json_decode($this->GetConfigurationForParent(), true);
        $cfg['Open'] = $open && $cfg['Open'];
        $cur = json_decode(IPS_GetConfiguration($io), true);
        $same = ($cur['Host'] ?? null) === $cfg['Host'] && (int)($cur['Port'] ?? 0) === $cfg['Port'] && (bool)($cur['Open'] ?? false) === $cfg['Open'];
        // Gleiche Einstellung reicht nicht, wenn der Socket trotz Open=true inaktiv steht (104): dann neu anwenden
        if ($same && !($cfg['Open'] && (int)IPS_GetInstance($io)['InstanceStatus'] === IS_INACTIVE)) {
            return;
        }
        IPS_SetConfiguration($io, (string)json_encode($cfg));
        // Ein Gerät, das gerade nicht erreichbar ist, würde sonst jede Minute "Connection refused" ins Log schreiben;
        // der Zustand steht ohnehin am Socket (200) und in der Statusvariable.
        @IPS_ApplyChanges($io);
    }

    private function withReadySession(callable $fn): void
    {
        if (!$this->lock()) {
            throw new RuntimeException($this->Translate('Connection is busy, try again in a moment.'));
        }
        try {
            $s = $this->loadSession();
            if (($s['phase'] ?? '') !== 'ready') {
                throw new RuntimeException($this->Translate('No session with the device.'));
            }
            $fn($s);
            $this->saveSession($s);
        } finally {
            $this->unlock();
        }
    }

    /** Fehlertexte der Bausteine sind englische Schlüssel der Form "Schritt: Text [(N s)]"; beide Teile übersetzen. */
    private function translateError(string $message): string
    {
        if (preg_match('/^([^:]+): (.+?)( \(\d+ s\))?$/', $message, $m) === 1) {
            return $this->Translate($m[1]) . ': ' . $this->Translate($m[2]) . ($m[3] ?? '');
        }
        return $this->Translate($message);
    }

    /** Weicht die Adresse des Client Socket von der gewünschten ab (Bonjour hat eine neue gefunden)? */
    private function addressChanged(): bool
    {
        $io = $this->ioId();
        if ($io <= 0) {
            return false;
        }
        [$host, $port] = $this->address();
        $cur = json_decode(IPS_GetConfiguration($io), true);
        return $host !== '' && (($cur['Host'] ?? '') !== $host || (int)($cur['Port'] ?? 0) !== $port);
    }

    private function updateState(): void
    {
        $phase = (string)($this->loadSession()['phase'] ?? 'closed');
        $this->SetValue('CONNECTED', $phase === 'ready');
        if ($this->address()[0] === '') {
            $this->SetStatus($this->ReadPropertyString('AccessoryId') === '' ? IS_INACTIVE : 203);
        } elseif ($this->GetBuffer('AuthFailed') === '1') {
            $this->SetStatus(202);
        } elseif ($this->pairing() === null) {
            $this->SetStatus(201);
        } elseif ($phase === 'ready') {
            $this->SetStatus(IS_ACTIVE);
        } else {
            $this->SetStatus(200);
        }
    }
}
