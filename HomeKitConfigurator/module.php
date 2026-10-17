<?php

declare(strict_types=1);

/**
 * Listet die HomeKit-Geräte im Netz (Bonjour "_hap._tcp", über Symcons DNS-SD-Steuerung) und legt
 * auf Klick ein HomeKit-Gerät samt eigenem Client Socket an. Bekannte Instanzen werden über die
 * HomeKit-ID (TXT "id") zugeordnet; Instanzen, deren Gerät nicht mehr im Netz ist, bleiben sichtbar.
 */
class HomeKitConfigurator extends IPSModuleStrict
{
    private const DEVICE = '{C11092D8-6115-460B-9882-CA3318C0E2A5}';
    private const CLIENT_SOCKET = '{3CFF0FD9-E306-41DB-9B5A-9D06D38576C3}';
    private const DNSSD = '{780B2D48-916C-4D59-AD35-5A429B2355A5}';

    /** HomeKit-Kategorien (TXT "ci"), Auszug der häufigsten. */
    private const CATEGORIES = [1 => 'Other', 2 => 'Bridge', 5 => 'Lightbulb', 7 => 'Outlet', 8 => 'Switch', 9 => 'Thermostat', 10 => 'Sensor', 14 => 'Window covering', 21 => 'Air conditioner'];

    public function GetConfigurationForm(): string
    {
        $form = json_decode((string)file_get_contents(__DIR__ . '/form.json'), true);
        $control = IPS_GetInstanceListByModuleID(self::DNSSD)[0] ?? 0;
        if ($control === 0 || !function_exists('ZC_QueryServiceType')) {
            $form['actions'][0]['caption'] = $this->Translate('DNS-SD Control (Bonjour) is not available.');
            return (string)json_encode($form);
        }
        $instances = [];
        foreach (IPS_GetInstanceListByModuleID(self::DEVICE) as $id) {
            $instances[strtoupper((string)IPS_GetProperty($id, 'AccessoryId'))] = $id;
        }
        $values = [];
        foreach ($this->discover($control) as $d) {
            $id = $instances[$d['id']] ?? 0;
            unset($instances[$d['id']]);
            $pairable = $d['sf'] === '1' ? $this->Translate('yes') : ($id > 0 ? $this->Translate('paired with Symcon') : $this->Translate('no (paired elsewhere)'));
            $values[] = [
                'name' => $d['name'],
                'model' => $d['md'],
                'category' => $this->Translate(self::CATEGORIES[(int)$d['ci']] ?? 'Other'),
                'accessoryId' => $d['id'],
                'pairable' => $pairable,
                'address' => $d['host'] . ':' . $d['port'],
                'instanceID' => $id,
                'create' => [
                    ['moduleID' => self::DEVICE, 'name' => $d['name'], 'configuration' => ['AccessoryId' => $d['id']]],
                    ['moduleID' => self::CLIENT_SOCKET, 'name' => 'HomeKit Socket ' . $d['name'], 'configuration' => ['Host' => $d['host'], 'Port' => $d['port'], 'Open' => false]],
                ],
            ];
        }
        foreach ($instances as $accId => $id) {
            if ($accId === '') {
                continue;
            }
            $values[] = ['name' => IPS_GetName($id), 'model' => '', 'category' => '', 'accessoryId' => $accId, 'pairable' => $this->Translate('not found'), 'address' => '', 'instanceID' => $id];
        }
        $form['actions'][1]['values'] = $values;
        return (string)json_encode($form);
    }

    /** @return array<int, array{name:string, id:string, md:string, ci:string, sf:string, host:string, port:int}> */
    private function discover(int $control): array
    {
        $out = [];
        foreach (@ZC_QueryServiceType($control, '_hap._tcp', '') ?: [] as $svc) {
            foreach (@ZC_QueryService($control, (string)$svc['Name'], '_hap._tcp', (string)($svc['Domain'] ?? 'local.')) ?: [] as $d) {
                $txt = [];
                foreach ((array)($d['TXTRecords'] ?? []) as $rec) {
                    [$k, $v] = array_pad(explode('=', (string)$rec, 2), 2, '');
                    $txt[strtolower($k)] = $v;
                }
                if (($txt['id'] ?? '') === '' || !isset($d['IPv4'][0])) {
                    continue;
                }
                $out[] = ['name' => (string)$svc['Name'], 'id' => strtoupper($txt['id']), 'md' => (string)($txt['md'] ?? ''), 'ci' => (string)($txt['ci'] ?? ''),
                          'sf' => (string)($txt['sf'] ?? ''), 'host' => (string)$d['IPv4'][0], 'port' => (int)$d['Port']];
            }
        }
        return $out;
    }
}
