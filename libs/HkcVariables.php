<?php

declare(strict_types=1);

/**
 * Variablen aus den Diensten des Geräts: eine Variable je bekanntem Merkmal (Ident "A<aid>_I<iid>"),
 * Darstellung je Art. Merkmale, die beim Gerät verschwinden, werden gelöscht (MaintainVariable false).
 */
trait HkcVariables
{
    /** @return array<string, array> bekannte Merkmale je Ident aus der zuletzt gelesenen Geräteliste */
    private function model(): array
    {
        $out = [];
        foreach (HapModel::characteristics((array)json_decode($this->ReadAttributeString('Accessories'), true)) as $c) {
            if ($c['kind'] !== '') {
                $out[$c['ident']] = $c;
            }
        }
        return $out;
    }

    private function afterAccessories(): void
    {
        $model = $this->model();
        $pos = 10;
        foreach ($model as $ident => $c) {
            // Ohne Dienstnamen trägt die Variable die (englische) Bezeichnung des Merkmals: übersetzen
            $name = str_ends_with($c['name'], $c['label']) ? substr($c['name'], 0, -strlen($c['label'])) . $this->Translate($c['label']) : $c['name'];
            $this->MaintainVariable($ident, $name, $c['vartype'], $this->presentation($c), $pos++, true);
            if ($c['writable']) {
                $this->EnableAction($ident);
            }
            if ($c['value'] !== null) {
                $this->SetValue($ident, HapModel::toSymcon($c['value'], $c['vartype']));
            }
        }
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $child) {
            $ident = IPS_GetObject($child)['ObjectIdent'];
            if (preg_match('/^A\d+_I\d+$/', $ident) === 1 && !isset($model[$ident])) {
                $this->MaintainVariable($ident, '', VARIABLETYPE_BOOLEAN, '', 0, false);
            }
        }
        foreach (HapModel::characteristics((array)json_decode($this->ReadAttributeString('Accessories'), true)) as $c) {
            if ($c['kind'] === '') {
                $this->SendDebug('Merkmal ohne Variable', $c['ident'] . ' Typ ' . $c['type'] . ' (' . $c['name'] . ') = ' . json_encode($c['value']), 0);
            }
        }
    }

    /** Werte aus Ereignissen oder Antworten auf GET /characteristics. */
    private function applyValues(array $list): void
    {
        $model = $this->model();
        foreach ($list as $v) {
            $ident = 'A' . (int)($v['aid'] ?? 0) . '_I' . (int)($v['iid'] ?? 0);
            if (!isset($model[$ident]) || !array_key_exists('value', $v) || @$this->GetIDForIdent($ident) === false) {
                continue;
            }
            $this->SetValue($ident, HapModel::toSymcon($v['value'], $model[$ident]['vartype']));
        }
    }

    private function presentation(array $c): array
    {
        $bool = fn(string $icon, string $on, string $off, int $color) => [
            'PRESENTATION' => VARIABLE_PRESENTATION_VALUE_PRESENTATION,
            'ICON' => $icon,
            'OPTIONS' => json_encode([
                ['Value' => false, 'Caption' => $this->Translate($off), 'IconActive' => false, 'IconValue' => '', 'ColorActive' => false, 'ColorValue' => -1, 'ContentColorActive' => false, 'ContentColorValue' => -1],
                ['Value' => true, 'Caption' => $this->Translate($on), 'IconActive' => false, 'IconValue' => '', 'ColorActive' => true, 'ColorValue' => $color, 'ContentColorActive' => false, 'ContentColorValue' => -1],
            ], JSON_UNESCAPED_UNICODE),
        ];
        $value = fn(string $icon, string $suffix, int $digits) => ['PRESENTATION' => VARIABLE_PRESENTATION_VALUE_PRESENTATION, 'ICON' => $icon, 'SUFFIX' => $suffix, 'DIGITS' => $digits];
        return match ($c['kind']) {
            'presence' => $bool('Presence', 'Present', 'Absent', 0x2E7D32),
            'motion' => $bool('Motion', 'Motion', 'No motion', 0x2E7D32),
            'contact' => $bool('Window', 'Open', 'Closed', 0xC62828),
            'lowbattery' => $bool('Battery', 'Low', 'OK', 0xC62828),
            'active' => $bool('Ok', 'Active', 'Inactive', 0x2E7D32),
            'lux' => $value('Sun', ' lx', 0),
            'temperature' => $value('Temperature', ' °C', 1),
            'humidity' => $value('Drops', ' %', 0),
            'battery' => $value('Battery', ' %', 0),
            'switch' => ['PRESENTATION' => VARIABLE_PRESENTATION_SWITCH, 'ICON' => 'Power'],
            'brightness' => ['PRESENTATION' => VARIABLE_PRESENTATION_SLIDER, 'ICON' => 'Intensity', 'SUFFIX' => ' %', 'MIN' => $c['min'] ?? 0, 'MAX' => $c['max'] ?? 100, 'STEP' => $c['step'] ?? 1],
            default => ['PRESENTATION' => VARIABLE_PRESENTATION_VALUE_PRESENTATION],
        };
    }
}
