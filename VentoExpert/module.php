<?php

declare(strict_types=1);

class VentoExpert extends IPSModuleStrict
{
    private const GUID_UDP_SOCKET = '{82347F20-F541-41E1-AC5B-A636FD3AE2D8}';
    private const DATA_ID_SOCKET_TX = '{C8792760-65CF-4C53-B5C7-A30FCC84FEFE}';
    private const DATA_ID_SOCKET_RX = '{7A1272A4-CBDB-46EF-BFC6-DCF4A53D2FC7}';
    private const DATA_ID_UDP_TX = '{8E4D9B23-E0F2-1E05-41D8-C21EA53B8706}';
    private const DATA_ID_UDP_RX = '{9082C662-7864-D5CA-863F-53999200D897}';

    private const STATUS_HOST_MISSING = 201;
    private const STATUS_PORT_INVALID = 202;
    private const STATUS_DEVICE_ID_INVALID = 203;
    private const STATUS_PASSWORD_INVALID = 204;
    private const STATUS_PARENT_INACTIVE = 205;

    private const PROTOCOL_TYPE = 0x02;
    private const FUNC_READ = 0x01;
    private const FUNC_WRITE = 0x02;
    private const FUNC_WRITE_RESPONSE = 0x03;
    private const FUNC_INCREMENT = 0x04;
    private const FUNC_DECREMENT = 0x05;
    private const FUNC_RESPONSE = 0x06;

    private const CMD_FUNC = 0xFC;
    private const CMD_NOT_SUPPORTED = 0xFD;
    private const CMD_SIZE = 0xFE;
    private const CMD_PAGE = 0xFF;

    private const DEBUG_ERROR = 1;
    private const DEBUG_WARNING = 2;
    private const DEBUG_INFO = 3;
    private const DEBUG_VERBOSE = 4;
    private const DEBUG_TRACE = 5;

    public function Create(): void
    {
        parent::Create();

        $this->RegisterPropertyString('Host', '');
        $this->RegisterPropertyInteger('Port', 4000);
        $this->RegisterPropertyBoolean('EnableBroadcast', false);
        $this->RegisterPropertyString('DeviceID', 'DEFAULT_DEVICEID');
        $this->RegisterPropertyString('Password', '1111');
        $this->RegisterPropertyInteger('Timeout', 1000);
        $this->RegisterPropertyInteger('Retries', 2);
        $this->RegisterPropertyInteger('RateLimit', 100);
        $this->RegisterPropertyInteger('PollInterval', 60);
        $this->RegisterPropertyInteger('DebugLevel', 3);
        $this->RegisterPropertyBoolean('LogRaw', false);
        $this->RegisterPropertyInteger('DebugBufferSize', 50);
        $this->RegisterPropertyBoolean('CreateVariables', true);
        $this->RegisterPropertyString('PollParameters', '[]');

        $this->RegisterAttributeString('Cache', '{}');
        $this->RegisterAttributeString('DebugBuffer', '[]');
        $this->RegisterAttributeString('LastResponse', '');
        $this->RegisterAttributeString('LastPacket', '');
        $this->RegisterAttributeString('LastError', '');
        $this->RegisterAttributeString('LastTxTime', '0');

        $this->RegisterTimer('PollTimer', 0, 'BVE_Poll($_IPS["TARGET"]);');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        $this->MaintainConfiguredVariables();

        if (!$this->ValidateConfiguration()) {
            $this->SetTimerInterval('PollTimer', 0);
            return;
        }

        $pollInterval = max(0, $this->ReadPropertyInteger('PollInterval'));
        $this->SetTimerInterval('PollTimer', $pollInterval > 0 ? $pollInterval * 1000 : 0);

        if (!$this->IsParentReady()) {
            $this->SetStatus(self::STATUS_PARENT_INACTIVE);
            $this->RegisterOnceTimer('ParentRecheckOnce', 'BVE_RecheckParent($_IPS["TARGET"]);');
            return;
        }

        $this->SetStatus(102);
    }

    public function RecheckParent(): void
    {
        if (!$this->ValidateConfiguration()) {
            return;
        }

        if ($this->IsParentReady()) {
            $this->SetStatus(102);
            return;
        }

        $this->SetStatus(self::STATUS_PARENT_INACTIVE);
        $this->RegisterOnceTimer('ParentRecheckOnce', 'BVE_RecheckParent($_IPS["TARGET"]);');
    }

    public function GetCompatibleParents(): string
    {
        return json_encode([
            'type' => 'require',
            'modules' => [
                [
                    'moduleID' => self::GUID_UDP_SOCKET,
                    'initial' => [
                        'Host' => $this->ReadPropertyString('Host'),
                        'Port' => $this->ReadPropertyInteger('Port'),
                        'BindIP' => '',
                        'BindPort' => 0,
                        'EnableBroadcast' => $this->ReadPropertyBoolean('EnableBroadcast'),
                        'EnableReuseAddress' => true
                    ]
                ]
            ]
        ]);
    }

    public function GetConfigurationForm(): string
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'), true);
        if (!is_array($form)) {
            return json_encode([
                'elements' => [
                    [
                        'type' => 'Label',
                        'caption' => 'form.json is not valid JSON.'
                    ]
                ],
                'actions' => [],
                'status' => []
            ]);
        }

        $this->SetFormFieldRecursive($form, 'PollParameters', 'values', $this->BuildPollParameterRows());
        $this->SetFormFieldRecursive($form, 'ParameterBrowser', 'values', $this->BuildParameterBrowserRows());
        if ($this->IsConfiguredDefaultDeviceId()) {
            $this->SetFormFieldRecursive($form, 'ReadAddress', 'value', '0x007C');
        }

        return json_encode($form);
    }

    public function ReceiveData(string $JSONString): string
    {
        $data = json_decode($JSONString, true);
        if (!is_array($data) || !isset($data['Buffer'])) {
            $this->TraceUnexpected('RX', 'Invalid ReceiveData JSON', ['json' => $JSONString]);
            return '';
        }

        $dataId = isset($data['DataID']) ? (string) $data['DataID'] : '';
        if (($dataId === self::DATA_ID_SOCKET_RX || $dataId === self::DATA_ID_UDP_RX) && isset($data['Type']) && (int) $data['Type'] !== 0) {
            $this->DebugLog(self::DEBUG_VERBOSE, 'RX Event', $this->JsonEncode($data));
            return '';
        }

        $packet = $this->DecodeIncomingBuffer((string) $data['Buffer']);
        $source = [
            'dataID' => $dataId,
            'clientIP' => isset($data['ClientIP']) ? (string) $data['ClientIP'] : '',
            'clientPort' => isset($data['ClientPort']) ? (int) $data['ClientPort'] : 0
        ];

        try {
            $parsed = $this->ParsePacket($packet);
            $parsed['source'] = $source;
            $this->AddDebugFrame('RX', $packet, $parsed, 'received');
            $this->LogParsedPacket('RX', $parsed);
            if ($this->GetStatus() === self::STATUS_PARENT_INACTIVE) {
                $this->SetStatus(102);
            }

            if (!$parsed['checksumOK']) {
                $this->TraceUnexpected('RX', 'Checksum mismatch', $parsed);
                return '';
            }

            if ((int) $parsed['type'] !== self::PROTOCOL_TYPE) {
                $this->TraceUnexpected('RX', 'Unexpected protocol type', $parsed);
                return '';
            }

            if (!$this->DeviceIdMatches($parsed)) {
                $this->TraceUnexpected('RX', 'Unexpected device ID', $parsed);
                return '';
            }

            if ((int) $parsed['func'] === self::FUNC_RESPONSE) {
                $parsed['parameters'] = $this->ParseDataBlock($parsed['dataBytes']);
                $parsed['receivedAt'] = microtime(true);
                $this->UpdateCache($parsed['parameters']);
                $this->WriteAttributeString('LastResponse', $this->JsonEncode($this->SanitizePacketForStorage($parsed)));
            }

            $this->WriteAttributeString('LastPacket', $this->JsonEncode($this->SanitizePacketForStorage($parsed)));
        } catch (Throwable $e) {
            $this->TraceUnexpected('RX', $e->getMessage(), [
                'hex' => $this->HexDump($packet),
                'length' => strlen($packet),
                'source' => $source
            ]);
        }

        return '';
    }

    public function RequestAction(string $ident, mixed $value): void
    {
        $this->DebugLog(self::DEBUG_VERBOSE, 'RequestAction', $ident . ' => ' . $this->ValueToDebugString($value));

        try {
            if (preg_match('/^P_([0-9A-Fa-f]{4})$/', $ident, $matches) === 1) {
                $address = hexdec($matches[1]);
                $this->WriteParameter($address, $value, true);
                return;
            }

            switch ($ident) {
                case 'SelfTest':
                    $this->EchoMessage($this->ToPrettyJson($this->SelfTest()));
                    break;

                case 'ReadParameterForm':
                    $address = $this->ParseAddress($value);
                    $result = $this->ReadParameter($address);
                    $this->UpdateFormField('ParameterBrowser', 'values', $this->JsonEncode($this->BuildParameterBrowserRows()));
                    $this->EchoMessage(sprintf('0x%04X = %s', $address, $this->ValueToDebugString($result)));
                    break;

                case 'DiscoverDeviceID':
                    $info = $this->DiscoverAndApplyDeviceId();
                    $this->EchoMessage(sprintf(
                        'Discovered DeviceID "%s" (UnitType: %s). DeviceID was applied and instance was reloaded.',
                        $info['deviceId'],
                        $this->ValueToDebugString($info['unitType'])
                    ));
                    break;

                case 'WriteParameterForm':
                    $payload = $this->DecodeActionPayload($value);
                    $address = $this->ParseAddress($payload['address'] ?? '');
                    $requireResponse = array_key_exists('requireResponse', $payload) ? (bool) $payload['requireResponse'] : true;
                    $result = $this->WriteParameter($address, $payload['value'] ?? '', $requireResponse);
                    $this->UpdateFormField('ParameterBrowser', 'values', $this->JsonEncode($this->BuildParameterBrowserRows()));
                    $this->EchoMessage($requireResponse ? sprintf('0x%04X = %s', $address, $this->ValueToDebugString($result)) : sprintf('0x%04X written without response.', $address));
                    break;

                case 'SendRawHex':
                    $this->SendRawHex((string) $value);
                    $this->EchoMessage('Raw frame sent.');
                    break;

                case 'DumpStatus':
                    $this->EchoMessage($this->DumpStatus());
                    break;

                case 'DumpDebugBuffer':
                    $this->EchoMessage($this->DumpDebugBuffer());
                    break;

                case 'ClearDebugBuffer':
                    $this->WriteAttributeString('DebugBuffer', '[]');
                    $this->EchoMessage('Debug buffer cleared.');
                    break;

                case 'PollNow':
                    $this->Poll();
                    $this->UpdateFormField('ParameterBrowser', 'values', $this->JsonEncode($this->BuildParameterBrowserRows()));
                    $this->EchoMessage('Polling completed.');
                    break;

                default:
                    throw new InvalidArgumentException('Unknown action: ' . $ident);
            }
        } catch (Throwable $e) {
            $this->WriteAttributeString('LastError', $e->getMessage());
            $this->DebugLog(self::DEBUG_ERROR, 'RequestAction Error', $e->getMessage());
            $this->EchoMessage('Error: ' . $e->getMessage());
        }
    }

    public function ReadParameter(int $address): mixed
    {
        $result = $this->ReadParametersBatch([$address]);
        if (!array_key_exists($address, $result)) {
            throw new RuntimeException(sprintf('No value returned for parameter 0x%04X.', $address));
        }

        return $result[$address];
    }

    public function WriteParameter(int $address, mixed $value, bool $requireResponse = true): mixed
    {
        $this->ValidateAddress($address);
        $data = $this->BuildWriteData([
            [
                'address' => $address,
                'value' => $value
            ]
        ]);

        $response = $this->Transact($requireResponse ? self::FUNC_WRITE_RESPONSE : self::FUNC_WRITE, $data, $requireResponse);
        if (!$requireResponse) {
            return null;
        }

        $parameters = $this->ExtractParametersFromResponse($response);
        if (!array_key_exists($address, $parameters)) {
            throw new RuntimeException(sprintf('No write confirmation returned for parameter 0x%04X.', $address));
        }

        return $parameters[$address];
    }

    public function ReadParametersBatch(array $addresses): array
    {
        if ($addresses === []) {
            return [];
        }

        $result = [];
        foreach ($this->BuildReadChunks($addresses) as $chunk) {
            $data = $this->BuildReadData($chunk);
            $response = $this->Transact(self::FUNC_READ, $data, true);
            foreach ($this->ExtractParametersFromResponse($response) as $address => $value) {
                $result[$address] = $value;
            }
        }

        return $result;
    }

    public function IncrementParameter(int $address): mixed
    {
        return $this->ChangeParameterByFunction($address, self::FUNC_INCREMENT);
    }

    public function DecrementParameter(int $address): mixed
    {
        return $this->ChangeParameterByFunction($address, self::FUNC_DECREMENT);
    }

    public function Poll(): void
    {
        $addresses = [];
        foreach ($this->GetPollRows() as $row) {
            if (array_key_exists('enabled', $row) && !(bool) $row['enabled']) {
                continue;
            }
            if (!isset($row['address']) || trim((string) $row['address']) === '') {
                continue;
            }
            $addresses[] = $this->ParseAddress($row['address']);
        }

        if ($addresses === []) {
            return;
        }

        $this->DebugLog(self::DEBUG_INFO, 'Poll', 'Reading ' . count($addresses) . ' parameter(s).');
        $this->ReadParametersBatch($addresses);
    }

    public function SelfTest(): array
    {
        $report = [
            'configuration' => [
                'host' => $this->GetEffectiveHost(),
                'port' => $this->GetEffectivePort(),
                'deviceID' => $this->ReadPropertyString('DeviceID'),
                'passwordLength' => strlen($this->ReadPropertyString('Password')),
                'timeoutMs' => $this->ReadPropertyInteger('Timeout'),
                'retries' => $this->ReadPropertyInteger('Retries'),
                'parentActive' => $this->IsParentReady()
            ],
            'packetBuilder' => [],
            'onlineRead' => null
        ];

        $packet = $this->BuildPacket(self::FUNC_READ, $this->BuildReadData([0x0001, 0x0002]));
        $parsed = $this->ParsePacket($packet);
        $report['packetBuilder'] = [
            'length' => strlen($packet),
            'hex' => $this->HexDump($packet),
            'checksum' => sprintf('0x%04X', $parsed['checksumCalculated']),
            'checksumOK' => $parsed['checksumOK']
        ];

        if ($this->ValidateConfiguration() && $this->IsParentReady()) {
            try {
                $report['onlineRead'] = $this->ReadParametersBatch([0x0001, 0x0002]);
            } catch (Throwable $e) {
                $report['onlineRead'] = [
                    'error' => $e->getMessage()
                ];
            }
        }

        return $report;
    }

    public function SendRawHex(string $hex): void
    {
        $packet = $this->StringFromBytes($this->HexToBytes($hex));
        if ($packet === '') {
            throw new InvalidArgumentException('Raw frame is empty.');
        }

        $this->SendPacket($packet, 1);
    }

    public function DumpDebugBuffer(): string
    {
        $buffer = json_decode($this->ReadAttributeString('DebugBuffer'), true);
        return $this->ToPrettyJson(is_array($buffer) ? $buffer : []);
    }

    public function DumpStatus(): string
    {
        $cache = json_decode($this->ReadAttributeString('Cache'), true);
        $lastPacket = json_decode($this->ReadAttributeString('LastPacket'), true);

        return $this->ToPrettyJson([
            'instanceID' => $this->InstanceID,
            'status' => [
                'host' => $this->GetEffectiveHost(),
                'port' => $this->GetEffectivePort(),
                'deviceID' => $this->ReadPropertyString('DeviceID'),
                'passwordLength' => strlen($this->ReadPropertyString('Password')),
                'timeoutMs' => $this->ReadPropertyInteger('Timeout'),
                'retries' => $this->ReadPropertyInteger('Retries'),
                'rateLimitMs' => $this->ReadPropertyInteger('RateLimit'),
                'pollIntervalSeconds' => $this->ReadPropertyInteger('PollInterval'),
                'debugLevel' => $this->ReadPropertyInteger('DebugLevel'),
                'parentActive' => $this->IsParentReady()
            ],
            'lastError' => $this->ReadAttributeString('LastError'),
            'cache' => is_array($cache) ? $cache : [],
            'lastPacket' => is_array($lastPacket) ? $lastPacket : null
        ]);
    }

    private function ValidateConfiguration(): bool
    {
        try {
            $this->GetDeviceIdBytes();
        } catch (Throwable $e) {
            $this->WriteAttributeString('LastError', $e->getMessage());
            $this->SetStatus(self::STATUS_DEVICE_ID_INVALID);
            return false;
        }

        try {
            $this->GetPasswordBytes();
        } catch (Throwable $e) {
            $this->WriteAttributeString('LastError', $e->getMessage());
            $this->SetStatus(self::STATUS_PASSWORD_INVALID);
            return false;
        }

        return true;
    }

    private function Transact(int $func, array $dataBytes, bool $expectResponse): ?array
    {
        $packet = $this->BuildPacket($func, $dataBytes);
        $retries = max(0, $this->ReadPropertyInteger('Retries'));
        $timeout = max(100, $this->ReadPropertyInteger('Timeout'));
        $lastError = '';
        $lastKnownRxError = $this->ReadAttributeString('LastError');

        for ($attempt = 1; $attempt <= $retries + 1; $attempt++) {
            $this->WriteAttributeString('LastResponse', '');
            $started = microtime(true);
            $this->SendPacket($packet, $attempt);

            if (!$expectResponse) {
                return null;
            }

            $response = $this->WaitForResponse($started, $timeout);
            if ($response !== null) {
                $rttMs = (int) round(((float) $response['receivedAt'] - $started) * 1000);
                $this->DebugLog(self::DEBUG_INFO, 'RTT', $rttMs . ' ms after attempt ' . $attempt);
                return $response;
            }

            $lastError = sprintf('Timeout after %d ms on attempt %d.', $timeout, $attempt);
            $this->DebugLog(self::DEBUG_WARNING, 'Timeout', $lastError);
        }

        $hint = $this->BuildTimeoutHint($func, $dataBytes, $lastKnownRxError);
        if ($hint !== '') {
            $lastError .= ' ' . $hint;
        }

        $this->WriteAttributeString('LastError', $lastError);
        throw new RuntimeException($lastError);
    }

    private function SendPacket(string $packet, int $attempt): void
    {
        $this->WaitForRateLimit();

        $parsed = null;
        try {
            $parsed = $this->ParsePacket($packet);
        } catch (Throwable $e) {
            $parsed = [
                'parseError' => $e->getMessage()
            ];
        }

        $this->AddDebugFrame('TX', $packet, $parsed, 'attempt ' . $attempt);
        $this->LogParsedPacket('TX', is_array($parsed) ? $parsed : []);

        $parentId = $this->GetParentInstanceId();
        if ($parentId <= 0) {
            throw new RuntimeException('UDP socket parent is not connected.');
        }

        $host = $this->GetEffectiveHost();
        $port = $this->GetEffectivePort();
        $sent = false;

        if (function_exists('USCK_SendPacket')) {
            $this->DebugLog(self::DEBUG_VERBOSE, 'TX Route', sprintf('USCK_SendPacket parent=%d host=%s port=%d', $parentId, $host, $port));
            $sent = @USCK_SendPacket($parentId, $packet, $host, $port);
            if (!$sent) {
                $this->DebugLog(self::DEBUG_WARNING, 'TX Route', 'USCK_SendPacket returned false, trying dataflow fallback.');
            }
        }

        if (!$sent) {
            $payloadUdp = [
                'DataID' => self::DATA_ID_UDP_TX,
                'Buffer' => utf8_encode($packet),
                'ClientIP' => $host,
                'ClientPort' => $port,
                'Broadcast' => $this->ReadPropertyBoolean('EnableBroadcast')
            ];
            $encodedUdp = json_encode($payloadUdp);
            if (is_string($encodedUdp)) {
                $responseUdp = $this->SendDataToParent($encodedUdp);
                $this->DebugLog(self::DEBUG_TRACE, 'TX Route', 'Fallback via Extended(UDP) dataflow.');
                if ($responseUdp !== '') {
                    $this->DebugLog(self::DEBUG_TRACE, 'ParentResponse UDP', $responseUdp);
                }
                $sent = true;
            }
        }

        if (!$sent) {
            $payloadSocket = [
                'DataID' => self::DATA_ID_SOCKET_TX,
                'Type' => 0,
                'Buffer' => utf8_encode($packet),
                'ClientIP' => $host,
                'ClientPort' => $port
            ];
            $encodedSocket = json_encode($payloadSocket);
            if (!is_string($encodedSocket)) {
                throw new RuntimeException('Unable to encode UDP payload for fallback transport.');
            }
            $responseSocket = $this->SendDataToParent($encodedSocket);
            $this->DebugLog(self::DEBUG_TRACE, 'TX Route', 'Fallback via Extended(Socket) dataflow.');
            if ($responseSocket !== '') {
                $this->DebugLog(self::DEBUG_TRACE, 'ParentResponse Socket', $responseSocket);
            }
        }

        $this->WriteAttributeString('LastTxTime', (string) microtime(true));
    }

    private function GetEffectiveHost(): string
    {
        $parentId = $this->GetParentInstanceId();
        if ($parentId > 0) {
            $host = trim((string) @IPS_GetProperty($parentId, 'Host'));
            if ($host !== '') {
                return $host;
            }
        }

        return trim($this->ReadPropertyString('Host'));
    }

    private function GetEffectivePort(): int
    {
        $parentId = $this->GetParentInstanceId();
        if ($parentId > 0) {
            $port = (int) @IPS_GetProperty($parentId, 'Port');
            if ($port > 0) {
                return $port;
            }
        }

        return $this->ReadPropertyInteger('Port');
    }

    private function GetParentInstanceId(): int
    {
        $instance = IPS_GetInstance($this->InstanceID);
        return isset($instance['ConnectionID']) ? (int) $instance['ConnectionID'] : 0;
    }

    private function IsParentReady(): bool
    {
        $parentId = $this->GetParentInstanceId();
        if ($parentId <= 0) {
            return false;
        }

        $parent = @IPS_GetInstance($parentId);
        if (!is_array($parent)) {
            return false;
        }

        $status = isset($parent['InstanceStatus']) ? (int) $parent['InstanceStatus'] : 0;
        if ($status === 102 || $status === 106) {
            return true;
        }

        $open = @IPS_GetProperty($parentId, 'Open');
        if (is_bool($open)) {
            return $open;
        }
        if (is_int($open)) {
            return $open > 0;
        }
        if (is_string($open)) {
            $normalized = strtolower(trim($open));
            if ($normalized === '1' || $normalized === 'true' || $normalized === 'on' || $normalized === 'yes') {
                return true;
            }
            if ($normalized === '0' || $normalized === 'false' || $normalized === 'off' || $normalized === 'no') {
                return false;
            }
        }

        return false;
    }

    private function BuildTimeoutHint(int $func, array $dataBytes, string $lastKnownRxError): string
    {
        $hints = [];

        if ($func === self::FUNC_READ && $this->IsConfiguredDefaultDeviceId() && !$this->IsDiscoveryReadData($dataBytes)) {
            $hints[] = 'Hint: DeviceID is DEFAULT_DEVICEID. With router/network mode the unit usually answers only 0x007C and 0x00B9. Use "Discover DeviceID (0x007C/0x00B9)" and apply the discovered 16-character DeviceID.';
        }

        if ($this->ReadPropertyString('Password') === '1111') {
            $hints[] = 'Hint: Password is still 1111. If changed in app, set the new password here.';
        }

        $currentRxError = $this->ReadAttributeString('LastError');
        if ($currentRxError !== '' && $currentRxError !== $lastKnownRxError && stripos($currentRxError, 'Timeout after') === false) {
            $hints[] = 'Last RX issue: ' . $currentRxError;
        }

        return implode(' ', $hints);
    }

    private function IsConfiguredDefaultDeviceId(): bool
    {
        return trim($this->ReadPropertyString('DeviceID')) === 'DEFAULT_DEVICEID';
    }

    private function IsDiscoveryReadData(array $dataBytes): bool
    {
        $addresses = $this->ExtractAddressesFromReadData($dataBytes);
        if ($addresses === []) {
            return false;
        }

        foreach ($addresses as $address) {
            if ($address !== 0x007C && $address !== 0x00B9) {
                return false;
            }
        }

        return true;
    }

    private function ExtractAddressesFromReadData(array $dataBytes): array
    {
        $addresses = [];
        $page = 0x00;

        $count = count($dataBytes);
        $i = 0;
        while ($i < $count) {
            $b = (int) $dataBytes[$i];
            if ($b === self::CMD_PAGE) {
                if (!isset($dataBytes[$i + 1])) {
                    break;
                }
                $page = (int) $dataBytes[$i + 1];
                $i += 2;
                continue;
            }

            if ($b >= self::CMD_FUNC) {
                $i++;
                continue;
            }

            $addresses[] = (($page & 0xFF) << 8) | ($b & 0xFF);
            $i++;
        }

        return $addresses;
    }

    private function DiscoverAndApplyDeviceId(): array
    {
        $data = $this->BuildReadData([0x007C, 0x00B9]);
        $response = $this->Transact(self::FUNC_READ, $data, true);
        $details = isset($response['parameters']) && is_array($response['parameters'])
            ? $response['parameters']
            : $this->ParseDataBlock($response['dataBytes'] ?? []);

        if (!isset($details[0x007C]) || !is_array($details[0x007C])) {
            throw new RuntimeException('Discovery response did not contain parameter 0x007C.');
        }

        $entryId = $details[0x007C];
        $rawValue = $entryId['value'] ?? null;
        $rawHex = isset($entryId['raw']) ? (string) $entryId['raw'] : '';
        $deviceId = $this->NormalizeDiscoveredDeviceId($rawValue, $rawHex);
        if (strlen($deviceId) !== 16) {
            throw new RuntimeException('Discovered DeviceID does not contain exactly 16 characters.');
        }

        IPS_SetProperty($this->InstanceID, 'DeviceID', $deviceId);
        IPS_ApplyChanges($this->InstanceID);

        $unitType = null;
        if (isset($details[0x00B9]) && is_array($details[0x00B9])) {
            $unitType = $details[0x00B9]['value'] ?? null;
        }

        $this->DebugLog(self::DEBUG_INFO, 'Discovery', 'Applied discovered DeviceID: ' . $deviceId);

        return [
            'deviceId' => $deviceId,
            'unitType' => $unitType
        ];
    }

    private function NormalizeDiscoveredDeviceId(mixed $value, string $rawHex): string
    {
        if (is_string($value)) {
            $text = trim($value, " \t\r\n\0");
            if (strlen($text) === 16) {
                return $text;
            }
        }

        $bytes = $this->HexToBytes($rawHex);
        if (count($bytes) === 16) {
            $text = trim($this->BytesToAscii($bytes), " \t\r\n\0");
            if (strlen($text) === 16) {
                return $text;
            }
        }

        throw new RuntimeException('Unable to normalize discovered DeviceID from 0x007C.');
    }

    private function WaitForResponse(float $started, int $timeoutMs): ?array
    {
        $deadline = $started + ($timeoutMs / 1000);
        while (microtime(true) < $deadline) {
            $raw = $this->ReadAttributeString('LastResponse');
            if ($raw !== '') {
                $response = json_decode($raw, true);
                if (is_array($response) && isset($response['receivedAt']) && (float) $response['receivedAt'] >= $started) {
                    return $response;
                }
            }

            IPS_Sleep(20);
        }

        return null;
    }

    private function WaitForRateLimit(): void
    {
        $rateLimit = max(0, $this->ReadPropertyInteger('RateLimit'));
        if ($rateLimit === 0) {
            return;
        }

        $lastTx = (float) $this->ReadAttributeString('LastTxTime');
        if ($lastTx <= 0) {
            return;
        }

        $elapsedMs = (microtime(true) - $lastTx) * 1000;
        if ($elapsedMs < $rateLimit) {
            IPS_Sleep((int) ceil($rateLimit - $elapsedMs));
        }
    }

    private function BuildPacket(int $func, array $dataBytes): string
    {
        if ($func < 0x01 || $func > 0x06) {
            throw new InvalidArgumentException('Invalid function number.');
        }

        $bytes = [
            0xFD,
            0xFD,
            self::PROTOCOL_TYPE,
            0x10
        ];
        $bytes = array_merge($bytes, $this->GetDeviceIdBytes());
        $passwordBytes = $this->GetPasswordBytes();
        $bytes[] = count($passwordBytes);
        $bytes = array_merge($bytes, $passwordBytes);
        $bytes[] = $func;
        $bytes = array_merge($bytes, $this->NormalizeByteArray($dataBytes));

        if (count($bytes) + 2 > 256) {
            throw new InvalidArgumentException('Packet exceeds the maximum size of 256 bytes.');
        }

        $checksum = 0;
        for ($i = 2; $i < count($bytes); $i++) {
            $checksum += $bytes[$i];
        }
        $checksum &= 0xFFFF;
        $bytes[] = $checksum & 0xFF;
        $bytes[] = ($checksum >> 8) & 0xFF;

        return $this->StringFromBytes($bytes);
    }

    private function ParsePacket(string $packet): array
    {
        $bytes = $this->BytesFromString($packet);
        $length = count($bytes);
        if ($length < 2 + 1 + 1 + 1 + 1 + 2) {
            throw new InvalidArgumentException('Packet too short.');
        }

        $checksumCalculated = 0;
        for ($i = 2; $i <= $length - 3; $i++) {
            $checksumCalculated += $bytes[$i];
        }
        $checksumCalculated &= 0xFFFF;
        $checksumReceived = $bytes[$length - 2] | ($bytes[$length - 1] << 8);

        $idSize = $bytes[3];
        $pwdSizeOffset = 4 + $idSize;
        if ($pwdSizeOffset >= $length - 2) {
            throw new InvalidArgumentException('Packet ID block exceeds frame length.');
        }

        $passwordSize = $bytes[$pwdSizeOffset];
        $funcOffset = $pwdSizeOffset + 1 + $passwordSize;
        if ($funcOffset >= $length - 2) {
            throw new InvalidArgumentException('Packet password block exceeds frame length.');
        }

        $deviceBytes = array_slice($bytes, 4, $idSize);
        $passwordBytes = array_slice($bytes, $pwdSizeOffset + 1, $passwordSize);
        $dataBytes = array_slice($bytes, $funcOffset + 1, $length - $funcOffset - 3);

        return [
            'length' => $length,
            'startOK' => $bytes[0] === 0xFD && $bytes[1] === 0xFD,
            'type' => $bytes[2],
            'idSize' => $idSize,
            'deviceId' => $this->BytesToAscii($deviceBytes),
            'deviceIdHex' => $this->BytesToHex($deviceBytes),
            'passwordSize' => $passwordSize,
            'password' => $this->BytesToAscii($passwordBytes),
            'func' => $bytes[$funcOffset],
            'dataLength' => count($dataBytes),
            'dataBytes' => $dataBytes,
            'dataHex' => $this->BytesToHex($dataBytes),
            'checksumReceived' => $checksumReceived,
            'checksumCalculated' => $checksumCalculated,
            'checksumOK' => $checksumReceived === $checksumCalculated,
            'rawHex' => $this->HexDump($packet)
        ];
    }

    private function BuildReadData(array $addresses): array
    {
        $data = [];
        $page = 0x00;
        foreach ($addresses as $address) {
            $address = $this->ValidateAddress((int) $address);
            $this->AppendAddress($data, $address, $page);
        }

        return $data;
    }

    private function BuildWriteData(array $items): array
    {
        $data = [];
        $page = 0x00;
        foreach ($items as $item) {
            $address = $this->ValidateAddress((int) $item['address']);
            $valueBytes = $this->EncodeParameterValue($address, $item['value']);
            if ($valueBytes === []) {
                throw new InvalidArgumentException(sprintf('Parameter 0x%04X value is empty.', $address));
            }

            $high = ($address >> 8) & 0xFF;
            $low = $address & 0xFF;
            if ($low >= 0xFC) {
                throw new InvalidArgumentException(sprintf('Parameter 0x%04X uses a reserved low byte.', $address));
            }
            if ($high !== $page) {
                $data[] = self::CMD_PAGE;
                $data[] = $high;
                $page = $high;
            }
            if (count($valueBytes) !== 1) {
                $data[] = self::CMD_SIZE;
                $data[] = count($valueBytes);
            }
            $data[] = $low;
            $data = array_merge($data, $valueBytes);
        }

        return $data;
    }

    private function BuildReadChunks(array $addresses): array
    {
        $chunks = [];
        $current = [];

        foreach ($addresses as $address) {
            $address = $this->ValidateAddress($this->ParseAddress($address));
            $candidate = array_merge($current, [$address]);
            try {
                $this->BuildPacket(self::FUNC_READ, $this->BuildReadData($candidate));
                $current = $candidate;
            } catch (Throwable $e) {
                if ($current === []) {
                    throw $e;
                }
                $chunks[] = $current;
                $current = [$address];
            }
        }

        if ($current !== []) {
            $chunks[] = $current;
        }

        return $chunks;
    }

    private function AppendAddress(array &$data, int $address, int &$page): void
    {
        $high = ($address >> 8) & 0xFF;
        $low = $address & 0xFF;
        if ($low >= 0xFC) {
            throw new InvalidArgumentException(sprintf('Parameter 0x%04X uses a reserved low byte.', $address));
        }

        if ($high !== $page) {
            $data[] = self::CMD_PAGE;
            $data[] = $high;
            $page = $high;
        }
        $data[] = $low;
    }

    private function ParseDataBlock(array $dataBytes): array
    {
        $parameters = [];
        $page = 0x00;
        $pos = 0;
        $activeFunc = self::FUNC_RESPONSE;

        while ($pos < count($dataBytes)) {
            $byte = $dataBytes[$pos];

            if ($byte === self::CMD_FUNC) {
                if (!isset($dataBytes[$pos + 1])) {
                    throw new RuntimeException('FUNC command without function byte.');
                }
                $activeFunc = $dataBytes[$pos + 1];
                $pos += 2;
                continue;
            }

            if ($byte === self::CMD_PAGE) {
                if (!isset($dataBytes[$pos + 1])) {
                    throw new RuntimeException('PAGE command without page byte.');
                }
                $page = $dataBytes[$pos + 1];
                $pos += 2;
                continue;
            }

            if ($byte === self::CMD_NOT_SUPPORTED) {
                if (!isset($dataBytes[$pos + 1])) {
                    throw new RuntimeException('NOT_SUPPORTED command without parameter byte.');
                }
                $address = ($page << 8) | $dataBytes[$pos + 1];
                $parameters[$address] = [
                    'address' => $address,
                    'supported' => false,
                    'function' => $activeFunc,
                    'raw' => '',
                    'value' => null,
                    'text' => 'not supported'
                ];
                $pos += 2;
                continue;
            }

            $valueSize = 1;
            if ($byte === self::CMD_SIZE) {
                if (!isset($dataBytes[$pos + 1], $dataBytes[$pos + 2])) {
                    throw new RuntimeException('SIZE command without size or parameter byte.');
                }
                $valueSize = $dataBytes[$pos + 1];
                $pos += 2;
                $byte = $dataBytes[$pos];
            }

            if ($byte >= 0xFC) {
                throw new RuntimeException(sprintf('Unexpected special byte 0x%02X in data block.', $byte));
            }

            $address = ($page << 8) | $byte;
            $pos++;
            if ($pos + $valueSize > count($dataBytes)) {
                throw new RuntimeException(sprintf('Parameter 0x%04X value exceeds data block.', $address));
            }

            $valueBytes = array_slice($dataBytes, $pos, $valueSize);
            $decoded = $this->DecodeParameterValue($address, $valueBytes);
            $parameters[$address] = [
                'address' => $address,
                'supported' => true,
                'function' => $activeFunc,
                'raw' => $this->BytesToHex($valueBytes),
                'value' => $decoded,
                'text' => $this->FormatValue($decoded)
            ];
            $pos += $valueSize;
        }

        return $parameters;
    }

    private function ExtractParametersFromResponse(?array $response): array
    {
        if ($response === null) {
            return [];
        }

        $details = isset($response['parameters']) && is_array($response['parameters'])
            ? $response['parameters']
            : $this->ParseDataBlock($response['dataBytes'] ?? []);

        $values = [];
        foreach ($details as $address => $entry) {
            $address = (int) $address;
            $values[$address] = is_array($entry) && array_key_exists('value', $entry) ? $entry['value'] : null;
        }

        return $values;
    }

    private function ChangeParameterByFunction(int $address, int $func): mixed
    {
        $data = $this->BuildReadData([$address]);
        $response = $this->Transact($func, $data, true);
        $parameters = $this->ExtractParametersFromResponse($response);
        if (!array_key_exists($address, $parameters)) {
            throw new RuntimeException(sprintf('No response returned for parameter 0x%04X.', $address));
        }

        return $parameters[$address];
    }

    private function UpdateCache(array $parameters): void
    {
        $cache = json_decode($this->ReadAttributeString('Cache'), true);
        if (!is_array($cache)) {
            $cache = [];
        }

        foreach ($parameters as $address => $entry) {
            $address = (int) $address;
            $key = sprintf('%04X', $address);
            $definition = $this->GetParameterDefinition($address);
            $cache[$key] = [
                'address' => sprintf('0x%04X', $address),
                'name' => $definition['name'] ?? sprintf('Parameter 0x%04X', $address),
                'supported' => (bool) ($entry['supported'] ?? true),
                'raw' => (string) ($entry['raw'] ?? ''),
                'value' => $entry['value'] ?? null,
                'text' => (string) ($entry['text'] ?? $this->FormatValue($entry['value'] ?? null)),
                'timestamp' => date('c')
            ];

            $this->UpdateVariableFromCache($address, $cache[$key]['value']);
        }

        $this->WriteAttributeString('Cache', $this->JsonEncode($cache));
    }

    private function UpdateVariableFromCache(int $address, mixed $value): void
    {
        if (!$this->ReadPropertyBoolean('CreateVariables')) {
            return;
        }

        $ident = $this->GetVariableIdent($address);
        $variableID = @$this->GetIDForIdent($ident);
        if ($variableID === false || $variableID === null) {
            return;
        }

        $type = $this->GetVariableType($address);
        if ($type === 3 && !is_string($value)) {
            $value = $this->FormatValue($value);
        }
        if ($type === 1 && !is_int($value)) {
            $value = (int) $value;
        }
        if ($type === 0 && !is_bool($value)) {
            $value = (bool) $value;
        }

        $this->SetValue($ident, $value);
    }

    private function MaintainConfiguredVariables(): void
    {
        $create = $this->ReadPropertyBoolean('CreateVariables');
        $position = 10;

        foreach ($this->GetPollRows() as $row) {
            if (array_key_exists('enabled', $row) && !(bool) $row['enabled']) {
                continue;
            }
            if (!isset($row['address']) || trim((string) $row['address']) === '') {
                continue;
            }

            try {
                $address = $this->ParseAddress($row['address']);
            } catch (Throwable $e) {
                continue;
            }

            $definition = $this->GetParameterDefinition($address);
            $name = $definition['name'] ?? sprintf('Parameter 0x%04X', $address);
            $ident = $this->GetVariableIdent($address);
            $type = $this->GetVariableType($address);
            $this->MaintainVariable($ident, $name, $type, '', $position, $create);
            $this->MaintainAction($ident, $create && $this->IsWritable($address));
            $position++;
        }
    }

    private function BuildPollParameterRows(): array
    {
        $rows = $this->GetPollRows();
        $defaultEnabled = [
            0x0001,
            0x0002,
            0x0006,
            0x0007,
            0x0025,
            0x004A,
            0x004B,
            0x0083,
            0x0088,
            0x00B9
        ];

        $configured = [];
        $unknownRows = [];
        foreach ($rows as $row) {
            $addressText = isset($row['address']) ? (string) $row['address'] : '';
            try {
                $address = $this->ParseAddress($addressText);
                $configured[$address] = array_key_exists('enabled', $row) ? (bool) $row['enabled'] : true;
            } catch (Throwable $e) {
                $unknownRows[] = [
                    'enabled' => array_key_exists('enabled', $row) ? (bool) $row['enabled'] : false,
                    'address' => $addressText,
                    'name' => 'Invalid address',
                    'access' => '',
                    'type' => ''
                ];
            }
        }

        $definitions = $this->GetParameterDefinitions();
        ksort($definitions);
        $values = [];
        foreach ($definitions as $address => $definition) {
            if (array_key_exists($address, $configured)) {
                $enabled = $configured[$address];
            } elseif ($rows === []) {
                $enabled = in_array($address, $defaultEnabled, true);
            } else {
                $enabled = false;
            }
            $values[] = [
                'enabled' => $enabled,
                'address' => sprintf('0x%04X', $address),
                'name' => $definition['name'] ?? sprintf('Parameter 0x%04X', $address),
                'access' => $definition['access'] ?? '',
                'type' => $definition['type'] ?? 'uint'
            ];
        }

        foreach ($configured as $address => $enabled) {
            if (isset($definitions[$address])) {
                continue;
            }
            $values[] = [
                'enabled' => $enabled,
                'address' => sprintf('0x%04X', $address),
                'name' => sprintf('Manual parameter 0x%04X', $address),
                'access' => '',
                'type' => 'auto'
            ];
        }

        foreach ($unknownRows as $unknownRow) {
            $values[] = $unknownRow;
        }

        return $values;
    }

    private function BuildParameterBrowserRows(): array
    {
        $cache = json_decode($this->ReadAttributeString('Cache'), true);
        if (!is_array($cache)) {
            $cache = [];
        }

        $definitions = $this->GetParameterDefinitions();
        foreach ($cache as $entry) {
            if (isset($entry['address'])) {
                $address = $this->ParseAddress($entry['address']);
                if (!isset($definitions[$address])) {
                    $definitions[$address] = [
                        'name' => 'Manual parameter',
                        'access' => '',
                        'type' => 'auto',
                        'size' => ''
                    ];
                }
            }
        }
        ksort($definitions);

        $rows = [];
        foreach ($definitions as $address => $definition) {
            $key = sprintf('%04X', $address);
            $entry = $cache[$key] ?? [];
            $rows[] = [
                'address' => sprintf('0x%04X', $address),
                'name' => $definition['name'] ?? '',
                'access' => $definition['access'] ?? '',
                'type' => $definition['type'] ?? 'uint',
                'size' => isset($definition['size']) ? (string) $definition['size'] : '',
                'value' => isset($entry['text']) ? (string) $entry['text'] : '',
                'raw' => isset($entry['raw']) ? (string) $entry['raw'] : '',
                'timestamp' => isset($entry['timestamp']) ? (string) $entry['timestamp'] : ''
            ];
        }

        return $rows;
    }

    private function GetPollRows(): array
    {
        $rows = json_decode($this->ReadPropertyString('PollParameters'), true);
        return is_array($rows) ? $rows : [];
    }

    private function EncodeParameterValue(int $address, mixed $value): array
    {
        if (is_array($value)) {
            return $this->NormalizeByteArray($value);
        }

        $definition = $this->GetParameterDefinition($address);
        $type = $definition['type'] ?? 'uint';
        $fixedSize = isset($definition['size']) && is_int($definition['size']) ? (int) $definition['size'] : 1;

        if (is_bool($value)) {
            return [(int) $value];
        }

        if (is_string($value)) {
            $text = trim($value);
            if ($text === '') {
                return [0];
            }
            if (stripos($text, 'hex:') === 0) {
                return $this->HexToBytes(substr($text, 4));
            }
            if (preg_match('/^(0x)?[0-9A-Fa-f]{2}([\\s,;:-]*(0x)?[0-9A-Fa-f]{2})+$/', $text) === 1 && $type !== 'text') {
                return $this->HexToBytes($text);
            }
            if ($type === 'text') {
                return $this->AsciiToBytes($text);
            }
            if ($type === 'ip') {
                return $this->IpToBytes($text);
            }
            if ($type === 'time3') {
                return $this->TimeStringToBytes($text);
            }
            if ($type === 'timer2') {
                return $this->TimerStringToBytes($text);
            }
            if (stripos($text, '0x') === 0) {
                return $this->IntegerToBytes(hexdec(substr($text, 2)), $fixedSize);
            }
            if (is_numeric($text)) {
                return $this->IntegerToBytes((int) $text, $fixedSize);
            }

            return $this->AsciiToBytes($text);
        }

        if (is_int($value) || is_float($value)) {
            return $this->IntegerToBytes((int) round((float) $value), $fixedSize);
        }

        throw new InvalidArgumentException(sprintf('Unsupported value type for parameter 0x%04X.', $address));
    }

    private function DecodeParameterValue(int $address, array $bytes): mixed
    {
        $definition = $this->GetParameterDefinition($address);
        $type = $definition['type'] ?? 'uint';

        switch ($type) {
            case 'text':
                return rtrim($this->BytesToAscii($bytes), "\0");

            case 'ip':
                return implode('.', $bytes);

            case 'time3':
                return [
                    'seconds' => $bytes[0] ?? 0,
                    'minutes' => $bytes[1] ?? 0,
                    'hours' => $bytes[2] ?? 0
                ];

            case 'timer2':
                return [
                    'minutes' => $bytes[0] ?? 0,
                    'hours' => $bytes[1] ?? 0
                ];

            case 'calendar4':
                return [
                    'day' => $bytes[0] ?? 0,
                    'weekday' => $bytes[1] ?? 0,
                    'month' => $bytes[2] ?? 0,
                    'year' => $bytes[3] ?? 0
                ];

            case 'machineHours4':
                return [
                    'minutes' => $bytes[0] ?? 0,
                    'hours' => $bytes[1] ?? 0,
                    'days' => (($bytes[3] ?? 0) << 8) | ($bytes[2] ?? 0)
                ];

            case 'firmware6':
                $year = (($bytes[5] ?? 0) << 8) | ($bytes[4] ?? 0);
                return sprintf('%d.%d %02d.%02d.%04d', $bytes[0] ?? 0, $bytes[1] ?? 0, $bytes[2] ?? 0, $bytes[3] ?? 0, $year);

            case 'schedule6':
                return [
                    'weekday' => $bytes[0] ?? 0,
                    'period' => $bytes[1] ?? 0,
                    'speed' => $bytes[2] ?? 0,
                    'reserved' => $bytes[3] ?? 0,
                    'endMinutes' => $bytes[4] ?? 0,
                    'endHours' => $bytes[5] ?? 0
                ];

            default:
                return $this->BytesToInteger($bytes);
        }
    }

    private function FormatValue(mixed $value): string
    {
        if (is_array($value)) {
            return $this->JsonEncode($value);
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return '';
        }

        return (string) $value;
    }

    private function IsWritable(int $address): bool
    {
        $definition = $this->GetParameterDefinition($address);
        $access = $definition['access'] ?? '';
        return strpos($access, 'W') !== false;
    }

    private function GetVariableType(int $address): int
    {
        $definition = $this->GetParameterDefinition($address);
        $type = $definition['type'] ?? 'uint';
        if (in_array($type, ['text', 'ip', 'time3', 'timer2', 'calendar4', 'machineHours4', 'firmware6', 'schedule6'], true)) {
            return 3;
        }

        return 1;
    }

    private function GetVariableIdent(int $address): string
    {
        return sprintf('P_%04X', $address);
    }

    private function GetParameterDefinition(int $address): array
    {
        $definitions = $this->GetParameterDefinitions();
        return $definitions[$address] ?? [];
    }

    private function GetParameterDefinitions(): array
    {
        return [
            0x0001 => ['name' => 'Unit On/Off', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1, 'min' => 0, 'max' => 2],
            0x0002 => ['name' => 'Speed number', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 1, 'max' => 255],
            0x0006 => ['name' => 'Boost mode status', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x0007 => ['name' => 'Timer mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1],
            0x000B => ['name' => 'Current countdown of Timer mode', 'access' => 'R', 'type' => 'time3', 'size' => 3],
            0x000F => ['name' => 'Humidity sensor activation', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0014 => ['name' => 'Relay sensor activation', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0016 => ['name' => '0-10 V sensor activation', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0019 => ['name' => 'Humidity threshold setpoint', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 40, 'max' => 80, 'unit' => 'RH%'],
            0x0024 => ['name' => 'Current RTC battery voltage', 'access' => 'R', 'type' => 'uint', 'size' => 2, 'unit' => 'mV'],
            0x0025 => ['name' => 'Current humidity', 'access' => 'R', 'type' => 'uint', 'size' => 1, 'unit' => 'RH%'],
            0x002D => ['name' => 'Current 0-10 V sensor signal value', 'access' => 'R', 'type' => 'uint', 'size' => 1, 'unit' => '%'],
            0x0032 => ['name' => 'Current relay sensor state', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x003A => ['name' => 'Supply fan speed in 1st speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x003B => ['name' => 'Exhaust fan speed in 1st speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x003C => ['name' => 'Supply fan speed in 2nd speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x003D => ['name' => 'Exhaust fan speed in 2nd speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x003E => ['name' => 'Supply fan speed in 3rd speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x003F => ['name' => 'Exhaust fan speed in 3rd speed mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 10, 'max' => 255],
            0x0044 => ['name' => 'Manual fan speed', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 0, 'max' => 255],
            0x004A => ['name' => 'Fan 1 speed', 'access' => 'R', 'type' => 'uint', 'size' => 2, 'unit' => 'rpm'],
            0x004B => ['name' => 'Fan 2 speed', 'access' => 'R', 'type' => 'uint', 'size' => 2, 'unit' => 'rpm'],
            0x0063 => ['name' => 'Filter replacement timer setup', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 2, 'unit' => 'days'],
            0x0064 => ['name' => 'Timer countdown to filter replacement', 'access' => 'R', 'type' => 'time3', 'size' => 3],
            0x0065 => ['name' => 'Reset timer countdown to filter replacement', 'access' => 'W', 'type' => 'uint', 'size' => 1],
            0x0066 => ['name' => 'Boost deactivation delay setpoint', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'unit' => 'minutes'],
            0x006F => ['name' => 'RTC time', 'access' => 'R/W/RW', 'type' => 'time3', 'size' => 3],
            0x0070 => ['name' => 'RTC calendar', 'access' => 'R/W/RW', 'type' => 'calendar4', 'size' => 4],
            0x0072 => ['name' => 'Weekly schedule mode', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0077 => ['name' => 'Schedule setup', 'access' => 'R/W/RW', 'type' => 'schedule6', 'size' => 6],
            0x007C => ['name' => 'Device search on local network, ID', 'access' => 'R', 'type' => 'text', 'size' => 16],
            0x007D => ['name' => 'Device password', 'access' => 'R/W/RW', 'type' => 'text', 'size' => '0-8'],
            0x007E => ['name' => 'Machine hours', 'access' => 'R', 'type' => 'machineHours4', 'size' => 4],
            0x0080 => ['name' => 'Reset alarms', 'access' => 'W', 'type' => 'uint', 'size' => 1],
            0x0083 => ['name' => 'Alarm/warning indicator', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x0085 => ['name' => 'Cloud server operation permission', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0086 => ['name' => 'Controller base firmware version and date', 'access' => 'R', 'type' => 'firmware6', 'size' => 6],
            0x0087 => ['name' => 'Restore factory settings', 'access' => 'W', 'type' => 'uint', 'size' => 1],
            0x0088 => ['name' => 'Filter replacement indicator', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x0094 => ['name' => 'Wi-Fi operation mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1],
            0x0095 => ['name' => 'Wi-Fi name in Client mode', 'access' => 'R/W/RW', 'type' => 'text', 'size' => '1-32'],
            0x0096 => ['name' => 'Wi-Fi password', 'access' => 'R/W/RW', 'type' => 'text', 'size' => '8-64'],
            0x0099 => ['name' => 'Wi-Fi data encryption type', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x009A => ['name' => 'Wi-Fi frequency channel', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1],
            0x009B => ['name' => 'Wi-Fi module DHCP', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x009C => ['name' => 'IP address assigned to Wi-Fi module', 'access' => 'R/W/RW', 'type' => 'ip', 'size' => 4],
            0x009D => ['name' => 'Wi-Fi module subnet mask', 'access' => 'R/W/RW', 'type' => 'ip', 'size' => 4],
            0x009E => ['name' => 'Wi-Fi module main gateway', 'access' => 'R/W/RW', 'type' => 'ip', 'size' => 4],
            0x00A0 => ['name' => 'Apply new Wi-Fi parameters and quit Setup Mode', 'access' => 'W', 'type' => 'uint', 'size' => 1],
            0x00A2 => ['name' => 'Discard new Wi-Fi parameters and quit Setup Mode', 'access' => 'W', 'type' => 'uint', 'size' => 1],
            0x00A3 => ['name' => 'Current Wi-Fi module IP address', 'access' => 'R', 'type' => 'ip', 'size' => 4],
            0x00B7 => ['name' => 'Ventilator operation mode', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1],
            0x00B8 => ['name' => '0-10 V sensor threshold setpoint', 'access' => 'R/W/RW/INC/DEC', 'type' => 'uint', 'size' => 1, 'min' => 5, 'max' => 100, 'unit' => '%'],
            0x00B9 => ['name' => 'Unit type', 'access' => 'R', 'type' => 'uint', 'size' => 2],
            0x012A => ['name' => 'Restore fan speed settings to factory defaults', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x0302 => ['name' => 'Night mode timer setpoint', 'access' => 'R/W/RW', 'type' => 'timer2', 'size' => 2],
            0x0303 => ['name' => 'Party mode timer setpoint', 'access' => 'R/W/RW', 'type' => 'timer2', 'size' => 2],
            0x0304 => ['name' => 'Humidity sensor status', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x0305 => ['name' => '0-10 V sensor status', 'access' => 'R', 'type' => 'uint', 'size' => 1],
            0x032A => ['name' => 'Enable Boost mode in passive ventilation mode', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1],
            0x032B => ['name' => 'Passive ventilation mode', 'access' => 'R/W/RW', 'type' => 'uint', 'size' => 1]
        ];
    }

    private function GetDeviceIdBytes(): array
    {
        $deviceId = trim($this->ReadPropertyString('DeviceID'));
        if (stripos($deviceId, 'hex:') === 0) {
            $bytes = $this->HexToBytes(substr($deviceId, 4));
            if (count($bytes) !== 16) {
                throw new InvalidArgumentException('DeviceID hex value must contain exactly 16 bytes.');
            }
            return $bytes;
        }

        if (strlen($deviceId) !== 16) {
            throw new InvalidArgumentException('DeviceID must contain exactly 16 ASCII characters or hex: followed by 16 bytes.');
        }

        return $this->AsciiToBytes($deviceId);
    }

    private function GetPasswordBytes(): array
    {
        $password = $this->ReadPropertyString('Password');
        if (strlen($password) > 8) {
            throw new InvalidArgumentException('Password must not exceed 8 ASCII characters.');
        }
        if ($password !== '' && preg_match('/^[0-9A-Za-z]+$/', $password) !== 1) {
            throw new InvalidArgumentException('Password may contain only 0-9, a-z and A-Z.');
        }

        return $this->AsciiToBytes($password);
    }

    private function DeviceIdMatches(array $parsed): bool
    {
        $configured = trim($this->ReadPropertyString('DeviceID'));
        if ($configured === 'DEFAULT_DEVICEID' || stripos($configured, 'hex:') === 0) {
            return true;
        }

        return isset($parsed['deviceId']) && $parsed['deviceId'] === $configured;
    }

    private function ParseAddress(mixed $value): int
    {
        if (is_int($value)) {
            return $this->ValidateAddress($value);
        }

        $text = trim((string) $value);
        if ($text === '') {
            throw new InvalidArgumentException('Address is empty.');
        }

        if (stripos($text, '0x') === 0) {
            return $this->ValidateAddress((int) hexdec(substr($text, 2)));
        }

        if (preg_match('/[A-Fa-f]/', $text) === 1) {
            return $this->ValidateAddress((int) hexdec($text));
        }

        if (preg_match('/^[0-9]+$/', $text) === 1) {
            return $this->ValidateAddress((int) $text);
        }

        throw new InvalidArgumentException('Invalid address: ' . $text);
    }

    private function ValidateAddress(int $address): int
    {
        if ($address < 0 || $address > 0xFFFF) {
            throw new InvalidArgumentException('Parameter address must be between 0x0000 and 0xFFFF.');
        }

        return $address;
    }

    private function DecodeActionPayload(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        $payload = json_decode((string) $value, true);
        if (!is_array($payload)) {
            throw new InvalidArgumentException('Action payload is not valid JSON.');
        }

        return $payload;
    }

    private function SetFormFieldRecursive(array &$container, string $name, string $parameter, mixed $value): bool
    {
        foreach (['elements', 'actions', 'items'] as $section) {
            if (!isset($container[$section]) || !is_array($container[$section])) {
                continue;
            }

            foreach ($container[$section] as &$item) {
                if (is_array($item) && isset($item['name']) && $item['name'] === $name) {
                    $item[$parameter] = $value;
                    return true;
                }
                if (is_array($item) && $this->SetFormFieldRecursive($item, $name, $parameter, $value)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function AddDebugFrame(string $direction, string $packet, ?array $parsed, string $note): void
    {
        $buffer = json_decode($this->ReadAttributeString('DebugBuffer'), true);
        if (!is_array($buffer)) {
            $buffer = [];
        }

        $entry = [
            'time' => date('c'),
            'direction' => $direction,
            'note' => $note,
            'length' => strlen($packet),
            'hex' => $this->HexDump($packet)
        ];

        if ($parsed !== null) {
            $entry['parsed'] = $this->SanitizePacketForStorage($parsed);
        }

        $buffer[] = $entry;
        $limit = max(1, $this->ReadPropertyInteger('DebugBufferSize'));
        while (count($buffer) > $limit) {
            array_shift($buffer);
        }

        $this->WriteAttributeString('DebugBuffer', $this->JsonEncode($buffer));
    }

    private function SanitizePacketForStorage(array $parsed): array
    {
        unset($parsed['password']);
        if (isset($parsed['passwordSize'])) {
            $parsed['password'] = str_repeat('*', (int) $parsed['passwordSize']);
        }

        return $parsed;
    }

    private function LogParsedPacket(string $direction, array $parsed): void
    {
        $debugLevel = $this->ReadPropertyInteger('DebugLevel');
        $logRaw = $this->ReadPropertyBoolean('LogRaw');
        if ($debugLevel < self::DEBUG_VERBOSE && !$logRaw) {
            return;
        }

        if (isset($parsed['rawHex'])) {
            $message = $parsed['rawHex'] . ' len=' . ($parsed['length'] ?? '?');
            if ($logRaw && $debugLevel < self::DEBUG_VERBOSE) {
                $this->SendDebug($direction . ' Hex', $message, 0);
            } else {
                $this->DebugLog(self::DEBUG_VERBOSE, $direction . ' Hex', $message);
            }
        }

        if ($debugLevel >= self::DEBUG_TRACE) {
            $fields = [
                'startOK' => $parsed['startOK'] ?? null,
                'type' => isset($parsed['type']) ? sprintf('0x%02X', $parsed['type']) : null,
                'idSize' => $parsed['idSize'] ?? null,
                'deviceId' => $parsed['deviceId'] ?? null,
                'passwordSize' => $parsed['passwordSize'] ?? null,
                'func' => isset($parsed['func']) ? sprintf('0x%02X', $parsed['func']) : null,
                'dataLength' => $parsed['dataLength'] ?? null,
                'checksumReceived' => isset($parsed['checksumReceived']) ? sprintf('0x%04X', $parsed['checksumReceived']) : null,
                'checksumCalculated' => isset($parsed['checksumCalculated']) ? sprintf('0x%04X', $parsed['checksumCalculated']) : null,
                'checksumOK' => $parsed['checksumOK'] ?? null
            ];
            $this->DebugLog(self::DEBUG_TRACE, $direction . ' Fields', $this->JsonEncode($fields));
        }
    }

    private function TraceUnexpected(string $direction, string $message, array $context): void
    {
        $this->WriteAttributeString('LastError', $message);
        $this->DebugLog(self::DEBUG_WARNING, $direction . ' Unexpected', $message . ' ' . $this->JsonEncode($context));
    }

    private function DebugLog(int $level, string $topic, string $message): void
    {
        if ($this->ReadPropertyInteger('DebugLevel') < $level) {
            return;
        }

        $this->SendDebug($topic, $message, 0);
    }

    private function BytesFromString(string $data): array
    {
        if ($data === '') {
            return [];
        }

        $bytes = unpack('C*', $data);
        return is_array($bytes) ? array_values($bytes) : [];
    }

    private function DecodeIncomingBuffer(string $buffer): string
    {
        // Standard Symcon socket flow: binary payload is transported as UTF-8 string.
        $packet = utf8_decode($buffer);
        $candidate = preg_replace('/\s+/', '', trim($packet));
        if (!is_string($candidate) || $candidate === '') {
            return $packet;
        }

        // Some environments echo packets as ASCII hex (e.g. "FDFD0210...").
        // Auto-convert this format back to binary before parsing.
        if ((strlen($candidate) % 2) === 0 && strlen($candidate) >= 4 && preg_match('/^[0-9A-Fa-f]+$/', $candidate) === 1) {
            $bytes = $this->HexToBytes($candidate);
            if (count($bytes) >= 2 && $bytes[0] === 0xFD && $bytes[1] === 0xFD) {
                $this->DebugLog(self::DEBUG_VERBOSE, 'RX Decode', 'Detected ASCII-hex packet, converting to binary.');
                return $this->StringFromBytes($bytes);
            }
        }

        return $packet;
    }

    private function StringFromBytes(array $bytes): string
    {
        $bytes = $this->NormalizeByteArray($bytes);
        if ($bytes === []) {
            return '';
        }

        return pack('C*', ...$bytes);
    }

    private function NormalizeByteArray(array $bytes): array
    {
        $result = [];
        foreach ($bytes as $byte) {
            $byte = (int) $byte;
            if ($byte < 0 || $byte > 255) {
                throw new InvalidArgumentException('Byte value out of range: ' . $byte);
            }
            $result[] = $byte;
        }

        return $result;
    }

    private function AsciiToBytes(string $text): array
    {
        $bytes = [];
        for ($i = 0; $i < strlen($text); $i++) {
            $byte = ord($text[$i]);
            if ($byte > 0x7F) {
                throw new InvalidArgumentException('Only ASCII characters are supported here.');
            }
            $bytes[] = $byte;
        }

        return $bytes;
    }

    private function BytesToAscii(array $bytes): string
    {
        $result = '';
        foreach ($bytes as $byte) {
            $result .= chr((int) $byte);
        }

        return $result;
    }

    private function HexToBytes(string $hex): array
    {
        $clean = preg_replace('/0x/i', '', $hex);
        $clean = preg_replace('/[^0-9A-Fa-f]/', '', is_string($clean) ? $clean : '');
        if (!is_string($clean) || $clean === '') {
            return [];
        }
        if (strlen($clean) % 2 !== 0) {
            throw new InvalidArgumentException('Hex string must contain an even number of digits.');
        }

        $bytes = [];
        for ($i = 0; $i < strlen($clean); $i += 2) {
            $bytes[] = hexdec(substr($clean, $i, 2));
        }

        return $bytes;
    }

    private function BytesToHex(array $bytes): string
    {
        $hex = [];
        foreach ($bytes as $byte) {
            $hex[] = sprintf('%02X', (int) $byte);
        }

        return implode(' ', $hex);
    }

    private function HexDump(string $packet): string
    {
        return $this->BytesToHex($this->BytesFromString($packet));
    }

    private function IntegerToBytes(int $value, int $size): array
    {
        if ($value < 0) {
            throw new InvalidArgumentException('Negative values are not supported by this protocol encoder.');
        }

        $size = max(1, $size);
        $bytes = [];
        for ($i = 0; $i < $size; $i++) {
            $bytes[] = ($value >> ($i * 8)) & 0xFF;
        }

        return $bytes;
    }

    private function BytesToInteger(array $bytes): int
    {
        $value = 0;
        foreach ($bytes as $index => $byte) {
            $value |= ((int) $byte) << ($index * 8);
        }

        return $value;
    }

    private function IpToBytes(string $ip): array
    {
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            throw new InvalidArgumentException('IP value must contain four octets.');
        }

        return $this->NormalizeByteArray($parts);
    }

    private function TimeStringToBytes(string $time): array
    {
        $parts = array_map('intval', explode(':', $time));
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Time value must use HH:MM:SS.');
        }

        return [$parts[2], $parts[1], $parts[0]];
    }

    private function TimerStringToBytes(string $time): array
    {
        $parts = array_map('intval', explode(':', $time));
        if (count($parts) !== 2) {
            throw new InvalidArgumentException('Timer value must use HH:MM.');
        }

        return [$parts[1], $parts[0]];
    }

    private function ToPrettyJson(mixed $value): string
    {
        $json = $this->JsonEncode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return $json;
    }

    private function JsonEncode(mixed $value, int $flags = 0): string
    {
        $json = json_encode($value, $flags | JSON_INVALID_UTF8_SUBSTITUTE);
        return is_string($json) ? $json : '';
    }

    private function ValueToDebugString(mixed $value): string
    {
        if (is_array($value) || is_object($value)) {
            return $this->ToPrettyJson($value);
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }

        return (string) $value;
    }

    private function EchoMessage(string $caption): void
    {
        $this->UpdateFormField('EchoMessage', 'caption', $caption);
        $this->UpdateFormField('EchoPopup', 'visible', true);
    }
}
