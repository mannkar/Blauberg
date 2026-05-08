# Vento Expert

IP-Symcon Modul fuer die lokale LAN-Integration von Blauberg VENTO Expert W V.2/V.3 Geraeten ueber UDP Port 4000.

## Funktionsumfang

- UDP-Kommunikation ueber den IP-Symcon UDP Socket Parent.
- Paketaufbau nach Blauberg Smart-Home-Protokoll: `FD FD`, Type `0x02`, 16-Byte Device ID, Passwort, Funktion, Datenblock und 16-Bit-Checksumme.
- Generische Parameter-Engine fuer Lesen, Schreiben mit/ohne Antwort sowie Batch-Reads.
- Unterstuetzte PHP-Funktionen:
  - `BVE_ReadParameter(integer $InstanzID, integer $address)`
  - `BVE_WriteParameter(integer $InstanzID, integer $address, mixed $value, boolean $requireResponse)`
  - `BVE_ReadParametersBatch(integer $InstanzID, array $addresses)`
  - `BVE_IncrementParameter(integer $InstanzID, integer $address)`
  - `BVE_DecrementParameter(integer $InstanzID, integer $address)`
- Parameter-Browser im Konfigurationsformular mit bekannten Parametern aus dem Smart-Home-Manual und Cache der zuletzt gelesenen Werte.
- Polling ausgewaehlter Parameter mit optionaler Variablenerzeugung.
- Debug-Level 0..5 mit TX/RX-Hexdump, geparsten Feldern, Checksumme, RTT, Retries, Timeouts und Ringbuffer.

## Voraussetzungen

- IP-Symcon ab Version 9.0
- Blauberg VENTO Expert W V.2/V.3 im gleichen LAN oder per Broadcast erreichbar
- Device ID vom Geraeteaufkleber oder `DEFAULT_DEVICEID` fuer Suche/Default-Betrieb
- Geraetepasswort, Standard: `1111`

## Einrichtung

1. Instanz `Vento Expert` anlegen.
2. Als Parent den `UDP Socket` zuweisen und dort Host/Port setzen (Port `4000`).
3. Bei `DeviceID = DEFAULT_DEVICEID` zuerst `Discover DeviceID (0x007C/0x00B9)` ausfuehren. Die gefundene 16-stellige DeviceID wird automatisch uebernommen.
4. Passwort setzen.
5. `SelfTest` ausfuehren.
6. Mit `Read Parameter` zum Beispiel `0x0001` oder `0x0002` lesen.

## Schreibbeispiele

- Geraet einschalten: Adresse `0x0001`, Wert `1`
- Geraet ausschalten: Adresse `0x0001`, Wert `0`
- Speed 2 setzen: Adresse `0x0002`, Wert `2`
- Rohbytes schreiben: Wert als `hex:01 02 03`

Mehrbyte-Werte werden little-endian kodiert. Fuer bekannte Parameter nutzt das Modul die hinterlegte Groesse; unbekannte Parameter koennen weiterhin manuell gelesen und geschrieben werden.
