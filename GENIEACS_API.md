# GenieACS NBI API — Integración Completa

## Índice

1. [Qué es el NBI y cómo se conecta](#1-qué-es-el-nbi-y-cómo-se-conecta)
2. [Autenticación](#2-autenticación)
3. [Estructura de datos de un dispositivo](#3-estructura-de-datos-de-un-dispositivo)
4. [Consultar dispositivos](#4-consultar-dispositivos)
5. [Encoding del Device ID — el truco más crítico](#5-encoding-del-device-id--el-truco-más-crítico)
6. [Sistema de tareas — cómo funciona realmente](#6-sistema-de-tareas--cómo-funciona-realmente)
7. [setParameterValues — cambiar parámetros](#7-setparametervalues--cambiar-parámetros)
8. [Rutas WiFi por vendor — el mapa completo](#8-rutas-wifi-por-vendor--el-mapa-completo)
9. [Detección de frecuencia por canal](#9-detección-de-frecuencia-por-canal)
10. [Reboot — cuándo y cómo](#10-reboot--cuándo-y-cómo)
11. [Connection Request — forzar conexión del ONU](#11-connection-request--forzar-conexión-del-onu)
12. [refreshObject — VirtualParameters](#12-refreshobject--virtualparameters)
13. [Detectar si el ONU está online](#13-detectar-si-el-onu-está-online)
14. [Detectar NAT — por qué las tareas quedan en cola](#14-detectar-nat--por-qué-las-tareas-quedan-en-cola)
15. [Métricas ópticas — RX Power y temperatura](#15-métricas-ópticas--rx-power-y-temperatura)
16. [VirtualParameters — datos calculados por GenieACS](#16-virtualparameters--datos-calculados-por-genieacs)
17. [Parseo del árbol de parámetros](#17-parseo-del-árbol-de-parámetros)
18. [Hosts LAN conectados al ONU](#18-hosts-lan-conectados-al-onu)
19. [Timeouts recomendados](#19-timeouts-recomendados)
20. [Clase de servicio completa en Python](#20-clase-de-servicio-completa-en-python)
21. [Clase de servicio completa en PHP](#21-clase-de-servicio-completa-en-php)
22. [Tabla de errores comunes](#22-tabla-de-errores-comunes)

---

## 1. Qué es el NBI y cómo se conecta

GenieACS expone tres interfaces. La que usamos es el **NBI (Northbound Interface)**:

```
Puerto 7557 → NBI (REST API para aplicaciones externas)  ← ESTE
Puerto 7547 → CWMP (para los ONUs, protocolo TR-069)
Puerto 3000 → UI web de GenieACS
```

```
http://{IP_SERVIDOR}:7557
```

No usa HTTPS por defecto. Si el servidor está en la red privada del ISP, HTTP es suficiente
y más rápido. No agregar SSL a menos que el tráfico cruce internet público.

---

## 2. Autenticación

GenieACS NBI usa **HTTP Basic Auth** — usuario y contraseña configurados al instalar GenieACS.
No usa API Key, no usa Bearer token.

```python
# Python — requests.Session con auth global
session = requests.Session()
session.auth = ("admin", "mi_password_genieacs")
```

```php
// PHP — cURL con CURLOPT_USERPWD
curl_setopt($ch, CURLOPT_USERPWD, "{$username}:{$password}");
```

> **Truco**: si GenieACS está instalado sin autenticación (común en redes internas del ISP),
> `username` y `password` pueden estar vacíos. En ese caso no pongas el header `Authorization`
> en absoluto — algunos deployments rechazan el header aunque esté vacío.

---

## 3. Estructura de datos de un dispositivo

GenieACS guarda los parámetros TR-069 como un árbol JSON anidado.
Cada hoja tiene esta forma:

```json
{
  "_value":     "MiRedWiFi",
  "_type":      "xsd:string",
  "_timestamp": "2025-05-10T14:32:00.000Z",
  "_writable":  true
}
```

El árbol completo de un ONU se ve así:

```json
{
  "_id":         "ZTEGC12345-ZXHN%20F663N-AABBCC112233",
  "_lastInform": "2025-05-12T10:15:00.000Z",
  "_tags":       ["activo", "zona-norte"],
  "_deviceId": {
    "_OUI":          "ZTEGC1",
    "_Manufacturer": "ZTE",
    "_ProductClass": "ZXHN F663N",
    "_SerialNumber": "AABBCC112233"
  },
  "InternetGatewayDevice": {
    "DeviceInfo": {
      "SoftwareVersion": { "_value": "V1.1.10P2T18", "_timestamp": "..." },
      "HardwareVersion": { "_value": "V2.0",          "_timestamp": "..." },
      "UpTime":          { "_value": 864321,           "_timestamp": "..." }
    },
    "ManagementServer": {
      "ConnectionRequestURL": {
        "_value": "http://181.55.100.22:51005/",
        "_timestamp": "..."
      }
    },
    "LANDevice": {
      "1": {
        "WLANConfiguration": {
          "1": {
            "SSID":          { "_value": "MiRedCasa",  "_timestamp": "..." },
            "KeyPassphrase": { "_value": "clave1234",  "_timestamp": "..." },
            "Channel":       { "_value": 6,            "_timestamp": "..." },
            "Enable":        { "_value": true,         "_timestamp": "..." },
            "BeaconType":    { "_value": "11i",        "_timestamp": "..." }
          },
          "5": {
            "SSID":    { "_value": "MiRedCasa-5G", "_timestamp": "..." },
            "Channel": { "_value": 36,             "_timestamp": "..." },
            "Enable":  { "_value": true,           "_timestamp": "..." }
          }
        }
      }
    },
    "WANDevice": {
      "1": {
        "WANConnectionDevice": {
          "1": {
            "WANPPPConnection": {
              "1": {
                "ExternalIPAddress": { "_value": "181.55.100.22", "_timestamp": "..." },
                "Username":          { "_value": "cliente@isp",  "_timestamp": "..." },
                "ConnectionStatus":  { "_value": "Connected",    "_timestamp": "..." }
              }
            }
          }
        }
      }
    }
  },
  "VirtualParameters": {
    "RXPower":       { "_value": -1823,  "_timestamp": "..." },
    "superAdmin":    { "_value": "admin","_timestamp": "..." },
    "superPassword": { "_value": "1234", "_timestamp": "..." }
  }
}
```

> **Puntos clave de la estructura**:
> - Los índices numéricos (`"1"`, `"5"`) son **strings**, no números enteros.
> - Los índices de WLANConfiguration **no son siempre secuenciales** (puede ser 1 y 5, no 1 y 2).
> - Todos los valores están envueltos en `{"_value": X}`.
> - Los campos que empiezan con `_` son metadatos de GenieACS, no parámetros TR-069.

---

## 4. Consultar dispositivos

### Obtener todos (con paginación)

```
GET /devices/?limit=100&skip=0
GET /devices/?limit=100&skip=100
GET /devices/?limit=100&skip=200
```

```
# Sin límite — puede tardar 2-5 minutos con 500+ ONUs
GET /devices/
```

### Filtrar con query MongoDB

GenieACS acepta queries estilo MongoDB en el parámetro `query`:

```python
import json

# Por _id exacto
params = {"query": json.dumps({"_id": device_id})}

# Por IP WAN — WANIPConnection
params = {"query": json.dumps({
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress._value": "181.55.100.22"
})}

# Por IP WAN — WANPPPConnection
params = {"query": json.dumps({
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value": "181.55.100.22"
})}

# Por tag
params = {"query": json.dumps({"_tags": "activo"})}

# Con projection — solo traer campos necesarios (mucho más rápido)
params = {
    "query":      json.dumps({}),
    "projection": "_id,_lastInform,InternetGatewayDevice.ManagementServer.ConnectionRequestURL"
}
```

```php
// PHP
$query = json_encode(['_id' => $deviceId]);
$endpoint = '/devices/?query=' . urlencode($query);
```

### Obtener un dispositivo por ID

```python
def get_device_by_id(self, device_id: str) -> dict | None:
    result = self.session.get(
        f"{self.base_url}/devices/",
        params={"query": json.dumps({"_id": device_id})}
    )
    data = result.json()
    return data[0] if data else None
```

> **Truco**: `GET /devices/{id}` no existe como endpoint directo en el NBI.
> Siempre usar `/devices/?query={"_id": "..."}` y tomar el primer elemento del array.

---

## 5. Encoding del Device ID — el truco más crítico

El `_id` de un dispositivo en GenieACS tiene este formato:

```
{OUI}-{ProductClass}-{SerialNumber}
```

Ejemplos reales:

```
ZTEGC1-ZXHN F663N-AABBCC112233       ← tiene espacio
A4F33B-ZX%2DF663NV3a XPON-ZIC123     ← tiene %2F (slash codificado) y espacio
HWT0C8-EG8145V5-48575443D5E50F8A     ← sin caracteres especiales
```

Cuando este ID va **en la URL como segmento de path** (para tareas), hay que codificarlo:

```python
import urllib.parse

def _encode_id(self, device_id: str) -> str:
    # Codifica TODOS los caracteres incluyendo /, espacio, %, +, etc.
    # safe='' significa que ningún carácter queda sin codificar
    return urllib.parse.quote(device_id, safe='')
```

```php
// PHP equivalente
$encodedId = rawurlencode($deviceId);
```

Resultado:

```
ZTEGC1-ZXHN F663N-AABBCC   →   ZTEGC1-ZXHN%20F663N-AABBCC
A4F33B-ZX%2DF663N-ZIC123   →   A4F33B-ZX%252DF663N-ZIC123
```

> **Error más frecuente en producción**: usar `urllib.parse.quote(device_id)` o `urlencode()`
> sin `safe=''`, que deja `-` y `/` sin codificar. Con ciertos modelos de ONU el ID tiene `/`
> y la URL queda rota silenciosamente — retorna 404 sin mensaje descriptivo.

**Regla de oro**: el encoding solo aplica cuando el device_id va en el **path** de la URL:
```
/devices/{AQUI_VA_ENCODED}/tasks
```
Para el parámetro `query` en query string, el JSON se urlencodea normalmente como valor completo.

---

## 6. Sistema de tareas — cómo funciona realmente

GenieACS trabaja con un sistema de tareas asíncronas. Cuando envías una tarea:

```
POST /devices/{encoded_id}/tasks
```

GenieACS puede responder de dos maneras:

| HTTP Code | Significado | Qué hacer en la app |
|-----------|-------------|---------------------|
| `200 OK` | La tarea se ejecutó **inmediatamente** — el ONU estaba online y respondió | Informar éxito inmediato al usuario |
| `202 Accepted` | La tarea quedó **encolada** — el ONU estaba offline o detrás de NAT | Informar que el cambio se aplicará cuando el ONU se reconecte |

Ambos son `success = True`. El error real solo pasa con 4xx/5xx.

```python
result = self._post_task(device_id, task_body)

if result["http_code"] == 200:
    return {"ok": True, "inmediato": True, "mensaje": "Cambio aplicado exitosamente."}
elif result["http_code"] == 202:
    return {"ok": True, "inmediato": False, "mensaje": "Cambio encolado. Se aplicará cuando el ONU se reconecte."}
else:
    return {"ok": False, "error": result.get("error")}
```

### Query strings del endpoint de tareas

```
POST /devices/{id}/tasks                                → tarea simple, sin connection request
POST /devices/{id}/tasks?connection_request             → fuerza conexión al ONU ahora
POST /devices/{id}/tasks?timeout=3000&connection_request → con timeout en ms + conexión
```

> **Truco**: `?connection_request` le dice a GenieACS que llame al ONU en este momento vía
> TR-069 Connection Request. Sin este flag, la tarea espera al próximo `Inform` periódico
> del ONU (puede ser 30-60 minutos o más dependiendo de la configuración).

---

## 7. setParameterValues — cambiar parámetros

### Formato del body

```json
{
  "name": "setParameterValues",
  "parameterValues": [
    ["ruta.completa.parametro", "valor",  "xsd:string"],
    ["otra.ruta.booleana",      true,     "xsd:boolean"],
    ["ruta.numerica",           6,        "xsd:unsignedInt"]
  ]
}
```

> **Trampa crítica**: `parameterValues` es un **array de arrays** `[ruta, valor, tipo]`,
> NO un array de objetos. Si mandas `[{"name": "...", "value": "..."}]` GenieACS
> retorna 200 pero no ejecuta nada — falla silenciosamente.

### Tipos xsd más usados

| Tipo xsd | Cuándo usarlo |
|----------|---------------|
| `xsd:string` | SSID, contraseña, username PPPoE, hostname |
| `xsd:boolean` | Enable, NATEnabled, DHCPServerEnable |
| `xsd:int` | Canal WiFi, VLAN ID con signo |
| `xsd:unsignedInt` | MTU, tiempos, índices |

### Llamada completa en Python

```python
def set_parameter_values(
    self,
    device_id: str,
    params: list[tuple],
    timeout_ms: int = 3000
) -> dict:
    encoded  = urllib.parse.quote(device_id, safe='')
    endpoint = f"/devices/{encoded}/tasks?timeout={timeout_ms}&connection_request"

    body = {
        "name": "setParameterValues",
        "parameterValues": [list(p) for p in params]   # tuplas → listas
    }

    resp = self.session.post(
        self.base_url + endpoint,
        json=body,
        timeout=(30, 60)
    )
    return {
        "success":   resp.status_code in (200, 202),
        "http_code": resp.status_code,
        "inmediato": resp.status_code == 200
    }
```

### Llamada completa en PHP

```php
public function setParameterValues(string $deviceId, array $parameters, int $timeout = 3000): array
{
    $encodedId = rawurlencode($deviceId);
    $endpoint  = "/devices/{$encodedId}/tasks?timeout={$timeout}&connection_request";

    $data = [
        'name'            => 'setParameterValues',
        'parameterValues' => $parameters   // array de arrays: [['ruta', 'valor', 'xsd:string']]
    ];

    return $this->request($endpoint, 'POST', $data);
}
```

---

## 8. Rutas WiFi por vendor — el mapa completo

Los modelos TR-069 definen dos caminos según el estándar implementado por el ONU:

### TR-098 — el más común (ZTE, Huawei, Calix, mayoría de ONUs GPON/EPON)

```
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.SSID
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.KeyPassphrase
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.PreSharedKey.1.KeyPassphrase
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.PreSharedKey.1.PreSharedKey
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.BeaconType
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.WPAAuthenticationMode
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.WPAEncryptionModes
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.Enable
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.Status
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.Channel
InternetGatewayDevice.LANDevice.1.WLANConfiguration.{N}.BSSID
```

### TR-181 — routers modernos, Technicolor, Sercomm, algunos Huawei

```
Device.WiFi.SSID.{N}.SSID
Device.WiFi.AccessPoint.{N}.Security.KeyPassphrase
Device.WiFi.AccessPoint.{N}.Security.ModeEnabled
Device.Ethernet.Interface.1.MACAddress
```

### El truco de las tres rutas de contraseña

Distintos vendors guardan la clave WiFi en campos distintos dentro del estándar TR-098.
Para garantizar que el cambio funcione en **cualquier** modelo, se setean las tres rutas
en el mismo `setParameterValues`. GenieACS intenta aplicar todos — los que no existen
en el dispositivo son ignorados silenciosamente.

```python
def _wifi_password_params(self, path: str, password: str) -> list[tuple]:
    """
    path = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1"
    Setear los tres campos posibles + modo auth + cifrado.
    """
    return [
        (f"{path}.KeyPassphrase",                 password,            "xsd:string"),
        (f"{path}.PreSharedKey.1.KeyPassphrase",  password,            "xsd:string"),
        (f"{path}.PreSharedKey.1.PreSharedKey",   password,            "xsd:string"),
        (f"{path}.WPAAuthenticationMode",         "PSKAuthentication", "xsd:string"),
        (f"{path}.WPAEncryptionModes",            "AESEncryption",     "xsd:string"),
    ]
```

```php
// PHP equivalente
private function wifiPasswordParams(string $path, string $password): array
{
    return [
        [$path . '.KeyPassphrase',                $password,            'xsd:string'],
        [$path . '.PreSharedKey.1.KeyPassphrase', $password,            'xsd:string'],
        [$path . '.PreSharedKey.1.PreSharedKey',  $password,            'xsd:string'],
        [$path . '.WPAAuthenticationMode',        'PSKAuthentication',  'xsd:string'],
        [$path . '.WPAEncryptionModes',           'AESEncryption',      'xsd:string'],
    ];
}
```

### Mapa de seguridad BeaconType

```python
BEACON_TYPE_MAP = {
    "WPA2PSK":       "11i",       # WPA2 Personal — el más común actualmente
    "WPAPSK":        "WPA",       # WPA Personal — legacy, evitar si es posible
    "WPA2PSKWPAPSK": "WPAand11i", # Mixed WPA/WPA2 — compatible con clientes legacy
    "None":          "Basic",     # Red abierta — sin contraseña
}
```

---

## 9. Detección de frecuencia por canal

El número de canal del WiFi determina la banda de frecuencia.
No confiar en el nombre de la interfaz — puede ser cualquier string según el firmware.

```python
def detectar_frecuencia(self, channel) -> str:
    """
    Canales 1-13  → 2.4 GHz
    Canales 36+   → 5 GHz  (36, 40, 44, 48, 52, 100, 149, 157, 161, 165...)
    Canal 0/None  → desconocido (interfaz no transmitiendo o valor no disponible)
    """
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return "unknown"

    if 1 <= ch <= 13:
        return "2.4GHz"
    if ch >= 36:
        return "5GHz"
    return "unknown"
```

```php
// PHP equivalente
private function detectarFrecuencia($channel): string
{
    $ch = intval($channel);
    if ($ch >= 1  && $ch <= 13) return '2.4GHz';
    if ($ch >= 36)              return '5GHz';
    return 'unknown';
}
```

### Iterar interfaces correctamente

Los índices de `WLANConfiguration` **no son secuenciales** en todos los modelos.
Un ONU dual-band puede tener las interfaces en `.1` y `.5`, no en `.1` y `.2`.

```python
def get_wifi_interfaces(self, device: dict) -> list[dict]:
    interfaces = []
    base = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"

    # Iterar del 1 al 8 — nunca asumir que los índices son consecutivos
    for i in range(1, 9):
        path   = f"{base}.{i}"
        ssid   = self._get_param(device, f"{path}.SSID")
        enable = self._get_param(device, f"{path}.Enable")
        status = self._get_param(device, f"{path}.Status")

        # Sin SSID = esta interfaz no existe en el modelo del ONU
        if ssid is None:
            continue

        # Activa si Enable=true O Status="Up"
        if not (enable is True or status == "Up"):
            continue

        channel = self._get_param(device, f"{path}.Channel")

        interfaces.append({
            "index":     i,
            "path":      path,
            "ssid":      ssid,
            "channel":   channel,
            "frequency": self.detectar_frecuencia(channel),
            "security":  self._get_param(device, f"{path}.BeaconType"),
            "enabled":   enable,
        })

    return interfaces
```

```php
// PHP equivalente — del GenieACS.php del proyecto
private function detectActiveWLANInterfaces(array $device): array
{
    $interfaces = [];
    for ($i = 1; $i <= 8; $i++) {
        $base   = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.{$i}";
        $ssid   = $this->getParam($device, "{$base}.SSID");
        $enable = $this->getParam($device, "{$base}.Enable");
        $status = $this->getParam($device, "{$base}.Status");

        if ($ssid === null) continue;
        if (!($enable === true || $status === 'Up')) continue;

        $channel = $this->getParam($device, "{$base}.Channel");

        $interfaces[] = [
            'index'     => $i,
            'path'      => $base,
            'ssid'      => $ssid,
            'channel'   => $channel,
            'frequency' => $this->detectarFrecuencia($channel),
            'security'  => $this->getParam($device, "{$base}.BeaconType"),
        ];
    }
    return $interfaces;
}
```

---

## 10. Reboot — cuándo y cómo

### El truco del reboot separado

El reboot va en una llamada **separada** y **sin** `?connection_request`:

```python
def reboot_device(self, device_id: str) -> dict:
    encoded  = urllib.parse.quote(device_id, safe='')
    # SIN ?connection_request — el reboot se encola y ejecuta
    # DESPUÉS de que completen las tareas setParameterValues previas
    endpoint = f"/devices/{encoded}/tasks"

    resp = self.session.post(
        self.base_url + endpoint,
        json={"name": "reboot"},
        timeout=(30, 60)
    )
    return {
        "success":   resp.status_code in (200, 202),
        "http_code": resp.status_code
    }
```

```php
// PHP — del GenieACS.php del proyecto
public function rebootDevice(string $deviceId): array
{
    return $this->executeTask($deviceId, 'reboot');
    // executeTask usa /devices/{id}/tasks SIN ?connection_request
}
```

### Orden correcto de operaciones

```
1. setParameterValues (SSID / contraseña)    → con ?timeout=3000&connection_request
2. Verificar HTTP 200 o 202
3. reboot_device                             → sin ?connection_request
```

> **Por qué este orden**: si mandas el reboot junto con `?connection_request` en la misma
> llamada que los parámetros, el ONU puede reiniciarse antes de que GenieACS termine
> de aplicar los cambios. El reboot sin `connection_request` se encola y ejecuta
> **después** de que las tareas anteriores completen en la sesión TR-069 actual.

---

## 11. Connection Request — forzar conexión del ONU

Fuerza al ONU a conectarse **ahora mismo** a GenieACS.
Equivalente al botón "Summon" en la interfaz web de GenieACS.

```python
def connection_request(self, device_id: str) -> dict:
    """
    POST /devices/{id}/tasks?connection_request
    Sin body, sin timeout en el body — solo el flag en la query string.
    """
    encoded  = urllib.parse.quote(device_id, safe='')
    endpoint = f"/devices/{encoded}/tasks?connection_request"

    resp = self.session.post(
        self.base_url + endpoint,
        timeout=(30, 15)
    )
    return {
        "success":   resp.status_code in (200, 202),
        "http_code": resp.status_code
    }
```

```php
// PHP — del GenieACS.php del proyecto
public function summonDevice(string $deviceId): array
{
    $encodedId = rawurlencode($deviceId);
    $endpoint  = "/devices/{$encodedId}/tasks?connection_request";
    return $this->request($endpoint, 'POST');  // sin body
}
```

Úsalo cuando quieras refrescar los datos del ONU sin enviar ningún cambio de configuración.

---

## 12. refreshObject — VirtualParameters

GenieACS puede tener VirtualParameters — scripts JavaScript que se ejecutan en el servidor
y calculan valores derivados de los parámetros reales del ONU.

Para forzar que GenieACS los recalcule y los actualice en la base de datos:

```python
def refresh_virtual_params(self, device_id: str) -> dict:
    encoded  = urllib.parse.quote(device_id, safe='')
    endpoint = f"/devices/{encoded}/tasks?timeout=3000&connection_request"

    body = {
        "name":       "refreshObject",
        "objectName": "VirtualParameters"   # recalcula TODOS los VirtualParameters
    }

    resp = self.session.post(self.base_url + endpoint, json=body, timeout=(30, 60))
    return {"success": resp.status_code in (200, 202)}
```

```php
// PHP — del GenieACS.php del proyecto
public function summonAndFetchAdminCredentials(string $deviceId): array
{
    $encodedId = rawurlencode($deviceId);
    $endpoint  = "/devices/{$encodedId}/tasks?timeout=3000&connection_request";

    $data = [
        'name'       => 'refreshObject',
        'objectName' => 'VirtualParameters'
    ];

    return $this->request($endpoint, 'POST', $data);
}
```

También se puede refrescar solo un sub-árbol específico:

```python
# Refrescar solo parámetros de gestión DHCP LAN
body = {
    "name":       "refreshObject",
    "objectName": "InternetGatewayDevice.LANDevice.1"
}

# Refrescar solo la configuración WiFi
body = {
    "name":       "refreshObject",
    "objectName": "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
}
```

---

## 13. Detectar si el ONU está online

GenieACS guarda el timestamp del último `Inform` en `_lastInform` (ISO 8601 UTC).

```python
from datetime import datetime, timezone, timedelta

def is_online(self, device: dict, threshold_minutes: int = 5) -> bool:
    """
    Online = último Inform hace menos de 5 minutos.
    El Inform periódico de la mayoría de ONUs es cada 30-300 segundos.
    5 minutos es el umbral estándar — ajustar según el InformInterval configurado en GenieACS.
    """
    last_inform = device.get("_lastInform")
    if not last_inform:
        return False
    try:
        ts = datetime.fromisoformat(last_inform.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - ts) < timedelta(minutes=threshold_minutes)
    except (ValueError, TypeError):
        return False

def tiempo_desde_ultimo_inform(self, device: dict) -> str:
    """Para mostrar al usuario: '2 min atrás', '3 horas atrás', etc."""
    last_inform = device.get("_lastInform")
    if not last_inform:
        return "Nunca"
    try:
        ts      = datetime.fromisoformat(last_inform.replace("Z", "+00:00"))
        diff    = datetime.now(timezone.utc) - ts
        seconds = int(diff.total_seconds())
        if seconds < 60:   return f"{seconds}s atrás"
        if seconds < 3600: return f"{seconds // 60}min atrás"
        return f"{seconds // 3600}h atrás"
    except Exception:
        return "Desconocido"
```

```php
// PHP — del GenieACS.php del proyecto
private function isDeviceOnline(array $device, int $thresholdMinutes = 5): bool
{
    $lastInform = $device['_lastInform'] ?? null;
    if (!$lastInform) return false;

    $lastInformTimestamp = strtotime($lastInform);
    if ($lastInformTimestamp === false) return false;

    return (time() - $lastInformTimestamp) < ($thresholdMinutes * 60);
}
```

---

## 14. Detectar NAT — por qué las tareas quedan en cola

Si el ONU está detrás de CGNAT o NAT del ISP, GenieACS no puede hacer Connection Request.
El `ConnectionRequestURL` del ONU reportará una IP **privada** inalcanzable desde el servidor.

```python
import re

def is_behind_nat(self, device: dict) -> bool:
    """
    Detecta IP privada en el ConnectionRequestURL.
    Si es privada → las tareas siempre retornarán HTTP 202 (encoladas).
    El cambio se aplica en el próximo Inform espontáneo del ONU (30-60 min típicamente).
    """
    url = (
        self._get_param(device, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL") or
        self._get_param(device, "Device.ManagementServer.ConnectionRequestURL") or ""
    )
    # Rangos RFC 1918 privados
    return bool(re.search(
        r"https?://(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
        url
    ))
```

```php
// PHP — del api/update-wifi-config.php del proyecto
private function isDeviceBehindNAT(array $device): bool
{
    $connectionUrl = $device['InternetGatewayDevice']['ManagementServer']['ConnectionRequestURL']['_value']
                  ?? $device['Device']['ManagementServer']['ConnectionRequestURL']['_value']
                  ?? null;

    if (!$connectionUrl) return false;

    return (bool) preg_match(
        '/https?:\/\/(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/',
        $connectionUrl
    );
}
```

Usar esto para dar feedback claro al usuario:

```python
if is_behind_nat(device):
    mensaje = (
        "Cambio encolado. El ONU está detrás de NAT — "
        "los cambios se aplicarán en el próximo ciclo del ONU (30-60 minutos) "
        "o puede reiniciarlo manualmente ahora."
    )
else:
    mensaje = "Cambio aplicado inmediatamente."
```

---

## 15. Métricas ópticas — RX Power y temperatura

### RX Power en dBm

GenieACS puede retornar el valor raw (entero > 100) que necesita conversión:

```python
def get_rx_power_dbm(self, device: dict) -> float | None:
    raw = (
        self._get_param(device, "VirtualParameters.RXPower") or
        self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower") or
        self._get_param(device, "Device.Optical.Interface.1.RxPower")
    )
    if raw is None:
        return None
    try:
        val = float(raw)
        # Valor raw mayor a 100 → convertir: (raw / 100) - 40
        # Ejemplo: raw = -1823 → (-1823 / 100) = -18.23 dBm (ya es el valor directo dividido)
        if val > 100:
            val = (val / 100) - 40
        elif val < -100:
            val = val / 100   # algunos vendors guardan en centidBm directamente
        return round(val, 2)
    except (TypeError, ValueError):
        return None
```

```php
// PHP — del GenieACS.php del proyecto
$rxPower = $getParam('VirtualParameters.RXPower')
        ?? $getParam('InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower')
        ?? $getParam('Device.Optical.Interface.1.RxPower');

if ($rxPower !== null && is_numeric($rxPower)) {
    $rxPower = floatval($rxPower);
    if ($rxPower > 100) {
        $rxPower = ($rxPower / 100) - 40;
    }
    $data['rx_power'] = number_format($rxPower, 2);
}
```

### Temperatura del transceptor

```python
def get_temperature(self, device: dict) -> float | None:
    raw = (
        self._get_param(device, "VirtualParameters.gettemp") or
        self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TransceiverTemperature")
    )
    if raw is None:
        return None
    try:
        val = float(raw)
        # Si el valor es > 1000 → está en formato raw: dividir por 256
        if val > 1000:
            val = val / 256
        return round(val, 1)
    except (TypeError, ValueError):
        return None
```

```php
// PHP — del GenieACS.php del proyecto
$temperature = $getParam('VirtualParameters.gettemp')
            ?? $getParam('InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TransceiverTemperature')
            ?? $getParam('VirtualParameters.Temperature');

if ($temperature !== null && is_numeric($temperature)) {
    $temperature = floatval($temperature);
    if ($temperature > 1000) {
        $temperature = $temperature / 256;
    }
    $data['temperature'] = number_format($temperature, 1);
}
```

---

## 16. VirtualParameters — datos calculados por GenieACS

Son scripts JavaScript configurados en GenieACS que leen parámetros reales del ONU
y exponen valores derivados. Se configuran en `genieacs.conf` o desde la UI de GenieACS.

| VirtualParameter | Qué contiene | Cómo se usa |
|---|---|---|
| `VirtualParameters.RXPower` | Potencia óptica recibida (raw) | Convertir a dBm |
| `VirtualParameters.gettemp` | Temperatura del transceptor (raw) | Convertir a °C |
| `VirtualParameters.superAdmin` | Usuario admin de la UI web del ONU | Acceso directo |
| `VirtualParameters.superPassword` | Contraseña admin de la UI web del ONU | Acceso directo |
| `VirtualParameters.Ping` | Latencia en ms | Mostrar en dashboard |

```python
# Acceso en Python
admin_user = self._get_param(device, "VirtualParameters.superAdmin")
admin_pass = self._get_param(device, "VirtualParameters.superPassword")
rx_power   = self._get_param(device, "VirtualParameters.RXPower")
ping_ms    = self._get_param(device, "VirtualParameters.Ping")
```

```php
// PHP — del GenieACS.php del proyecto
$data['admin_user']      = $getParam('VirtualParameters.superAdmin')    ?? 'N/A';
$data['admin_password']  = $getParam('VirtualParameters.superPassword') ?? 'N/A';
$data['telecom_password']= $getParam('InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password') ?? 'N/A';
```

> **Truco**: los VirtualParameters pueden estar desactualizados si el ONU no ha hecho
> Inform recientemente. Llamar `refresh_virtual_params()` antes de leerlos si necesitas
> el valor actual en tiempo real.

---

## 17. Parseo del árbol de parámetros

La función más importante — navegar el árbol anidado de GenieACS por ruta con puntos:

```python
def _get_param(self, device: dict, dotted_path: str):
    """
    Navega el árbol JSON de GenieACS por ruta con puntos.
    Retorna el _value si existe, None si la ruta no existe en ningún nivel.

    Ejemplo:
      _get_param(d, "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID")
      Navega: device["InternetGatewayDevice"]["LANDevice"]["1"]["WLANConfiguration"]["1"]["SSID"]
      Retorna: device[...]["SSID"]["_value"]
    """
    node = device
    for key in dotted_path.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]

    # GenieACS envuelve cada valor: {"_value": X, "_timestamp": "...", "_writable": true}
    if isinstance(node, dict) and "_value" in node:
        return node["_value"]

    # Nodo intermedio (objeto, no hoja) — retornar None
    return None if isinstance(node, dict) else node
```

```php
// PHP — del GenieACS.php del proyecto (closure interna en parseDeviceData)
$getParam = function($path) use ($device) {
    $keys  = explode('.', $path);
    $value = $device;

    foreach ($keys as $key) {
        if (isset($value[$key])) {
            $value = $value[$key];
        } else {
            return null;
        }
    }

    // GenieACS usa object format con _value field
    if (is_array($value) && isset($value['_value'])) {
        return $value['_value'];
    }

    return is_array($value) ? null : $value;
};
```

---

## 18. Hosts LAN conectados al ONU

GenieACS acumula el historial de hosts DHCP sin limpiarlos — puede haber cientos de entradas
históricas mezcladas con los dispositivos actualmente conectados.

El truco es filtrar por timestamp relativo al último Inform del ONU:

```python
def get_connected_hosts(self, device: dict) -> list[dict]:
    hosts_node = (
        device
        .get("InternetGatewayDevice", {})
        .get("LANDevice", {})
        .get("1", {})
        .get("Hosts", {})
        .get("Host", {})
    )
    if not hosts_node:
        return []

    # Timestamp del último Inform — base para filtrar hosts históricos
    last_inform_str = device.get("_lastInform", "")
    try:
        device_ts = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
    except Exception:
        device_ts = None

    result = []
    for host_id, host_data in hosts_node.items():
        if host_id.startswith("_"):   # ignorar metadatos (_object, _timestamp, etc.)
            continue

        ip  = host_data.get("IPAddress",  {}).get("_value")
        mac = host_data.get("MACAddress", {}).get("_value")
        if not ip or not mac:
            continue

        # Filtrar hosts históricos por ventana de tiempo relativa al último Inform
        # Host actualizado más de 3 horas antes/después del Inform → histórico, ignorar
        if device_ts:
            host_ts_str = host_data.get("_timestamp", "")
            try:
                host_ts = datetime.fromisoformat(host_ts_str.replace("Z", "+00:00"))
                diff    = abs((host_ts - device_ts).total_seconds())
                if diff > 10800:   # 3 horas
                    continue
            except Exception:
                pass

        iface_type = host_data.get("InterfaceType", {}).get("_value", "Unknown")
        conn_type  = {"802.11": "WiFi", "Ethernet": "Ethernet"}.get(iface_type, "LAN")

        result.append({
            "ip":        ip,
            "mac":       mac,
            "hostname":  host_data.get("HostName", {}).get("_value", ""),
            "interface": conn_type,
            "active":    host_data.get("Active", {}).get("_value", True),
        })

    return result
```

---

## 19. Timeouts recomendados

| Operación | connect timeout | read timeout | Por qué |
|---|---|---|---|
| `GET /devices/` (todos, sin límite) | 30 s | 300 s | 500+ ONUs pueden tardar minutos |
| `GET /devices/?limit=100` | 30 s | 60 s | Paginado, más rápido |
| `GET /devices/?query={id}` | 10 s | 30 s | Un solo dispositivo |
| `POST /tasks?connection_request` | 30 s | 60 s | Espera respuesta del ONU en campo |
| `POST /tasks` (sin conn req) | 10 s | 15 s | Solo encola, no espera ONU |
| `DELETE /devices/{id}` | 10 s | 15 s | Operación local en GenieACS |
| `POST /tasks?connection_request` (refresh) | 30 s | 30 s | refreshObject |

```python
TIMEOUTS = {
    "get_all":      (30, 300),
    "get_paginated":(30, 60),
    "get_one":      (10, 30),
    "task_cr":      (30, 60),
    "task_queue":   (10, 15),
    "delete":       (10, 15),
}
```

```php
// PHP — del GenieACS.php del proyecto
curl_setopt($ch, CURLOPT_TIMEOUT, 300);        // 5 minutos read timeout (datasets grandes)
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);  // 30 segundos connection timeout
```

---

## 20. Clase de servicio completa en Python

```python
# services/genieacs.py
import json
import re
import urllib.parse
from datetime import datetime, timezone, timedelta

import requests


class GenieACService:

    TIMEOUTS = {
        "get_all":      (30, 300),
        "get_paginated":(30, 60),
        "get_one":      (10, 30),
        "task_cr":      (30, 60),
        "task_queue":   (10, 15),
        "delete":       (10, 15),
    }

    def __init__(self, host: str, port: int = 7557,
                 username: str = None, password: str = None):
        self.base_url = f"http://{host}:{port}"
        self.session  = requests.Session()
        if username:
            self.session.auth = (username, password)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _encode_id(self, device_id: str) -> str:
        return urllib.parse.quote(device_id, safe="")

    def _get_param(self, device: dict, dotted_path: str):
        node = device
        for key in dotted_path.split("."):
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        if isinstance(node, dict) and "_value" in node:
            return node["_value"]
        return None if isinstance(node, dict) else node

    def _get(self, endpoint: str, params: dict = None,
             timeout_key: str = "get_one") -> dict:
        try:
            resp = self.session.get(
                self.base_url + endpoint,
                params=params,
                timeout=self.TIMEOUTS[timeout_key]
            )
            return {
                "success":   resp.ok,
                "http_code": resp.status_code,
                "data":      resp.json() if resp.text else None
            }
        except requests.exceptions.Timeout:
            return {"success": False, "error": "timeout", "data": None}
        except Exception as e:
            return {"success": False, "error": str(e), "data": None}

    def _post_task(self, device_id: str, body: dict,
                   connection_request: bool = True,
                   timeout_ms: int = 3000) -> dict:
        encoded = self._encode_id(device_id)
        qs = f"?timeout={timeout_ms}" + ("&connection_request" if connection_request else "")
        tk = "task_cr" if connection_request else "task_queue"
        try:
            resp = self.session.post(
                f"{self.base_url}/devices/{encoded}/tasks{qs}",
                json=body,
                timeout=self.TIMEOUTS[tk]
            )
            return {
                "success":   resp.status_code in (200, 202),
                "http_code": resp.status_code,
                "inmediato": resp.status_code == 200
            }
        except requests.exceptions.Timeout:
            return {"success": False, "error": "timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── consultas ─────────────────────────────────────────────────────────────

    def test_connection(self) -> bool:
        r = self._get("/devices/", params={"limit": 1})
        return r["success"]

    def get_device_by_id(self, device_id: str) -> dict | None:
        r = self._get("/devices/", params={
            "query": json.dumps({"_id": device_id})
        })
        data = r.get("data") or []
        return data[0] if data else None

    def get_device_by_ip(self, ip: str) -> dict | None:
        paths = [
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress._value",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value",
        ]
        for path in paths:
            r    = self._get("/devices/", params={"query": json.dumps({path: ip})})
            data = r.get("data") or []
            if data:
                return data[0]
        return None

    def get_all_devices(self, limit: int = 0, projection: str = None) -> list[dict]:
        params = {}
        if limit > 0:
            params["limit"] = limit
        if projection:
            params["projection"] = projection
        tk = "get_all" if limit == 0 else "get_paginated"
        r  = self._get("/devices/", params=params, timeout_key=tk)
        return r.get("data") or []

    # ── estado ────────────────────────────────────────────────────────────────

    def is_online(self, device: dict, threshold_minutes: int = 5) -> bool:
        li = device.get("_lastInform")
        if not li:
            return False
        try:
            ts = datetime.fromisoformat(li.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - ts) < timedelta(minutes=threshold_minutes)
        except Exception:
            return False

    def is_behind_nat(self, device: dict) -> bool:
        url = (
            self._get_param(device, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL") or
            self._get_param(device, "Device.ManagementServer.ConnectionRequestURL") or ""
        )
        return bool(re.search(
            r"https?://(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", url
        ))

    # ── WiFi ──────────────────────────────────────────────────────────────────

    def detectar_frecuencia(self, channel) -> str:
        try:
            ch = int(channel)
            if 1 <= ch <= 13: return "2.4GHz"
            if ch >= 36:      return "5GHz"
        except (TypeError, ValueError):
            pass
        return "unknown"

    def get_wifi_interfaces(self, device: dict) -> list[dict]:
        interfaces = []
        base = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
        for i in range(1, 9):
            path   = f"{base}.{i}"
            ssid   = self._get_param(device, f"{path}.SSID")
            enable = self._get_param(device, f"{path}.Enable")
            status = self._get_param(device, f"{path}.Status")
            if ssid is None:
                continue
            if not (enable is True or status == "Up"):
                continue
            ch = self._get_param(device, f"{path}.Channel")
            interfaces.append({
                "index":     i,
                "path":      path,
                "ssid":      ssid,
                "channel":   ch,
                "frequency": self.detectar_frecuencia(ch),
                "security":  self._get_param(device, f"{path}.BeaconType"),
                "enabled":   enable,
            })
        return interfaces

    # ── tareas ────────────────────────────────────────────────────────────────

    def set_parameter_values(self, device_id: str,
                             params: list[tuple],
                             timeout_ms: int = 3000) -> dict:
        return self._post_task(device_id, {
            "name":            "setParameterValues",
            "parameterValues": [list(p) for p in params],
        }, connection_request=True, timeout_ms=timeout_ms)

    def set_wifi_password(self, device_id: str,
                          interfaces: list[dict],
                          password: str) -> dict:
        params = []
        for iface in interfaces:
            p = iface["path"]
            params += [
                (f"{p}.KeyPassphrase",                 password,            "xsd:string"),
                (f"{p}.PreSharedKey.1.KeyPassphrase",  password,            "xsd:string"),
                (f"{p}.PreSharedKey.1.PreSharedKey",   password,            "xsd:string"),
                (f"{p}.WPAAuthenticationMode",         "PSKAuthentication", "xsd:string"),
                (f"{p}.WPAEncryptionModes",            "AESEncryption",     "xsd:string"),
            ]
        return self.set_parameter_values(device_id, params)

    def set_wifi_ssid(self, device_id: str,
                      interfaces: list[dict],
                      ssid: str,
                      dual_band_suffixes: bool = True) -> dict:
        params  = []
        suffixes = {"2.4GHz": "-2.4GHz", "5GHz": "-5GHz", "unknown": ""}
        for iface in interfaces:
            final = (ssid + suffixes.get(iface["frequency"], "")
                     if dual_band_suffixes and len(interfaces) > 1
                     else ssid)
            params.append((f"{iface['path']}.SSID", final, "xsd:string"))
        return self.set_parameter_values(device_id, params)

    def reboot_device(self, device_id: str) -> dict:
        return self._post_task(
            device_id,
            {"name": "reboot"},
            connection_request=False   # encolar DESPUÉS de tareas previas
        )

    def connection_request(self, device_id: str) -> dict:
        encoded = self._encode_id(device_id)
        try:
            resp = self.session.post(
                f"{self.base_url}/devices/{encoded}/tasks?connection_request",
                timeout=self.TIMEOUTS["task_cr"]
            )
            return {"success": resp.status_code in (200, 202), "http_code": resp.status_code}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def refresh_virtual_params(self, device_id: str) -> dict:
        return self._post_task(device_id, {
            "name":       "refreshObject",
            "objectName": "VirtualParameters",
        }, connection_request=True, timeout_ms=3000)

    def delete_device(self, device_id: str) -> dict:
        encoded = self._encode_id(device_id)
        try:
            resp = self.session.delete(
                f"{self.base_url}/devices/{encoded}",
                timeout=self.TIMEOUTS["delete"]
            )
            return {"success": resp.ok, "http_code": resp.status_code}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── métricas ──────────────────────────────────────────────────────────────

    def get_rx_power_dbm(self, device: dict) -> float | None:
        raw = (
            self._get_param(device, "VirtualParameters.RXPower") or
            self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower") or
            self._get_param(device, "Device.Optical.Interface.1.RxPower")
        )
        if raw is None:
            return None
        try:
            val = float(raw)
            return round((val / 100) - 40 if val > 100 else val, 2)
        except (TypeError, ValueError):
            return None

    def get_temperature(self, device: dict) -> float | None:
        raw = (
            self._get_param(device, "VirtualParameters.gettemp") or
            self._get_param(device, "VirtualParameters.Temperature") or
            self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TransceiverTemperature")
        )
        if raw is None:
            return None
        try:
            val = float(raw)
            return round(val / 256 if val > 1000 else val, 1)
        except (TypeError, ValueError):
            return None

    # ── admin ─────────────────────────────────────────────────────────────────

    def get_admin_credentials(self, device: dict) -> dict:
        return {
            "admin_user":        self._get_param(device, "VirtualParameters.superAdmin"),
            "admin_password":    self._get_param(device, "VirtualParameters.superPassword"),
            "telecom_password":  self._get_param(
                device,
                "InternetGatewayDevice.DeviceInfo.X_CT-COM_TeleComAccount.Password"
            ),
        }
```

---

## 21. Clase de servicio completa en PHP

```php
<?php
namespace App;

class GenieACS
{
    private string  $host;
    private int     $port;
    private ?string $username;
    private ?string $password;
    private string  $baseUrl;

    public function __construct(
        string  $host,
        int     $port     = 7557,
        ?string $username = null,
        ?string $password = null
    ) {
        $this->host     = $host;
        $this->port     = $port;
        $this->username = $username;
        $this->password = $password;
        $this->baseUrl  = "http://{$host}:{$port}";
    }

    // ── request base ─────────────────────────────────────────────────────────

    private function request(string $endpoint, string $method = 'GET', $data = null): array
    {
        $url = $this->baseUrl . $endpoint;
        $ch  = curl_init();

        curl_setopt($ch, CURLOPT_URL,            $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT,        300);  // 5 min para datasets grandes
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);

        if ($this->username && $this->password) {
            curl_setopt($ch, CURLOPT_USERPWD, "{$this->username}:{$this->password}");
        }

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($data) {
                curl_setopt($ch, CURLOPT_POSTFIELDS,  json_encode($data));
                curl_setopt($ch, CURLOPT_HTTPHEADER,  ['Content-Type: application/json']);
            }
        } elseif ($method === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($error) {
            return ['success' => false, 'error' => $error];
        }

        return [
            'success'   => $httpCode >= 200 && $httpCode < 300,
            'http_code' => $httpCode,
            'data'      => json_decode($response, true),
        ];
    }

    // ── consultas ─────────────────────────────────────────────────────────────

    public function testConnection(): bool
    {
        $result = $this->request('/devices/?limit=1');
        return $result['success'];
    }

    public function getDevice(string $deviceId): array
    {
        $query  = json_encode(['_id' => $deviceId]);
        $result = $this->request('/devices/?query=' . urlencode($query));

        if ($result['success'] && !empty($result['data'])) {
            return ['success' => true, 'data' => $result['data'][0]];
        }
        return ['success' => false, 'error' => 'Dispositivo no encontrado'];
    }

    public function getDevices(array $query = [], int $limit = 0, int $skip = 0): array
    {
        $params = [];
        if (!empty($query)) $params[] = 'query=' . urlencode(json_encode($query));
        if ($limit > 0)     $params[] = 'limit=' . $limit;
        if ($skip > 0)      $params[] = 'skip=' . $skip;

        $qs = $params ? '?' . implode('&', $params) : '';
        return $this->request('/devices/' . $qs);
    }

    // ── tareas ────────────────────────────────────────────────────────────────

    public function setParameterValues(
        string $deviceId,
        array  $parameters,
        int    $timeout = 3000
    ): array {
        $encodedId = rawurlencode($deviceId);
        $endpoint  = "/devices/{$encodedId}/tasks?timeout={$timeout}&connection_request";

        return $this->request($endpoint, 'POST', [
            'name'            => 'setParameterValues',
            'parameterValues' => $parameters,  // array de arrays [ruta, valor, tipo]
        ]);
    }

    public function setWiFiConfig(
        string $deviceId,
        string $ssid,
        string $password   = '',
        int    $wlanIndex  = 1,
        string $securityMode = 'WPA2PSK'
    ): array {
        $path = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.{$wlanIndex}";

        $beaconTypeMap = [
            'WPA2PSK'       => '11i',
            'WPAPSK'        => 'WPA',
            'WPA2PSKWPAPSK' => 'WPAand11i',
            'None'          => 'Basic',
        ];

        $parameters = [
            [$path . '.SSID',       $ssid,                                     'xsd:string'],
            [$path . '.BeaconType', $beaconTypeMap[$securityMode] ?? '11i',    'xsd:string'],
        ];

        if ($securityMode !== 'None' && !empty($password)) {
            $parameters[] = [$path . '.KeyPassphrase',                $password,            'xsd:string'];
            $parameters[] = [$path . '.PreSharedKey.1.KeyPassphrase', $password,            'xsd:string'];
            $parameters[] = [$path . '.PreSharedKey.1.PreSharedKey',  $password,            'xsd:string'];
            $parameters[] = [$path . '.WPAAuthenticationMode',        'PSKAuthentication',  'xsd:string'];
            $parameters[] = [$path . '.WPAEncryptionModes',           'AESEncryption',      'xsd:string'];
        }

        return $this->setParameterValues($deviceId, $parameters);
    }

    public function rebootDevice(string $deviceId): array
    {
        // Sin connection_request — encolar DESPUÉS de tareas previas
        $encodedId = rawurlencode($deviceId);
        return $this->request("/devices/{$encodedId}/tasks", 'POST', ['name' => 'reboot']);
    }

    public function summonDevice(string $deviceId): array
    {
        $encodedId = rawurlencode($deviceId);
        return $this->request("/devices/{$encodedId}/tasks?connection_request", 'POST');
    }

    public function refreshObject(string $deviceId, string $objectName = 'VirtualParameters'): array
    {
        $encodedId = rawurlencode($deviceId);
        $endpoint  = "/devices/{$encodedId}/tasks?timeout=3000&connection_request";

        return $this->request($endpoint, 'POST', [
            'name'       => 'refreshObject',
            'objectName' => $objectName,
        ]);
    }

    public function deleteDevice(string $deviceId): array
    {
        $encodedId = rawurlencode($deviceId);
        return $this->request("/devices/{$encodedId}", 'DELETE');
    }

    // ── parseo ────────────────────────────────────────────────────────────────

    public function parseDeviceData(array $device): array
    {
        $getParam = function (string $path) use ($device) {
            $keys  = explode('.', $path);
            $value = $device;
            foreach ($keys as $key) {
                if (!isset($value[$key])) return null;
                $value = $value[$key];
            }
            if (is_array($value) && isset($value['_value'])) {
                return $value['_value'];
            }
            return is_array($value) ? null : $value;
        };

        $lastInform          = $device['_lastInform'] ?? null;
        $lastInformTimestamp = $lastInform ? strtotime($lastInform) : null;

        return [
            'device_id'      => $device['_id'] ?? 'N/A',
            'serial_number'  => $getParam('_deviceId._SerialNumber')
                             ?? $getParam('InternetGatewayDevice.DeviceInfo.SerialNumber')
                             ?? 'N/A',
            'manufacturer'   => $getParam('_deviceId._Manufacturer') ?? 'N/A',
            'product_class'  => $getParam('_deviceId._ProductClass') ?? 'N/A',
            'software_version'=> $getParam('InternetGatewayDevice.DeviceInfo.SoftwareVersion') ?? 'N/A',
            'status'         => ($lastInformTimestamp && (time() - $lastInformTimestamp) < 300)
                                ? 'online' : 'offline',
            'last_inform'    => $lastInformTimestamp ? date('Y-m-d H:i:s', $lastInformTimestamp) : 'N/A',
            'ip_address'     => $getParam('InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress')
                             ?? $getParam('InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress')
                             ?? 'N/A',
            'wifi_ssid'      => $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID')
                             ?? $getParam('InternetGatewayDevice.LANDevice.1.WLANConfiguration.2.SSID')
                             ?? 'N/A',
            'admin_user'     => $getParam('VirtualParameters.superAdmin')    ?? 'N/A',
            'admin_password' => $getParam('VirtualParameters.superPassword') ?? 'N/A',
            'tags'           => $device['_tags'] ?? [],
        ];
    }
}
```

---

## 22. Tabla de errores comunes

| Síntoma | Causa | Solución |
|---|---|---|
| `404` al enviar tarea | Device ID no codificado con `safe=''` | Usar `urllib.parse.quote(id, safe='')` / `rawurlencode()` en PHP |
| Tarea siempre retorna `202`, nunca `200` | ONU detrás de CGNAT/NAT | Es normal — informar al usuario, el cambio se aplica en el próximo Inform |
| `setParameterValues` retorna `200` pero el ONU no cambia | `parameterValues` enviado como array de dicts en vez de array de arrays | Convertir: `[list(p) for p in params]` en Python |
| Contraseña cambia en 2.4GHz pero no en 5GHz | Solo se seteó `WLANConfiguration.1`, la interfaz 5GHz está en índice diferente | Iterar rangos 1-8, no solo índice 1 |
| `_get_param` retorna `None` en parámetro que sí existe | Se accede directamente a `device["param"]["_value"]` sin manejar rutas anidadas | Siempre usar la función helper `_get_param` con ruta con puntos |
| Timeout en `GET /devices/` | Sin límite en red con 500+ ONUs | Agregar `?limit=100&skip=N` para paginar |
| `ConnectionRequestURL` tiene IP privada | ONU detrás de CGNAT del ISP | Esperar Inform periódico (30-60 min) o indicar al usuario que reinicie el ONU |
| VirtualParameters desactualizados | No se llamó `refresh_virtual_params` antes de leer | Llamar `refreshObject("VirtualParameters")` con `connection_request` |
| Reboot interrumpe cambios WiFi | Reboot enviado con `?connection_request` junto al setParameterValues | Enviar reboot en llamada separada **sin** `?connection_request` |
| Credenciales de admin vacías (`N/A`) | Scripts de VirtualParameters no configurados en GenieACS | Verificar que existen los scripts `superAdmin`/`superPassword` en la config de GenieACS |
| Índice de WLANConfiguration incorrecto | Asumir que siempre es `.1` y `.2` | Iterar del 1 al 8 y filtrar por `Enable=true` o `Status=Up` |
| Error de conexión sin mensaje descriptivo | GenieACS instalado sin auth, pero se envía header `Authorization` vacío | No enviar auth si `username` está vacío |

---

*Extraído de implementación real en producción — GACS Dashboard v1.1.0*
*Basado en análisis de `lib/GenieACS.php`, `lib/GenieACS_Fast.php` y endpoints en `api/`*
