from __future__ import annotations

import json
import os
import re
import subprocess
import platform
import urllib.parse
from datetime import datetime, timezone, timedelta

import requests


class GenieACService:

    TIMEOUTS = {
        "get_all":       (30, 300),
        "get_paginated": (30, 60),
        "get_one":       (10, 30),
        "task_cr":       (30, 60),
        "task_queue":    (10, 15),
        "delete":        (10, 15),
    }

    def __init__(self, base_url: str, username: str = None, password: str = None):
        self.base_url = base_url.rstrip("/")
        self.session  = requests.Session()
        if username:
            self.session.auth = (username, password or "")

    # ── helpers ───────────────────────────────────────────────────────────────

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

    def _get(self, endpoint: str, params: dict = None, timeout_key: str = "get_one") -> dict:
        try:
            resp = self.session.get(
                self.base_url + endpoint,
                params=params,
                timeout=self.TIMEOUTS[timeout_key]
            )
            return {
                "success":   resp.ok,
                "http_code": resp.status_code,
                "data":      resp.json() if resp.text else None,
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
                "inmediato": resp.status_code == 200,
            }
        except requests.exceptions.Timeout:
            return {"success": False, "error": "timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── consultas ─────────────────────────────────────────────────────────────

    def get_device_by_id(self, device_id: str) -> dict | None:
        r = self._get("/devices/", params={"query": json.dumps({"_id": device_id})})
        data = r.get("data") or []
        return data[0] if data else None

    def get_device_by_ip(self, ip: str) -> dict | None:
        """
        Busca por IP WAN. Intenta WANIPConnection → WANPPPConnection →
        regex en ConnectionRequestURL (fallback para IPs privadas / CGNAT).
        """
        wan_paths = [
            "VirtualParameters.IPTR069._value",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress._value",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress._value",
        ]
        for path in wan_paths:
            r    = self._get("/devices/", params={"query": json.dumps({path: ip})})
            data = r.get("data") or []
            if data:
                return data[0]

        ip_escaped = ip.replace(".", r"\.")
        r = self._get("/devices/", params={
            "query": json.dumps({
                "InternetGatewayDevice.ManagementServer.ConnectionRequestURL._value": {
                    "$regex": f"http://{ip_escaped}:"
                }
            })
        })
        data = r.get("data") or []
        return data[0] if data else None

    def get_all_devices(self, limit: int = 0, projection: str = None) -> list[dict]:
        """
        Trae todos los dispositivos paginando internamente en bloques de 200.
        limit=0 significa sin límite (trae todos).
        Con projection la respuesta es pequeña — tolerable incluso con 1000+ ONUs.
        """
        PAGE = 200
        result = []
        skip   = 0
        while True:
            params: dict = {"limit": PAGE, "skip": skip}
            if projection:
                params["projection"] = projection
            r    = self._get("/devices/", params=params, timeout_key="get_paginated")
            page = r.get("data") or []
            result.extend(page)
            if len(page) < PAGE or (limit > 0 and len(result) >= limit):
                break
            skip += PAGE
        return result[:limit] if limit > 0 else result

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

    def tiempo_desde_ultimo_inform(self, device: dict) -> str:
        li = device.get("_lastInform")
        if not li:
            return "Nunca"
        try:
            ts      = datetime.fromisoformat(li.replace("Z", "+00:00"))
            seconds = int((datetime.now(timezone.utc) - ts).total_seconds())
            if seconds < 60:   return f"{seconds}s"
            if seconds < 3600: return f"{seconds // 60}min"
            return f"{seconds // 3600}h"
        except Exception:
            return "Desconocido"

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
        """
        Itera WLANConfiguration 1-8. Activa = Enable=True OR Status='Up'.
        Los índices no son siempre consecutivos (p.ej. 1 y 5 en dual-band).
        """
        interfaces = []
        base = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
        for i in range(1, 9):
            path   = f"{base}.{i}"
            ssid   = self._get_param(device, f"{path}.SSID")
            enable = self._get_param(device, f"{path}.Enable")
            status = self._get_param(device, f"{path}.Status")
            if ssid is None:
                continue
            if not (enable is True or enable == "true" or enable == 1
                    or str(enable).lower() == "true" or status == "Up"):
                continue
            ch = (self._get_param(device, f"{path}.Channel") or
                  self._get_param(device, f"{path}.ChannelsInUse"))
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

    def get_wifi_associated_devices(self, device: dict) -> list[dict]:
        """
        Lee WLANConfiguration.*.AssociatedDevice para cada interfaz activa.
        Devuelve clientes con IP, MAC y SSID de la interfaz a la que pertenecen.
        """
        result = []
        wlan_node = (
            device.get("InternetGatewayDevice", {})
            .get("LANDevice", {})
            .get("1", {})
            .get("WLANConfiguration", {})
        )
        if not isinstance(wlan_node, dict):
            return result

        for iface_idx, iface_data in wlan_node.items():
            if iface_idx.startswith("_") or not isinstance(iface_data, dict):
                continue
            enable = (iface_data.get("Enable", {}) or {}).get("_value")
            status = (iface_data.get("Status", {}) or {}).get("_value")
            ssid   = (iface_data.get("SSID",   {}) or {}).get("_value")
            if not (enable is True or enable == "true" or enable == 1 or status == "Up"):
                continue
            assoc_node = iface_data.get("AssociatedDevice", {})
            if not isinstance(assoc_node, dict):
                continue
            for dev_idx, dev_data in assoc_node.items():
                if dev_idx.startswith("_") or not isinstance(dev_data, dict):
                    continue
                ip  = (dev_data.get("AssociatedDeviceIPAddress",  {}) or {}).get("_value")
                mac = (dev_data.get("AssociatedDeviceMACAddress", {}) or {}).get("_value")
                if not mac:
                    continue
                result.append({
                    "ip":        ip or "",
                    "mac":       str(mac).lower(),
                    "ssid":      ssid or "",
                    "interface": f"WiFi ({iface_idx})",
                    "active":    True,
                })
        return result

    def get_merged_hosts(self, device: dict) -> list[dict]:
        """
        Activos: AssociatedDevice enriquecidos con hostname de Hosts.Host.
        Inactivos: entradas DHCP cuya MAC ya no está en AssociatedDevice.
        """
        lan_hosts = {h["mac"]: h for h in self.get_lan_hosts(device)}
        active = self.get_wifi_associated_devices(device)
        for h in active:
            dhcp = lan_hosts.get(h["mac"])
            h["hostname"] = (dhcp or {}).get("hostname", "")
        active_macs = {h["mac"] for h in active}
        for mac, h in lan_hosts.items():
            if mac not in active_macs:
                h["active"] = False
                active.append(h)
        return active

    def get_serial(self, device: dict) -> str:
        sn = self._get_param(device, "InternetGatewayDevice.DeviceInfo.SerialNumber")
        if sn:
            return str(sn)
        meta = device.get("_deviceId") or {}
        if isinstance(meta, dict) and "_SerialNumber" in meta:
            return meta["_SerialNumber"]
        dev_id = device.get("_id", "")
        parts = dev_id.split("-", 2)
        return parts[2] if len(parts) >= 3 else dev_id

    def get_mac(self, device: dict) -> str | None:
        for p in [
            "VirtualParameters.PonMac",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress",
            "InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.MACAddress",
            "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress",
        ]:
            v = self._get_param(device, p)
            if v:
                return str(v).lower()
        return None

    def get_ssid_primary(self, device: dict) -> str | None:
        base = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
        for i in range(1, 9):
            v = self._get_param(device, f"{base}.{i}.SSID")
            if v:
                return str(v)
        return None

    def get_uptime_seconds(self, device: dict) -> int | None:
        v = self._get_param(device, "InternetGatewayDevice.DeviceInfo.UpTime")
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
        return None

    def format_uptime(self, seconds: int | None) -> str:
        if seconds is None:
            return "--"
        h = seconds // 3600
        m = (seconds % 3600) // 60
        if h >= 24:
            d = h // 24
            h = h % 24
            return f"{d}d {h:02d}h{m:02d}m"
        return f"{h}h {m:02d}m"

    def get_rx_power(self, device: dict) -> float | None:
        raw = (
            self._get_param(device, "VirtualParameters.RXPower") or
            self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.RXPower") or
            self._get_param(device, "Device.Optical.Interface.1.RxPower")
        )
        if raw is None:
            return None
        try:
            val = float(raw)
            if val > 100:
                val = (val / 100) - 40
            elif val < -100:
                val = val / 100
            return round(val, 2)
        except (TypeError, ValueError):
            return None

    def get_temperature(self, device: dict) -> float | None:
        raw = (
            self._get_param(device, "VirtualParameters.gettemp") or
            self._get_param(device, "InternetGatewayDevice.WANDevice.1.X_CT-COM_EponInterfaceConfig.TransceiverTemperature") or
            self._get_param(device, "VirtualParameters.Temperature")
        )
        if raw is None:
            return None
        try:
            val = float(raw)
            if val > 1000:
                val = val / 256
            return round(val, 1)
        except (TypeError, ValueError):
            return None

    def get_connected_hosts_count(self, device: dict) -> int | None:
        v = self._get_param(device, "InternetGatewayDevice.LANDevice.1.Hosts.HostNumberOfEntries")
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
        return None

    def get_lan_hosts(self, device: dict) -> list[dict]:
        hosts_node = (
            device.get("InternetGatewayDevice", {})
            .get("LANDevice", {})
            .get("1", {})
            .get("Hosts", {})
            .get("Host", {})
        )
        # Soporte para routers modernos TR-181
        if not hosts_node or not isinstance(hosts_node, dict):
            hosts_node = (
                device.get("Device", {})
                .get("Hosts", {})
                .get("Host", {})
            )
            
        if not hosts_node or not isinstance(hosts_node, dict):
            return []
            
        last_inform_str = device.get("_lastInform", "")
        try:
            device_ts = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
        except Exception:
            device_ts = None
            
        result = []
        for host_id, host_data in hosts_node.items():
            if host_id.startswith("_") or not isinstance(host_data, dict):
                continue
            ip  = host_data.get("IPAddress",  {}).get("_value")
            mac = host_data.get("MACAddress", {}).get("_value")
            if not ip or not mac:
                continue
                
            if device_ts:
                # El nodo padre no tiene _timestamp, usamos el de MACAddress o IPAddress
                host_ts_str = host_data.get("MACAddress", {}).get("_timestamp") or host_data.get("IPAddress", {}).get("_timestamp", "")
                try:
                    host_ts = datetime.fromisoformat(host_ts_str.replace("Z", "+00:00"))
                    if abs((host_ts - device_ts).total_seconds()) > 10800:
                        continue
                except Exception:
                    pass
                    
            iface_type = host_data.get("InterfaceType", {}).get("_value", "Unknown")
            conn_type = {"802.11": "WiFi", "Ethernet": "Ethernet"}.get(iface_type, "LAN")
            
            active_raw = host_data.get("Active", {}).get("_value", True)
            if isinstance(active_raw, str):
                is_active = active_raw.lower() not in ("0", "false", "no")
            else:
                is_active = bool(active_raw)

            result.append({
                "ip":       ip,
                "mac":      str(mac).lower(),
                "hostname": host_data.get("HostName", {}).get("_value", ""),
                "interface": conn_type,
                "active":   is_active,
            })
        return result

    def rx_signal_quality(self, rx_dbm: float | None) -> str:
        if rx_dbm is None:
            return "unknown"
        if rx_dbm >= -24:
            return "ok"
        if rx_dbm >= -27:
            return "warning"
        return "critical"

    # ── tareas ────────────────────────────────────────────────────────────────

    def set_parameter_values(self, device_id: str, params: list[tuple],
                             timeout_ms: int = 3000) -> dict:
        return self._post_task(device_id, {
            "name":            "setParameterValues",
            "parameterValues": [list(p) for p in params],
        }, connection_request=True, timeout_ms=timeout_ms)

    def set_wifi_password(self, device_id: str, interfaces: list[dict],
                          password: str) -> dict:
        params = []
        for iface in interfaces:
            p = iface["path"]
            params.append((f"{p}.PreSharedKey.1.KeyPassphrase", password, "xsd:string"))
            params.append((f"{p}.KeyPassphrase", password, "xsd:string"))
        return self.set_parameter_values(device_id, params)

    def set_wifi_ssid(self, device_id: str, interfaces: list[dict], ssid: str) -> dict:
        """Añade sufijos -2.4GHz / -5GHz automáticamente si hay 2 interfaces."""
        params = []
        dual   = len(interfaces) > 1
        for iface in interfaces:
            if dual:
                freq  = iface.get("frequency", "")
                final = (f"{ssid}-2.4GHz" if freq == "2.4GHz" else
                         f"{ssid}-5GHz"   if freq == "5GHz"   else ssid)
            else:
                final = ssid
            params.append((f"{iface['path']}.SSID", final, "xsd:string"))
        return self.set_parameter_values(device_id, params)

    def reboot_device(self, device_id: str, force: bool = False) -> dict:
        # force=True usa connection_request para contactar la ONU de inmediato.
        # force=False encola el reboot para que se procese en el próximo inform.
        return self._post_task(device_id, {"name": "reboot"}, connection_request=force)

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

    def limpiar_duplicados_ip(self) -> dict:
        """
        Detecta dispositivos con la misma IP WAN en GenieACS.
        Si en un grupo hay al menos uno online y otros offline,
        elimina los offline. Nunca toca grupos donde todos están offline.

        Retorna:
          { "duplicados_encontrados": int,
            "eliminados": [{"device_id": str, "ip": str}],
            "errores":    [{"device_id": str, "ip": str, "error": str}] }
        """
        ip_url_re = re.compile(r'https?://(\d{1,3}(?:\.\d{1,3}){3}):')

        proj = ",".join([
            "_id", "_lastInform",
            "VirtualParameters.IPTR069",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
        ])

        devices = self.get_all_devices(projection=proj)

        ip_map: dict[str, list[dict]] = {}
        for d in devices:
            device_id = d.get("_id")
            if not device_id:
                continue

            ip = (
                self._get_param(d, "VirtualParameters.IPTR069") or
                self._get_param(d, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress") or
                self._get_param(d, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress")
            )
            if not ip:
                cr_url = self._get_param(d, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL")
                if cr_url:
                    m = ip_url_re.search(str(cr_url))
                    if m:
                        ip = m.group(1)
            if not ip:
                continue

            ip_map.setdefault(ip, []).append({
                "device_id": device_id,
                "is_online": self.is_online(d),
            })

        eliminados: list[dict] = []
        errores:    list[dict] = []
        duplicados = 0

        for ip, group in ip_map.items():
            if len(group) < 2:
                continue
            online_devs  = [e for e in group if     e["is_online"]]
            offline_devs = [e for e in group if not e["is_online"]]
            # Solo actuar si hay al menos uno online y al menos uno offline
            if not online_devs or not offline_devs:
                continue
            duplicados += 1
            for entry in offline_devs:
                result = self.delete_device(entry["device_id"])
                if result.get("success"):
                    eliminados.append({"device_id": entry["device_id"], "ip": ip})
                else:
                    errores.append({
                        "device_id": entry["device_id"],
                        "ip":        ip,
                        "error":     result.get("error") or f"HTTP {result.get('http_code')}",
                    })

        return {
            "duplicados_encontrados": duplicados,
            "eliminados":             eliminados,
            "errores":                errores,
        }


# =============================================================================
# Singleton y wrappers de compatibilidad con app.py
# =============================================================================

_base_url = os.getenv("GENIEACS_API_URL", "").rstrip("/")
_user     = os.getenv("GENIEACS_USER") or None
_password = os.getenv("GENIEACS_PASSWORD", "")
_svc: GenieACService | None = GenieACService(_base_url, _user, _password) if _base_url else None


def _get_svc() -> GenieACService:
    if not _svc:
        raise RuntimeError("GENIEACS_API_URL no configurada en .env")
    return _svc


def obtener_device_id_por_ip(ip: str) -> str | None:
    try:
        device = _get_svc().get_device_by_ip(ip)
        return device.get("_id") if device else None
    except Exception as e:
        print(f"[GenieACS] Error buscando device_id para {ip}: {e}")
        return None


def obtener_estado_online_device(ip: str,
                                 minutos_online: int = 5) -> tuple[bool, str | None]:
    try:
        svc    = _get_svc()
        device = svc.get_device_by_ip(ip)
        if not device:
            return False, None
        return svc.is_online(device, minutos_online), device.get("_id")
    except Exception as e:
        print(f"[GenieACS] Error verificando estado de {ip}: {e}")
        return False, None


def verificar_dispositivo_online_alternativo(ip: str) -> bool:
    """Ping fallback cuando GenieACS no responde o no encuentra el dispositivo."""
    try:
        cmd = (["ping", "-n", "1", "-w", "3000", ip]
               if platform.system().lower() == "windows"
               else ["ping", "-c", "1", "-W", "3", ip])
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).returncode == 0
    except Exception:
        return False


def detectar_interfaces_wifi_activas(device_id: str) -> list[int]:
    try:
        svc    = _get_svc()
        device = svc.get_device_by_id(device_id)
        if not device:
            return []
        return [i["index"] for i in svc.get_wifi_interfaces(device)]
    except Exception as e:
        print(f"[GenieACS] Error detectando interfaces de {device_id}: {e}")
        return []


def detectar_interfaces_y_frecuencias(device_id: str) -> tuple[list[int], dict]:
    """Retorna (indices, {indice: {canal, frecuencia, ssid_actual}})."""
    try:
        svc    = _get_svc()
        device = svc.get_device_by_id(device_id)
        if not device:
            return [], {}
        ifaces  = svc.get_wifi_interfaces(device)
        activas = [i["index"] for i in ifaces]
        info    = {
            i["index"]: {
                "canal":      i["channel"],
                "frecuencia": i["frequency"],
                "ssid_actual": i["ssid"],
            }
            for i in ifaces
        }
        return activas, info
    except Exception as e:
        print(f"[GenieACS] Error detectando frecuencias de {device_id}: {e}")
        return [], {}


def cambiar_contraseña_wifi_interfaces_ya_detectadas(
        device_id: str,
        interfaces_activas: list[int],
        password: str) -> tuple[bool, str]:
    try:
        svc    = _get_svc()
        base   = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
        ifaces = [{"index": i, "path": f"{base}.{i}"} for i in interfaces_activas]
        r      = svc.set_wifi_password(device_id, ifaces, password)
        if r["success"]:
            svc.reboot_device(device_id, force=True)
            return True, f"Contraseña WiFi aplicada en {len(ifaces)} interfaz(es): {interfaces_activas}"
        return False, r.get("error", "Error al cambiar contraseña")
    except Exception as e:
        return False, str(e)


def cambiar_nombre_red_wifi_inteligente(
        device_id: str,
        interfaces_info: dict,
        nuevo_nombre: str) -> tuple[bool, str]:
    try:
        svc    = _get_svc()
        base   = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
        ifaces = [
            {"index": k, "path": f"{base}.{k}", "frequency": v.get("frecuencia", "unknown")}
            for k, v in interfaces_info.items()
        ]
        r = svc.set_wifi_ssid(device_id, ifaces, nuevo_nombre)
        if not r["success"]:
            return False, r.get("error", "Error al cambiar nombre")

        svc.reboot_device(device_id, force=True)
        dual = len(ifaces) == 2
        lines = []
        for iface in sorted(ifaces, key=lambda x: x["frequency"]):
            freq  = iface["frequency"]
            name  = (f"{nuevo_nombre}-2.4GHz" if dual and freq == "2.4GHz" else
                     f"{nuevo_nombre}-5GHz"   if dual and freq == "5GHz"   else nuevo_nombre)
            lines.append(f"• {freq}: {name}")
        return True, "✅ Nombre de red WiFi cambiado exitosamente:\n" + "\n".join(lines)
    except Exception as e:
        return False, str(e)


def cambiar_parametro_genieacs_sin_reinicio(device_id: str,
                                            parametro: str,
                                            valor: str) -> bool:
    try:
        r = _get_svc().set_parameter_values(device_id, [(parametro, valor, "xsd:string")])
        return r["success"]
    except Exception as e:
        print(f"[GenieACS] Error cambiando {parametro}: {e}")
        return False


def reiniciar_onu_genieacs(device_id: str) -> bool:
    try:
        return _get_svc().reboot_device(device_id)["success"]
    except Exception as e:
        print(f"[GenieACS] Error reiniciando {device_id}: {e}")
        return False


def eliminar_device_genieacs(device_id: str) -> bool:
    try:
        return _get_svc().delete_device(device_id)["success"]
    except Exception as e:
        print(f"[GenieACS] Error eliminando {device_id}: {e}")
        return False
