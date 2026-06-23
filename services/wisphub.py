from __future__ import annotations

import os
import time
import concurrent.futures
import requests

API_KEY  = os.getenv('API_KEY_WISPHUB')
BASE_URL = os.getenv('BASE_URL_WISPHUB')

# ── Cache en memoria (igual que soporte.py) ──────────────────────────────────
_cache_clientes: list  = []
_cache_ts: float       = 0.0
_CACHE_TTL             = 300   # 5 minutos


def _headers():
    return {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }


def buscar_cliente(cedula, timeout=10):
    """
    Busca un cliente en WispHub por cédula.
    Returns: (cliente_dict, None) si se encontró, (None, error_dict) si no.
    error_dict tiene claves 'code' y 'message'.
    """
    try:
        response = requests.get(
            BASE_URL,
            headers=_headers(),
            params={'cedula': cedula},
            timeout=timeout
        )

        if response.status_code == 401:
            return None, {"code": "error_auth", "message": "❌ Error de autenticación con Wisphub. Verifique su API Key."}
        elif response.status_code == 403:
            return None, {"code": "error_permisos", "message": "❌ No tiene permisos suficientes en Wisphub."}
        elif response.status_code != 200:
            return None, {"code": "error_api", "message": f"❌ Error al consultar Wisphub. Status: {response.status_code}"}

        data = response.json()
        clientes = data.get('results', [])

        for cliente in clientes:
            if cliente.get('cedula') == cedula:
                telefono = cliente.get('telefono', '')
                ip = cliente.get('ip') or cliente.get('ip_address')

                if not telefono:
                    return None, {"code": "sin_telefono", "message": "⚠️ El cliente no tiene número telefónico registrado."}
                if not ip:
                    return None, {"code": "sin_ip", "message": "⚠️ El cliente no tiene IP asociada."}

                return cliente, None

        return None, {"code": "cliente_no_encontrado", "message": "⚠️ Cliente no encontrado. Verifica la cédula e inténtalo de nuevo."}

    except requests.exceptions.ConnectionError:
        return None, {"code": "error_conexion", "message": "❌ No se pudo establecer conexión con Wisphub. Verifique su conexión a internet."}
    except requests.exceptions.Timeout:
        return None, {"code": "error_timeout", "message": "❌ La conexión con Wisphub ha expirado. Intente nuevamente."}
    except Exception as e:
        print(f"[WispHub] Error inesperado: {e}")
        return None, {"code": "error_inesperado", "message": "❌ Error inesperado al consultar Wisphub. Intente más tarde."}


def buscar_por_ip(ip, timeout=7):
    """
    Busca un cliente en WispHub por IP exacta.
    Returns: cliente_dict o None.
    """
    try:
        resp = requests.get(BASE_URL, headers=_headers(), params={'ip': ip}, timeout=timeout)
        if resp.status_code != 200:
            return None
        for c in resp.json().get('results', []):
            if c.get('ip') == ip or c.get('ip_address') == ip:
                return c
    except Exception as e:
        print(f"[WispHub] Error buscando por IP {ip}: {e}")
    return None


def _normalizar_resultados(results):
    out = []
    for c in results:
        out.append({
            'ip':       c.get('ip') or c.get('ip_address') or '',
            'nombre':   c.get('nombre', ''),
            'cedula':   c.get('cedula', ''),
            'telefono': c.get('telefono', '') or c.get('celular', ''),
            'estado':   c.get('estado', ''),
        })
    return out


def buscar_por_nombre_parcial(q, timeout=6):
    try:
        resp = requests.get(BASE_URL, headers=_headers(), params={'nombre__contains': q}, timeout=timeout)
        if resp.status_code != 200:
            return []
        return _normalizar_resultados(resp.json().get('results', []))
    except Exception as e:
        print(f"[WispHub] Error buscando por nombre '{q}': {e}")
        return []


def buscar_por_cedula_parcial(q, timeout=6):
    try:
        resp = requests.get(BASE_URL, headers=_headers(), params={'cedula__contains': q}, timeout=timeout)
        if resp.status_code != 200:
            return []
        return _normalizar_resultados(resp.json().get('results', []))
    except Exception as e:
        print(f"[WispHub] Error buscando por cédula '{q}': {e}")
        return []


def buscar_por_ip_parcial(q, timeout=6):
    try:
        resp = requests.get(BASE_URL, headers=_headers(), params={'ip__contains': q}, timeout=timeout)
        if resp.status_code != 200:
            return []
        return _normalizar_resultados(resp.json().get('results', []))
    except Exception as e:
        print(f"[WispHub] Error buscando por IP '{q}': {e}")
        return []


def _extraer(c: dict) -> list[dict]:
    """Normaliza un cliente de WispHub a lista de filas (una por servicio con IP)."""
    base = {
        'nombre':   c.get('nombre', ''),
        'cedula':   c.get('cedula', ''),
        'telefono': c.get('telefono', '') or c.get('celular', ''),
    }
    servicios = c.get('servicios', [])
    if servicios:
        rows = []
        for s in servicios:
            ip = s.get('ip', '')
            if ip:
                rows.append({**base, 'ip': ip, 'estado': s.get('estado', '')})
        return rows if rows else [{**base, 'ip': '', 'estado': c.get('estado', '')}]
    ip = c.get('ip') or c.get('ip_address') or ''
    estado = c.get('estado', '')
    return [{**base, 'ip': ip, 'estado': estado}]


def obtener_servicios_por_cedula(cedula: str, timeout: int = 10) -> tuple:
    """
    Devuelve (cliente_dict, lista_servicios) para una cédula.
    lista_servicios: [{ ip, nombre_servicio, ssid_router_wifi, estado, direccion, nombre_cliente }]
    Retorna (None, []) si no se encuentra o hay error.
    """
    try:
        resp = requests.get(BASE_URL, headers=_headers(), params={'cedula': cedula}, timeout=timeout)
        if resp.status_code != 200:
            return None, []
        cliente_principal = None
        servicios = []
        for c in resp.json().get('results', []):
            if c.get('cedula') != cedula:
                continue
            if not cliente_principal:
                cliente_principal = c
            nombre_cliente = c.get('nombre', '')
            c_servicios = c.get('servicios', [])
            if c_servicios:
                for s in c_servicios:
                    if s.get('ip'):
                        entry = dict(s)
                        entry['direccion']     = c.get('direccion', '')
                        entry['nombre_cliente'] = nombre_cliente
                        servicios.append(entry)
            elif c.get('ip'):
                servicios.append({
                    'ip':               c.get('ip', ''),
                    'nombre_servicio':  c.get('nombre_servicio', ''),
                    'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                    'estado':           c.get('estado', ''),
                    'direccion':        c.get('direccion', ''),
                    'nombre_cliente':   nombre_cliente,
                })
        return cliente_principal, servicios
    except Exception as e:
        print(f'[WispHub] Error en obtener_servicios_por_cedula({cedula}): {e}')
        return None, []


def listar_todos(force_refresh: bool = False) -> list:
    """
    Devuelve todos los clientes normalizados usando la misma lógica de soporte:
    limit/offset con fetch paralelo y caché de 5 min.
    """
    global _cache_clientes, _cache_ts
    if not force_refresh and _cache_clientes and (time.time() - _cache_ts) < _CACHE_TTL:
        return _cache_clientes

    LIMIT = 300

    def fetch_offset(offset: int) -> list:
        try:
            r = requests.get(
                BASE_URL, headers=_headers(),
                params={'limit': LIMIT, 'offset': offset}, timeout=15
            )
            if r.status_code == 200:
                return r.json().get('results', [])
        except Exception as e:
            print(f'[WispHub] Error offset {offset}: {e}')
        return []

    try:
        primera = requests.get(
            BASE_URL, headers=_headers(),
            params={'limit': LIMIT, 'offset': 0}, timeout=15
        )
        if primera.status_code != 200:
            return _cache_clientes

        data       = primera.json()
        results    = data.get('results', [])
        total      = data.get('count', 0)
        todos_raw  = list(results)

        if total > LIMIT:
            offsets = range(LIMIT, total, LIMIT)
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                for partial in ex.map(fetch_offset, offsets):
                    todos_raw.extend(partial)

        todos = []
        for c in todos_raw:
            todos.extend(_extraer(c))

        _cache_clientes = todos
        _cache_ts       = time.time()
        print(f'[WispHub] listar_todos: {len(todos)} registros cargados')
        return todos

    except Exception as e:
        print(f'[WispHub] Error en listar_todos: {e}')
        return _cache_clientes


def actualizar_parametros(cedula, nueva_clave=None, nuevo_ssid=None, ip_especifica=None):
    """
    Actualiza SSID y/o contraseña WiFi del cliente en WispHub.
    Returns: True si se actualizó correctamente, False si no.
    """
    print(f'[WispHub] Actualizando parámetros — Cédula: {cedula}, IP: {ip_especifica}')

    cliente, _ = buscar_cliente(cedula, timeout=10)
    if not cliente:
        print('[WispHub] Cliente no encontrado para actualizar parámetros')
        return False

    id_cliente = None

    if ip_especifica:
        try:
            resp = requests.get(BASE_URL, headers=_headers(), params={'cedula': cedula}, timeout=10)
            if resp.status_code == 200:
                for c in resp.json().get('results', []):
                    if c.get('cedula') == cedula:
                        servicios = c.get('servicios', [])
                        if servicios:
                            for s in servicios:
                                if s.get('ip') == ip_especifica:
                                    id_cliente = c.get('id_servicio') or c.get('id')
                                    break
                            if id_cliente:
                                break
                        elif c.get('ip') == ip_especifica:
                            id_cliente = c.get('id_servicio') or c.get('id')
                            break
        except Exception as e:
            print(f'[WispHub] Error buscando cliente por IP específica: {e}')

    if not id_cliente:
        id_cliente = cliente.get('id_servicio') or cliente.get('id')

    if not id_cliente:
        print('[WispHub] No se encontró ID del servicio')
        return False

    data = {}
    if nueva_clave:
        data['password_ssid_router_wifi'] = nueva_clave
    if nuevo_ssid:
        data['ssid_router_wifi'] = nuevo_ssid
    if not data:
        print('[WispHub] No hay datos para actualizar')
        return False

    url = f'{BASE_URL}/{id_cliente}/'
    try:
        resp = requests.patch(url, headers=_headers(), json=data, timeout=10)
        print(f'[WispHub] Respuesta: {resp.status_code}')
        if resp.status_code in (200, 204):
            print('[WispHub] Parámetros actualizados exitosamente')
            return True
        print(f'[WispHub] Error en respuesta: {resp.status_code} - {resp.text}')
        return False
    except requests.exceptions.Timeout:
        print('[WispHub] Timeout al actualizar parámetros')
        return False
    except requests.exceptions.ConnectionError:
        print('[WispHub] Error de conexión al actualizar parámetros')
        return False
    except Exception as e:
        print(f'[WispHub] Error actualizando parámetros: {e}')
        return False
