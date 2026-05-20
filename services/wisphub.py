import os
import requests

API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = os.getenv('BASE_URL_WISPHUB')


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


def buscar_por_nombre_parcial(q, timeout=6):
    """
    Busca clientes cuyo nombre contiene q (búsqueda parcial, case-insensitive).
    Returns: lista de dicts con ip, nombre, cedula, telefono.
    """
    try:
        resp = requests.get(BASE_URL, headers=_headers(), timeout=timeout)
        if resp.status_code != 200:
            return []
        q_lower = q.lower()
        resultado = []
        for c in resp.json().get('results', []):
            nombre = c.get('nombre', '')
            if nombre and q_lower in nombre.lower():
                resultado.append({
                    'ip': c.get('ip') or c.get('ip_address'),
                    'nombre': nombre,
                    'cedula': c.get('cedula', ''),
                    'telefono': c.get('telefono', '') or c.get('celular', '')
                })
        return resultado
    except Exception as e:
        print(f"[WispHub] Error buscando por nombre '{q}': {e}")
        return []


def buscar_por_cedula_parcial(q, timeout=6):
    """
    Busca clientes cuya cédula contiene q (búsqueda parcial).
    Returns: lista de dicts con ip, nombre, cedula, telefono.
    """
    try:
        resp = requests.get(BASE_URL, headers=_headers(), timeout=timeout)
        if resp.status_code != 200:
            return []
        q_lower = q.lower()
        resultado = []
        for c in resp.json().get('results', []):
            cedula = c.get('cedula', '')
            if cedula and q_lower in cedula.lower():
                resultado.append({
                    'ip': c.get('ip') or c.get('ip_address'),
                    'nombre': c.get('nombre', ''),
                    'cedula': cedula,
                    'telefono': c.get('telefono', '') or c.get('celular', '')
                })
        return resultado
    except Exception as e:
        print(f"[WispHub] Error buscando por cédula '{q}': {e}")
        return []


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
