from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import requests
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
import re
import sqlite3
import time

# Cargar variables de entorno
load_dotenv()

# Configuración de APIs
API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = os.getenv('BASE_URL_WISPHUB')
GENIEACS_API = os.getenv("GENIEACS_API_URL")
ip_server = os.getenv("IP_SERVER")
qr_server = os.getenv("QR_SERVER")

# Crear Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Decorador para proteger rutas de admin
def admin_requerido(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Por favor inicie sesión como administrador', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

# Funciones de autenticación
def verificar_admin(username, password):
    """Verifica las credenciales del administrador en la base de datos local"""
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM admin_users WHERE username = ? OR email = ?", (username, username))
        admin = cur.fetchone()
        conn.close()
        if admin and check_password_hash(admin['password'], password):
            return admin
        return None
    except Exception as e:
        print(f"Error al verificar admin: {e}")
        return None

def registrar_cambio(admin_id, cedula, tipo_cambio, valor_nuevo):
    """Registra un cambio en el historial (sin valor_anterior)"""
    try:
        conn = get_db_connection()
        cur = conn.execute("INSERT INTO change_history (admin_id, cedula, tipo_cambio, valor_nuevo, fecha) VALUES (?, ?, ?, ?, ?)",
                           (admin_id, cedula, tipo_cambio, valor_nuevo, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al registrar cambio: {e}")
        return False

def obtener_historial_cambios(cedula=None, admin_id=None, limit=50):
    """Obtiene el historial de cambios"""
    try:
        conn = get_db_connection()
        query = "SELECT * FROM change_history"
        if cedula:
            query += " WHERE cedula = ?"
        if admin_id:
            query += " WHERE admin_id = ?"
        query += " ORDER BY fecha DESC LIMIT ?"
        cur = conn.execute(query, (cedula, admin_id, limit))
        data = [dict(row) for row in cur.fetchall()]
        conn.close()
        return data
    except Exception as e:
        print(f"Error al obtener historial: {e}")
        return []

def obtener_estadisticas_uso():
    """Obtiene estadísticas de uso"""
    try:
        # Cambios por tipo (SQL directo)
        conn = get_db_connection()
        cur = conn.execute("SELECT tipo_cambio, COUNT(*) as count FROM change_history GROUP BY tipo_cambio")
        cambios_por_tipo = [dict(row) for row in cur.fetchall()]
        # Cambios por mes (SQL directo, compatible con SQLite)
        cur = conn.execute("SELECT substr(fecha, 1, 7) as mes, COUNT(*) as count FROM change_history GROUP BY mes")
        cambios_por_mes = [dict(row) for row in cur.fetchall()]
        # Límites más comunes (SQL directo)
        cur = conn.execute("SELECT limite_personalizado, COUNT(*) as count FROM user_limits GROUP BY limite_personalizado")
        limites_comunes = [dict(row) for row in cur.fetchall()]
        conn.close()
        return {
            "cambios_por_tipo": cambios_por_tipo,
            "cambios_por_mes": cambios_por_mes,
            "limites_comunes": limites_comunes
        }
    except Exception as e:
        print(f"Error al obtener estadísticas: {e}")
        return {}

def actualizar_limite_cliente(ip, nombre, nuevo_limite, cedula=''):
    """Actualiza o inserta el límite de cambios para un cliente por IP"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, cedula, nombre, limite_personalizado)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET limite_personalizado=excluded.limite_personalizado, nombre=excluded.nombre, cedula=excluded.cedula;
        """, (ip, cedula, nombre, nuevo_limite))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al actualizar límite: {e}")
        return False

# Funciones de utilidad
def obtener_configuracion_global():
    """Obtiene la configuración global desde la base de datos local"""
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM admin_settings")
        data = [dict(row) for row in cur.fetchall()]
        conn.close()
        return data
    except Exception as e:
        print(f"Error al obtener configuración global: {e}")
        return []

def actualizar_configuracion_global(clave, valor):
    """Actualiza una configuración global en la base de datos local"""
    try:
        conn = get_db_connection()
        cur = conn.execute("UPDATE admin_settings SET valor = ? WHERE clave = ?", (valor, clave))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al actualizar configuración global: {e}")
        return False

def buscar_cliente_por_cedula(cedula):
    """Busca un cliente en WispHub por su cédula de forma eficiente"""
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    print(f'[LOG] Buscando cédula {cedula} en Wisphub con filtro directo')
    try:
        response = requests.get(BASE_URL, headers=headers, params={'cedula': cedula}, timeout=3)
    except Exception as e:
        print(f"[ERROR] Wisphub no responde o es muy lento: {e}")
        return None
    if response.status_code != 200:
        print(f"[ERROR] Wisphub respondió con status {response.status_code}")
        return None
    data = response.json()
    clientes = data.get('results', [])
    print(f'[LOG] Resultados obtenidos: {len(clientes)} clientes')
    for cliente in clientes:
        if cliente.get('cedula') == cedula:
            print(f'[LOG] Cliente encontrado')
            return cliente
    print('[LOG] Cliente no encontrado ')
    return None

def obtener_device_id_por_ip(ip_buscada):
    """Obtiene el ID del dispositivo en GenieACS por su IP, buscando en ConnectionRequestURL"""
    try:
        response = requests.get(f"{GENIEACS_API}/devices")
        response.raise_for_status()
        dispositivos = response.json()
        print(f"[GENIEACS] Buscando IP: {ip_buscada}")
        for device in dispositivos:
            device_id = device.get('_id')
            # Buscar la IP en ConnectionRequestURL
            url = device.get("InternetGatewayDevice", {}) \
                      .get("ManagementServer", {}) \
                      .get("ConnectionRequestURL", {}) \
                      .get("_value")
            ip_actual = None
            if url:
                match = re.search(r"https?://([\d.]+):", url)
                if match:
                    ip_actual = match.group(1)
            print(f"[GENIEACS] device_id: {device_id} | url: {url} | ip_actual: {ip_actual}")
            if ip_actual == ip_buscada:
                print(f"[GENIEACS] ¡Coincidencia encontrada!")
                return device_id
    except Exception as e:
        print(f"Error al buscar dispositivo en GenieACS: {e}")
    print(f"[GENIEACS] No se encontró ningún device_id para la IP: {ip_buscada}")
    return None

def obtener_parametro_genieacs(device_id, parametro):
    """Obtiene un parámetro de GenieACS"""
    try:
        from urllib.parse import quote
        url = f"{GENIEACS_API}/devices/{quote(device_id, safe='')}/tasks?connection_request"
        data = {
            "name": "getParameterValues",
            "parameterNames": [parametro]
        }
        print(f"[GenieACS] 🔍 SOLICITANDO PARÁMETRO:")
        print(f"[GenieACS]   - Device ID: {device_id}")
        print(f"[GenieACS]   - Parámetro: {parametro}")
        print(f"[GenieACS]   - URL: {url}")
        print(f"[GenieACS]   - Data: {data}")
        
        response = requests.post(url, json=data, timeout=15)
        
        print(f"[GenieACS] 📡 RESPUESTA RECIBIDA:")
        print(f"[GenieACS]   - Status Code: {response.status_code}")
        print(f"[GenieACS]   - Headers: {dict(response.headers)}")
        print(f"[GenieACS]   - Response Text: {response.text[:500]}...")
        
        if response.status_code == 200:
            try:
                json_response = response.json()
                print(f"[GenieACS] ✅ PARÁMETRO OBTENIDO EXITOSAMENTE:")
                print(f"[GenieACS]   - Response JSON: {json_response}")
                return json_response
            except Exception as json_error:
                print(f"[GenieACS] ❌ ERROR AL PARSEAR JSON: {json_error}")
                return None
        else:
            print(f"[GenieACS] ❌ ERROR HTTP: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.Timeout:
        print(f"[GenieACS] ⏰ TIMEOUT al obtener parámetro {parametro}")
        return None
    except requests.exceptions.ConnectionError as conn_error:
        print(f"[GenieACS] 🔌 ERROR DE CONEXIÓN: {conn_error}")
        return None
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR INESPERADO obteniendo parámetro: {e}")
        print(f"[GenieACS]   - Tipo de error: {type(e).__name__}")
        import traceback
        print(f"[GenieACS]   - Traceback: {traceback.format_exc()}")
        return None

# Función eliminada - ahora se usa desde genieacs_utils.py

# Función eliminada - ahora se usa desde genieacs_utils.py

# Funciones eliminadas - ahora se usan desde genieacs_utils.py

def cambiar_contraseña_wifi_interfaces_activas(device_id, nueva_password):
    """Cambia la contraseña WiFi solo en las interfaces que están activas"""
    print(f"[GenieACS] 🔐 INICIANDO CAMBIO DE CONTRASEÑA WIFI")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - Nueva contraseña: {'*' * len(nueva_password)} (longitud: {len(nueva_password)})")
    
    # 1. Detectar interfaces WiFi activas
    print(f"[GenieACS] 📡 PASO 1: Detectando interfaces WiFi activas...")
    interfaces_activas = detectar_interfaces_wifi_activas(device_id)
    
    if not interfaces_activas:
        mensaje = "No se encontraron interfaces WiFi activas en la ONU"
        print(f"[GenieACS] ❌ ERROR: {mensaje}")
        print(f"[GenieACS]   - Posibles soluciones:")
        print(f"[GenieACS]     * Verificar que la ONU esté online")
        print(f"[GenieACS]     * Verificar que el device_id sea correcto")
        print(f"[GenieACS]     * Verificar que GenieACS esté funcionando")
        return False, mensaje
    
    print(f"[GenieACS] ✅ PASO 1 COMPLETADO: Se encontraron {len(interfaces_activas)} interfaces activas")
    print(f"[GenieACS] 📝 PASO 2: Aplicando contraseña a interfaces activas: {interfaces_activas}")
    
    # 2. Aplicar contraseña a cada interfaz activa
    interfaces_cambiadas = []
    interfaces_fallidas = []
    
    for i, interfaz in enumerate(interfaces_activas, 1):
        parametro_password = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.KeyPassphrase"
        print(f"[GenieACS] 🔧 INTERFAZ {i}/{len(interfaces_activas)}: {interfaz}")
        print(f"[GenieACS]   - Parámetro: {parametro_password}")
        
        if cambiar_parametro_genieacs(device_id, parametro_password, nueva_password):
            interfaces_cambiadas.append(interfaz)
            print(f"[GenieACS] ✅ Contraseña cambiada exitosamente en interfaz {interfaz}")
        else:
            interfaces_fallidas.append(interfaz)
            print(f"[GenieACS] ❌ Error al cambiar contraseña en interfaz {interfaz}")
    
    # 3. Generar mensaje de resultado
    print(f"[GenieACS] 📊 PASO 3: Generando resumen de resultados...")
    print(f"[GenieACS]   - Interfaces cambiadas exitosamente: {interfaces_cambiadas}")
    print(f"[GenieACS]   - Interfaces con error: {interfaces_fallidas}")
    
    if interfaces_cambiadas:
        mensaje = f"Contraseña WiFi aplicada exitosamente a {len(interfaces_cambiadas)} interfaz(es) activa(s): {interfaces_cambiadas}"
        if interfaces_fallidas:
            mensaje += f". Error en {len(interfaces_fallidas)} interfaz(es): {interfaces_fallidas}"
        print(f"[GenieACS] 🎉 ÉXITO: {mensaje}")
        return True, mensaje
    else:
        mensaje = f"Error al cambiar contraseña en todas las interfaces activas: {interfaces_activas}"
        print(f"[GenieACS] 💥 FALLO TOTAL: {mensaje}")
        return False, mensaje

def cambiar_parametro_genieacs(device_id, parametro, valor):
    """Cambia un parámetro en GenieACS"""
    try:
        from urllib.parse import quote
        url = f"{GENIEACS_API}/devices/{quote(device_id, safe='')}/tasks?connection_request"
        data = {
            "name": "setParameterValues",
            "parameterValues": [[parametro, valor]]
        }
        print(f"[GenieACS] Cambiando parámetro: {parametro} = {valor} en device {device_id}")
        response = requests.post(url, json=data, timeout=10)
        print(f"[GenieACS] Respuesta: {response.status_code} - {response.text}")
        response.raise_for_status()
        
        # Verificar que la tarea se creó correctamente
        if response.status_code in [200, 201, 202]:
            print(f"[GenieACS] Parámetro {parametro} cambiado exitosamente")
            
            # Si es un cambio de WiFi, reiniciar la ONU para aplicar cambios
            if 'WLANConfiguration' in parametro:
                print(f"[GenieACS] Cambio de WiFi detectado, reiniciando ONU...")
                try:
                    reiniciar_onu_genieacs(device_id)
                except Exception as e:
                    print(f"[GenieACS] Error al reiniciar ONU: {e}")
            
            return True
        else:
            print(f"[GenieACS] Error inesperado: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"[GenieACS] Timeout al cambiar parámetro {parametro}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"[GenieACS] Error de conexión al cambiar parámetro {parametro}")
        return False
    except Exception as e:
        print(f"[GenieACS] Error al cambiar parámetro {parametro}: {e}")
        return False

# Función eliminada - ahora se usa desde genieacs_utils.py

def reiniciar_onu_genieacs(device_id):
    """Reinicia la ONU para aplicar cambios WiFi"""
    try:
        from urllib.parse import quote
        url = f"{GENIEACS_API}/devices/{quote(device_id, safe='')}/tasks?connection_request"
        
        # Reiniciar ONU completa
        data_reboot = {
            "name": "reboot",
            "parameterValues": []
        }
        print(f"[GenieACS] Reiniciando ONU completa en device {device_id}")
        response = requests.post(url, json=data_reboot, timeout=15)
        print(f"[GenieACS] Respuesta reinicio ONU: {response.status_code} - {response.text}")
        
        if response.status_code in [200, 201, 202]:
            print(f"[GenieACS] ONU reiniciada exitosamente")
            return True
        else:
            print(f"[GenieACS] Error al reiniciar ONU: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[GenieACS] Error al reiniciar ONU: {e}")
        return False

def eliminar_device_genieacs(device_id):
    """Elimina un dispositivo de GenieACS"""
    try:
        from urllib.parse import quote
        url = f"{GENIEACS_API}/devices/{quote(device_id, safe='')}"
        response = requests.delete(url)
        response.raise_for_status()
        print(f"[GENIEACS] Dispositivo eliminado exitosamente: {device_id}")
        return True
    except Exception as e:
        print(f"Error al eliminar dispositivo de GenieACS: {e}")
        return False

def obtener_cambios_por_mes_global():
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT valor FROM admin_settings WHERE clave = 'max_cambios_mes'")
        data = cur.fetchone()
        conn.close()
        if data and data['valor']:
            return int(data['valor'])
    except Exception as e:
        print(f"Error obteniendo max_cambios_mes: {e}")
    return 3  # Valor por defecto si no hay config

def get_db_connection():
    conn = sqlite3.connect('skypass.db')
    conn.row_factory = sqlite3.Row
    return conn

def actualizar_parametros_wisphub(cedula, nueva_clave=None, nuevo_ssid=None, ip_especifica=None):
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    # Busca el cliente para obtener su ID en Wisphub
    cliente = buscar_cliente_por_cedula(cedula)
    if not cliente:
        print('[Wisphub] Cliente no encontrado para actualizar parámetros')
        return False
    
    # Si se especifica una IP, buscar el cliente específico con esa IP
    if ip_especifica:
        print(f'[Wisphub] Buscando cliente específico con IP: {ip_especifica}')
        try:
            response = requests.get(BASE_URL, headers=headers, params={'cedula': cedula}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                clientes = data.get('results', [])
                for c in clientes:
                    if c.get('cedula') == cedula:
                        servicios = c.get('servicios', [])
                        if servicios:
                            for s in servicios:
                                if s.get('ip') == ip_especifica:
                                    print(f'[Wisphub] Encontrado servicio específico con IP: {ip_especifica}')
                                    id_cliente = c.get('id_servicio') or c.get('id')
                                    break
                            else:
                                continue
                            break
                        elif c.get('ip') == ip_especifica:
                            print(f'[Wisphub] Encontrado cliente directo con IP: {ip_especifica}')
                            id_cliente = c.get('id_servicio') or c.get('id')
                            break
                else:
                    print(f'[Wisphub] No se encontró cliente específico con IP: {ip_especifica}')
                    id_cliente = cliente.get('id_servicio') or cliente.get('id')
        except Exception as e:
            print(f'[Wisphub] Error buscando cliente específico: {e}')
            id_cliente = cliente.get('id_servicio') or cliente.get('id')
    else:
        id_cliente = cliente.get('id_servicio') or cliente.get('id')
    data = {}
    if nueva_clave:
        data['password_ssid_router_wifi'] = nueva_clave
        print(f'[Wisphub] Actualizando contraseña WiFi para cliente {cedula}')
    if nuevo_ssid:
        data['ssid_router_wifi'] = nuevo_ssid
        print(f'[Wisphub] Actualizando SSID WiFi para cliente {cedula}')
    if not data:
        print('[Wisphub] No hay datos para actualizar')
        return False
    url = f'https://api.wisphub.net/api/clientes/{id_cliente}/'
    try:
        print(f'[Wisphub] Enviando datos: {data} a {url}')
        response = requests.patch(url, headers=headers, json=data, timeout=10)
        print(f'[Wisphub] Respuesta actualización: {response.status_code} - {response.text}')
        if response.status_code in (200, 204):
            print('[Wisphub] Parámetros actualizados exitosamente en Wisphub')
            return True
        else:
            print(f'[Wisphub] Error en respuesta: {response.status_code}')
            return False
    except requests.exceptions.Timeout:
        print('[Wisphub] Timeout al actualizar parámetros')
        return False
    except requests.exceptions.ConnectionError:
        print('[Wisphub] Error de conexión al actualizar parámetros')
        return False
    except Exception as e:
        print(f'[Wisphub] Error actualizando parámetros: {e}')
        return False

def verificar_dispositivo_online_alternativo(ip_buscada):
    """Verificación alternativa más permisiva para dispositivos online"""
    print(f"[GenieACS] 🔄 VERIFICACIÓN ALTERNATIVA DE DISPOSITIVO ONLINE:")
    print(f"[GenieACS]   - IP buscada: {ip_buscada}")
    
    try:
        # Intentar hacer ping al dispositivo
        import subprocess
        import platform
        
        # Comando ping según el sistema operativo
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "3000", ip_buscada]
        else:
            cmd = ["ping", "-c", "1", "-W", "3", ip_buscada]
        
        print(f"[GenieACS] 📡 Haciendo ping a {ip_buscada}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print(f"[GenieACS] ✅ PING EXITOSO - Dispositivo responde")
            return True
        else:
            print(f"[GenieACS] ❌ PING FALLIDO - Dispositivo no responde")
            print(f"[GenieACS]   - Código de salida: {result.returncode}")
            print(f"[GenieACS]   - Salida: {result.stdout}")
            print(f"[GenieACS]   - Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"[GenieACS] ⏰ TIMEOUT en ping")
        return False
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR en ping: {e}")
        return False

def obtener_estado_online_device(ip_buscada, minutos_online=5):
    """Devuelve True si el dispositivo con esa IP está online en GenieACS (último informe reciente)."""
    print(f"[GenieACS] 🔍 VERIFICANDO ESTADO ONLINE DEL DISPOSITIVO:")
    print(f"[GenieACS]   - IP buscada: {ip_buscada}")
    print(f"[GenieACS]   - Minutos online requeridos: {minutos_online}")
    print(f"[GenieACS]   - GenieACS API: {GENIEACS_API}")
    
    try:
        import re
        from datetime import datetime, timezone, timedelta
        
        print(f"[GenieACS] 📡 Solicitando lista de dispositivos...")
        response = requests.get(f"{GENIEACS_API}/devices", timeout=7)
        print(f"[GenieACS]   - Status Code: {response.status_code}")
        
        response.raise_for_status()
        dispositivos = response.json()
        print(f"[GenieACS]   - Total dispositivos encontrados: {len(dispositivos)}")
        
        for i, device in enumerate(dispositivos):
            print(f"[GenieACS] 🔍 DISPOSITIVO {i+1}:")
            print(f"[GenieACS]   - Device ID: {device.get('_id', 'N/A')}")
            
            # Obtener URL de conexión
            url = device.get("InternetGatewayDevice", {}) \
                .get("ManagementServer", {}) \
                .get("ConnectionRequestURL", {}) \
                .get("_value", '')
            
            print(f"[GenieACS]   - ConnectionRequestURL: {url}")
            
            ip_actual = ''
            if url:
                match = re.search(r"https?://([\d.]+):", url)
                if match:
                    ip_actual = match.group(1)
                    print(f"[GenieACS]   - IP extraída: {ip_actual}")
                else:
                    print(f"[GenieACS]   - No se pudo extraer IP de la URL")
            else:
                print(f"[GenieACS]   - No hay URL de conexión")
            
            if ip_actual == ip_buscada:
                print(f"[GenieACS] ✅ ¡IP COINCIDENTE ENCONTRADA!")
                print(f"[GenieACS]   - IP buscada: {ip_buscada}")
                print(f"[GenieACS]   - IP encontrada: {ip_actual}")
                
                # Revisar _lastInform
                last_inform = device.get('_lastInform')
                print(f"[GenieACS]   - _lastInform: {last_inform}")
                
                if last_inform:
                    try:
                        dt = datetime.fromisoformat(last_inform.replace('Z', '+00:00'))
                        ahora = datetime.now(timezone.utc)
                        diferencia = ahora - dt
                        minutos_transcurridos = diferencia.total_seconds() / 60
                        
                        print(f"[GenieACS]   - Último informe: {dt}")
                        print(f"[GenieACS]   - Ahora: {ahora}")
                        print(f"[GenieACS]   - Minutos transcurridos: {minutos_transcurridos:.2f}")
                        print(f"[GenieACS]   - Límite requerido: {minutos_online}")
                        
                        if diferencia <= timedelta(minutes=minutos_online):
                            print(f"[GenieACS] ✅ DISPOSITIVO ONLINE - Dentro del límite de tiempo")
                            return True, device.get('_id')
                        else:
                            print(f"[GenieACS] ❌ DISPOSITIVO OFFLINE - Fuera del límite de tiempo")
                            return False, None
                    except Exception as parse_error:
                        print(f"[GenieACS] ❌ Error al parsear fecha: {parse_error}")
                        return False, None
                else:
                    print(f"[GenieACS] ❌ DISPOSITIVO OFFLINE - No hay _lastInform")
                    return False, None
            else:
                print(f"[GenieACS]   - IP no coincide (buscada: {ip_buscada}, actual: {ip_actual})")
        
        print(f"[GenieACS] ❌ DISPOSITIVO NO ENCONTRADO")
        print(f"[GenieACS]   - No se encontró ningún dispositivo con IP: {ip_buscada}")
        print(f"[GenieACS]   - IPs encontradas en GenieACS:")
        for device in dispositivos:
            url = device.get("InternetGatewayDevice", {}) \
                .get("ManagementServer", {}) \
                .get("ConnectionRequestURL", {}) \
                .get("_value", '')
            if url:
                match = re.search(r"https?://([\d.]+):", url)
                if match:
                    print(f"[GenieACS]     * {match.group(1)}")
        
        return False
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR al validar online GenieACS: {e}")
        print(f"[GenieACS]   - Tipo de error: {type(e).__name__}")
        import traceback
        print(f"[GenieACS]   - Traceback: {traceback.format_exc()}")
        return False

# Rutas
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
        data = request.get_json()
        email = data.get('username')
        password = data.get('password')
        try:
            result = verificar_admin(email, password)
            if result:
                #session.permanent = True
                session['admin_autenticado'] = True
                session['admin_id'] = result['id']
                session['admin_username'] = result['email']
                return jsonify({'success': True, 'redirect': url_for('admin.dashboard')})
            else:
                return jsonify({'success': False, 'message': 'Credenciales inválidas'})
        except Exception as e:
            return jsonify({'success': False, 'message': 'Credenciales inválidas'})
    return render_template('admin/admin_login.html')

@admin_bp.route('/dashboard', methods=['GET', 'POST'])
@admin_requerido
def dashboard():
    # Consulta el estado del bot de WhatsApp
    try:
        resp = requests.get(f'http://{ip_server}:3002/status', timeout=5)
        data = resp.json()
        if data.get('conectado'):
            flash('✅ WhatsApp conectado correctamente.', 'success')
        else:
            flash('❌ WhatsApp desconectado. No se pueden enviar mensajes automáticos.', 'danger')
    except Exception as e:
        flash('⚠️ No se pudo consultar el estado del bot de WhatsApp.', 'warning')

    cliente = None
    if request.method == 'POST' and 'cedula' in request.form:
        cedula = request.form['cedula']
        cliente = buscar_cliente_por_cedula(cedula)
        if cliente:
            session['cliente_encontrado'] = cliente
        else:
            flash('Cliente no encontrado', 'error')

    configuraciones = obtener_configuracion_global()
    estadisticas = obtener_estadisticas_uso()
    return render_template('admin/admin_dashboard.html', 
                         cliente=cliente, 
                         configuraciones=configuraciones,
                         estadisticas=estadisticas)

@admin_bp.route('/historial')
@admin_requerido
def historial():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    filtro_cedula = request.args.get('cedula', '').strip()
    filtro_tipo = request.args.get('tipo_cambio', '').strip()

    query = "SELECT * FROM change_history"
    params = []
    where_clauses = []
    if filtro_cedula:
        where_clauses.append("cedula = ?")
        params.append(filtro_cedula)
    if filtro_tipo:
        where_clauses.append("tipo_cambio = ?")
        params.append(filtro_tipo)
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
    query += " ORDER BY fecha DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page-1)*per_page])

    conn = get_db_connection()
    cur = conn.execute(query, params)
    historial = [dict(row) for row in cur.fetchall()]

    # Obtener el total de registros filtrados
    count_query = "SELECT COUNT(*) as total FROM change_history"
    count_params = []
    if where_clauses:
        count_query += " WHERE " + " AND ".join(where_clauses)
        count_params = params[:-2]  # solo los filtros, sin limit/offset
    cur = conn.execute(count_query, count_params)
    total_count = cur.fetchone()[0]
    total_pages = (total_count + per_page - 1) // per_page

    # Obtener todos los tipos de cambio distintos para el filtro
    cur = conn.execute("SELECT DISTINCT tipo_cambio FROM change_history ORDER BY tipo_cambio")
    tipos_cambio = [row['tipo_cambio'] for row in cur.fetchall()]

    conn.close()
    return render_template('admin/admin_historial.html', 
                         historial=historial,
                         current_page=page,
                         total_pages=total_pages,
                         filtro_cedula=filtro_cedula,
                         filtro_tipo=filtro_tipo,
                         tipos_cambio=tipos_cambio)

@admin_bp.route('/estadisticas')
@admin_requerido
def estadisticas():
    stats = obtener_estadisticas_uso()
    return render_template('admin/admin_estadisticas.html', estadisticas=stats)

@admin_bp.route('/limites', methods=['GET', 'POST'])
@admin_requerido
def limites():
    if request.method == 'POST':
        ip = request.form.get('ip')
        nuevo_limite = int(request.form.get('nuevo_limite'))
        print('[LOG] POST /limites - ip:', ip, 'nuevo_limite:', nuevo_limite)
        # Buscar nombre del cliente por IP
        cliente = None
        try:
            from app import BASE_URL, API_KEY
            import requests
            headers = {
                'Authorization': f'Api-Key {API_KEY}',
                'Content-Type': 'application/json'
            }
            resp = requests.get(BASE_URL, headers=headers, params={'ip': ip}, timeout=7)
            if resp.status_code == 200:
                data = resp.json()
                clientes = data.get('results', [])
                for c in clientes:
                    if c.get('ip') == ip or c.get('ip_address') == ip:
                        cliente = c
                        break
        except Exception as e:
            print('[LOG] Error buscando cliente por IP:', e)
        if not cliente:
            flash('La IP ingresada no corresponde a ningún cliente.', 'error')
            return redirect(url_for('admin.limites'))
        nombre = cliente.get('nombre', '')
        cedula = cliente.get('cedula', '')
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM user_limits WHERE ip = ?", (ip,))
        existe = cur.fetchone()
        conn.close()
        if actualizar_limite_cliente(ip, nombre, nuevo_limite, cedula):
            if existe:
                flash('Límite personalizado actualizado correctamente.', 'personalizado')
            else:
                flash('Límite personalizado creado correctamente.', 'personalizado')
        else:
            flash('Error al actualizar el límite personalizado.', 'error')
        return redirect(url_for('admin.limites'))
    # Obtener todos los límites personalizados y el límite global
    try:
        print('[LOG] GET /limites - Consultando user_limits')
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM user_limits ORDER BY ip")
        limites = [dict(row) for row in cur.fetchall()]
        print('[LOG] user_limits:', limites)
        print('[LOG] Consultando admin_settings para max_cambios_mes')
        cur = conn.execute("SELECT valor FROM admin_settings WHERE clave = 'max_cambios_mes'")
        data = cur.fetchone()
        print('[LOG] admin_settings:', data)
        cambios_por_mes = 1
        if data and data['valor']:
            try:
                cambios_por_mes = max(1, int(data['valor']))
            except Exception as e:
                print('[LOG] Error convirtiendo cambios_por_mes:', e)
                cambios_por_mes = 1
        print('[LOG] Renderizando admin_limites.html')
        conn.close()
        return render_template('admin/admin_limites.html', limites=limites, cambios_por_mes=cambios_por_mes)
    except Exception as e:
        print('[LOG] Error en /limites:', e)
        flash('Error al cargar los límites', 'error')
        return render_template('admin/admin_limites.html', limites=[], cambios_por_mes=1)

@admin_bp.route('/configuracion', methods=['GET'])
@admin_requerido
def configuracion():
    # Obtener la configuración actual
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT valor FROM admin_settings WHERE clave = 'max_cambios_mes'")
        data = cur.fetchone()
        cambios_por_mes = int(data['valor']) if data else 2
        conn.close()
    except Exception as e:
        print(f"Error al obtener max_cambios_mes: {e}")
        cambios_por_mes = 2
    return render_template('admin/admin_configuracion.html', cambios_por_mes=cambios_por_mes)

@admin_bp.route('/cambiar_config', methods=['POST'])
@admin_requerido
def cambiar_config():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    try:
        cambios_por_mes = int(data.get('cambios_por_mes'))
        if cambios_por_mes < 1:
            return jsonify({'success': False, 'message': 'El valor debe ser mayor a 0'})
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO admin_settings (clave, valor)
            VALUES ('max_cambios_mes', ?)
            ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor;
        """, (str(cambios_por_mes),))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Límite global actualizado correctamente.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al actualizar la configuración global: {str(e)}'})

@admin_bp.route('/cambiar_password', methods=['POST'])
@admin_requerido
def cambiar_password():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    try:
        password_actual = data.get('password_actual')
        nueva_password = data.get('nueva_password')
        confirmar_password = data.get('confirmar_password')
        if len(nueva_password) < 8:
            return jsonify({'success': False, 'message': 'La nueva contraseña debe tener al menos 8 caracteres'})
        if nueva_password != confirmar_password:
            return jsonify({'success': False, 'message': 'Las contraseñas no coinciden'})
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM admin_users WHERE id = ?", (session['admin_id'],))
        admin_data = cur.fetchone()
        if not admin_data or not check_password_hash(admin_data['password'], password_actual):
            conn.close()
            return jsonify({'success': False, 'message': 'Contraseña actual incorrecta'})
        hashed_password = generate_password_hash(nueva_password)
        conn.execute("UPDATE admin_users SET password = ? WHERE id = ?", (hashed_password, session['admin_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Contraseña actualizada exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al cambiar la contraseña: {str(e)}'})

@admin_bp.route('/eliminar_limite', methods=['POST'])
@admin_requerido
def eliminar_limite():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'message': 'IP no proporcionada'})
    try:
        conn = get_db_connection()
        cur = conn.execute("DELETE FROM user_limits WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Límite personalizado eliminado.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al eliminar el límite personalizado: {str(e)}'})

@admin_bp.route('/buscar_cliente_limite', methods=['POST'])
@admin_requerido
def buscar_cliente_limite():
    """Busca un cliente por IP o cédula para límites"""
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    busqueda = data.get('busqueda', '').strip()
    
    if not busqueda:
        return jsonify({'success': False, 'message': 'Debe ingresar una IP o cédula'})
    
    try:
        headers = {
            'Authorization': f'Api-Key {API_KEY}',
            'Content-Type': 'application/json'
        }
        
        cliente = None
        # Determinar si es IP o cédula
        if busqueda.replace('.', '').isdigit() and len(busqueda.split('.')) == 4:
            # Es una IP
            resp = requests.get(BASE_URL, headers=headers, params={'ip': busqueda}, timeout=7)
            if resp.status_code == 200:
                data_ws = resp.json()
                clientes = data_ws.get('results', [])
                for c in clientes:
                    if c.get('ip') == busqueda or c.get('ip_address') == busqueda:
                        cliente = c
                        break
        else:
            # Es una cédula
            resp = requests.get(BASE_URL, headers=headers, params={'cedula': busqueda}, timeout=7)
            if resp.status_code == 200:
                data_ws = resp.json()
                clientes = data_ws.get('results', [])
                for c in clientes:
                    if c.get('cedula') == busqueda:
                        cliente = c
                        break
        
        if not cliente:
            return jsonify({'success': False, 'message': 'Cliente no encontrado'})
        
        # Obtener IP y cédula del cliente
        ip_cliente = cliente.get('ip') or cliente.get('ip_address', '')
        cedula_cliente = cliente.get('cedula', '')
        nombre_cliente = cliente.get('nombre', '')
        
        if not ip_cliente:
            return jsonify({'success': False, 'message': 'El cliente no tiene IP asignada'})
        
        return jsonify({
            'success': True,
            'cliente': {
                'ip': ip_cliente,
                'cedula': cedula_cliente,
                'nombre': nombre_cliente
            }
        })
        
    except Exception as e:
        print(f'[LOG] Error buscando cliente: {e}')
        return jsonify({'success': False, 'message': f'Error al buscar cliente: {str(e)}'})

@admin_bp.route('/editar_limite', methods=['POST'])
@admin_requerido
def editar_limite():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    ip = data.get('ip')
    cedula = data.get('cedula', '')
    nuevo_limite = data.get('nuevo_limite')
    if not ip or not nuevo_limite:
        return jsonify({'success': False, 'message': 'Datos incompletos para editar el límite'})
    try:
        # Buscar nombre del cliente por IP
        nombre = ''
        try:
            from app import BASE_URL, API_KEY
            import requests
            headers = {
                'Authorization': f'Api-Key {API_KEY}',
                'Content-Type': 'application/json'
            }
            resp = requests.get(BASE_URL, headers=headers, params={'ip': ip}, timeout=7)
            if resp.status_code == 200:
                data_ws = resp.json()
                clientes = data_ws.get('results', [])
                for c in clientes:
                    if c.get('ip') == ip or c.get('ip_address') == ip:
                        nombre = c.get('nombre', '')
                        cedula = c.get('cedula', cedula)  # Usar cédula encontrada si no se proporcionó
                        break
        except Exception as e:
            print('[LOG] Error buscando nombre por IP:', e)
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, cedula, nombre, limite_personalizado)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET limite_personalizado=excluded.limite_personalizado, nombre=excluded.nombre, cedula=excluded.cedula;
        """, (ip, cedula, nombre, int(nuevo_limite)))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Límite personalizado actualizado correctamente.', 'nuevo_limite': int(nuevo_limite)})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al actualizar el límite personalizado: {str(e)}'})

@admin_bp.route('/cambiar_wifi_cliente', methods=['GET', 'POST'])
@admin_requerido
def cambiar_wifi_cliente():
    cliente = None
    cliente_no_encontrado = False
    estado_servicio = None
    if request.method == 'GET':
        cedula = request.args.get('cedula')
        ip_seleccionada = request.args.get('ip')
        if cedula:
            # Obtener TODOS los clientes con esa cédula (igual que en el login)
            headers = {
                'Authorization': f'Api-Key {API_KEY}',
                'Content-Type': 'application/json'
            }
            try:
                response = requests.get(BASE_URL, headers=headers, params={'cedula': cedula}, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    clientes = data.get('results', [])
                    print(f'[DEBUG] Clientes encontrados: {len(clientes)}')
                    
                    # Unificar servicios de todos los clientes con la misma cédula
                    servicios_unificados = []
                    cliente_principal = None
                    
                    for c in clientes:
                        if c.get('cedula') == cedula:
                            if not cliente_principal:
                                cliente_principal = c  # Usar el primer cliente como principal
                            
                            servicios = c.get('servicios', [])
                            if servicios:
                                for s in servicios:
                                    if s.get('ip'):
                                        # Crear servicio con datos específicos de cada cliente
                                        s_copy = dict(s)
                                        s_copy['direccion'] = c.get('direccion', '')
                                        s_copy['nombre_cliente'] = c.get('nombre', '')  # Nombre específico de cada cliente
                                        servicios_unificados.append(s_copy)
                            elif c.get('ip'):
                                servicios_unificados.append({
                                    'ip': c.get('ip'),
                                    'nombre_servicio': c.get('nombre_servicio', ''),
                                    'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                                    'estado': c.get('estado', ''),
                                    'direccion': c.get('direccion', ''),
                                    'nombre_cliente': c.get('nombre', '')  # Nombre específico de cada cliente
                                })
                    
                    print(f'[DEBUG] Servicios unificados: {servicios_unificados}')
                    print(f'[DEBUG] Cantidad de servicios: {len(servicios_unificados)}')
                    
                    if cliente_principal:
                        cliente = cliente_principal
                        servicios = servicios_unificados
                    else:
                        cliente_no_encontrado = True
                else:
                    cliente_no_encontrado = True
            except Exception as e:
                print(f'[ERROR] Error obteniendo clientes: {e}')
                cliente_no_encontrado = True
        
        # Determinar estado del servicio si hay cliente
        if cliente and servicios and len(servicios) > 0:
            # Si se especificó una IP, buscar ese servicio específico
            if ip_seleccionada:
                for servicio in servicios:
                    if servicio.get('ip') == ip_seleccionada:
                        estado_servicio = servicio.get('estado', '').lower()
                        break
                else:
                    estado_servicio = 'desconocido'
            else:
                estado_servicio = servicios[0].get('estado', '').lower()
        elif cliente and 'estado' in cliente:
            estado_servicio = cliente.get('estado', '').lower()
        else:
            estado_servicio = 'desconocido'
        
        # Agregar servicios al cliente para el template
        if cliente:
            cliente['servicios'] = servicios
            
            # Si hay un cliente válido y no hay múltiples servicios, hacer validaciones en segundo plano
            if len(servicios) == 1 or (ip_seleccionada and len(servicios) > 1):
                ip_a_usar = ip_seleccionada if ip_seleccionada else servicios[0].get('ip')
                if ip_a_usar:
                    print(f"[DEBUG] Validando dispositivo para IP: {ip_a_usar}")
                    
                    # Verificar estado online del dispositivo
                    device_id = obtener_device_id_por_ip(ip_a_usar)
                    if device_id:
                        print(f"[DEBUG] Device ID encontrado: {device_id}")
                        
                        # Detectar interfaces WiFi activas
                        interfaces_activas = detectar_interfaces_wifi_activas(device_id)
                        print(f"[DEBUG] Interfaces activas detectadas: {interfaces_activas}")
                        
                        # Detectar interfaces y frecuencias para SSID
                        _, interfaces_info = detectar_interfaces_y_frecuencias(device_id)
                        print(f"[DEBUG] Interfaces info detectada: {interfaces_info}")
                        
                        # Guardar información en la sesión
                        session[f'admin_device_info_{cedula}_{ip_a_usar}'] = {
                            'device_id': device_id,
                            'interfaces_activas': interfaces_activas,
                            'interfaces_info': interfaces_info,
                            'timestamp': time.time()
                        }
                        print(f"[DEBUG] Información guardada en sesión para {cedula}-{ip_a_usar}")
                    else:
                        print(f"[DEBUG] No se pudo obtener Device ID para IP: {ip_a_usar}")
        
        return render_template('admin/admin_cambiar_wifi_cliente.html', 
                             cliente=cliente, 
                             cliente_no_encontrado=cliente_no_encontrado, 
                             estado_servicio=estado_servicio,
                             ip_seleccionada=ip_seleccionada)
    # POST solo AJAX
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    cedula = data.get('cedula')
    accion = data.get('accion')
    ip_seleccionada = data.get('ip')
    
    cliente = buscar_cliente_por_cedula(cedula)
    if not cliente:
        return jsonify({'success': False, 'message': 'Cliente no encontrado'})
    
    # Determinar qué IP usar
    ip_a_usar = None
    servicios = cliente.get('servicios', [])
    
    if ip_seleccionada:
        # Usar la IP seleccionada
        ip_a_usar = ip_seleccionada
    elif servicios and isinstance(servicios, list) and len(servicios) > 0:
        # Usar la primera IP de los servicios
        ip_a_usar = servicios[0].get('ip')
    else:
        # Usar la IP directa del cliente
        ip_a_usar = cliente.get('ip')
    
    if not ip_a_usar:
        return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
    
    # Validar estado del servicio específico
    estado_servicio = 'desconocido'
    if servicios and isinstance(servicios, list):
        for servicio in servicios:
            if servicio.get('ip') == ip_a_usar:
                estado_servicio = servicio.get('estado', '').lower()
                break
    
    if estado_servicio == 'suspendido':
        return jsonify({'success': False, 'message': 'El servicio del cliente está suspendido. No se pueden realizar cambios hasta que se reactive.'})
    
    # Verificar si tenemos información en la sesión (validaciones ya hechas)
    session_key = f'admin_device_info_{cedula}_{ip_a_usar}'
    device_info = session.get(session_key)
    
    if device_info:
        # Verificar que la información no sea muy antigua (más de 10 minutos)
        if time.time() - device_info.get('timestamp', 0) > 600:  # 10 minutos
            print(f"[DEBUG] Información de sesión expirada, eliminando...")
            session.pop(session_key, None)
            device_info = None
    
    if device_info:
        print(f"[DEBUG] Usando información de sesión para {cedula}-{ip_a_usar}")
        device_id = device_info['device_id']
        interfaces_activas = device_info['interfaces_activas']
        interfaces_info = device_info['interfaces_info']
    else:
        print(f"[DEBUG] No hay información en sesión, validando dispositivo...")
        
        # Verificar estado online del dispositivo
        dispositivo_online, device_id = obtener_estado_online_device(ip_a_usar)
        if not dispositivo_online:
            print(f"[GenieACS] ⚠️  Verificación principal falló, intentando verificación alternativa...")
            if not verificar_dispositivo_online_alternativo(ip_a_usar):
                return jsonify({'success': False, 'message': 'El dispositivo está desconectado. Debe estar online para realizar cambios.'})
            else:
                print(f"[GenieACS] ✅ Verificación alternativa exitosa - Continuando con el proceso")
    device_id = obtener_device_id_por_ip(ip_a_usar)
        
    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró el dispositivo del cliente'})
        
        # Detectar interfaces
        interfaces_activas = detectar_interfaces_wifi_activas(device_id)
        _, interfaces_info = detectar_interfaces_y_frecuencias(device_id)
    if accion == 'ssid':
        nuevo_ssid = data.get('nuevo_ssid')
        if not nuevo_ssid:
            return jsonify({'success': False, 'message': 'Debe ingresar el nuevo nombre de red'})
        
        # Usar interfaces_info de la sesión o detectar si no están disponibles
        if not interfaces_info:
            return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas en la ONU'})
        
        # Cambiar SSID de manera inteligente
        interfaces_cambiadas = []
        necesita_sufijos = len(interfaces_info) == 2
        
        for interfaz, info in interfaces_info.items():
            frecuencia = info.get('frecuencia', 'Desconocida')
            
            # Construir el nombre final
            if necesita_sufijos:
                if frecuencia == "2.4GHz":
                    nombre_final = f"{nuevo_ssid}-2.4GHz"
                elif frecuencia == "5GHz":
                    nombre_final = f"{nuevo_ssid}-5GHz"
                else:
                    nombre_final = nuevo_ssid  # Fallback
            else:
                nombre_final = nuevo_ssid
            
            parametro_ssid = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.SSID"
            if cambiar_parametro_genieacs_sin_reinicio(device_id, parametro_ssid, nombre_final):
                interfaces_cambiadas.append({
                    'interfaz': interfaz,
                    'frecuencia': frecuencia,
                    'nombre_final': nombre_final
                })
        
        if interfaces_cambiadas:
            # Reiniciar ONU una sola vez al final
            reiniciar_onu_genieacs(device_id)
            actualizar_parametros_wisphub(cedula, nuevo_ssid=nuevo_ssid, ip_especifica=ip_a_usar)
            registrar_cambio(session['admin_id'], cedula, 'SSID', nuevo_ssid)
            
            # Construir mensaje detallado
            if len(interfaces_cambiadas) == 2:
                mensaje = f"✅ Nombre de red WiFi cambiado exitosamente:\n"
                mensaje += f"• 2.4GHz: {interfaces_cambiadas[0]['nombre_final']}\n"
                mensaje += f"• 5GHz: {interfaces_cambiadas[1]['nombre_final']}"
            else:
                interfaz_cambiada = interfaces_cambiadas[0]
                mensaje = f"✅ Nombre de red WiFi cambiado exitosamente:\n"
                mensaje += f"• {interfaz_cambiada['frecuencia']}: {interfaz_cambiada['nombre_final']}"
            
            mensaje += f"\n\nLa ONU se reiniciará automáticamente para aplicar los cambios. Por favor espere unos minutos."
            return jsonify({'success': True, 'message': mensaje})
        else:
            return jsonify({'success': False, 'message': 'Error al cambiar el nombre de la red'})
    elif accion == 'password':
        nueva_password = data.get('nueva_password')
        if not nueva_password:
            return jsonify({'success': False, 'message': 'Debe ingresar la nueva contraseña'})
        
        print(f"[GenieACS] 🚀 INICIANDO PROCESO DE CAMBIO DE CONTRASEÑA WIFI (ADMIN)")
        print(f"[GenieACS]   - Cédula del cliente: {cedula}")
        print(f"[GenieACS]   - IP a usar: {ip_a_usar}")
        print(f"[GenieACS]   - Device ID encontrado: {device_id}")
        
        # Diagnóstico inicial
        print(f"[GenieACS] 🔧 DIAGNÓSTICO DE CONFIGURACIÓN (ADMIN):")
        print(f"[GenieACS]   - GENIEACS_API: {GENIEACS_API}")
        print(f"[GenieACS]   - IP_SERVER: {ip_server}")
        print(f"[GenieACS]   - QR_SERVER: {qr_server}")
        
        # Usar interfaces_activas de la sesión o detectar si no están disponibles
        if not interfaces_activas:
            return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas en la ONU'})
        
        # Cambiar contraseña en todas las interfaces activas
        interfaces_cambiadas = []
        for interfaz in interfaces_activas:
            parametro_password = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.KeyPassphrase"
            if cambiar_parametro_genieacs_sin_reinicio(device_id, parametro_password, nueva_password):
                interfaces_cambiadas.append(interfaz)
        
        if interfaces_cambiadas:
            # Reiniciar ONU una sola vez al final
            reiniciar_onu_genieacs(device_id)
            ok, mensaje = True, f"Contraseña WiFi aplicada exitosamente a {len(interfaces_cambiadas)} interfaz(es) activa(s): {interfaces_cambiadas}"
        else:
            ok, mensaje = False, f"Error al cambiar contraseña en todas las interfaces activas: {interfaces_activas}"
        if ok:
            actualizar_parametros_wisphub(cedula, nueva_clave=nueva_password, ip_especifica=ip_a_usar)
            registrar_cambio(session['admin_id'], cedula, 'Password', 'Nueva')
            return jsonify({'success': True, 'message': f'{mensaje}. La ONU se reiniciará automáticamente para aplicar los cambios. Por favor espere unos minutos.'})
        else:
            return jsonify({'success': False, 'message': f'Error al cambiar la contraseña: {mensaje}'})
    return jsonify({'success': False, 'message': 'Acción no válida.'})

@admin_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('admin_autenticado', None)
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('cliente_encontrado', None)
    return jsonify({'success': True, 'redirect': url_for('admin.login')})

@admin_bp.route('/conectar-whatsapp')
@admin_requerido
def conectar_whatsapp():
    estado = None
    try:
        resp = requests.get(f'http://{ip_server}:3002/status', timeout=3)
        data = resp.json()
        estado = data.get('estado')
        print(f"[DEBUG] Estado del bot: {estado}, Datos completos: {data}")
    except Exception as e:
        print(f"[DEBUG] Error al consultar bot: {e}")
        estado = 'error'
    # Si el estado es iniciando o desconocido, tratarlo como desconectado
    if estado not in ['conectado', 'esperando_qr', 'desconectado', 'error']:
        estado = 'desconectado'
    qr_url = f"https://{qr_server}/qr-image?time={int(time.time())}"
    return render_template('admin/conectar_whatsapp.html', estado=estado, qr_url=qr_url)


@admin_bp.route('/estado-bot', methods=['GET'])
@admin_requerido
def estado_bot():
    try:
        resp = requests.get(f'http://{ip_server}:3002/status', timeout=5)
        data = resp.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({'conectado': False, 'error': str(e)})

@admin_bp.route('/reiniciar-bot', methods=['POST'])
@admin_requerido
def reiniciar_bot():
    try:
        resp = requests.post(f'http://{ip_server}:3002/restart', timeout=10)
        data = resp.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/verificar-sesion', methods=['POST'])
def verificar_sesion_admin():
    if 'admin_id' not in session:
        return jsonify({'error': 'Sesión expirada'}), 401
    return jsonify({'ok': True})

@admin_bp.route('/renovar-sesion', methods=['POST'])
@admin_requerido
def renovar_sesion_admin():
    session.modified = True  # Renueva la sesión
    return '', 204


@admin_bp.route('/api/buscar_clientes')
def api_buscar_clientes():
    q = request.args.get('q', '').strip()
    tipo_busqueda = request.args.get('tipo', 'nombre').strip()  # nombre, cedula, ip
    print("*** FUNCION API_BUSCAR_CLIENTES INICIADA ***")
    print(f"[DEBUG] Búsqueda recibida: '{q}' - Tipo: '{tipo_busqueda}'")
    
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    clientes = []
    try:
        if q:
            print(f"[DEBUG] Query válida, buscando por tipo: {tipo_busqueda}")
            
            if tipo_busqueda == 'ip':
                # Búsqueda exacta por IP
                print(f"[DEBUG] Búsqueda por IP exacta: {q}")
                resp = requests.get(BASE_URL, headers=headers, params={'ip': q}, timeout=6)
                if resp.status_code == 200:
                    data = resp.json()
                    for c in data.get('results', []):
                        if c.get('ip') == q or c.get('ip_address') == q:
                            clientes.append({
                                'ip': c.get('ip') or c.get('ip_address'),
                                    'nombre': c.get('nombre', ''),
                                    'cedula': c.get('cedula', ''),
                                'telefono': c.get('telefono', '') or c.get('celular', '')
                            })
                            break
            elif tipo_busqueda == 'cedula':
                # Búsqueda parcial por cédula
                print(f"[DEBUG] Búsqueda por cédula parcial: {q}")
                resp = requests.get(BASE_URL, headers=headers, timeout=6)
                if resp.status_code == 200:
                    data = resp.json()
                    q_lower = q.lower()
                    for c in data.get('results', []):
                        cedula = c.get('cedula', '')
                        if cedula and q_lower in cedula.lower():
                            clientes.append({
                                'ip': c.get('ip') or c.get('ip_address'),
                                'nombre': c.get('nombre', ''),
                                'cedula': cedula,
                                'telefono': c.get('telefono', '') or c.get('celular', '')
                            })
            else:  # tipo_busqueda == 'nombre'
                # Búsqueda parcial por nombre
                print(f"[DEBUG] Búsqueda por nombre parcial: {q}")
                resp = requests.get(BASE_URL, headers=headers, timeout=6)
                if resp.status_code == 200:
                    data = resp.json()
                    q_lower = q.lower()
                    for c in data.get('results', []):
                        nombre = c.get('nombre', '')
                        if nombre and q_lower in nombre.lower():
                            clientes.append({
                                'ip': c.get('ip') or c.get('ip_address'),
                                'nombre': nombre,
                                    'cedula': c.get('cedula', ''),
                                'telefono': c.get('telefono', '') or c.get('celular', '')
                                })
            
            print(f"[DEBUG] Resultado final: {len(clientes)} clientes encontrados")
            return jsonify({'success': True, 'clientes': clientes})
        else:
            print("[DEBUG] Query vacía, retornando vacío")
            return jsonify({'success': True, 'clientes': []})
    except Exception as e:
        print(f'[DEBUG] Error en api_buscar_clientes: {e}')
        return jsonify({'success': False, 'clientes': []})

@admin_bp.route('/buscar-cliente')
@admin_requerido
def buscar_cliente():
    return render_template('admin/buscar_cliente.html')

@admin_bp.route('/dispositivos_conectados')
@admin_requerido
def admin_dispositivos_conectados():
    return render_template('admin/dispositivos_conectados.html')

@admin_bp.route('/api/dispositivos_conectados')
@admin_requerido
def api_dispositivos_conectados():
    try:
        response = requests.get(f"{GENIEACS_API}/devices", timeout=10)
        response.raise_for_status()
        dispositivos = response.json()
        lista = []
        for device in dispositivos:
            device_id = device.get('_id')
            # Obtener la IP desde ConnectionRequestURL
            url_conexion = device.get("InternetGatewayDevice", {}) \
                .get("ManagementServer", {}) \
                .get("ConnectionRequestURL", {}) \
                .get("_value", '')
            ip_actual = ''
            if url_conexion:
                match = re.search(r'http://([\d\.]+):', url_conexion)
                if match:
                    ip_actual = match.group(1)
            ultimo_informe = device.get('_lastInform')
            modelo = device.get("InternetGatewayDevice", {}) \
                .get("DeviceInfo", {}) \
                .get("ModelName", {}) \
                .get("_value", '')
            fabricante = device.get("InternetGatewayDevice", {}) \
                .get("DeviceInfo", {}) \
                .get("Manufacturer", {}) \
                .get("_value", '')
            lista.append({
                'device_id': device_id,
                'ip': ip_actual,
                'ultimo_informe': ultimo_informe,
                'modelo': modelo,
                'fabricante': fabricante
            })
        return jsonify({'success': True, 'dispositivos': lista})
    except Exception as e:
        return jsonify({'success': False, 'dispositivos': [], 'error': str(e)})

@admin_bp.route('/eliminar_cambio_historial', methods=['POST'])
@admin_requerido
def eliminar_cambio_historial():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    id_cambio = data.get('id')
    if not id_cambio:
        return jsonify({'success': False, 'message': 'ID no proporcionado.'})
    try:
        conn = get_db_connection()
        cur = conn.execute("DELETE FROM change_history WHERE id = ?", (id_cambio,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al eliminar el registro: {str(e)}'})

@admin_bp.route('/eliminar_device', methods=['POST'])
@admin_requerido
def eliminar_device():
    """Elimina un dispositivo de GenieACS"""
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    
    data = request.get_json()
    device_id = data.get('device_id')
    ip = data.get('ip')
    
    if not device_id and not ip:
        return jsonify({'success': False, 'message': 'Se requiere device_id o IP del dispositivo.'})
    
    try:
        # Si solo se proporciona IP, buscar el device_id
        if not device_id and ip:
            device_id = obtener_device_id_por_ip(ip)
            if not device_id:
                return jsonify({'success': False, 'message': f'No se encontró el dispositivo con IP: {ip}'})
        
        # Eliminar el dispositivo
        if eliminar_device_genieacs(device_id):
            return jsonify({'success': True, 'message': 'Dispositivo eliminado exitosamente.'})
        else:
            return jsonify({'success': False, 'message': 'Error al eliminar el dispositivo.'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al eliminar dispositivo: {str(e)}'})

# --- FUNCIONES DE GENIEACS ---
def obtener_interfaces_wifi_activas_directo(device_id):
    """Obtiene interfaces WiFi activas usando el formato correcto de GenieACS"""
    print(f"[GenieACS] 🔍 OBTENIENDO INTERFACES WIFI ACTIVAS:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - API: {GENIEACS_API}")
    
    interfaces_activas = []
    
    try:
        # Usar el formato correcto según la documentación de GenieACS
        query = f'{{"_id":"{device_id}"}}'
        
        # Construir projection para todas las interfaces WiFi
        projection_params = []
        for i in range(1, 11):  # Interfaces 1-10
            projection_params.append(f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.Status._value")
        
        projection_str = ",".join(projection_params)
        
        url = f"{GENIEACS_API}/devices/"
        params = {
            'query': query,
            'projection': projection_str
        }
        
        print(f"[GenieACS] 📡 Solicitando interfaces WiFi...")
        print(f"[GenieACS]   - URL: {url}")
        print(f"[GenieACS]   - Query: {query}")
        print(f"[GenieACS]   - Projection: {projection_str}")
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            devices_data = response.json()
            print(f"[GenieACS] ✅ Respuesta recibida: {len(devices_data)} dispositivos")
            
            if devices_data and len(devices_data) > 0:
                device_data = devices_data[0]  # Tomar el primer (y único) dispositivo
                
                # Extraer interfaces activas
                if 'InternetGatewayDevice' in device_data:
                    lan_device = device_data['InternetGatewayDevice'].get('LANDevice', {}).get('1', {})
                    wlan_config = lan_device.get('WLANConfiguration', {})
                    
                    if wlan_config:
                        print(f"[GenieACS] 🔍 WLANConfiguration encontrado")
                        
                        for interface_num in range(1, 11):  # Máximo 10 interfaces
                            interface_key = str(interface_num)
                            
                            if interface_key in wlan_config:
                                interface_data = wlan_config[interface_key]
                                status_data = interface_data.get('Status', {})
                                
                                if '_value' in status_data:
                                    status_value = status_data['_value']
                                    print(f"[GenieACS] 🔍 Interfaz {interface_num}: {status_value}")
                                    
                                    if status_value == 'Up':
                                        interfaces_activas.append(interface_num)
                                        print(f"[GenieACS] ✅ Interfaz {interface_num} está ACTIVA")
                                    else:
                                        print(f"[GenieACS] ❌ Interfaz {interface_num} está INACTIVA ({status_value})")
                                else:
                                    print(f"[GenieACS] ⚠️  Interfaz {interface_num} sin _value en Status")
                            else:
                                print(f"[GenieACS] ⚠️  Interfaz {interface_num} no existe")
                    else:
                        print(f"[GenieACS] ❌ WLANConfiguration no encontrado")
                else:
                    print(f"[GenieACS] ❌ InternetGatewayDevice no encontrado")
                
                print(f"[GenieACS] 🎯 INTERFACES ACTIVAS ENCONTRADAS: {interfaces_activas}")
                return interfaces_activas
            else:
                print(f"[GenieACS] ❌ No se encontró el dispositivo")
                return []
        else:
            print(f"[GenieACS] ❌ Error HTTP: {response.status_code}")
            return []
        
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR: {e}")
        import traceback
        traceback.print_exc()
        return []

def detectar_interfaces_wifi_activas(device_id):
    """Detecta qué interfaces WiFi están activas solicitando directamente a la ONU"""
    print(f"[GenieACS] 🚀 DETECTANDO INTERFACES WIFI ACTIVAS:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    
    # Obtener interfaces activas directamente
    interfaces_activas = obtener_interfaces_wifi_activas_directo(device_id)
    
    if interfaces_activas:
        print(f"[GenieACS] ✅ Se encontraron {len(interfaces_activas)} interfaces activas: {interfaces_activas}")
    else:
        print(f"[GenieACS] ✅ No se encontraron interfaces activas")
    
    return interfaces_activas

def obtener_canal_y_ssid_interfaz(device_id, interfaz):
    """Obtiene el canal y SSID de una interfaz específica usando el formato correcto"""
    print(f"[GenieACS] 🔍 OBTENIENDO CANAL Y SSID:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - Interfaz: {interfaz}")
    
    try:
        # Usar el formato correcto según la documentación de GenieACS
        query = f'{{"_id":"{device_id}"}}'
        
        # Construir projection para Channel, ChannelsInUse y SSID
        projection_params = [
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.Channel._value",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.ChannelsInUse._value",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.SSID._value"
        ]
        projection_str = ",".join(projection_params)
        
        url = f"{GENIEACS_API}/devices/"
        params = {
            'query': query,
            'projection': projection_str
        }
        
        print(f"[GenieACS] 📡 Solicitando canal y SSID...")
        print(f"[GenieACS]   - URL: {url}")
        print(f"[GenieACS]   - Query: {query}")
        print(f"[GenieACS]   - Projection: {projection_str}")
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            devices_data = response.json()
            print(f"[GenieACS] ✅ Respuesta recibida: {len(devices_data)} dispositivos")
            
            if devices_data and len(devices_data) > 0:
                device_data = devices_data[0]  # Tomar el primer (y único) dispositivo
                
                # Extraer canal y SSID
                canal = None
                ssid_actual = None
                
                if 'InternetGatewayDevice' in device_data:
                    lan_device = device_data['InternetGatewayDevice'].get('LANDevice', {}).get('1', {})
                    wlan_config = lan_device.get('WLANConfiguration', {}).get(str(interfaz), {})
                    
                    # Obtener canal
                    channel_data = wlan_config.get('Channel', {})
                    if '_value' in channel_data:
                        canal = channel_data['_value']
                        print(f"[GenieACS] 📡 Canal obtenido: {canal}")
                    
                    # Si canal es 0, usar ChannelsInUse
                    if canal == 0:
                        channels_in_use_data = wlan_config.get('ChannelsInUse', {})
                        if '_value' in channels_in_use_data:
                            canal = channels_in_use_data['_value']
                            print(f"[GenieACS] 📡 Canal actualizado desde ChannelsInUse: {canal}")
                    
                    # Obtener SSID
                    ssid_data = wlan_config.get('SSID', {})
                    if '_value' in ssid_data:
                        ssid_actual = ssid_data['_value']
                        print(f"[GenieACS] 📡 SSID obtenido: {ssid_actual}")
                
                print(f"[GenieACS] ✅ Canal: {canal}, SSID: {ssid_actual}")
                return canal, ssid_actual
            else:
                print(f"[GenieACS] ❌ No se encontró el dispositivo")
                return None, None
        else:
            print(f"[GenieACS] ❌ Error obteniendo canal y SSID: {response.status_code}")
            return None, None
            
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR obteniendo canal y SSID: {e}")
        return None, None

def identificar_frecuencia_por_canal(canal):
    """Identifica la frecuencia basada en el canal"""
    if canal is None:
        return "Desconocida"
    
    try:
        canal_int = int(canal)
        if 1 <= canal_int <= 14:
            return "2.4GHz"
        elif 36 <= canal_int <= 165:
            return "5GHz"
        else:
            return "Desconocida"
    except:
        return "Desconocida"

def detectar_interfaces_y_frecuencias(device_id):
    """Detecta interfaces activas y sus frecuencias"""
    print(f"[GenieACS] 🔍 DETECTANDO INTERFACES Y FRECUENCIAS")
    
    # Obtener interfaces activas
    interfaces_activas = detectar_interfaces_wifi_activas(device_id)
    
    if not interfaces_activas:
        return [], {}
    
    interfaces_info = {}
    
    for interfaz in interfaces_activas:
        print(f"[GenieACS] 📡 Analizando interfaz {interfaz}")
        
        # Obtener canal y SSID en una sola petición
        canal, ssid_actual = obtener_canal_y_ssid_interfaz(device_id, interfaz)
        
        # Identificar frecuencia
        frecuencia = identificar_frecuencia_por_canal(canal)
        
        interfaces_info[interfaz] = {
            'canal': canal,
            'frecuencia': frecuencia,
            'ssid_actual': ssid_actual
        }
        
        print(f"[GenieACS]   - Interfaz {interfaz}: Canal {canal} → {frecuencia}, SSID: {ssid_actual}")
    
    return interfaces_activas, interfaces_info

def cambiar_parametro_genieacs_sin_reinicio(device_id, parametro, valor):
    """Cambia un parámetro en GenieACS sin reiniciar automáticamente usando el formato correcto"""
    print(f"[GenieACS] 🔧 CAMBIANDO PARÁMETRO SIN REINICIO:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - Parámetro: {parametro}")
    print(f"[GenieACS]   - Valor: {valor}")
    
    try:
        # Usar el formato correcto según la documentación de GenieACS
        url = f"{GENIEACS_API}/devices/{device_id}/tasks?connection_request"
        
        # Formato correcto para setParameterValues según documentación GenieACS
        payload = {
            "name": "setParameterValues",
            "parameterValues": [[parametro, valor]]
        }
        
        print(f"[GenieACS] 📡 Enviando comando...")
        print(f"[GenieACS]   - URL: {url}")
        print(f"[GenieACS]   - Payload: {payload}")
        
        response = requests.post(url, json=payload, timeout=30)
        
        print(f"[GenieACS] 📡 Respuesta: {response.status_code} - {response.text}")
        
        if response.status_code in [200, 201, 202]:
            print(f"[GenieACS] ✅ Parámetro cambiado exitosamente")
            return True
        else:
            print(f"[GenieACS] ❌ Error cambiando parámetro: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR cambiando parámetro: {e}")
        return False
