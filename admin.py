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
BASE_URL = 'https://api.wisphub.net/api/clientes'
GENIEACS_API = os.getenv("GENIEACS_API_URL")
ip_server = os.getenv("IP_SERVER")

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

def actualizar_limite_cliente(ip, nombre, nuevo_limite):
    """Actualiza o inserta el límite de cambios para un cliente por IP"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, nombre, limite_personalizado)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET limite_personalizado=excluded.limite_personalizado, nombre=excluded.nombre;
        """, (ip, nombre, nuevo_limite))
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
    print('[LOG] Cliente no encontrado en Wisphub')
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

def cambiar_parametro_genieacs(device_id, parametro, valor):
    """Cambia un parámetro en GenieACS"""
    try:
        from urllib.parse import quote
        url = f"{GENIEACS_API}/devices/{quote(device_id, safe='')}/tasks?connection_request"
        data = {
            "name": "setParameterValues",
            "parameterValues": [[parametro, valor, "xsd:string"]]
        }
        response = requests.post(url, json=data)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error al cambiar parámetro en GenieACS: {e}")
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

def actualizar_parametros_wisphub(cedula, nueva_clave=None, nuevo_ssid=None):
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    # Busca el cliente para obtener su ID en Wisphub
    cliente = buscar_cliente_por_cedula(cedula)
    if not cliente:
        print('[Wisphub] Cliente no encontrado para actualizar parámetros')
        return False
    id_cliente = cliente.get('id_servicio') or cliente.get('id')
    data = {}
    if nueva_clave:
        data['password_ssid_router_wifi'] = nueva_clave
    if nuevo_ssid:
        data['ssid_router_wifi'] = nuevo_ssid
    if not data:
        return False
    url = f'https://api.wisphub.net/api/clientes/{id_cliente}/'
    try:
        response = requests.patch(url, headers=headers, json=data, timeout=5)
        print('[Wisphub] Respuesta actualización:', response.status_code, response.text)
        return response.status_code in (200, 204)
    except Exception as e:
        print('[Wisphub] Error actualizando parámetros:', e)
        return False

def obtener_estado_online_device(ip_buscada, minutos_online=5):
    """Devuelve True si el dispositivo con esa IP está online en GenieACS (último informe reciente)."""
    try:
        response = requests.get(f"{GENIEACS_API}/devices", timeout=7)
        response.raise_for_status()
        dispositivos = response.json()
        for device in dispositivos:
            url = device.get("InternetGatewayDevice", {}) \
                .get("ManagementServer", {}) \
                .get("ConnectionRequestURL", {}) \
                .get("_value", '')
            ip_actual = ''
            if url:
                match = re.search(r"https?://([\d.]+):", url)
                if match:
                    ip_actual = match.group(1)
            if ip_actual == ip_buscada:
                # Revisar _lastInform
                last_inform = device.get('_lastInform')
                if last_inform:
                    try:
                        dt = datetime.fromisoformat(last_inform.replace('Z', '+00:00'))
                        ahora = datetime.now(timezone.utc)
                        if (ahora - dt) <= timedelta(minutes=minutos_online):
                            return True
                    except Exception:
                        pass
                return False
        return False
    except Exception as e:
        print(f"Error al validar online GenieACS: {e}")
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
            flash('La IP ingresada no corresponde a ningún cliente en Wisphub.', 'error')
            return redirect(url_for('admin.limites'))
        nombre = cliente.get('nombre', '')
        conn = get_db_connection()
        cur = conn.execute("SELECT * FROM user_limits WHERE ip = ?", (ip,))
        existe = cur.fetchone()
        conn.close()
        if actualizar_limite_cliente(ip, nombre, nuevo_limite):
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
        cur = conn.execute("SELECT * FROM user_limits")
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
        cambios_por_mes = int(data['valor']) if data else 3
        conn.close()
    except Exception as e:
        print(f"Error al obtener max_cambios_mes: {e}")
        cambios_por_mes = 3
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

@admin_bp.route('/editar_limite', methods=['POST'])
@admin_requerido
def editar_limite():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    ip = data.get('ip')
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
                        break
        except Exception as e:
            print('[LOG] Error buscando nombre por IP:', e)
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, nombre, limite_personalizado)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET limite_personalizado=excluded.limite_personalizado, nombre=excluded.nombre;
        """, (ip, nombre, int(nuevo_limite)))
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
        if cedula:
            cliente = buscar_cliente_por_cedula(cedula)
            if not cliente:
                cliente_no_encontrado = True
            else:
                # Extraer estado del servicio Wisphub
                servicios = cliente.get('servicios', [])
                if servicios and isinstance(servicios, list) and len(servicios) > 0:
                    estado_servicio = servicios[0].get('estado', '').lower()
                elif 'estado' in cliente:
                    estado_servicio = cliente.get('estado', '').lower()
                else:
                    estado_servicio = 'desconocido'
        return render_template('admin/admin_cambiar_wifi_cliente.html', cliente=cliente, cliente_no_encontrado=cliente_no_encontrado, estado_servicio=estado_servicio)
    # POST solo AJAX
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    cedula = data.get('cedula')
    accion = data.get('accion')
    cliente = buscar_cliente_por_cedula(cedula)
    if not cliente:
        return jsonify({'success': False, 'message': 'Cliente no encontrado'})
    id_cliente = cliente.get('id')
    # Validar estado del servicio Wisphub
    servicios = cliente.get('servicios', [])
    if servicios and isinstance(servicios, list) and len(servicios) > 0:
        estado_servicio = servicios[0].get('estado', '').lower()
    elif 'estado' in cliente:
        estado_servicio = cliente.get('estado', '').lower()
    else:
        estado_servicio = 'desconocido'
    if estado_servicio == 'suspendido':
        return jsonify({'success': False, 'message': 'El servicio del cliente está suspendido. No se pueden realizar cambios hasta que se reactive.'})
    ip_cliente = cliente.get('ip')
    if not ip_cliente:
        return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
    if not obtener_estado_online_device(ip_cliente):
        return jsonify({'success': False, 'message': 'El dispositivo está desconectado. Debe estar online para realizar cambios.'})
    device_id = obtener_device_id_por_ip(ip_cliente)
    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró el dispositivo del cliente'})
    if accion == 'ssid':
        nuevo_ssid = data.get('nuevo_ssid')
        if not nuevo_ssid:
            return jsonify({'success': False, 'message': 'Debe ingresar el nuevo nombre de red'})
        if cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', nuevo_ssid):
            actualizar_parametros_wisphub(cedula, nuevo_ssid=nuevo_ssid)
            registrar_cambio(session['admin_id'], cedula, 'SSID', nuevo_ssid)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Error al cambiar el nombre de la red'})
    elif accion == 'password':
        nueva_password = data.get('nueva_password')
        if not nueva_password:
            return jsonify({'success': False, 'message': 'Debe ingresar la nueva contraseña'})
        if cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase', nueva_password):
            actualizar_parametros_wisphub(cedula, nueva_clave=nueva_password)
            registrar_cambio(session['admin_id'], cedula, 'Password', 'Nueva')
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Error al cambiar la contraseña'})
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
    except Exception as e:
        estado = 'error'
    # Si el estado es iniciando o desconocido, tratarlo como desconectado
    if estado not in ['conectado', 'esperando_qr', 'desconectado', 'error']:
        estado = 'desconectado'
    qr_url = f"http://{ip_server}:5050/qr.png?time={int(time.time())}"
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

@admin_bp.route('/api/buscar_clientes')
def api_buscar_clientes():
    q = request.args.get('q', '').strip()
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    clientes = []
    seen = set()
    try:
        if q:
            if q.isdigit():
                campos = ['cedula']
            else:
                campos = ['nombre', 'usuario']
            for campo in campos:
                params = {'page_size': 50, f'{campo}__contains': q}
                resp = requests.get(BASE_URL, headers=headers, params=params, timeout=6)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for c in data.get('results', []):
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            key = (c.get('cedula', ''), s.get('ip', ''))
                            if key not in seen:
                                seen.add(key)
                                clientes.append({
                                    'id_servicio': s.get('id_servicio', ''),
                                    'nombre': c.get('nombre', ''),
                                    'cedula': c.get('cedula', ''),
                                    'telefono': c.get('telefono', ''),
                                    'ip': s.get('ip', ''),
                                    'ssid_router_wifi': s.get('ssid_router_wifi', ''),
                                    'password_ssid_router_wifi': s.get('password_ssid_router_wifi', '')
                                })
                    else:
                        key = (c.get('cedula', ''), c.get('ip') or c.get('ip_address', ''))
                        if key not in seen:
                            seen.add(key)
                            clientes.append({
                                'id_servicio': c.get('id_servicio', ''),
                                'nombre': c.get('nombre', ''),
                                'cedula': c.get('cedula', ''),
                                'telefono': c.get('telefono', ''),
                                'ip': c.get('ip') or c.get('ip_address', ''),
                                'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                                'password_ssid_router_wifi': c.get('password_ssid_router_wifi', '')
                            })
        else:
            params = {'page_size': 100}
            resp = requests.get(BASE_URL, headers=headers, params=params, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                for c in data.get('results', []):
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            key = (c.get('cedula', ''), s.get('ip', ''))
                            if key not in seen:
                                seen.add(key)
                                clientes.append({
                                    'id_servicio': s.get('id_servicio', ''),
                                    'nombre': c.get('nombre', ''),
                                    'cedula': c.get('cedula', ''),
                                    'telefono': c.get('telefono', ''),
                                    'ip': s.get('ip', ''),
                                    'ssid_router_wifi': s.get('ssid_router_wifi', ''),
                                    'password_ssid_router_wifi': s.get('password_ssid_router_wifi', '')
                                })
                    else:
                        key = (c.get('cedula', ''), c.get('ip') or c.get('ip_address', ''))
                        if key not in seen:
                            seen.add(key)
                            clientes.append({
                                'id_servicio': c.get('id_servicio', ''),
                                'nombre': c.get('nombre', ''),
                                'cedula': c.get('cedula', ''),
                                'telefono': c.get('telefono', ''),
                                'ip': c.get('ip') or c.get('ip_address', ''),
                                'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                                'password_ssid_router_wifi': c.get('password_ssid_router_wifi', '')
                            })
        return jsonify({'success': True, 'clientes': clientes[:100]})
    except Exception as e:
        print('[Wisphub] Error en búsqueda rápida:', e)
        return jsonify({'success': False, 'clientes': [], 'error': str(e)})

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

@admin_bp.route('/buscar_clientes')
@admin_requerido
def buscar_clientes():
    query = request.args.get('query', '').strip()
    if not query or len(query) < 2:
        return jsonify({'success': True, 'clientes': []})
    try:
        from app import BASE_URL, API_KEY
        import requests
        headers = {
            'Authorization': f'Api-Key {API_KEY}',
            'Content-Type': 'application/json'
        }
        # Buscar por nombre o IP
        params = {'search': query}
        resp = requests.get(BASE_URL, headers=headers, params=params, timeout=7)
        clientes = []
        if resp.status_code == 200:
            data = resp.json()
            for c in data.get('results', []):
                ip = c.get('ip') or c.get('ip_address')
                nombre = c.get('nombre', '')
                if ip:
                    clientes.append({'ip': ip, 'nombre': nombre})
        return jsonify({'success': True, 'clientes': clientes})
    except Exception as e:
        print('[LOG] Error en buscar_clientes:', e)
        return jsonify({'success': False, 'clientes': []}) 