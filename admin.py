from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import requests
from datetime import datetime
from supabase import create_client
import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

# Cargar variables de entorno
load_dotenv()

# Configuración de Supabase
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")
supabase = create_client(url, key)

# Configuración de APIs
API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = 'https://api.wisphub.net/api/clientes'
GENIEACS_API = os.getenv("GENIEACS_API_URL")

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
    """Verifica las credenciales del administrador en Supabase"""
    try:
        response = supabase.table("admin_users").select("*").eq("username", username).execute()
        if response.data:
            admin = response.data[0]
            if check_password_hash(admin['password'], password):
                return admin
        return None
    except Exception as e:
        print(f"Error al verificar admin: {e}")
        return None

def registrar_cambio(admin_id, cedula, tipo_cambio, valor_anterior, valor_nuevo):
    """Registra un cambio en el historial"""
    try:
        supabase.table("change_history").insert({
            "admin_id": admin_id,
            "cedula": cedula,
            "tipo_cambio": tipo_cambio,
            "valor_anterior": valor_anterior,
            "valor_nuevo": valor_nuevo,
            "fecha": datetime.now().isoformat()
        }).execute()
        return True
    except Exception as e:
        print(f"Error al registrar cambio: {e}")
        return False

def obtener_historial_cambios(cedula=None, admin_id=None, limit=50):
    """Obtiene el historial de cambios"""
    try:
        query = supabase.table("change_history").select("*").order("fecha", desc=True).limit(limit)
        
        if cedula:
            query = query.eq("cedula", cedula)
        if admin_id:
            query = query.eq("admin_id", admin_id)
            
        response = query.execute()
        return response.data
    except Exception as e:
        print(f"Error al obtener historial: {e}")
        return []

def obtener_estadisticas_uso():
    """Obtiene estadísticas de uso"""
    try:
        # Cambios por tipo (SQL directo)
        sql_tipo = "SELECT tipo_cambio, COUNT(*) as count FROM change_history GROUP BY tipo_cambio"
        cambios_por_tipo = supabase.rpc('execute_sql', {'sql': sql_tipo}).execute()
        # Cambios por mes (SQL directo)
        sql_mes = "SELECT DATE_TRUNC('month', fecha) as mes, COUNT(*) as count FROM change_history GROUP BY mes"
        cambios_por_mes = supabase.rpc('execute_sql', {'sql': sql_mes}).execute()
        # Límites más comunes (SQL directo)
        sql_limite = "SELECT limite_personalizado, COUNT(*) as count FROM user_limits GROUP BY limite_personalizado"
        limites_comunes = supabase.rpc('execute_sql', {'sql': sql_limite}).execute()
        return {
            "cambios_por_tipo": cambios_por_tipo.data,
            "cambios_por_mes": cambios_por_mes.data,
            "limites_comunes": limites_comunes.data
        }
    except Exception as e:
        print(f"Error al obtener estadísticas: {e}")
        return {}

def actualizar_limite_cliente(cedula, nuevo_limite):
    """Actualiza el límite de cambios para un cliente"""
    try:
        supabase.table("user_limits").upsert({
            "cedula": cedula,
            "limite_personalizado": nuevo_limite
        }).execute()
        return True
    except Exception as e:
        print(f"Error al actualizar límite: {e}")
        return False

# Funciones de utilidad
def obtener_configuracion_global():
    """Obtiene la configuración global desde Supabase"""
    try:
        response = supabase.table("admin_settings").select("*").execute()
        return response.data
    except Exception as e:
        print(f"Error al obtener configuración global: {e}")
        return []

def actualizar_configuracion_global(clave, valor):
    """Actualiza una configuración global en Supabase"""
    try:
        supabase.table("admin_settings").update({"valor": valor}).eq("clave", clave).execute()
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
    """Obtiene el ID del dispositivo en GenieACS por su IP"""
    try:
        response = requests.get(f"{GENIEACS_API}/devices")
        response.raise_for_status()
        dispositivos = response.json()

        for device in dispositivos:
            device_id = device.get('_id')
            ip_actual = device.get("InternetGatewayDevice", {}) \
                              .get("WANDevice", {}) \
                              .get("1", {}) \
                              .get("WANConnectionDevice", {}) \
                              .get("2", {}) \
                              .get("WANIPConnection", {}) \
                              .get("1", {}) \
                              .get("ExternalIPAddress", {}) \
                              .get("_value")

            if ip_actual == ip_buscada:
                return device_id

    except Exception as e:
        print(f"Error al buscar dispositivo en GenieACS: {e}")
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
        data = supabase.table("admin_settings").select("valor").eq("clave", "max_cambios_mes").limit(1).execute()
        if data.data and data.data[0].get("valor"):
            return int(data.data[0]["valor"])
    except Exception as e:
        print(f"Error obteniendo max_cambios_mes: {e}")
    return 3  # Valor por defecto si no hay config

# Rutas
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')
        try:
            result = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user = result.user
            if user:
                session['admin_autenticado'] = True
                session['admin_id'] = user.id
                session['admin_username'] = user.email
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Credenciales inválidas', 'error')
        except Exception as e:
            flash('Credenciales inválidas', 'error')
    return render_template('admin/admin_login.html')

@admin_bp.route('/dashboard', methods=['GET', 'POST'])
@admin_requerido
def dashboard():
    # Consulta el estado del bot de WhatsApp
    try:
        resp = requests.get('http://localhost:3002/status', timeout=5)
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

    # Construir la consulta con filtros
    query = supabase.table('change_history').select('*')
    if filtro_cedula:
        query = query.eq('cedula', filtro_cedula)
    if filtro_tipo:
        query = query.eq('tipo_cambio', filtro_tipo)
    query = query.order('fecha', desc=True)

    # Obtener el total de registros filtrados
    total_count = query.execute()
    total_registros = len(total_count.data)
    total_pages = (total_registros + per_page - 1) // per_page

    # Obtener los registros de la página actual
    historial = query.range((page-1)*per_page, page*per_page-1).execute()

    # Obtener todos los tipos de cambio distintos para el filtro
    tipos_cambio = supabase.table('change_history').select('tipo_cambio').execute()
    tipos_cambio_unicos = sorted(list(set([c['tipo_cambio'] for c in tipos_cambio.data if c.get('tipo_cambio')])) )

    return render_template('admin/admin_historial.html', 
                         historial=historial.data,
                         current_page=page,
                         total_pages=total_pages,
                         filtro_cedula=filtro_cedula,
                         filtro_tipo=filtro_tipo,
                         tipos_cambio=tipos_cambio_unicos)

@admin_bp.route('/estadisticas')
@admin_requerido
def estadisticas():
    stats = obtener_estadisticas_uso()
    return render_template('admin/admin_estadisticas.html', estadisticas=stats)

@admin_bp.route('/limites', methods=['GET', 'POST'])
@admin_requerido
def limites():
    if request.method == 'POST':
        cedula = request.form.get('cedula')
        nuevo_limite = int(request.form.get('nuevo_limite'))
        print('[LOG] POST /limites - cedula:', cedula, 'nuevo_limite:', nuevo_limite)
        # Verificar existencia del cliente en Wisphub
        cliente = buscar_cliente_por_cedula(cedula)
        print('[LOG] Resultado buscar_cliente_por_cedula:', cliente)
        if not cliente:
            flash('La cédula ingresada no corresponde a ningún cliente en Wisphub.', 'error')
            return redirect(url_for('admin.limites'))
        if actualizar_limite_cliente(cedula, nuevo_limite):
            print('[LOG] Límite actualizado exitosamente')
            flash('Límite actualizado exitosamente', 'success')
        else:
            print('[LOG] Error al actualizar el límite')
            flash('Error al actualizar el límite', 'error')
        return redirect(url_for('admin.limites'))
    # Obtener todos los límites personalizados y el límite global
    try:
        print('[LOG] GET /limites - Consultando user_limits')
        limites = supabase.table("user_limits").select("*").execute()
        print('[LOG] user_limits:', limites.data)
        print('[LOG] Consultando admin_settings para max_cambios_mes')
        data = supabase.table("admin_settings").select("valor").eq("clave", "max_cambios_mes").limit(1).execute()
        print('[LOG] admin_settings:', data.data)
        cambios_por_mes = 1
        if data.data and data.data[0].get("valor"):
            try:
                cambios_por_mes = max(1, int(data.data[0]["valor"]))
            except Exception as e:
                print('[LOG] Error convirtiendo cambios_por_mes:', e)
                cambios_por_mes = 1
        print('[LOG] Renderizando admin_limites.html')
        return render_template('admin/admin_limites.html', limites=limites.data, cambios_por_mes=cambios_por_mes)
    except Exception as e:
        print('[LOG] Error en /limites:', e)
        flash('Error al cargar los límites', 'error')
        return render_template('admin/admin_limites.html', limites=[], cambios_por_mes=1)

@admin_bp.route('/configuracion', methods=['GET'])
@admin_requerido
def configuracion():
    # Obtener la configuración actual
    try:
        data = supabase.table("admin_settings").select("valor").eq("clave", "max_cambios_mes").limit(1).execute()
        cambios_por_mes = int(data.data[0]["valor"]) if data.data and data.data[0].get("valor") else 3
    except Exception as e:
        print(f"Error al obtener max_cambios_mes: {e}")
        cambios_por_mes = 3
    return render_template('admin/admin_configuracion.html', cambios_por_mes=cambios_por_mes)

@admin_bp.route('/cambiar_config', methods=['POST'])
@admin_requerido
def cambiar_config():
    try:
        cambios_por_mes = int(request.form.get('cambios_por_mes'))
        if cambios_por_mes < 1:
            flash('El valor debe ser mayor a 0', 'error')
            return redirect(url_for('admin.limites'))
        supabase.table('admin_settings').update({
            'valor': str(cambios_por_mes)
        }).eq('clave', 'max_cambios_mes').execute()
        flash('Configuración actualizada exitosamente', 'success')
    except Exception as e:
        flash(f'Error al actualizar la configuración: {str(e)}', 'error')
    return redirect(url_for('admin.limites'))

@admin_bp.route('/cambiar_password', methods=['POST'])
@admin_requerido
def cambiar_password():
    try:
        password_actual = request.form.get('password_actual')
        nueva_password = request.form.get('nueva_password')
        confirmar_password = request.form.get('confirmar_password')
        
        if len(nueva_password) < 8:
            flash('La nueva contraseña debe tener al menos 8 caracteres', 'error')
            return redirect(url_for('admin.configuracion'))
        
        if nueva_password != confirmar_password:
            flash('Las contraseñas no coinciden', 'error')
            return redirect(url_for('admin.configuracion'))
        
        # Verificar la contraseña actual
        admin_id = session.get('admin_id')
        admin_data = supabase.table('admin_users').select('*').eq('id', admin_id).execute()
        
        if not admin_data.data or not check_password_hash(admin_data.data[0]['password'], password_actual):
            flash('Contraseña actual incorrecta', 'error')
            return redirect(url_for('admin.configuracion'))
        
        # Actualizar la contraseña
        hashed_password = generate_password_hash(nueva_password)
        supabase.table('admin_users').update({
            'password': hashed_password
        }).eq('id', admin_id).execute()
        
        flash('Contraseña actualizada exitosamente', 'success')
    except Exception as e:
        flash(f'Error al cambiar la contraseña: {str(e)}', 'error')
    
    return redirect(url_for('admin.configuracion'))

@admin_bp.route('/cambiar_wifi_cliente', methods=['GET', 'POST'])
@admin_requerido
def cambiar_wifi_cliente():
    cliente = None
    if request.method == 'GET':
        cedula = request.args.get('cedula')
        if cedula:
            cliente = buscar_cliente_por_cedula(cedula)
            if not cliente:
                flash('Cliente no encontrado', 'error')
        return render_template('admin/admin_cambiar_wifi_cliente.html', cliente=cliente)
    # POST
    cedula = request.form.get('cedula')
    accion = request.form.get('accion')
    cliente = buscar_cliente_por_cedula(cedula)
    if not cliente:
        flash('Cliente no encontrado', 'error')
        return redirect(url_for('admin.cambiar_wifi_cliente', cedula=cedula))
    device_id = obtener_device_id_por_ip(cliente.get('ip'))
    if not device_id:
        flash('No se encontró el dispositivo del cliente', 'error')
        return redirect(url_for('admin.cambiar_wifi_cliente', cedula=cedula))
    if accion == 'ssid':
        nuevo_ssid = request.form.get('nuevo_ssid')
        if nuevo_ssid:
            if cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', nuevo_ssid):
                registrar_cambio(session['admin_id'], cedula, 'SSID', 'Anterior', nuevo_ssid)
                flash('Nombre de red actualizado exitosamente', 'success')
            else:
                flash('Error al cambiar el nombre de la red', 'error')
        else:
            flash('Debe ingresar el nuevo nombre de red', 'error')
    elif accion == 'password':
        nueva_password = request.form.get('nueva_password')
        if nueva_password:
            if cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase', nueva_password):
                registrar_cambio(session['admin_id'], cedula, 'Password', 'Anterior', 'Nueva')
                flash('Contraseña WiFi actualizada exitosamente', 'success')
            else:
                flash('Error al cambiar la contraseña', 'error')
        else:
            flash('Debe ingresar la nueva contraseña', 'error')
    return redirect(url_for('admin.cambiar_wifi_cliente', cedula=cedula))

@admin_bp.route('/eliminar_limite', methods=['POST'])
@admin_requerido
def eliminar_limite():
    cedula = request.form.get('cedula')
    if not cedula:
        flash('Cédula no proporcionada', 'error')
        return redirect(url_for('admin.limites'))
    try:
        supabase.table('user_limits').delete().eq('cedula', cedula).execute()
        flash('Límite personalizado eliminado. El cliente ahora usará el límite global.', 'success')
    except Exception as e:
        flash(f'Error al eliminar el límite personalizado: {str(e)}', 'error')
    return redirect(url_for('admin.limites'))

@admin_bp.route('/editar_limite', methods=['POST'])
@admin_requerido
def editar_limite():
    cedula = request.form.get('cedula')
    nuevo_limite = request.form.get('nuevo_limite')
    if not cedula or not nuevo_limite:
        flash('Datos incompletos para editar el límite', 'error')
        return redirect(url_for('admin.limites'))
    try:
        supabase.table('user_limits').upsert({
            'cedula': cedula,
            'limite_personalizado': int(nuevo_limite)
        }).execute()
        flash('Límite personalizado actualizado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al actualizar el límite personalizado: {str(e)}', 'error')
    return redirect(url_for('admin.limites'))

@admin_bp.route('/editar_limite_ajax', methods=['POST'])
@admin_requerido
def editar_limite_ajax():
    cedula = request.form.get('cedula')
    nuevo_limite = request.form.get('nuevo_limite')
    if not cedula or not nuevo_limite:
        return jsonify(success=False, message='Datos incompletos para editar el límite')
    try:
        supabase.table('user_limits').upsert({
            'cedula': cedula,
            'limite_personalizado': int(nuevo_limite)
        }).execute()
        return jsonify(success=True, message='Límite personalizado actualizado correctamente.', nuevo_limite=int(nuevo_limite))
    except Exception as e:
        return jsonify(success=False, message=f'Error al actualizar el límite personalizado: {str(e)}')

@admin_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('admin_autenticado', None)
    session.pop('cliente_encontrado', None)
    flash('Sesión cerrada exitosamente', 'success')
    return redirect(url_for('admin.login'))

@admin_bp.route('/conectar-whatsapp')
@admin_requerido
def conectar_whatsapp():
    estado = None
    try:
        resp = requests.get('http://localhost:3002/status', timeout=3)
        data = resp.json()
        estado = data.get('estado')
    except Exception as e:
        estado = 'error'
    # Si el estado es iniciando o desconocido, tratarlo como desconectado
    if estado not in ['conectado', 'esperando_qr', 'desconectado', 'error']:
        estado = 'desconectado'
    qr_url = "http://localhost:3002/qr-image"
    return render_template('admin/conectar_whatsapp.html', estado=estado, qr_url=qr_url)

@admin_bp.route('/desconectar-whatsapp', methods=['POST'])
@admin_requerido
def desconectar_whatsapp():
    try:
        resp = requests.post('http://localhost:3002/disconnect', timeout=5)
        print('[DEPURACIÓN FLASK] Respuesta de /disconnect:', resp.text)
        data = resp.json()
        if data.get('success'):
            flash('WhatsApp desconectado correctamente.', 'success')
        else:
            flash('No se pudo desconectar el bot: ' + data.get('message', ''), 'danger')
    except Exception as e:
        flash('Error al intentar desconectar el bot: ' + str(e), 'danger')
    # Redirige a la página de conectar WhatsApp
    return redirect(url_for('admin.conectar_whatsapp'))

@admin_bp.route('/estado-bot', methods=['GET'])
@admin_requerido
def estado_bot():
    try:
        resp = requests.get('http://localhost:3002/status', timeout=5)
        data = resp.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({'conectado': False, 'error': str(e)})

@admin_bp.route('/api/buscar_clientes')
def api_buscar_clientes():
    tipo = request.args.get('tipo', 'cedula')
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'success': True, 'clientes': []})
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    params = {'page_size': 10}
    if tipo == 'cedula':
        params['cedula__contains'] = q
    else:
        params['usuario__contains'] = q
    try:
        resp = requests.get(BASE_URL, headers=headers, params=params, timeout=4)
        if resp.status_code != 200:
            return jsonify({'success': False, 'clientes': [], 'error': 'Error consultando Wisphub'})
        data = resp.json()
        clientes = []
        for c in data.get('results', []):
            servicios = c.get('servicios', [])
            if servicios:
                for s in servicios:
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
                clientes.append({
                    'id_servicio': c.get('id_servicio', ''),
                    'nombre': c.get('nombre', ''),
                    'cedula': c.get('cedula', ''),
                    'telefono': c.get('telefono', ''),
                    'ip': c.get('ip') or c.get('ip_address', ''),
                    'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                    'password_ssid_router_wifi': c.get('password_ssid_router_wifi', '')
                })
        return jsonify({'success': True, 'clientes': clientes[:10]})
    except Exception as e:
        print('[Wisphub] Error en búsqueda rápida:', e)
        return jsonify({'success': False, 'clientes': [], 'error': str(e)})

@admin_bp.route('/buscar-cliente')
@admin_requerido
def buscar_cliente():
    return render_template('admin/buscar_cliente.html') 