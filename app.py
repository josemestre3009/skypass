from dotenv import load_dotenv
load_dotenv()

from flask import Flask, Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import os
import functools
import random
import sqlite3
import time
import signal
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

from soporte import soporte_bp
from services import ycloud, wisphub, genieacs

# ---------------------------------------------------------------------------
# App y Blueprints
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(minutes=2)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

# Blueprint admin (prefijo /admin, nombre 'admin' para que url_for('admin.XXX') funcione)
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.context_processor
def inject_empresa():
    return {'empresa': os.getenv('EMPRESA', 'SkyPass')}

# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------

def get_db_connection():
    conn = sqlite3.connect('skypass.db')
    conn.row_factory = sqlite3.Row
    return conn



# ===========================================================================
# ██╗   ██╗███████╗██╗   ██╗ █████╗ ██████╗ ██╗ ██████╗
# ██║   ██║██╔════╝██║   ██║██╔══██╗██╔══██╗██║██╔═══██╗
# ██║   ██║███████╗██║   ██║███████║██████╔╝██║██║   ██║
# ██║   ██║╚════██║██║   ██║██╔══██║██╔══██╗██║██║   ██║
# ╚██████╔╝███████║╚██████╔╝██║  ██║██║  ██║██║╚██████╔╝
#  ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝
# ===========================================================================


# ---------------------------------------------------------------------------
# Límites de cambios mensuales (usuario)
# ---------------------------------------------------------------------------

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
    return 2


def contar_cambios_usuario_mes(cedula):
    ahora = datetime.now()
    inicio_mes = ahora.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT COUNT(*) as total FROM change_history WHERE cedula = ? AND fecha >= ?",
            (cedula, inicio_mes.isoformat())
        )
        data = cur.fetchone()
        conn.close()
        return data['total'] if data else 0
    except Exception as e:
        print(f"Error contando cambios del usuario: {e}")
        return 0


def obtener_limite_cliente(ip):
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT limite_personalizado FROM user_limits WHERE ip = ?", (ip,))
        data = cur.fetchone()
        conn.close()
        if data and data['limite_personalizado']:
            return int(data['limite_personalizado'])
    except Exception as e:
        print(f"Error obteniendo límite personalizado: {e}")
    return obtener_cambios_por_mes_global()


def limpiar_historial_antiguo():
    ahora = datetime.now()
    primer_dia_mes_actual = ahora.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if primer_dia_mes_actual.month == 1:
        primer_dia_mes_anterior = primer_dia_mes_actual.replace(year=primer_dia_mes_actual.year - 1, month=12)
    else:
        primer_dia_mes_anterior = primer_dia_mes_actual.replace(month=primer_dia_mes_actual.month - 1)
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM change_history WHERE fecha < ?", (primer_dia_mes_anterior.isoformat(),))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error limpiando historial antiguo: {e}")


def registrar_cambio_usuario(cedula, tipo_cambio, valor_nuevo):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO change_history (admin_id, cedula, tipo_cambio, valor_nuevo, fecha) VALUES (?, ?, ?, ?, ?)",
            (None, cedula, tipo_cambio, valor_nuevo, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al registrar cambio (usuario): {e}")
        return False


# ---------------------------------------------------------------------------
# Sesión del cliente
# ---------------------------------------------------------------------------

def cliente_requerido(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("cliente_encontrado"):
            return redirect(url_for("index"))
        return func(*args, **kwargs)
    return wrapper


def obtener_cliente_actual():
    return {
        'nombre':     session.get('nombre', ''),
        'cedula':     session.get('cedula', ''),
        'celular':    session.get('telefono', ''),
        'poblacion':  session.get('poblacion', ''),
        'plan_megas': session.get('plan_megas', '')
    }


# ---------------------------------------------------------------------------
# Filtros Jinja
# ---------------------------------------------------------------------------

def formatear_fecha(value, formato='%d/%m/%Y %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except Exception:
            return value
    return value.strftime(formato)

app.jinja_env.filters['formatear_fecha'] = formatear_fecha


# ---------------------------------------------------------------------------
# Rutas — cliente
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        session.clear()
        return render_template("users/user_login.html")

    intentos_cedula = session.get('intentos_cedula', 0)
    bloqueo_cedula_hasta = session.get('bloqueo_cedula_hasta')
    ahora = datetime.now()

    if bloqueo_cedula_hasta:
        try:
            bloqueo_dt = datetime.fromisoformat(bloqueo_cedula_hasta)
            if ahora < bloqueo_dt:
                seg = int((bloqueo_dt - ahora).total_seconds())
                return jsonify({'success': False, 'code': 'bloqueo_cedula',
                                'message': f'Has superado el número de intentos. Intenta de nuevo en {seg // 60} minutos y {seg % 60} segundos.'})
        except Exception:
            pass

    cedula = request.form.get("cedula")
    if not cedula:
        intentos_cedula += 1
        session['intentos_cedula'] = intentos_cedula
        restantes = 3 - intentos_cedula
        if intentos_cedula >= 3:
            session['bloqueo_cedula_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
            session['intentos_cedula'] = 0
            return jsonify({'success': False, 'code': 'bloqueo_cedula',
                            'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
        return jsonify({'success': False, 'code': 'sin_cedula',
                        'message': f'Por favor ingrese su cédula. Te quedan {restantes} intento(s) antes de ser bloqueado.'})

    cliente, error = wisphub.buscar_cliente(cedula)
    if error:
        intentos_cedula += 1
        session['intentos_cedula'] = intentos_cedula
        restantes = 3 - intentos_cedula
        if intentos_cedula >= 3:
            session['bloqueo_cedula_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
            session['intentos_cedula'] = 0
            return jsonify({'success': False, 'code': 'bloqueo_cedula',
                            'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
        return jsonify({'success': False, 'code': error['code'],
                        'message': f"{error['message']} Te quedan {restantes} intento(s) antes de ser bloqueado."})

    session.permanent = True
    session.pop('intentos_cedula', None)
    session.pop('bloqueo_cedula_hasta', None)

    whatsapp = ycloud.normalizar_numero(cliente.get('telefono', ''))
    if not whatsapp:
        return jsonify({'success': False, 'code': 'error_numero',
                        'message': 'El número de teléfono no es válido para WhatsApp Colombia.'})

    codigo = str(random.randint(100000, 999999))
    session['codigo_verificacion'] = codigo
    session['telefono'] = whatsapp
    session['nombre'] = cliente.get('nombre', '')
    session['cedula'] = cedula

    if not ycloud.enviar_otp(whatsapp, codigo):
        return jsonify({'success': False, 'code': 'error_envio',
                        'message': 'No se pudo enviar el código por WhatsApp.'})

    return jsonify({'success': True, 'ultimos4': whatsapp[-4:]})


@app.route('/verificar_codigo_ajax', methods=['POST'])
def verificar_codigo_ajax():
    codigo = request.form.get('codigo')
    intentos = session.get('intentos_codigo', 0)
    bloqueo_hasta = session.get('bloqueo_codigo_hasta')
    ahora = datetime.now()

    if bloqueo_hasta:
        try:
            bloqueo_dt = datetime.fromisoformat(bloqueo_hasta)
            if ahora < bloqueo_dt:
                seg = int((bloqueo_dt - ahora).total_seconds())
                return jsonify({'success': False,
                                'message': f'Has superado el número de intentos. Intenta de nuevo en {seg // 60} minutos y {seg % 60} segundos.'})
        except Exception:
            pass

    if codigo != session.get('codigo_verificacion'):
        intentos += 1
        session['intentos_codigo'] = intentos
        restantes = 3 - intentos
        if intentos >= 3:
            session['bloqueo_codigo_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
            session['intentos_codigo'] = 0
            return jsonify({'success': False,
                            'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
        return jsonify({'success': False,
                        'message': f'Código incorrecto. Te quedan {restantes} intento(s) antes de ser bloqueado.'})

    # Código correcto
    session.pop('intentos_codigo', None)
    session.pop('bloqueo_codigo_hasta', None)
    session.pop('_flashes', None)

    cedula = session.get('cedula')
    servicios_unificados = []
    try:
        import requests as req
        resp = req.get(
            os.getenv('BASE_URL_WISPHUB'),
            headers={'Authorization': f'Api-Key {os.getenv("API_KEY_WISPHUB")}',
                     'Content-Type': 'application/json'},
            params={'cedula': cedula},
            timeout=10
        )
        if resp.status_code == 200:
            for c in resp.json().get('results', []):
                if c.get('cedula') == cedula:
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            if s.get('ip'):
                                s_copy = dict(s)
                                s_copy['direccion'] = c.get('direccion', '')
                                servicios_unificados.append(s_copy)
                    elif c.get('ip'):
                        servicios_unificados.append({
                            'ip': c.get('ip'),
                            'nombre_servicio': c.get('nombre_servicio', ''),
                            'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                            'estado': c.get('estado', ''),
                            'direccion': c.get('direccion', '')
                        })
    except Exception:
        pass

    if len(servicios_unificados) > 1:
        lista = []
        for idx, s in enumerate(servicios_unificados, 1):
            texto = f"Servicio de Internet {idx}"
            if s.get('direccion'):
                texto += f" ({s['direccion']})"
            if s.get('ssid_router_wifi'):
                texto += f" - SSID: {s['ssid_router_wifi']}"
            lista.append({'ip': s.get('ip', ''), 'texto': texto})
        return jsonify({'success': True, 'multiple_servicios': True, 'servicios': lista})

    ip = servicios_unificados[0]['ip'] if servicios_unificados else session.get('ip')
    session['ip'] = ip
    session['cliente_encontrado'] = True
    flash('Sesión iniciada correctamente', 'success')
    return jsonify({'success': True, 'redirect': url_for('dashboard')})


@app.route("/seleccionar_servicio", methods=["POST"])
def seleccionar_servicio():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({'success': False})
    session['ip'] = ip
    session['cliente_encontrado'] = True
    return jsonify({'success': True, 'redirect': url_for('dashboard')})


@app.route("/dashboard")
@cliente_requerido
def dashboard():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    ip_seleccionada = session.get('ip')
    estado_servicio = None
    ssid_actual = ''
    password_actual = ''

    try:
        import requests as req
        resp = req.get(
            os.getenv('BASE_URL_WISPHUB'),
            headers={'Authorization': f'Api-Key {os.getenv("API_KEY_WISPHUB")}',
                     'Content-Type': 'application/json'},
            params={'cedula': cliente['cedula']},
            timeout=7
        )
        if resp.status_code == 200:
            servicio_encontrado = None
            resultados = resp.json().get('results', [])
            for c in resultados:
                if c.get('cedula') == cliente['cedula']:
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            if s.get('ip') == ip_seleccionada:
                                servicio_encontrado = s
                                break
                    elif c.get('ip') == ip_seleccionada:
                        servicio_encontrado = c
                    if servicio_encontrado:
                        break
            if not servicio_encontrado:
                for c in resultados:
                    if c.get('cedula') == cliente['cedula']:
                        servicios = c.get('servicios', [])
                        servicio_encontrado = servicios[0] if servicios else c
                        break
            if servicio_encontrado:
                estado_servicio = servicio_encontrado.get('estado', '').lower()
                ssid_actual     = servicio_encontrado.get('ssid_router_wifi', '')
                password_actual = servicio_encontrado.get('password_ssid_router_wifi', '')
    except Exception:
        pass

    cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
    return render_template(
        "users/user_dashboard.html",
        cliente=cliente,
        cambios_realizados=cambios_realizados,
        estado_servicio=estado_servicio,
        ssid_actual=ssid_actual,
        password_actual=password_actual
    )


@app.route("/cambiar_clave", methods=["GET", "POST"])
@cliente_requerido
def cambiar_clave():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()

    if request.method == "GET":
        return render_template("users/user_cambiar_clave.html", cliente=cliente)

    accion = request.args.get('accion')

    if accion == 'validar_dispositivo':
        ip = session.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
        try:
            dispositivo_online, device_id = genieacs.obtener_estado_online_device(ip)
            if not dispositivo_online:
                if not genieacs.verificar_dispositivo_online_alternativo(ip):
                    return jsonify({'success': False, 'message': 'El dispositivo está desconectado'})
                device_id = genieacs.obtener_device_id_por_ip(ip)
                if not device_id:
                    return jsonify({'success': False, 'message': 'No se encontró el dispositivo'})
            interfaces_activas = genieacs.detectar_interfaces_wifi_activas(device_id)
            if not interfaces_activas:
                return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas'})
            session['device_info'] = {
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'detected_at': datetime.now().isoformat()
            }
            return jsonify({'success': True, 'device_id': device_id,
                            'interfaces_activas': interfaces_activas,
                            'interfaces_count': len(interfaces_activas)})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error validando dispositivo: {e}'})

    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})

    limite_cambios = obtener_limite_cliente(session.get('ip'))
    if contar_cambios_usuario_mes(cliente['cedula']) >= limite_cambios:
        return jsonify({'success': False,
                        'message': f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."})

    data = request.get_json()
    nueva_clave    = data.get("nueva_clave")
    confirmar_clave = data.get("confirmar_clave")

    if not nueva_clave or not confirmar_clave:
        return jsonify({'success': False, 'message': 'Por favor ingrese y confirme la nueva clave'})
    if nueva_clave != confirmar_clave:
        return jsonify({'success': False, 'message': 'Las contraseñas no coinciden'})
    if len(nueva_clave) < 8:
        return jsonify({'success': False, 'message': 'La contraseña debe tener al menos 8 caracteres'})

    device_info      = session.get('device_info', {})
    device_id        = device_info.get('device_id')
    interfaces_activas = device_info.get('interfaces_activas', [])

    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró información del dispositivo. Recarga la página.'})

    if accion == 'whatsapp':
        whatsapp = ycloud.normalizar_numero(cliente['celular'])
        if not whatsapp:
            return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
        if not ycloud.enviar_confirmacion_cambio(whatsapp, nueva_clave):
            return jsonify({'success': False, 'message': 'No se pudo enviar el WhatsApp.'})
        return jsonify({'success': True})

    if accion == 'cambiar':
        ok, mensaje = genieacs.cambiar_contraseña_wifi_interfaces_ya_detectadas(device_id, interfaces_activas, nueva_clave)
        if ok:
            wisphub.actualizar_parametros(cliente['cedula'], nueva_clave=nueva_clave, ip_especifica=session.get('ip'))
            registrar_cambio_usuario(cliente['cedula'], 'Password', 'Nueva')
            return jsonify({'success': True,
                            'message': f'{mensaje}. La ONU se reiniciará automáticamente para aplicar los cambios.'})
        return jsonify({'success': False, 'message': f'Error al cambiar la clave: {mensaje}'})

    return jsonify({'success': False, 'message': 'Acción no válida.'})


@app.route("/cambiar_nombre_red", methods=["GET", "POST"])
@cliente_requerido
def cambiar_nombre_red():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()

    if request.method == "GET":
        return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)

    accion = request.args.get('accion')

    if accion == 'validar_dispositivo':
        ip = session.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
        try:
            dispositivo_online, device_id = genieacs.obtener_estado_online_device(ip)
            if not dispositivo_online:
                if not genieacs.verificar_dispositivo_online_alternativo(ip):
                    return jsonify({'success': False, 'message': 'El dispositivo está desconectado'})
                device_id = genieacs.obtener_device_id_por_ip(ip)
                if not device_id:
                    return jsonify({'success': False, 'message': 'No se encontró el dispositivo'})
            interfaces_activas, interfaces_info = genieacs.detectar_interfaces_y_frecuencias(device_id)
            if not interfaces_activas:
                return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas'})
            session['device_info_red'] = {
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'interfaces_info': interfaces_info,
                'detected_at': datetime.now().isoformat()
            }
            return jsonify({'success': True, 'device_id': device_id,
                            'interfaces_activas': interfaces_activas,
                            'interfaces_info': interfaces_info,
                            'interfaces_count': len(interfaces_activas)})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error validando dispositivo: {e}'})

    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})

    limite_cambios = obtener_limite_cliente(session.get('ip'))
    if contar_cambios_usuario_mes(cliente['cedula']) >= limite_cambios:
        return jsonify({'success': False,
                        'message': f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."})

    data = request.get_json()
    nuevo_nombre = data.get("nuevo_nombre")
    if not nuevo_nombre:
        return jsonify({'success': False, 'message': 'Por favor ingrese un nuevo nombre'})

    device_info    = session.get('device_info_red', {})
    device_id      = device_info.get('device_id')
    interfaces_info = device_info.get('interfaces_info', {})

    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró información del dispositivo. Recarga la página.'})

    if accion == 'whatsapp':
        whatsapp = ycloud.normalizar_numero(cliente['celular'])
        if not whatsapp:
            return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
        if not ycloud.enviar_confirmacion_cambio(whatsapp, nuevo_nombre):
            return jsonify({'success': False, 'message': 'No se pudo enviar el WhatsApp.'})
        return jsonify({'success': True})

    if accion == 'cambiar':
        ok, mensaje = genieacs.cambiar_nombre_red_wifi_inteligente(device_id, interfaces_info, nuevo_nombre)
        if ok:
            wisphub.actualizar_parametros(cliente['cedula'], nuevo_ssid=nuevo_nombre, ip_especifica=session.get('ip'))
            registrar_cambio_usuario(cliente['cedula'], 'SSID', nuevo_nombre)
            return jsonify({'success': True,
                            'message': f'{mensaje}. La ONU se reiniciará automáticamente para aplicar los cambios.'})
        return jsonify({'success': False, 'message': f'Error al cambiar el nombre de la red: {mensaje}'})

    return jsonify({'success': False, 'message': 'Acción no válida.'})


@app.route('/reenviar_codigo', methods=['POST'])
def reenviar_codigo():
    telefono = session.get('telefono')
    codigo   = session.get('codigo_verificacion')
    if not telefono or not codigo:
        return jsonify({'success': False, 'message': 'No hay sesión activa.'})
    if not ycloud.enviar_otp(telefono, codigo):
        return jsonify({'success': False, 'message': 'No se pudo enviar el código.'})
    return jsonify({'success': True})


@app.route("/cerrar_sesion", methods=["POST"])
def cerrar_sesion():
    session.clear()
    flash("Sesión cerrada exitosamente", "success")
    return redirect(url_for("index"))


@app.route('/verificar_sesion', methods=['POST'])
def verificar_sesion():
    if not session.get("cliente_encontrado"):
        return jsonify({'error': 'Sesión expirada'}), 401
    return jsonify({'ok': True})


@app.route('/renovar_sesion', methods=['POST'])
def renovar_sesion():
    session.modified = True
    return '', 204


# ===========================================================================
#  █████╗ ██████╗ ███╗   ███╗██╗███╗   ██╗
# ██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║
# ███████║██║  ██║██╔████╔██║██║██╔██╗ ██║
# ██╔══██║██║  ██║██║╚██╔╝██║██║██║╚██╗██║
# ██║  ██║██████╔╝██║ ╚═╝ ██║██║██║ ╚████║
# ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝
# ===========================================================================


# ---------------------------------------------------------------------------
# Autenticación y decoradores admin
# ---------------------------------------------------------------------------

def admin_requerido(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Por favor inicie sesión como administrador', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function


def verificar_admin(username, password):
    try:
        conn = get_db_connection()
        cur = conn.execute(
            "SELECT * FROM admin_users WHERE username = ? OR email = ?",
            (username, username)
        )
        admin = cur.fetchone()
        conn.close()
        if admin and check_password_hash(admin['password'], password):
            return admin
        return None
    except Exception as e:
        print(f"Error al verificar admin: {e}")
        return None


# ---------------------------------------------------------------------------
# Registro de cambios (admin)
# ---------------------------------------------------------------------------

def registrar_cambio(admin_id, cedula, tipo_cambio, valor_nuevo):
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO change_history (admin_id, cedula, tipo_cambio, valor_nuevo, fecha) VALUES (?, ?, ?, ?, ?)",
            (admin_id, cedula, tipo_cambio, valor_nuevo, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al registrar cambio: {e}")
        return False


# ---------------------------------------------------------------------------
# Configuración y estadísticas (admin)
# ---------------------------------------------------------------------------

def obtener_estadisticas_uso():
    try:
        conn = get_db_connection()
        cambios_por_tipo = [dict(r) for r in conn.execute(
            "SELECT tipo_cambio, COUNT(*) as count FROM change_history GROUP BY tipo_cambio"
        ).fetchall()]
        cambios_por_mes = [dict(r) for r in conn.execute(
            "SELECT substr(fecha, 1, 7) as mes, COUNT(*) as count FROM change_history GROUP BY mes"
        ).fetchall()]
        limites_comunes = [dict(r) for r in conn.execute(
            "SELECT limite_personalizado, COUNT(*) as count FROM user_limits GROUP BY limite_personalizado"
        ).fetchall()]
        conn.close()
        return {"cambios_por_tipo": cambios_por_tipo,
                "cambios_por_mes": cambios_por_mes,
                "limites_comunes": limites_comunes}
    except Exception as e:
        print(f"Error al obtener estadísticas: {e}")
        return {}


def obtener_configuracion_global():
    try:
        conn = get_db_connection()
        data = [dict(r) for r in conn.execute("SELECT * FROM admin_settings").fetchall()]
        conn.close()
        return data
    except Exception as e:
        print(f"Error al obtener configuración global: {e}")
        return []


def actualizar_limite_cliente(ip, nombre, nuevo_limite, cedula=''):
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, cedula, nombre, limite_personalizado)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                limite_personalizado=excluded.limite_personalizado,
                nombre=excluded.nombre,
                cedula=excluded.cedula;
        """, (ip, cedula, nombre, nuevo_limite))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al actualizar límite: {e}")
        return False


# ---------------------------------------------------------------------------
# Rutas admin — autenticación
# ---------------------------------------------------------------------------

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
        data = request.get_json()
        result = verificar_admin(data.get('username'), data.get('password'))
        if result:
            session['admin_autenticado'] = True
            session['admin_id'] = result['id']
            session['admin_username'] = result['email']
            return jsonify({'success': True, 'redirect': url_for('admin.dashboard_admin')})
        return jsonify({'success': False, 'message': 'Credenciales inválidas'})
    return render_template('admin/admin_login.html')


@admin_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('admin_autenticado', None)
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    session.pop('cliente_encontrado', None)
    return jsonify({'success': True, 'redirect': url_for('admin.login')})


# ---------------------------------------------------------------------------
# Rutas admin — dashboard
# ---------------------------------------------------------------------------

@admin_bp.route('/dashboard', methods=['GET', 'POST'])
@admin_requerido
def dashboard_admin():
    return render_template(
        'admin/admin_dashboard.html',
        empresa=os.getenv("EMPRESA", "SkyPass"),
    )


# ---------------------------------------------------------------------------
# Rutas admin — historial
# ---------------------------------------------------------------------------

@admin_bp.route('/historial')
@admin_requerido
def historial():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    filtro_cedula = request.args.get('cedula', '').strip()
    filtro_tipo   = request.args.get('tipo_cambio', '').strip()

    where_clauses = []
    params = []
    if filtro_cedula:
        where_clauses.append("cedula = ?")
        params.append(filtro_cedula)
    if filtro_tipo:
        where_clauses.append("tipo_cambio = ?")
        params.append(filtro_tipo)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    query = f"SELECT * FROM change_history{where_sql} ORDER BY fecha DESC LIMIT ? OFFSET ?"
    params_pag = params + [per_page, (page - 1) * per_page]

    count_query = f"SELECT COUNT(*) as total FROM change_history{where_sql}"

    conn = get_db_connection()
    historial_data = [dict(r) for r in conn.execute(query, params_pag).fetchall()]
    total_count    = conn.execute(count_query, params).fetchone()[0]
    tipos_cambio   = [r['tipo_cambio'] for r in
                      conn.execute("SELECT DISTINCT tipo_cambio FROM change_history ORDER BY tipo_cambio").fetchall()]
    conn.close()

    return render_template(
        'admin/admin_historial.html',
        historial=historial_data,
        current_page=page,
        total_pages=(total_count + per_page - 1) // per_page,
        filtro_cedula=filtro_cedula,
        filtro_tipo=filtro_tipo,
        tipos_cambio=tipos_cambio
    )


@admin_bp.route('/eliminar_cambio_historial', methods=['POST'])
@admin_requerido
def eliminar_cambio_historial():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    id_cambio = request.get_json().get('id')
    if not id_cambio:
        return jsonify({'success': False, 'message': 'ID no proporcionado.'})
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM change_history WHERE id = ?", (id_cambio,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al eliminar el registro: {str(e)}'})


# ---------------------------------------------------------------------------
# Rutas admin — estadísticas y configuración
# ---------------------------------------------------------------------------

@admin_bp.route('/estadisticas')
@admin_requerido
def estadisticas():
    return render_template('admin/admin_estadisticas.html', estadisticas=obtener_estadisticas_uso())


@admin_bp.route('/configuracion', methods=['GET'])
@admin_requerido
def configuracion():
    try:
        conn = get_db_connection()
        data = conn.execute("SELECT valor FROM admin_settings WHERE clave = 'max_cambios_mes'").fetchone()
        conn.close()
        cambios_por_mes = int(data['valor']) if data else 2
    except Exception:
        cambios_por_mes = 2
    return render_template('admin/admin_configuracion.html', cambios_por_mes=cambios_por_mes)


@admin_bp.route('/cambiar_config', methods=['POST'])
@admin_requerido
def cambiar_config():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    try:
        cambios_por_mes = int(request.get_json().get('cambios_por_mes'))
        if cambios_por_mes < 1:
            return jsonify({'success': False, 'message': 'El valor debe ser mayor a 0'})
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO admin_settings (clave, valor) VALUES ('max_cambios_mes', ?)
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
    nueva_password = data.get('nueva_password', '')
    if len(nueva_password) < 8:
        return jsonify({'success': False, 'message': 'La nueva contraseña debe tener al menos 8 caracteres'})
    if nueva_password != data.get('confirmar_password'):
        return jsonify({'success': False, 'message': 'Las contraseñas no coinciden'})
    try:
        conn = get_db_connection()
        admin_data = conn.execute("SELECT * FROM admin_users WHERE id = ?", (session['admin_id'],)).fetchone()
        if not admin_data or not check_password_hash(admin_data['password'], data.get('password_actual')):
            conn.close()
            return jsonify({'success': False, 'message': 'Contraseña actual incorrecta'})
        conn.execute("UPDATE admin_users SET password = ? WHERE id = ?",
                     (generate_password_hash(nueva_password), session['admin_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Contraseña actualizada exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al cambiar la contraseña: {str(e)}'})


# ---------------------------------------------------------------------------
# Rutas admin — límites personalizados
# ---------------------------------------------------------------------------

@admin_bp.route('/limites', methods=['GET', 'POST'])
@admin_requerido
def limites():
    if request.method == 'POST':
        ip = request.form.get('ip')
        nuevo_limite = int(request.form.get('nuevo_limite'))
        cliente = wisphub.buscar_por_ip(ip)
        if not cliente:
            flash('La IP ingresada no corresponde a ningún cliente.', 'error')
            return redirect(url_for('admin.limites'))
        conn = get_db_connection()
        existe = conn.execute("SELECT * FROM user_limits WHERE ip = ?", (ip,)).fetchone()
        conn.close()
        if actualizar_limite_cliente(ip, cliente.get('nombre', ''), nuevo_limite, cliente.get('cedula', '')):
            flash('Límite actualizado correctamente.' if existe else 'Límite creado correctamente.', 'personalizado')
        else:
            flash('Error al actualizar el límite personalizado.', 'error')
        return redirect(url_for('admin.limites'))

    try:
        conn = get_db_connection()
        limites_data    = [dict(r) for r in conn.execute("SELECT * FROM user_limits ORDER BY ip").fetchall()]
        data            = conn.execute("SELECT valor FROM admin_settings WHERE clave = 'max_cambios_mes'").fetchone()
        conn.close()
        cambios_por_mes = max(1, int(data['valor'])) if data and data['valor'] else 1
        return render_template('admin/admin_limites.html', limites=limites_data, cambios_por_mes=cambios_por_mes)
    except Exception as e:
        print(f'Error en /limites: {e}')
        flash('Error al cargar los límites', 'error')
        return render_template('admin/admin_limites.html', limites=[], cambios_por_mes=1)


@admin_bp.route('/buscar_cliente_limite', methods=['POST'])
@admin_requerido
def buscar_cliente_limite():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    busqueda = request.get_json().get('busqueda', '').strip()
    if not busqueda:
        return jsonify({'success': False, 'message': 'Debe ingresar una IP o cédula'})
    try:
        partes = busqueda.split('.')
        if len(partes) == 4 and all(p.isdigit() for p in partes):
            cliente = wisphub.buscar_por_ip(busqueda)
        else:
            resultados = wisphub.buscar_por_cedula_parcial(busqueda)
            cedula_exacta = next((c for c in resultados if c.get('cedula') == busqueda), None)
            item = cedula_exacta or (resultados[0] if resultados else None)
            cliente, _ = wisphub.buscar_cliente(item['cedula'], timeout=7) if item else (None, None)

        if not cliente:
            return jsonify({'success': False, 'message': 'Cliente no encontrado'})

        ip_cliente = cliente.get('ip') or cliente.get('ip_address', '')
        if not ip_cliente:
            return jsonify({'success': False, 'message': 'El cliente no tiene IP asignada'})

        return jsonify({'success': True, 'cliente': {
            'ip': ip_cliente,
            'cedula': cliente.get('cedula', ''),
            'nombre': cliente.get('nombre', '')
        }})
    except Exception as e:
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
        nombre = ''
        cliente = wisphub.buscar_por_ip(ip)
        if cliente:
            nombre = cliente.get('nombre', '')
            cedula = cliente.get('cedula', cedula)
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO user_limits (ip, cedula, nombre, limite_personalizado)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                limite_personalizado=excluded.limite_personalizado,
                nombre=excluded.nombre,
                cedula=excluded.cedula;
        """, (ip, cedula, nombre, int(nuevo_limite)))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Límite actualizado correctamente.',
                        'nuevo_limite': int(nuevo_limite)})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al actualizar el límite: {str(e)}'})


@admin_bp.route('/eliminar_limite', methods=['POST'])
@admin_requerido
def eliminar_limite():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    ip = request.get_json().get('ip')
    if not ip:
        return jsonify({'success': False, 'message': 'IP no proporcionada'})
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM user_limits WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Límite personalizado eliminado.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error al eliminar el límite: {str(e)}'})


# ---------------------------------------------------------------------------
# Rutas admin — cambio de WiFi por admin
# ---------------------------------------------------------------------------

@admin_bp.route('/cambiar_wifi_cliente', methods=['GET', 'POST'])
@admin_requerido
def cambiar_wifi_cliente():
    if request.method == 'GET':
        cedula = request.args.get('cedula')
        ip_seleccionada = request.args.get('ip')
        cliente = None
        cliente_no_encontrado = False
        estado_servicio = 'desconocido'
        servicios = []

        if cedula:
            import requests as req
            try:
                resp = req.get(
                    os.getenv('BASE_URL_WISPHUB'),
                    headers={'Authorization': f'Api-Key {os.getenv("API_KEY_WISPHUB")}',
                             'Content-Type': 'application/json'},
                    params={'cedula': cedula},
                    timeout=10
                )
                if resp.status_code == 200:
                    cliente_principal = None
                    for c in resp.json().get('results', []):
                        if c.get('cedula') == cedula:
                            if not cliente_principal:
                                cliente_principal = c
                            c_servicios = c.get('servicios', [])
                            if c_servicios:
                                for s in c_servicios:
                                    if s.get('ip'):
                                        s_copy = dict(s)
                                        s_copy['direccion'] = c.get('direccion', '')
                                        s_copy['nombre_cliente'] = c.get('nombre', '')
                                        servicios.append(s_copy)
                            elif c.get('ip'):
                                servicios.append({
                                    'ip': c.get('ip'),
                                    'nombre_servicio': c.get('nombre_servicio', ''),
                                    'ssid_router_wifi': c.get('ssid_router_wifi', ''),
                                    'estado': c.get('estado', ''),
                                    'direccion': c.get('direccion', ''),
                                    'nombre_cliente': c.get('nombre', '')
                                })
                    cliente = cliente_principal
                    if not cliente:
                        cliente_no_encontrado = True
                else:
                    cliente_no_encontrado = True
            except Exception as e:
                print(f'[ERROR] Error obteniendo clientes: {e}')
                cliente_no_encontrado = True

        if cliente and servicios:
            if ip_seleccionada:
                for s in servicios:
                    if s.get('ip') == ip_seleccionada:
                        estado_servicio = s.get('estado', '').lower()
                        break
                else:
                    estado_servicio = 'desconocido'
            else:
                estado_servicio = servicios[0].get('estado', '').lower()

            cliente['servicios'] = servicios

            if len(servicios) == 1 or ip_seleccionada:
                ip_a_usar = ip_seleccionada or servicios[0].get('ip')
                if ip_a_usar:
                    device_id = genieacs.obtener_device_id_por_ip(ip_a_usar)
                    if device_id:
                        interfaces_activas = genieacs.detectar_interfaces_wifi_activas(device_id)
                        _, interfaces_info = genieacs.detectar_interfaces_y_frecuencias(device_id)
                        session[f'admin_device_info_{cedula}_{ip_a_usar}'] = {
                            'device_id': device_id,
                            'interfaces_activas': interfaces_activas,
                            'interfaces_info': interfaces_info,
                            'timestamp': time.time()
                        }

        return render_template(
            'admin/admin_cambiar_wifi_cliente.html',
            cliente=cliente,
            cliente_no_encontrado=cliente_no_encontrado,
            estado_servicio=estado_servicio,
            ip_seleccionada=ip_seleccionada
        )

    # POST — solo AJAX
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})

    data = request.get_json()
    cedula       = data.get('cedula')
    accion       = data.get('accion')
    ip_seleccionada = data.get('ip')

    cliente, _ = wisphub.buscar_cliente(cedula, timeout=3)
    if not cliente:
        return jsonify({'success': False, 'message': 'Cliente no encontrado'})

    servicios = cliente.get('servicios', [])
    if ip_seleccionada:
        ip_a_usar = ip_seleccionada
    elif servicios:
        ip_a_usar = servicios[0].get('ip')
    else:
        ip_a_usar = cliente.get('ip')

    if not ip_a_usar:
        return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})

    estado_servicio = 'desconocido'
    for s in servicios:
        if s.get('ip') == ip_a_usar:
            estado_servicio = s.get('estado', '').lower()
            break
    if estado_servicio == 'suspendido':
        return jsonify({'success': False,
                        'message': 'El servicio está suspendido. No se pueden realizar cambios hasta que se reactive.'})

    device_id      = None
    interfaces_activas = []
    interfaces_info    = {}

    modo_prueba = request.args.get('modo_prueba', 'false').lower() == 'true'
    if modo_prueba:
        device_id          = genieacs.obtener_device_id_por_ip(ip_a_usar)
        interfaces_activas = [1, 2]
        interfaces_info    = {1: {'frecuencia': '2.4GHz'}, 2: {'frecuencia': '5GHz'}}
    else:
        session_key = f'admin_device_info_{cedula}_{ip_a_usar}'
        device_info = session.get(session_key)

        if device_info and (time.time() - device_info.get('timestamp', 0)) > 600:
            session.pop(session_key, None)
            device_info = None

        if device_info:
            device_id          = device_info['device_id']
            interfaces_activas = device_info['interfaces_activas']
            interfaces_info    = device_info['interfaces_info']
        else:
            try:
                def _timeout_handler(signum, frame):
                    raise TimeoutError("Timeout en validación")

                signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(10)
                dispositivo_online, device_id = genieacs.obtener_estado_online_device(ip_a_usar)
                signal.alarm(0)

                if not dispositivo_online:
                    signal.alarm(5)
                    ping_ok = genieacs.verificar_dispositivo_online_alternativo(ip_a_usar)
                    signal.alarm(0)
                    if not ping_ok:
                        return jsonify({'success': False,
                                        'message': 'El dispositivo está desconectado. Debe estar online para realizar cambios.'})
            except TimeoutError:
                signal.alarm(0)
                return jsonify({'success': False,
                                'message': 'Timeout: El dispositivo no responde. Verifique que esté online.'})
            except Exception as e:
                signal.alarm(0)
                return jsonify({'success': False, 'message': f'Error validando dispositivo: {str(e)}'})

    if not device_id:
        device_id = genieacs.obtener_device_id_por_ip(ip_a_usar)
    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró el dispositivo del cliente'})

    if not interfaces_activas:
        interfaces_activas = genieacs.detectar_interfaces_wifi_activas(device_id)
    if not interfaces_info:
        _, interfaces_info = genieacs.detectar_interfaces_y_frecuencias(device_id)

    # Acción: cambiar SSID
    if accion == 'ssid':
        nuevo_ssid = data.get('nuevo_ssid')
        if not nuevo_ssid:
            return jsonify({'success': False, 'message': 'Debe ingresar el nuevo nombre de red'})
        if not interfaces_info:
            return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas en la ONU'})

        necesita_sufijos = len(interfaces_info) == 2
        cambiadas = []
        for interfaz, info in interfaces_info.items():
            frecuencia = info.get('frecuencia', 'Desconocida')
            if necesita_sufijos:
                nombre_final = (f"{nuevo_ssid}-2.4GHz" if frecuencia == "2.4GHz"
                                else f"{nuevo_ssid}-5GHz" if frecuencia == "5GHz"
                                else nuevo_ssid)
            else:
                nombre_final = nuevo_ssid
            parametro = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.SSID"
            if genieacs.cambiar_parametro_genieacs_sin_reinicio(device_id, parametro, nombre_final):
                cambiadas.append({'interfaz': interfaz, 'frecuencia': frecuencia, 'nombre_final': nombre_final})

        if not cambiadas:
            return jsonify({'success': False, 'message': 'Error al cambiar el nombre de la red'})

        genieacs.reiniciar_onu_genieacs(device_id)
        wisphub.actualizar_parametros(cedula, nuevo_ssid=nuevo_ssid, ip_especifica=ip_a_usar)
        registrar_cambio(session['admin_id'], cedula, 'SSID', nuevo_ssid)

        if len(cambiadas) == 2:
            ordenadas = sorted(cambiadas, key=lambda x: x['frecuencia'])
            mensaje = "✅ Nombre de red WiFi cambiado exitosamente:\n" + \
                      "".join(f"• {c['frecuencia']}: {c['nombre_final']}\n" for c in ordenadas)
            mensaje = mensaje.rstrip('\n')
        else:
            mensaje = f"✅ Nombre de red WiFi cambiado exitosamente:\n• {cambiadas[0]['frecuencia']}: {cambiadas[0]['nombre_final']}"

        return jsonify({'success': True,
                        'message': mensaje + "\n\nLa ONU se reiniciará automáticamente para aplicar los cambios. Por favor espere unos minutos."})

    # Acción: cambiar contraseña
    if accion == 'password':
        nueva_password = data.get('nueva_password')
        if not nueva_password:
            return jsonify({'success': False, 'message': 'Debe ingresar la nueva contraseña'})
        if not interfaces_activas:
            return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas en la ONU'})

        cambiadas = []
        for interfaz in interfaces_activas:
            parametro = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.KeyPassphrase"
            if genieacs.cambiar_parametro_genieacs_sin_reinicio(device_id, parametro, nueva_password):
                cambiadas.append(interfaz)

        if not cambiadas:
            return jsonify({'success': False,
                            'message': f'Error al cambiar contraseña en todas las interfaces: {interfaces_activas}'})

        genieacs.reiniciar_onu_genieacs(device_id)
        wisphub.actualizar_parametros(cedula, nueva_clave=nueva_password, ip_especifica=ip_a_usar)
        registrar_cambio(session['admin_id'], cedula, 'Password', 'Nueva')
        return jsonify({'success': True,
                        'message': f'Contraseña WiFi aplicada en {len(cambiadas)} interfaz(es): {cambiadas}. La ONU se reiniciará automáticamente. Por favor espere unos minutos.'})

    return jsonify({'success': False, 'message': 'Acción no válida.'})


# ---------------------------------------------------------------------------
# Rutas admin — búsqueda de clientes (autocomplete)
# ---------------------------------------------------------------------------

@admin_bp.route('/api/buscar_clientes')
def api_buscar_clientes():
    q = request.args.get('q', '').strip()
    tipo_busqueda = request.args.get('tipo', 'nombre').strip()

    if not q:
        return jsonify({'success': True, 'clientes': []})
    try:
        if tipo_busqueda == 'ip':
            cliente = wisphub.buscar_por_ip(q)
            clientes = [{
                'ip': cliente.get('ip') or cliente.get('ip_address'),
                'nombre': cliente.get('nombre', ''),
                'cedula': cliente.get('cedula', ''),
                'telefono': cliente.get('telefono', '') or cliente.get('celular', '')
            }] if cliente else []
        elif tipo_busqueda == 'cedula':
            clientes = wisphub.buscar_por_cedula_parcial(q)
        else:
            clientes = wisphub.buscar_por_nombre_parcial(q)
        return jsonify({'success': True, 'clientes': clientes})
    except Exception as e:
        print(f'Error en api_buscar_clientes: {e}')
        return jsonify({'success': False, 'clientes': []})


@admin_bp.route('/api/device_id_por_ip')
@admin_requerido
def api_device_id_por_ip():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'found': False})
    try:
        device_id = genieacs.obtener_device_id_por_ip(ip)
        if device_id:
            return jsonify({'found': True, 'device_id': device_id})
        return jsonify({'found': False})
    except Exception:
        return jsonify({'found': False})


@admin_bp.route('/buscar-cliente')
@admin_requerido
def buscar_cliente():
    return render_template('admin/buscar_cliente.html')


# ---------------------------------------------------------------------------
# Rutas admin — dispositivos conectados (GenieACS)
# ---------------------------------------------------------------------------

@admin_bp.route('/dispositivos_conectados')
@admin_requerido
def admin_dispositivos_conectados():
    return render_template('admin/dispositivos_conectados.html')


@admin_bp.route('/api/dispositivos_conectados')
@admin_requerido
def api_dispositivos_conectados():
    import re
    try:
        svc = genieacs._get_svc()
        projection = ",".join([
            "_id", "_lastInform", "_deviceId",
            "InternetGatewayDevice.DeviceInfo.ModelName",
            "InternetGatewayDevice.DeviceInfo.Manufacturer",
            "InternetGatewayDevice.DeviceInfo.SerialNumber",
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
            "VirtualParameters.IPTR069",
            "VirtualParameters.PonMac",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.MACAddress",
            "InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1.MACAddress",
            "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
            "InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID",
            "VirtualParameters.activedevices",
            "VirtualParameters.RXPower",
            "VirtualParameters.gettemp",
        ])
        devices = svc.get_all_devices(projection=projection)
        lista = []
        for device in devices:
            ip_actual = (
                svc._get_param(device, "VirtualParameters.IPTR069") or
                svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress") or
                svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress") or ''
            )
            if not ip_actual:
                url_conn = svc._get_param(device, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL") or ''
                m = re.search(r'http://([\d\.]+):', url_conn)
                if m:
                    ip_actual = m.group(1)
            dev_id  = device.get('_id', '')
            meta    = device.get('_deviceId') or {}
            if not isinstance(meta, dict):
                meta = {}
            serial  = meta.get('_SerialNumber') or (dev_id.split('-', 2)[2] if dev_id.count('-') >= 2 else dev_id)
            rx      = svc.get_rx_power(device)
            temp    = svc.get_temperature(device)
            ut      = svc.get_uptime_seconds(device)
            lista.append({
                'device_id':      dev_id,
                'serial':         serial or dev_id,
                'ip':             ip_actual,
                'mac':            svc.get_mac(device) or '',
                'ssid':           svc.get_ssid_primary(device) or '',
                'ultimo_informe': device.get('_lastInform'),
                'online':         svc.is_online(device),
                'tiempo':         svc.tiempo_desde_ultimo_inform(device),
                'modelo':         svc._get_param(device, "InternetGatewayDevice.DeviceInfo.ModelName") or meta.get('_ProductClass') or '',
                'fabricante':     svc._get_param(device, "InternetGatewayDevice.DeviceInfo.Manufacturer") or '',
                'uptime':         svc.format_uptime(ut),
                'rx':             rx,
                'rx_calidad':     svc.rx_signal_quality(rx),
                'temp':           temp,
                'hosts':          svc._get_param(device, "VirtualParameters.activedevices") or '0',
                'detras_nat':     svc.is_behind_nat(device),
            })
        return jsonify({'success': True, 'dispositivos': lista})
    except Exception as e:
        return jsonify({'success': False, 'dispositivos': [], 'error': str(e)})


@admin_bp.route('/api/dashboard_stats')
@admin_requerido
def api_dashboard_stats():
    import re
    result = {}
    try:
        conn = get_db_connection()
        ahora = datetime.now()
        inicio_mes = ahora.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        row = conn.execute(
            "SELECT COUNT(*) as total FROM change_history WHERE fecha >= ?",
            (inicio_mes.isoformat(),)
        ).fetchone()
        result['cambios_mes'] = row['total'] if row else 0
        recent_ch = conn.execute(
            "SELECT cedula, tipo_cambio, fecha FROM change_history ORDER BY fecha DESC LIMIT 8"
        ).fetchall()
        result['cambios_recientes'] = [dict(r) for r in recent_ch]
        conn.close()
    except Exception:
        result['cambios_mes'] = 0
        result['cambios_recientes'] = []
    try:
        svc = genieacs._get_svc()
        proj = ",".join([
            "_id", "_lastInform", "_deviceId",
            "InternetGatewayDevice.DeviceInfo.ModelName",
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
            "VirtualParameters.RXPower",
            "VirtualParameters.gettemp",
        ])
        devices = svc.get_all_devices(projection=proj)
        online_c = offline_c = 0
        uptimes = []
        rx_ok = rx_warn = rx_crit = 0
        recent_devs = []
        for d in devices:
            is_on = svc.is_online(d)
            if is_on:
                online_c += 1
            else:
                offline_c += 1
            ut = svc.get_uptime_seconds(d)
            if ut:
                uptimes.append(ut)
            rx = svc.get_rx_power(d)
            if rx is not None:
                q = svc.rx_signal_quality(rx)
                if q == "ok":      rx_ok   += 1
                elif q == "warning": rx_warn += 1
                else:              rx_crit += 1
            ip = (
                svc._get_param(d, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress") or
                svc._get_param(d, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress") or ''
            )
            if not ip:
                url_c = svc._get_param(d, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL") or ''
                m = re.search(r'http://([\d\.]+):', url_c)
                if m:
                    ip = m.group(1)
            recent_devs.append({
                'device_id': d.get('_id'),
                'ip': ip,
                'modelo': svc._get_param(d, "InternetGatewayDevice.DeviceInfo.ModelName") or '',
                'online': is_on,
                'tiempo': svc.tiempo_desde_ultimo_inform(d),
                'rx': rx,
                'ultimo_informe': d.get('_lastInform') or '',
            })
        recent_devs.sort(key=lambda x: x['ultimo_informe'], reverse=True)
        result.update({
            'devices_online':    online_c,
            'devices_offline':   offline_c,
            'uptime_promedio_h': round(sum(uptimes) / len(uptimes) / 3600, 1) if uptimes else None,
            'rx_ok':   rx_ok,
            'rx_warn': rx_warn,
            'rx_crit': rx_crit,
            'rx_total': rx_ok + rx_warn + rx_crit,
            'recent_devices': recent_devs[:6],
            'success': True,
        })
    except RuntimeError as e:
        result.update({
            'devices_online': 0, 'devices_offline': 0,
            'uptime_promedio_h': None,
            'rx_ok': 0, 'rx_warn': 0, 'rx_crit': 0, 'rx_total': 0,
            'recent_devices': [],
            'success': False, 'error': str(e),
        })
    return jsonify(result)


@admin_bp.route('/dispositivo/<path:device_id>')
@admin_requerido
def admin_device_detail(device_id):
    return render_template('admin/admin_device_detail.html', device_id=device_id)


@admin_bp.route('/api/dispositivo/<path:device_id>')
@admin_requerido
def api_device_detail(device_id):
    try:
        svc    = genieacs._get_svc()
        device = svc.get_device_by_id(device_id)
        if not device:
            return jsonify({'success': False, 'error': 'Dispositivo no encontrado'})
        dev_id = device.get('_id', '')
        meta   = device.get('_deviceId') or {}
        if not isinstance(meta, dict):
            meta = {}
        serial        = meta.get('_SerialNumber') or (dev_id.split('-', 2)[2] if dev_id.count('-') >= 2 else dev_id)
        oui           = meta.get('_OUI')           or dev_id.split('-')[0]
        product_class = meta.get('_ProductClass')  or (dev_id.split('-', 2)[1] if dev_id.count('-') >= 2 else '')
        ip_wan = (
            svc._get_param(device, "VirtualParameters.IPTR069") or
            svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress") or
            svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress") or ''
        )
        wan_status = (
            svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ConnectionStatus") or
            svc._get_param(device, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ConnectionStatus") or ''
        )
        rx    = svc.get_rx_power(device)
        temp  = svc.get_temperature(device)
        ut    = svc.get_uptime_seconds(device)
        ifaces = svc.get_wifi_interfaces(device)
        ifaces_out = []
        for iface in ifaces:
            beacon = iface.get("security", "") or ""
            sec_map = {"11i": "WPA2", "WPAand11i": "WPA/WPA2", "WPA": "WPA", "None": "Abierta"}
            security = sec_map.get(beacon, beacon) or "WPA/WPA2"
            ifaces_out.append({
                "index":     iface["index"],
                "ssid":      iface["ssid"],
                "channel":   iface["channel"],
                "frequency": iface["frequency"],
                "security":  security,
            })
        return jsonify({
            'success': True,
            'device': {
                'id':             dev_id,
                'serial':         serial,
                'oui':            oui,
                'product_class':  product_class,
                'fabricante':     svc._get_param(device, "InternetGatewayDevice.DeviceInfo.Manufacturer") or meta.get('_Manufacturer', ''),
                'modelo':         svc._get_param(device, "InternetGatewayDevice.DeviceInfo.ModelName") or product_class,
                'firmware':       svc._get_param(device, "InternetGatewayDevice.DeviceInfo.SoftwareVersion") or '',
                'hardware':       svc._get_param(device, "InternetGatewayDevice.DeviceInfo.HardwareVersion") or '',
                'mac_wan':        svc.get_mac(device) or '',
                'ip_wan':         ip_wan,
                'wan_status':     wan_status,
                'conn_request_url': svc._get_param(device, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL") or '',
                'uptime':         svc.format_uptime(ut),
                'ultimo_informe': device.get('_lastInform'),
                'online':         svc.is_online(device),
                'tiempo':         svc.tiempo_desde_ultimo_inform(device),
                'detras_nat':     svc.is_behind_nat(device),
                'rx_power':       rx,
                'rx_calidad':     svc.rx_signal_quality(rx),
                'temperatura':    temp,
                'hosts_count':    svc._get_param(device, "VirtualParameters.activedevices") or '0',
                'wifi_interfaces': ifaces_out,
                'lan_hosts':      svc.get_merged_hosts(device),
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/eliminar_device', methods=['POST'])
@admin_requerido
def eliminar_device():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    data = request.get_json()
    device_id = data.get('device_id')
    ip = data.get('ip')
    if not device_id and not ip:
        return jsonify({'success': False, 'message': 'Se requiere device_id o IP del dispositivo.'})
    if not device_id and ip:
        device_id = genieacs.obtener_device_id_por_ip(ip)
        if not device_id:
            return jsonify({'success': False, 'message': f'No se encontró dispositivo con IP: {ip}'})
    if genieacs.eliminar_device_genieacs(device_id):
        return jsonify({'success': True, 'message': 'Dispositivo eliminado exitosamente.'})
    return jsonify({'success': False, 'message': 'Error al eliminar el dispositivo.'})


@admin_bp.route('/summon_device', methods=['POST'])
@admin_requerido
def summon_device():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    try:
        device_id = request.json.get('device_id')
        if not device_id:
            return jsonify({'success': False, 'message': 'Falta device_id'})
        
        svc = genieacs._get_svc()
        # Una tarea refreshObject con connection_request=True fuerza la reconexión (summon)
        r = svc._post_task(device_id, {"name": "refreshObject", "objectName": ""}, connection_request=True)
        return jsonify({'success': r.get('success', False)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# ---------------------------------------------------------------------------
# Rutas admin — WhatsApp / YCloud
# ---------------------------------------------------------------------------

@admin_bp.route('/conectar-whatsapp')
@admin_requerido
def conectar_whatsapp():
    try:
        estado = 'conectado' if ycloud.verificar_estado() == 'CONNECTED' else 'desconectado'
    except Exception:
        estado = 'error'
    return render_template('admin/conectar_whatsapp.html', estado=estado, qr_url=None)


@admin_bp.route('/estado-bot', methods=['GET'])
@admin_requerido
def estado_bot():
    try:
        estado_ycloud = ycloud.verificar_estado()
        if estado_ycloud == 'CONNECTED':
            return jsonify({'conectado': True, 'estado': 'conectado'})
        return jsonify({'conectado': False, 'estado': 'desconectado', 'detalle': estado_ycloud})
    except Exception as e:
        return jsonify({'conectado': False, 'estado': 'error', 'error': str(e)})


# ---------------------------------------------------------------------------
# Rutas admin — sesión
# ---------------------------------------------------------------------------

@admin_bp.route('/verificar-sesion', methods=['POST'])
def verificar_sesion_admin():
    if 'admin_id' not in session:
        return jsonify({'error': 'Sesión expirada'}), 401
    return jsonify({'ok': True})


@admin_bp.route('/renovar-sesion', methods=['POST'])
@admin_requerido
def renovar_sesion_admin():
    session.modified = True
    return '', 204


# ===========================================================================
# Handlers globales
# ===========================================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


app.register_blueprint(admin_bp)
app.register_blueprint(soporte_bp)

if __name__ == "__main__":
    app.run(debug=False)
