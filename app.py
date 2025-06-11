from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
import os
from dotenv import load_dotenv
import functools
from admin import admin_bp
from datetime import datetime, timedelta
import random
import sqlite3
from time import time
from soporte import soporte_bp

# Cargar variables desde .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Registrar Blueprint de admin
app.register_blueprint(admin_bp)
app.register_blueprint(soporte_bp)

# Configuración desde .env
API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = 'https://api.wisphub.net/api/clientes'
GENIEACS_API = os.getenv("GENIEACS_API_URL")
ip_server = os.getenv("IP_SERVER")

# Funciones de utilidad para clientes
# (Aquí puedes agregar funciones propias si necesitas lógica de cliente)

def buscar_cliente_por_cedula(cedula):
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    print('--- DEPURACIÓN WISPHUB ---')
    print('URL:', BASE_URL)
    print('TOKEN:', API_KEY)
    print('HEADERS:', headers)
    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params={'cedula': cedula},  # Filtrar por cédula directamente
            timeout=10
        )
        print('STATUS CODE:', response.status_code)
        print('RESPONSE TEXT:', response.text)

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
                nombre = cliente.get('nombre', '')
                telefono = cliente.get('telefono', '')
                ip = cliente.get('ip') or cliente.get('ip_address')

                if not telefono:
                    return None, {"code": "sin_telefono", "message": "⚠️ El cliente no tiene número telefónico registrado."}
                if not ip:
                    return None, {"code": "sin_ip", "message": "⚠️ El cliente no tiene IP asociada."}

                session['telefono'] = telefono
                session['nombre'] = nombre
                session['cliente_encontrado'] = True
                session['ip'] = ip
                session['cedula'] = cedula
                return cliente, None

        return None, {"code": "cliente_no_encontrado", "message": "⚠️ Cliente no encontrado. Verifica la cédula e inténtalo de nuevo."}

    except requests.exceptions.ConnectionError:
        return None, {"code": "error_conexion", "message": "❌ No se pudo establecer conexión con Wisphub. Verifique su conexión a internet."}
    except requests.exceptions.Timeout:
        return None, {"code": "error_timeout", "message": "❌ La conexión con Wisphub ha expirado. Intente nuevamente."}
    except Exception as e:
        print(f"Error inesperado: {str(e)}")
        return None, {"code": "error_inesperado", "message": "❌ Error inesperado al consultar Wisphub. Intente más tarde."}

# Decorador para proteger rutas de cliente
def cliente_requerido(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("cliente_encontrado"):
            return redirect(url_for("index"))
        return func(*args, **kwargs)
    return wrapper

# Rutas para clientes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        session.clear()  # Limpia cualquier sesión previa al mostrar el login
    if request.method == "POST":
        # --- BLOQUEO POR INTENTOS FALLIDOS DE CÉDULA ---
        intentos_cedula = session.get('intentos_cedula', 0)
        bloqueo_cedula_hasta = session.get('bloqueo_cedula_hasta')
        ahora = datetime.now()
        if bloqueo_cedula_hasta:
            try:
                bloqueo_cedula_dt = datetime.fromisoformat(bloqueo_cedula_hasta)
                if ahora < bloqueo_cedula_dt:
                    segundos_restantes = int((bloqueo_cedula_dt - ahora).total_seconds())
                    minutos = segundos_restantes // 60
                    segundos = segundos_restantes % 60
                    return jsonify({'success': False, 'code': 'bloqueo_cedula', 'message': f'Has superado el número de intentos. Intenta de nuevo en {minutos} minutos y {segundos} segundos.'})
            except Exception:
                pass
        cedula = request.form.get("cedula")
        if not cedula:
            intentos_cedula += 1
            intentos_restantes = 3 - intentos_cedula
            session['intentos_cedula'] = intentos_cedula
            if intentos_cedula >= 3:
                session['bloqueo_cedula_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
                session['intentos_cedula'] = 0
                return jsonify({'success': False, 'code': 'bloqueo_cedula', 'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
            else:
                return jsonify({'success': False, 'code': 'sin_cedula', 'message': f'Por favor ingrese su cédula. Te quedan {intentos_restantes} intento(s) antes de ser bloqueado.'})
        cliente, error = buscar_cliente_por_cedula(cedula)
        if error:
            intentos_cedula += 1
            intentos_restantes = 3 - intentos_cedula
            session['intentos_cedula'] = intentos_cedula
            if intentos_cedula >= 3:
                session['bloqueo_cedula_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
                session['intentos_cedula'] = 0
                return jsonify({'success': False, 'code': 'bloqueo_cedula', 'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
            else:
                return jsonify({'success': False, 'code': error['code'], 'message': f"{error['message']} Te quedan {intentos_restantes} intento(s) antes de ser bloqueado."})
        if cliente:
            session.pop('intentos_cedula', None)
            session.pop('bloqueo_cedula_hasta', None)
            whatsapp = cliente.get('telefono', '')
            whatsapp = normalizar_numero(whatsapp)
            if not whatsapp:
                print(f"[DEPURACIÓN] Número de teléfono no válido, no se envía código.")
                return jsonify({'success': False, 'code': 'error_numero', 'message': 'El número de teléfono no es válido para WhatsApp Colombia.'})
            ultimos4 = whatsapp[-4:] if whatsapp else 'XXXX'
            # Generar código aleatorio de 6 dígitos
            codigo = str(random.randint(100000, 999999))
            session['codigo_verificacion'] = codigo
            session['telefono'] = whatsapp
            session['nombre'] = cliente.get('nombre', '')
            session['cedula'] = cedula
            # Enviar WhatsApp automáticamente
            try:
                enviar_whatsapp(whatsapp, f'Tu código de verificación es: {codigo}')
            except Exception as e:
                print(f"[DEPURACIÓN] Error al enviar WhatsApp: {e}")
                return jsonify({'success': False, 'code': 'error_envio', 'message': 'No se pudo enviar el código por WhatsApp. ' + str(e)})
            return jsonify({'success': True, 'ultimos4': ultimos4})
    return render_template("users/user_login.html")

@app.route("/seleccionar_servicio", methods=["POST"])
def seleccionar_servicio():
    ip = request.form.get("ip")
    if not ip:
        return jsonify({'success': False})
    session['ip'] = ip
    return jsonify({'success': True, 'redirect': url_for('dashboard')})

@app.route('/verificar_codigo_ajax', methods=['POST'])
def verificar_codigo_ajax():
    codigo = request.form.get('codigo')
    # --- BLOQUEO POR INTENTOS FALLIDOS ---
    intentos = session.get('intentos_codigo', 0)
    bloqueo_hasta = session.get('bloqueo_codigo_hasta')
    ahora = datetime.now()
    if bloqueo_hasta:
        try:
            bloqueo_hasta_dt = datetime.fromisoformat(bloqueo_hasta)
            if ahora < bloqueo_hasta_dt:
                segundos_restantes = int((bloqueo_hasta_dt - ahora).total_seconds())
                minutos = segundos_restantes // 60
                segundos = segundos_restantes % 60
                return jsonify({'success': False, 'message': f'Has superado el número de intentos. Intenta de nuevo en {minutos} minutos y {segundos} segundos.'})
        except Exception:
            pass  # Si hay error, ignora y sigue
    if codigo == session.get('codigo_verificacion'):
        session.pop('_flashes', None)  # Limpiar mensajes anteriores
        session.pop('intentos_codigo', None)
        session.pop('bloqueo_codigo_hasta', None)
        cedula = session.get('cedula')
        # Unificar servicios de todos los clientes con la misma cédula
        data = None
        try:
            response = requests.get(BASE_URL, headers={
                'Authorization': f'Api-Key {API_KEY}',
                'Content-Type': 'application/json'
            }, params={'cedula': cedula}, timeout=10)
            if response.status_code == 200:
                data = response.json()
        except Exception as e:
            data = None
        servicios_unificados = []
        if data and 'results' in data:
            for c in data['results']:
                if c.get('cedula') == cedula:
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            if s.get('ip'):
                                # Añadir la dirección si existe
                                s_copy = dict(s)
                                s_copy['direccion'] = c.get('direccion', '')
                                servicios_unificados.append(s_copy)
                    elif c.get('ip'):
                        servicios_unificados.append({'ip': c.get('ip'), 'nombre_servicio': c.get('nombre_servicio', ''), 'ssid_router_wifi': c.get('ssid_router_wifi', ''), 'estado': c.get('estado', ''), 'direccion': c.get('direccion', '')})
        # Si hay más de un servicio, pedir selección
        if len(servicios_unificados) > 1:
            lista_servicios = []
            for idx, s in enumerate(servicios_unificados, 1):
                nombre = f"Servicio de Internet {idx}"
                direccion = s.get('direccion', '')
                ssid = s.get('ssid_router_wifi', '')
                texto = nombre
                if direccion:
                    texto += f" ({direccion})"
                if ssid:
                    texto += f" - SSID: {ssid}"
                lista_servicios.append({
                    'ip': s.get('ip', ''),
                    'texto': texto
                })
            return jsonify({'success': True, 'multiple_servicios': True, 'servicios': lista_servicios})
        # Si solo hay uno, guardar en sesión y redirigir
        ip = servicios_unificados[0]['ip'] if servicios_unificados else session.get('ip')
        session['ip'] = ip
        flash('Sesión iniciada correctamente', 'success')
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    # Si el código es incorrecto
    intentos += 1
    intentos_restantes = 3 - intentos
    session['intentos_codigo'] = intentos
    if intentos >= 3:
        session['bloqueo_codigo_hasta'] = (ahora + timedelta(minutes=2)).isoformat()
        session['intentos_codigo'] = 0  # Reinicia el contador tras bloquear
        return jsonify({'success': False, 'message': 'Has superado el número de intentos permitidos. Tu acceso ha sido bloqueado por 2 minutos.'})
    else:
        return jsonify({'success': False, 'message': f'Código incorrecto. Te quedan {intentos_restantes} intento(s) antes de ser bloqueado.'})

@app.route("/dashboard")
@cliente_requerido
def dashboard():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    # Obtener el estado del servicio Wisphub y datos wifi
    estado_servicio = None
    ssid_actual = ''
    password_actual = ''
    ip_seleccionada = session.get('ip')
    try:
        headers = {
            'Authorization': f'Api-Key {API_KEY}',
            'Content-Type': 'application/json'
        }
        response = requests.get(BASE_URL, headers=headers, params={'cedula': cliente['cedula']}, timeout=7)
        print('--- RESPUESTA WISPHUB ---')
        print(response.text)
        if response.status_code == 200:
            data = response.json()
            clientes = data.get('results', [])
            servicio_encontrado = None
            for c in clientes:
                if c.get('cedula') == cliente['cedula']:
                    servicios = c.get('servicios', [])
                    if servicios and isinstance(servicios, list) and len(servicios) > 0:
                        for s in servicios:
                            if s.get('ip') == ip_seleccionada:
                                servicio_encontrado = s
                                break
                        if servicio_encontrado:
                            break
                    elif c.get('ip') == ip_seleccionada:
                        # Caso de cliente sin lista de servicios pero con ip directa
                        servicio_encontrado = c
                        break
            if servicio_encontrado:
                estado_servicio = servicio_encontrado.get('estado', '').lower()
                ssid_actual = servicio_encontrado.get('ssid_router_wifi', '')
                password_actual = servicio_encontrado.get('password_ssid_router_wifi', '')
            else:
                # Fallback: primer servicio del primer cliente
                for c in clientes:
                    if c.get('cedula') == cliente['cedula']:
                        servicios = c.get('servicios', [])
                        if servicios and isinstance(servicios, list) and len(servicios) > 0:
                            s = servicios[0]
                            estado_servicio = s.get('estado', '').lower()
                            ssid_actual = s.get('ssid_router_wifi', '')
                            password_actual = s.get('password_ssid_router_wifi', '')
                        else:
                            estado_servicio = c.get('estado', '').lower() if 'estado' in c else 'desconocido'
                            ssid_actual = c.get('ssid_router_wifi', '')
                            password_actual = c.get('password_ssid_router_wifi', '')
                        break
    except Exception as e:
        estado_servicio = None
    cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
    return render_template("users/user_dashboard.html", cliente=cliente, cambios_realizados=cambios_realizados, estado_servicio=estado_servicio, ssid_actual=ssid_actual, password_actual=password_actual)

# Función para obtener el cliente actual desde la sesión
def obtener_cliente_actual():
    return {
        'nombre': session.get('nombre', ''),
        'cedula': session.get('cedula', ''),
        'celular': session.get('telefono', ''),
        'poblacion': session.get('poblacion', ''),
        'plan_megas': session.get('plan_megas', '')
    }


import requests
import time

def enviar_whatsapp(telefono, mensaje):
    try:
        url = f"http://{ip_server}:3002/send"
        data = {"telefono": telefono, "mensaje": mensaje}
        response = requests.post(url, json=data, timeout=5)
        print("WhatsApp enviado:", response.text)
    except Exception as e:
        print("Error enviando WhatsApp:", e)



@app.route("/cambiar_clave", methods=["GET", "POST"])
@cliente_requerido
def cambiar_clave():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    accion = request.args.get('accion')
    if request.method == "POST":
        # Control de límite de cambios para ambos flujos
        limite_cambios = obtener_limite_cliente(cliente['cedula'])
        cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
        if cambios_realizados >= limite_cambios:
            msg = f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."
            return jsonify({'success': False, 'message': msg})
        # Solo aceptar datos JSON (AJAX)
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
        # Validar estado del servicio Wisphub
        headers = {
            'Authorization': f'Api-Key {API_KEY}',
            'Content-Type': 'application/json'
        }
        estado_servicio = None
        try:
            response = requests.get(BASE_URL, headers=headers, params={'cedula': cliente['cedula']}, timeout=7)
            if response.status_code == 200:
                data = response.json()
                clientes = data.get('results', [])
                for c in clientes:
                    if c.get('cedula') == cliente['cedula']:
                        servicios = c.get('servicios', [])
                        if servicios and isinstance(servicios, list) and len(servicios) > 0:
                            estado_servicio = servicios[0].get('estado', '').lower()
                        elif 'estado' in c:
                            estado_servicio = c.get('estado', '').lower()
                        else:
                            estado_servicio = 'desconocido'
        except Exception as e:
            estado_servicio = None
        if estado_servicio != 'activo':
            return jsonify({'success': False, 'message': 'El servicio debe estar ACTIVO para poder realizar cambios.'})
        data = request.get_json()
        nueva_clave = data.get("nueva_clave")
        confirmar_clave = data.get("confirmar_clave")
        # Validaciones comunes
        if not nueva_clave or not confirmar_clave:
            msg = "Por favor ingrese y confirme la nueva clave"
            return jsonify({'success': False, 'message': msg})
        if nueva_clave != confirmar_clave:
            msg = "Las contraseñas no coinciden"
            return jsonify({'success': False, 'message': msg})
        if len(nueva_clave) < 8:
            msg = "La contraseña debe tener al menos 8 caracteres"
            return jsonify({'success': False, 'message': msg})
        ip = session.get('ip')
        if not ip:
            msg = "No se encontró la IP del cliente"
            return jsonify({'success': False, 'message': msg})
        device_id = obtener_device_id_por_ip(ip)
        if not device_id:
            msg = "No se encontró el dispositivo del cliente"
            return jsonify({'success': False, 'message': msg})
        # Lógica AJAX: solo enviar WhatsApp
        if accion == 'whatsapp':
            whatsapp = normalizar_numero(cliente['celular'])
            if not whatsapp:
                return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
            try:
                enviar_whatsapp(whatsapp, f"¡Hola! tu contraseña Wifi será cambiada en unos segundos. Nueva Contraseña: {nueva_clave}")
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        # Lógica AJAX: solo cambiar la clave
        if accion == 'cambiar':
            ok = cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase', nueva_clave)
            if ok:
                actualizar_parametros_wisphub(cliente['cedula'], nueva_clave=nueva_clave)
                registrar_cambio_usuario(cliente['cedula'], 'Password', 'Nueva')
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'message': 'Error al cambiar la clave en el dispositivo.'})
        # Si no es una acción válida
        return jsonify({'success': False, 'message': 'Acción no válida.'})
    # Solo renderiza la plantilla en GET
    return render_template("users/user_cambiar_clave.html", cliente=cliente)

@app.route("/cambiar_nombre_red", methods=["GET", "POST"])
@cliente_requerido
def cambiar_nombre_red():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    accion = request.args.get('accion')
    if request.method == "POST":
        # Control de límite de cambios para ambos flujos
        limite_cambios = obtener_limite_cliente(cliente['cedula'])
        cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
        if cambios_realizados >= limite_cambios:
            msg = f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."
            return jsonify({'success': False, 'message': msg})
        # Solo aceptar datos JSON (AJAX)
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
        # Validar estado del servicio Wisphub
        headers = {
            'Authorization': f'Api-Key {API_KEY}',
            'Content-Type': 'application/json'
        }
        estado_servicio = None
        try:
            response = requests.get(BASE_URL, headers=headers, params={'cedula': cliente['cedula']}, timeout=7)
            if response.status_code == 200:
                data = response.json()
                clientes = data.get('results', [])
                for c in clientes:
                    if c.get('cedula') == cliente['cedula']:
                        servicios = c.get('servicios', [])
                        if servicios and isinstance(servicios, list) and len(servicios) > 0:
                            estado_servicio = servicios[0].get('estado', '').lower()
                        elif 'estado' in c:
                            estado_servicio = c.get('estado', '').lower()
                        else:
                            estado_servicio = 'desconocido'
        except Exception as e:
            estado_servicio = None
        if estado_servicio != 'activo':
            return jsonify({'success': False, 'message': 'El servicio debe estar ACTIVO para poder realizar cambios.'})
        data = request.get_json()
        nuevo_nombre = data.get("nuevo_nombre")
        # Validaciones comunes
        if not nuevo_nombre:
            msg = "Por favor ingrese un nuevo nombre"
            return jsonify({'success': False, 'message': msg})
        ip = session.get('ip')
        if not ip:
            msg = "No se encontró la IP del cliente"
            return jsonify({'success': False, 'message': msg})
        device_id = obtener_device_id_por_ip(ip)
        if not device_id:
            msg = "No se encontró el dispositivo del cliente"
            return jsonify({'success': False, 'message': msg})
        # Lógica AJAX: solo enviar WhatsApp
        if accion == 'whatsapp':
            whatsapp = normalizar_numero(cliente['celular'])
            if not whatsapp:
                return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
            try:
                enviar_whatsapp(whatsapp, f"¡Hola! tu Nombre de la Red Wifi será cambiada en unos segundos. Nuevo Nombre: {nuevo_nombre}")
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        # Lógica AJAX: solo cambiar el nombre
        if accion == 'cambiar':
            ok = cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', nuevo_nombre)
            if ok:
                actualizar_parametros_wisphub(cliente['cedula'], nuevo_ssid=nuevo_nombre)
                registrar_cambio_usuario(cliente['cedula'], 'SSID', nuevo_nombre)
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'message': 'Error al cambiar el nombre de la red en el dispositivo.'})
        # Si no es una acción válida
        return jsonify({'success': False, 'message': 'Acción no válida.'})
    # Solo renderiza la plantilla en GET
    return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)

@app.route("/cerrar_sesion", methods=["POST"])
def cerrar_sesion():
    session.clear()
    flash("Sesión cerrada exitosamente", "success")
    return redirect(url_for("index"))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# --- FUNCIONES DE GENIEACS COPIADAS DEL ADMIN ---
def obtener_device_id_por_ip(ip_buscada):
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
                import re
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

def registrar_cambio_usuario(cedula, tipo_cambio, valor_nuevo):
    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO change_history (admin_id, cedula, tipo_cambio, valor_nuevo, fecha) VALUES (?, ?, ?, ?, ?)",
                     (None, cedula, tipo_cambio, valor_nuevo, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al registrar cambio (usuario): {e}")
        return False

# --- FUNCIONES AUXILIARES PARA VALIDAR CAMBIOS POR MES ---
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

def contar_cambios_usuario_mes(cedula):
    ahora = datetime.now()
    inicio_mes = ahora.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT COUNT(*) as total FROM change_history WHERE cedula = ? AND fecha >= ?", (cedula, inicio_mes.isoformat()))
        data = cur.fetchone()
        conn.close()
        return data['total'] if data else 0
    except Exception as e:
        print(f"Error contando cambios del usuario: {e}")
        return 0

def obtener_limite_cliente(cedula):
    try:
        conn = get_db_connection()
        cur = conn.execute("SELECT limite_personalizado FROM user_limits WHERE cedula = ?", (cedula,))
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
        primer_dia_mes_anterior = primer_dia_mes_actual.replace(year=primer_dia_mes_actual.year-1, month=12)
    else:
        primer_dia_mes_anterior = primer_dia_mes_actual.replace(month=primer_dia_mes_actual.month-1)
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM change_history WHERE fecha < ?", (primer_dia_mes_anterior.isoformat(),))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error limpiando historial antiguo: {e}")

def formatear_fecha(value, formato='%d/%m/%Y %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except Exception:
            return value
    return value.strftime(formato)

app.jinja_env.filters['formatear_fecha'] = formatear_fecha

@app.route("/api/clientes/", methods=["GET"])
def buscar_cliente_api():
    cedula = request.args.get("cedula")
    if not cedula:
        return jsonify({
            "success": False,
            "message": "Debe proporcionar una cédula"
        }), 400
    
    cliente, error = buscar_cliente_por_cedula(cedula)
    
    if error:
        return jsonify({
            "success": False,
            "message": error["message"],
            "code": error["code"]
        }), 404
    
    if cliente:
        return jsonify({
            "success": True,
            "cliente": {
                "nombre": cliente.get("nombre"),
                "cedula": cliente.get("cedula"),
                "telefono": cliente.get("telefono"),
                "ip": cliente.get("ip") or cliente.get("ip_address"),
                "poblacion": cliente.get("poblacion"),
                "plan_megas": cliente.get("plan_megas")
            }
        })

def normalizar_numero(telefono):
    # Elimina todo lo que no sea dígito
    print(f"[DEPURACIÓN] Teléfono original: {telefono}")
    numero = ''.join(filter(str.isdigit, telefono))
    print(f"[DEPURACIÓN] Teléfono solo dígitos: {numero}")
    # Si es un número nacional de 10 dígitos, agrega el código de país
    if len(numero) == 10:
        numero = '57' + numero
        print(f"[DEPURACIÓN] Número nacional convertido a internacional: {numero}")
    # Si ya tiene el código de país y tiene 12 dígitos, lo dejamos igual
    if len(numero) == 12 and numero.startswith('57'):
        print(f"[DEPURACIÓN] Número válido para WhatsApp Colombia: {numero}")
        return numero
    print(f"[DEPURACIÓN] Número NO válido para WhatsApp Colombia: {numero}")
    return None

def actualizar_parametros_wisphub(cedula, nueva_clave=None, nuevo_ssid=None):
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    # Busca el cliente para obtener su ID en Wisphub
    cliente, _ = buscar_cliente_por_cedula(cedula)
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

def get_db_connection():
    conn = sqlite3.connect('skypass.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/reenviar_codigo', methods=['POST'])
def reenviar_codigo():
    telefono = session.get('telefono')
    codigo = session.get('codigo_verificacion')
    if not telefono or not codigo:
        return jsonify({'success': False, 'message': 'No hay sesión activa.'})
    try:
        enviar_whatsapp(telefono, f'Tu código de verificación es: {codigo}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

if __name__ == "__main__":
    app.run(debug=True)
