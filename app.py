from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
import os
from dotenv import load_dotenv
import functools
from admin import admin_bp
from datetime import datetime, timedelta, timezone
import random
import sqlite3
from soporte import soporte_bp

# Cargar variables desde .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(minutes=2)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

# Registrar Blueprint de admin
app.register_blueprint(admin_bp)
app.register_blueprint(soporte_bp)

# Configuración desde .env
API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = os.getenv('BASE_URL_WISPHUB')
GENIEACS_API = os.getenv("GENIEACS_API_URL")
ip_server = os.getenv("IP_SERVER")

# Configuración WhatsApp API
EVOLUTION_BASE_URL = os.getenv("EVOLUTION_BASE_URL", "")
EVOLUTION_API_KEY = os.getenv("EVOLUTION_API_KEY", "")
EVOLUTION_INSTANCE = os.getenv("EVOLUTION_INSTANCE", "default")

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
            session.permanent = True
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
            if not enviar_otp_ycloud(whatsapp,codigo):
                return jsonify({'success': False, 'code': 'error_envio', 'message': 'No se pudo enviar el código por WhatsApp.  '})
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

def verificar_estado_whatsapp():
    """
    Verifica el estado de conexión de WhatsApp usando YCloud API.
    
    YCloud API retorna: {"items": [{"status": "CONNECTED", ...}]}
    
    Returns:
        str: 'CONNECTED' si está conectado, 'DISCONNECTED' si está desconectado, None si hay error
    """
    try:
        api_key = os.getenv('YCLOUD_API_KEY')
        sender_id = os.getenv('YCLOUD_SENDER_ID') # ID del número en YCloud (ej: 862353686972427)
        
        if not api_key:
            print(f"[YCloud] ❌ ERROR: Variables de YCloud API no configuradas en .env")
            return None
        
        url = "https://api.ycloud.com/v2/whatsapp/phoneNumbers"
        headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # YCloud retorna una lista de items
        items = data.get('items', [])
        
        if sender_id:
            # Filtrar por el ID específico si está configurado
            for item in items:
                if item.get('id') == sender_id:
                     estado = item.get('status', 'UNKNOWN')
                     print(f"[YCloud] 🔍 Estado de conexión ({sender_id}): {estado}")
                     return estado
            print(f"[YCloud] ⚠️ No se encontró el número con ID {sender_id}")
        elif items:
            # Si no hay ID específico, tomar el primero
            estado = items[0].get('status', 'UNKNOWN')
            print(f"[YCloud] 🔍 Estado de conexión (primer número): {estado}")
            return estado
            
        print("[YCloud] ⚠️ No se encontraron números en la cuenta")
        return None
        
    except Exception as e:
        print(f"[YCloud] ⚠️ Error al verificar estado: {e}")
        return None



def enviar_confirmacion_de_cambio(telefono,mensaje):
    try:
        api_key = os.getenv('YCLOUD_API_KEY')
        empresa = os.getenv('EMPRESA')
        
        if not api_key:
            print("[YCloud] ❌ ERROR: API Key no configurada")
            return False

        # Endpoint oficial de YCloud para enviar mensajes
        url = "https://api.ycloud.com/v2/whatsapp/messages/sendDirectly"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }


        # Estructura del payload SEGÚN TU SOLICITUD
        data = {
            "from": "573127313737", # Tu número de envío
            "to": telefono,
            "type": "template",
            "template": {
                "name": "solicitud_cambio_skypass_v2",
                "language": {
                    "code": "es_CO",
                    "policy": "deterministic"
                },
                "components": [
                    {
                        "type": "header",
                        "parameters": [
                            {
                                "type": "text",
                                "text": empresa
                            }
                        ]
                    },
                    {
                        "type": "body",
                        "parameters": [
                            {
                                "type": "text",
                                "text": mensaje
                            }
                        ]
                    }
                ]
            }
        }

        print(f"[YCloud] Mensaje de Cambio Enviando mensaje {mensaje} a {telefono}...")

        response = requests.post(url, json=data, headers=headers, timeout=15)
        response.raise_for_status()
        
        resultado = response.json()
        print(f"[YCloud] ✅ Mensaje enviado. ID: {resultado.get('id')}")
        return True

    except requests.exceptions.HTTPError as e:
        print(f"[YCloud] ❌ ERROR HTTP: {e.response.text}")
        return False
    except Exception as e:
        print(f"[YCloud] 💥 ERROR: {e}")
        return False
    


def enviar_otp_ycloud(telefono, codigo):
    """
    Envía un código OTP usando una plantilla de autenticación de YCloud.
    
    Args:
        telefono: Número de teléfono (E.164, ej: +573001234567)
        codigo: El código de verificación (ej: "123456")
    """
    try:
        api_key = os.getenv('YCLOUD_API_KEY')
        
        if not api_key:
            print("[YCloud] ❌ ERROR: API Key no configurada")
            return False

        # Endpoint oficial de YCloud para enviar mensajes
        url = "https://api.ycloud.com/v2/whatsapp/messages/sendDirectly"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }

        # Estructura del payload SEGÚN TU SOLICITUD
        data = {
            "from": "573127313737", # Tu número de envío
            "to": telefono,
            "type": "template",
            "template": {
                "name": "auth_skypass",
                "language": {
                    "code": "es_CO",
                    "policy": "deterministic"
                },
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            {
                                "type": "text",
                                "text": codigo
                            }
                        ]
                    },
                    {
                        "type": "button",
                        "sub_type": "url",
                        "index": "0",
                        "parameters": [
                            {
                                "type": "text",
                                "text": codigo
                            }
                        ]
                    }
                ]
            }
        }

        print(f"[YCloud] outbox_tray Enviando OTP {codigo} a {telefono}...")

        response = requests.post(url, json=data, headers=headers, timeout=15)
        response.raise_for_status()
        
        resultado = response.json()
        print(f"[YCloud] ✅ Mensaje enviado. ID: {resultado.get('id')}")
        return True

    except requests.exceptions.HTTPError as e:
        print(f"[YCloud] ❌ ERROR HTTP: {e.response.text}")
        return False
    except Exception as e:
        print(f"[YCloud] 💥 ERROR: {e}")
        return False


@app.route("/cambiar_clave", methods=["GET", "POST"])
@cliente_requerido
def cambiar_clave():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    
    # GET: Cargar página inmediatamente
    if request.method == "GET":
        return render_template("users/user_cambiar_clave.html", cliente=cliente)
    
    # POST: Procesar cambio de contraseña
    accion = request.args.get('accion')
    
    if accion == 'validar_dispositivo':
        # Validar dispositivo en segundo plano
        ip = session.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
        
        try:
            # Verificar dispositivo
            dispositivo_online, device_id = obtener_estado_online_device(ip)
            
            if not dispositivo_online:
                if not verificar_dispositivo_online_alternativo(ip):
                    return jsonify({'success': False, 'message': 'El dispositivo está desconectado'})
                device_id = obtener_device_id_por_ip(ip)
                if not device_id:
                    return jsonify({'success': False, 'message': 'No se encontró el dispositivo'})
            
            # Detectar interfaces
            interfaces_activas = detectar_interfaces_wifi_activas(device_id)
            
            if not interfaces_activas:
                return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas'})
            
            # Guardar en sesión
            session['device_info'] = {
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'detected_at': datetime.now().isoformat()
            }
            
            return jsonify({
                'success': True, 
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'interfaces_count': len(interfaces_activas)
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error validando dispositivo: {e}'})
    
    # Validaciones para cambio de contraseña
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    
    # CONTROL DE LÍMITE DE CAMBIOS POR MES
    limite_cambios = obtener_limite_cliente(session.get('ip'))
    cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
    if cambios_realizados >= limite_cambios:
        msg = f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."
        return jsonify({'success': False, 'message': msg})
    
    data = request.get_json()
    nueva_clave = data.get("nueva_clave")
    confirmar_clave = data.get("confirmar_clave")
    
    # Validaciones básicas
    if not nueva_clave or not confirmar_clave:
        return jsonify({'success': False, 'message': 'Por favor ingrese y confirme la nueva clave'})
    if nueva_clave != confirmar_clave:
        return jsonify({'success': False, 'message': 'Las contraseñas no coinciden'})
    if len(nueva_clave) < 8:
        return jsonify({'success': False, 'message': 'La contraseña debe tener al menos 8 caracteres'})
    
    # Obtener información del dispositivo
    device_info = session.get('device_info', {})
    device_id = device_info.get('device_id')
    interfaces_activas = device_info.get('interfaces_activas', [])
    
    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró información del dispositivo. Recarga la página.'})
    
    # Enviar WhatsApp
    if accion == 'whatsapp':
        whatsapp = normalizar_numero(cliente['celular'])
        if not whatsapp:
            return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
        if not enviar_confirmacion_de_cambio(whatsapp, nueva_clave):
            return jsonify({'success': False, 'message': 'No se pudo enviar el WhatsApp.'})
        return jsonify({'success': True})
    
    # Cambiar contraseña
    if accion == 'cambiar':
        ok, mensaje = cambiar_contraseña_wifi_interfaces_ya_detectadas(device_id, interfaces_activas, nueva_clave)
        if ok:
            actualizar_parametros_wisphub(cliente['cedula'], nueva_clave=nueva_clave, ip_especifica=session.get('ip'))
            registrar_cambio_usuario(cliente['cedula'], 'Password', 'Nueva')
            return jsonify({'success': True, 'message': f'{mensaje}. La ONU se reiniciará automáticamente para aplicar los cambios.'})
        else:
            return jsonify({'success': False, 'message': f'Error al cambiar la clave: {mensaje}'})
    
    return jsonify({'success': False, 'message': 'Acción no válida.'})

@app.route("/cambiar_nombre_red", methods=["GET", "POST"])
@cliente_requerido
def cambiar_nombre_red():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    
    # GET: Cargar página inmediatamente
    if request.method == "GET":
        return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
    
    # POST: Procesar cambio de nombre de red
    accion = request.args.get('accion')
    
    if accion == 'validar_dispositivo':
        # Validar dispositivo en segundo plano
        ip = session.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'No se encontró la IP del cliente'})
        
        try:
            # Verificar dispositivo
            dispositivo_online, device_id = obtener_estado_online_device(ip)
            
            if not dispositivo_online:
                if not verificar_dispositivo_online_alternativo(ip):
                    return jsonify({'success': False, 'message': 'El dispositivo está desconectado'})
                device_id = obtener_device_id_por_ip(ip)
                if not device_id:
                    return jsonify({'success': False, 'message': 'No se encontró el dispositivo'})
            
            # Detectar interfaces y frecuencias
            interfaces_activas, interfaces_info = detectar_interfaces_y_frecuencias(device_id)
            
            if not interfaces_activas:
                return jsonify({'success': False, 'message': 'No se encontraron interfaces WiFi activas'})
            
            # Guardar en sesión
            session['device_info_red'] = {
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'interfaces_info': interfaces_info,
                'detected_at': datetime.now().isoformat()
            }
            
            return jsonify({
                'success': True, 
                'device_id': device_id,
                'interfaces_activas': interfaces_activas,
                'interfaces_info': interfaces_info,
                'interfaces_count': len(interfaces_activas)
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error validando dispositivo: {e}'})
    
    # Validaciones para cambio de nombre de red
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Solo se permite el flujo AJAX.'})
    
    # CONTROL DE LÍMITE DE CAMBIOS POR MES
    limite_cambios = obtener_limite_cliente(session.get('ip'))
    cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
    if cambios_realizados >= limite_cambios:
        msg = f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes."
        return jsonify({'success': False, 'message': msg})
    
    data = request.get_json()
    nuevo_nombre = data.get("nuevo_nombre")
    
    # Validaciones básicas
    if not nuevo_nombre:
        return jsonify({'success': False, 'message': 'Por favor ingrese un nuevo nombre'})
    
    # Obtener información del dispositivo
    device_info = session.get('device_info_red', {})
    device_id = device_info.get('device_id')
    interfaces_info = device_info.get('interfaces_info', {})
    
    if not device_id:
        return jsonify({'success': False, 'message': 'No se encontró información del dispositivo. Recarga la página.'})
    
    # Enviar WhatsApp
    if accion == 'whatsapp':
        whatsapp = normalizar_numero(cliente['celular'])
        if not whatsapp:
            return jsonify({'success': False, 'message': 'El número de teléfono no es válido para WhatsApp.'})
        if not enviar_confirmacion_de_cambio(whatsapp,nuevo_nombre):
            return jsonify({'success': False, 'message': 'No se pudo enviar el WhatsApp.'})
        return jsonify({'success': True})
    
    # Cambiar nombre de red
    if accion == 'cambiar':
        ok, mensaje = cambiar_nombre_red_wifi_inteligente(device_id, interfaces_info, nuevo_nombre)
        if ok:
            actualizar_parametros_wisphub(cliente['cedula'], nuevo_ssid=nuevo_nombre, ip_especifica=session.get('ip'))
            registrar_cambio_usuario(cliente['cedula'], 'SSID', nuevo_nombre)
            return jsonify({'success': True, 'message': f'{mensaje}. La ONU se reiniciará automáticamente para aplicar los cambios.'})
        else:
            return jsonify({'success': False, 'message': f'Error al cambiar el nombre de la red: {mensaje}'})
    
    return jsonify({'success': False, 'message': 'Acción no válida.'})

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
    """Obtiene el device_id por IP usando query optimizada MongoDB"""
    try:
        import re
        import json
        
        # OPTIMIZACIÓN: Usar query MongoDB con regex para filtrar directamente
        ip_escaped = ip_buscada.replace('.', r'\.')
        
        query_dict = {
            "InternetGatewayDevice.ManagementServer.ConnectionRequestURL._value": {
                "$regex": f"http://{ip_escaped}:"
            }
        }
        
        query_str = json.dumps(query_dict)
        url = f"{GENIEACS_API}/devices/"
        params = {'query': query_str}
        
        print(f"[GENIEACS] Buscando IP con query optimizada: {ip_buscada}")
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        dispositivos = response.json()
        
        # Si la query optimizada no funciona, usar método tradicional
        if len(dispositivos) == 0:
            print(f"[GENIEACS] Query optimizada sin resultados, usando método tradicional...")
            response = requests.get(f"{GENIEACS_API}/devices", timeout=10)
            response.raise_for_status()
            todos_dispositivos = response.json()
            
            for device in todos_dispositivos:
                url_val = device.get("InternetGatewayDevice", {}) \
                    .get("ManagementServer", {}) \
                    .get("ConnectionRequestURL", {}) \
                    .get("_value")
                if url_val:
                    match = re.search(r"https?://([\d.]+):", url_val)
                    if match and match.group(1) == ip_buscada:
                        print(f"[GENIEACS] ¡Coincidencia encontrada!")
                        return device.get('_id')
        else:
            # Verificar que la IP coincida exactamente
            for device in dispositivos:
                url_val = device.get("InternetGatewayDevice", {}) \
                    .get("ManagementServer", {}) \
                    .get("ConnectionRequestURL", {}) \
                    .get("_value", '')
                if url_val:
                    match = re.search(r"https?://([\d.]+):", url_val)
                    if match and match.group(1) == ip_buscada:
                        print(f"[GENIEACS] ¡Coincidencia encontrada!")
                        return device.get('_id')
    except Exception as e:
        print(f"Error al buscar dispositivo en GenieACS: {e}")
    print(f"[GENIEACS] No se encontró ningún device_id para la IP: {ip_buscada}")
    return None

# Funciones eliminadas - ahora se usan desde genieacs_utils.py

def cambiar_nombre_red_interfaz_sin_reinicio(device_id, interfaz, nuevo_nombre):
    """Cambia el nombre de red WiFi de una interfaz específica SIN reiniciar la ONU"""
    try:
        parametro_ssid = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.SSID"
        print(f"[GenieACS] 📡 Cambiando SSID interfaz {interfaz} SIN reinicio")
        print(f"[GenieACS]   - Parámetro: {parametro_ssid}")
        print(f"[GenieACS]   - Nuevo nombre: {nuevo_nombre}")
        
        resultado = cambiar_parametro_genieacs_sin_reinicio(device_id, parametro_ssid, nuevo_nombre)
        
        if resultado:
            print(f"[GenieACS] ✅ SSID cambiado exitosamente en interfaz {interfaz}")
            return True
        else:
            print(f"[GenieACS] ❌ Error cambiando SSID en interfaz {interfaz}")
            print(f"[GenieACS] ❌ Device ID: {device_id}")
            print(f"[GenieACS] ❌ Parámetro: {parametro_ssid}")
            print(f"[GenieACS] ❌ Valor: {nuevo_nombre}")
            return False
            
    except Exception as e:
        print(f"[GenieACS] ❌ Error cambiando SSID interfaz {interfaz}: {e}")
        return False

def cambiar_nombre_red_wifi_inteligente(device_id, interfaces_info, nuevo_nombre):
    """
    Cambia el nombre de la red WiFi de manera inteligente:
    - Si hay 2 interfaces: aplica sufijos -2.4GHz y -5GHz
    - Si hay 1 interface: aplica el nombre original
    - Reinicia la ONU solo UNA VEZ al final
    """
    try:
        interfaces_cambiadas = []
        interfaces_fallidas = []
        
        print(f"[WiFi] 🎯 Cambiando nombre de red WiFi inteligentemente")
        print(f"[WiFi]   - Nombre base: {nuevo_nombre}")
        print(f"[WiFi]   - Interfaces detectadas: {len(interfaces_info)}")
        
        # Determinar si necesitamos sufijos de frecuencia
        necesita_sufijos = len(interfaces_info) == 2
        
        for interfaz, info in interfaces_info.items():
            frecuencia = info.get('frecuencia', 'Desconocida')
            ssid_actual = info.get('ssid_actual', 'Desconocido')
            
            # Construir el nombre final
            if necesita_sufijos:
                if frecuencia == "2.4GHz":
                    nombre_final = f"{nuevo_nombre}-2.4GHz"
                elif frecuencia == "5GHz":
                    nombre_final = f"{nuevo_nombre}-5GHz"
                else:
                    nombre_final = nuevo_nombre  # Fallback
            else:
                nombre_final = nuevo_nombre
            
            print(f"[WiFi] 🔧 Interfaz {interfaz} ({frecuencia})")
            print(f"[WiFi]   - SSID actual: {ssid_actual}")
            print(f"[WiFi]   - SSID nuevo: {nombre_final}")
            
            # Cambiar el SSID SIN REINICIAR (usar función sin reinicio)
            resultado = cambiar_nombre_red_interfaz_sin_reinicio(device_id, interfaz, nombre_final)
            
            if resultado:
                interfaces_cambiadas.append({
                    'interfaz': interfaz,
                    'frecuencia': frecuencia,
                    'ssid_anterior': ssid_actual,
                    'ssid_nuevo': nombre_final
                })
                print(f"[WiFi] ✅ SSID cambiado exitosamente en interfaz {interfaz}")
            else:
                interfaces_fallidas.append({
                    'interfaz': interfaz,
                    'frecuencia': frecuencia,
                    'error': 'Error en cambio de parámetro'
                })
                print(f"[WiFi] ❌ Error cambiando SSID en interfaz {interfaz}")
        
        # REINICIAR LA ONU SOLO UNA VEZ AL FINAL si hubo cambios exitosos
        if interfaces_cambiadas:
            print(f"[WiFi] 🔄 Reiniciando ONU para aplicar cambios de nombres de red...")
            reinicio_ok = reiniciar_onu_genieacs(device_id)
            if reinicio_ok:
                print(f"[WiFi] ✅ ONU reiniciada exitosamente")
            else:
                print(f"[WiFi] ⚠️  Error reiniciando ONU, pero los cambios se aplicarán en el próximo reinicio")
        
        # Construir mensaje de resultado
        if interfaces_cambiadas:
            if len(interfaces_cambiadas) == 2:
                mensaje = f"✅ Nombre de red WiFi cambiado exitosamente:\n"
                mensaje += f"• 2.4GHz: {interfaces_cambiadas[0]['ssid_nuevo']}\n"
                mensaje += f"• 5GHz: {interfaces_cambiadas[1]['ssid_nuevo']}"
            else:
                interfaz_cambiada = interfaces_cambiadas[0]
                mensaje = f"✅ Nombre de red WiFi cambiado exitosamente:\n"
                mensaje += f"• {interfaz_cambiada['frecuencia']}: {interfaz_cambiada['ssid_nuevo']}"
            
            if interfaces_fallidas:
                mensaje += f"\n\n⚠️ Algunas interfaces fallaron:\n"
                for fallida in interfaces_fallidas:
                    mensaje += f"• {fallida['frecuencia']}: {fallida['error']}\n"
            
            return True, mensaje
        else:
            return False, "❌ No se pudo cambiar el nombre de ninguna red WiFi"
            
    except Exception as e:
        print(f"[WiFi] ❌ Error en cambio inteligente de nombre: {e}")
        return False, f"❌ Error interno: {str(e)}"

def cambiar_contraseña_wifi_interfaces_ya_detectadas(device_id, interfaces_activas, nueva_password):
    print(f"[GenieACS] 🔐 PROCESO RÁPIDO DE CAMBIO DE CONTRASEÑA WIFI")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - Interfaces activas: {interfaces_activas}")
    print(f"[GenieACS]   - Nueva contraseña: {'*' * len(nueva_password)} (longitud: {len(nueva_password)})")
    
    if not interfaces_activas:
        mensaje = "No se encontraron interfaces WiFi activas"
        print(f"[GenieACS] ❌ ERROR: {mensaje}")
        return False, mensaje
    
    print(f"[GenieACS] 📝 APLICANDO CONTRASEÑA A INTERFACES ACTIVAS: {interfaces_activas}")
    
    # Aplicar contraseña a cada interfaz activa (SIN REINICIAR)
    interfaces_cambiadas = []
    interfaces_fallidas = []
    
    for i, interfaz in enumerate(interfaces_activas, 1):
        print(f"[GenieACS] 🔧 INTERFAZ {i}/{len(interfaces_activas)}: {interfaz}")
        
        ok = cambiar_contraseña_wifi_interfaz_sin_reinicio(device_id, interfaz, nueva_password)
        if ok:
            interfaces_cambiadas.append(interfaz)
            print(f"[GenieACS] ✅ Interfaz {interfaz} cambiada exitosamente")
        else:
            interfaces_fallidas.append(interfaz)
            print(f"[GenieACS] ❌ Error en interfaz {interfaz}")
    
    print(f"[GenieACS] 📊 RESULTADO FINAL:")
    print(f"[GenieACS]   - Interfaces cambiadas exitosamente: {interfaces_cambiadas}")
    print(f"[GenieACS]   - Interfaces con error: {interfaces_fallidas}")
    
    if interfaces_cambiadas:
        # REINICIAR SOLO UNA VEZ AL FINAL
        print(f"[GenieACS] 🔄 REINICIANDO ONU UNA SOLA VEZ AL FINAL...")
        try:
            reiniciar_onu_genieacs(device_id)
            print(f"[GenieACS] ✅ ONU reiniciada exitosamente")
        except Exception as e:
            print(f"[GenieACS] ⚠️  Error al reiniciar ONU: {e}")
        
        mensaje = f"Contraseña WiFi aplicada exitosamente a {len(interfaces_cambiadas)} interfaz(es) activa(s): {interfaces_cambiadas}"
        if interfaces_fallidas:
            mensaje += f". Error en {len(interfaces_fallidas)} interfaz(es): {interfaces_fallidas}"
        return True, mensaje
    else:
        mensaje = f"Error al cambiar contraseña en todas las interfaces activas: {interfaces_activas}"
        print(f"[GenieACS] ❌ ERROR FINAL: {mensaje}")
        return False, mensaje


def cambiar_parametro_genieacs(device_id, parametro, valor):
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

def reiniciar_onu_genieacs(device_id):
    """Reinicia la ONU para aplicar cambios WiFi"""
    try:
        from urllib.parse import quote, unquote
        
        # Probar diferentes formatos de device_id para URLs POST
        formats_to_try = [
            ("Original", device_id),
            ("Doble codificado", device_id.replace('%', '%25')),
            ("Decodificado", device_id.replace('%2D', '-').replace('%2B', '+')),
            ("Codificado simple", device_id.replace('-', '%2D').replace('+', '%2B')),
            ("Quote completo", quote(device_id, safe='')),
            ("Quote decodificado", quote(device_id.replace('%2D', '-').replace('%2B', '+'), safe=''))
        ]
        
        # Reiniciar ONU completa
        data_reboot = {
            "name": "reboot",
            "parameterValues": []
        }
        
        print(f"[GenieACS] 🔄 Reiniciando ONU - Probando diferentes formatos...")
        
        for format_name, test_device_id in formats_to_try:
            print(f"[GenieACS] 🔄 Intento reinicio {format_name}: {test_device_id}")
            
            url = f"{GENIEACS_API}/devices/{test_device_id}/tasks?connection_request"
            
            try:
                response = requests.post(url, json=data_reboot, timeout=15)
                print(f"[GenieACS] 📡 Respuesta reinicio {format_name}: {response.status_code} - {response.text[:100]}...")
                
                if response.status_code in [200, 201, 202]:
                    print(f"[GenieACS] ✅ ONU reiniciada exitosamente con formato: {format_name}")
                    return True
                elif response.status_code == 404:
                    print(f"[GenieACS] ❌ Formato reinicio {format_name} falló con 404 - Probando siguiente...")
                    continue
                else:
                    print(f"[GenieACS] ❌ Formato reinicio {format_name} falló con {response.status_code}")
                    continue
                    
            except Exception as e:
                print(f"[GenieACS] ❌ Error en formato reinicio {format_name}: {e}")
                continue
        
        print(f"[GenieACS] 💥 TODOS LOS FORMATOS DE REINICIO FALLARON")
        return False
            
    except Exception as e:
        print(f"[GenieACS] Error al reiniciar ONU: {e}")
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
    return 2  # Valor por defecto si no hay config

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

# ─── ENDPOINTS ADMIN PARA PRUEBAS (sin login ni sesión) ───────────────────────

@app.route("/admin/api/cambiar_password_wifi", methods=["POST"])
def admin_cambiar_password_wifi():
    """
    Endpoint directo para cambiar contraseña WiFi sin sesión.
    Body JSON:
    {
        "ip": "192.168.1.100",
        "nueva_password": "MiClave123"
    }
    """
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type debe ser application/json"}), 400

    data = request.get_json()
    ip = data.get("ip")
    nueva_password = data.get("nueva_password")

    if not ip:
        return jsonify({"success": False, "message": "Falta el campo 'ip'"}), 400
    if not nueva_password:
        return jsonify({"success": False, "message": "Falta el campo 'nueva_password'"}), 400
    if len(nueva_password) < 8:
        return jsonify({"success": False, "message": "La contraseña debe tener al menos 8 caracteres"}), 400

    # Buscar device_id por IP
    dispositivo_online, device_id = obtener_estado_online_device(ip)
    if not dispositivo_online or not device_id:
        device_id = obtener_device_id_por_ip(ip)
    if not device_id:
        return jsonify({"success": False, "message": f"No se encontró ningún dispositivo con la IP {ip}"}), 404

    # Detectar interfaces activas
    interfaces_activas = detectar_interfaces_wifi_activas(device_id)
    if not interfaces_activas:
        return jsonify({"success": False, "message": "No se encontraron interfaces WiFi activas en el dispositivo"}), 404

    ok, mensaje = cambiar_contraseña_wifi_interfaces_ya_detectadas(device_id, interfaces_activas, nueva_password)
    return jsonify({"success": ok, "message": mensaje, "device_id": device_id, "interfaces": interfaces_activas})


@app.route("/admin/api/cambiar_nombre_red", methods=["POST"])
def admin_cambiar_nombre_red():
    """
    Endpoint directo para cambiar nombre de red WiFi sin sesión.
    Body JSON:
    {
        "ip": "192.168.1.100",
        "nuevo_nombre": "MiRedNueva"
    }
    """
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type debe ser application/json"}), 400

    data = request.get_json()
    ip = data.get("ip")
    nuevo_nombre = data.get("nuevo_nombre")

    if not ip:
        return jsonify({"success": False, "message": "Falta el campo 'ip'"}), 400
    if not nuevo_nombre:
        return jsonify({"success": False, "message": "Falta el campo 'nuevo_nombre'"}), 400

    # Buscar device_id por IP
    dispositivo_online, device_id = obtener_estado_online_device(ip)
    if not dispositivo_online or not device_id:
        device_id = obtener_device_id_por_ip(ip)
    if not device_id:
        return jsonify({"success": False, "message": f"No se encontró ningún dispositivo con la IP {ip}"}), 404

    # Detectar interfaces y frecuencias
    interfaces_activas, interfaces_info = detectar_interfaces_y_frecuencias(device_id)
    if not interfaces_activas:
        return jsonify({"success": False, "message": "No se encontraron interfaces WiFi activas en el dispositivo"}), 404

    ok, mensaje = cambiar_nombre_red_wifi_inteligente(device_id, interfaces_info, nuevo_nombre)
    return jsonify({"success": ok, "message": mensaje, "device_id": device_id, "interfaces": interfaces_activas})

# ──────────────────────────────────────────────────────────────────────────────

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

def actualizar_parametros_wisphub(cedula, nueva_clave=None, nuevo_ssid=None, ip_especifica=None):
    print(f'[Wisphub] INICIO: actualizar_parametros_wisphub - Cédula: {cedula}, Nueva clave: {nueva_clave}, Nuevo SSID: {nuevo_ssid}, IP específica: {ip_especifica}')
    print(f'[Wisphub] DEBUG: API_KEY existe: {bool(API_KEY)}, BASE_URL: {BASE_URL}')
    headers = {
        'Authorization': f'Api-Key {API_KEY}',
        'Content-Type': 'application/json'
    }
    # Busca el cliente para obtener su ID en Wisphub
    cliente, _ = buscar_cliente_por_cedula(cedula)
    if not cliente:
        print('[Wisphub] Cliente no encontrado para actualizar parámetros')
        return False
    
    print(f'[Wisphub] Cliente encontrado: {cliente.get("nombre", "Sin nombre")} - ID: {cliente.get("id", "Sin ID")} - ID Servicio: {cliente.get("id_servicio", "Sin ID Servicio")}')
    print(f'[Wisphub] DEBUG: Cliente completo: {cliente}')
    
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
    
    print(f'[Wisphub] ID del servicio a actualizar: {id_cliente}')
    
    # Validar que tenemos un ID válido
    if not id_cliente:
        print('[Wisphub] ERROR: No se encontró ID del servicio')
        return False
    
    data = {}
    if nueva_clave:
        data['password_ssid_router_wifi'] = nueva_clave
        print(f'[Wisphub] Actualizando contraseña WiFi para cliente {cedula}')
    if nuevo_ssid:
        data['ssid_router_wifi'] = nuevo_ssid
        print(f'[Wisphub] Actualizando SSID WiFi para cliente {cedula}')
        print(f'[Wisphub] Nuevo SSID: {nuevo_ssid}')
    if not data:
        print('[Wisphub] No hay datos para actualizar')
        return False
    
    url = f'{BASE_URL}/{id_cliente}/'
    print(f'[Wisphub] URL construida: {url}')
    print(f'[Wisphub] BASE_URL: {BASE_URL}')
    print(f'[Wisphub] ID Servicio: {id_cliente}')
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
    if not enviar_otp_ycloud(telefono, codigo):
        return jsonify({'success': False, 'message': 'No se pudo enviar el código.  '})
    return jsonify({'success': True})

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

def diagnosticar_genieacs_config():
    """Diagnóstica la configuración de GenieACS"""
    print(f"[GenieACS] 🔧 DIAGNÓSTICO DE CONFIGURACIÓN:")
    print(f"[GenieACS]   - GENIEACS_API: {GENIEACS_API}")
    print(f"[GenieACS]   - IP_SERVER: {ip_server}")
    
    try:
        print(f"[GenieACS] 📡 Probando conexión con GenieACS...")
        response = requests.get(f"{GENIEACS_API}/devices", timeout=5)
        print(f"[GenieACS]   - Status Code: {response.status_code}")
        if response.status_code == 200:
            devices = response.json()
            print(f"[GenieACS] ✅ Conexión exitosa - {len(devices)} dispositivos encontrados")
            return True
        else:
            print(f"[GenieACS] ❌ Error de conexión: {response.status_code}")
            return False
    except Exception as e:
        print(f"[GenieACS] 💥 Error de conexión: {e}")
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
    """Devuelve (True, device_id) si el dispositivo está online, (False, None) si no.
    Usa query MongoDB optimizada para buscar directamente por IP sin iterar todos los dispositivos."""
    print(f"[GenieACS] 🔍 VERIFICANDO ESTADO ONLINE DEL DISPOSITIVO:")
    print(f"[GenieACS]   - IP buscada: {ip_buscada}")
    print(f"[GenieACS]   - Minutos online requeridos: {minutos_online}")
    print(f"[GenieACS]   - GenieACS API: {GENIEACS_API}")
    
    try:
        import re
        import json
        from datetime import datetime, timezone, timedelta
        from urllib.parse import quote
        
        # OPTIMIZACIÓN: Usar query MongoDB con regex para filtrar directamente en el servidor
        # Esto evita traer todos los dispositivos y filtrar en el cliente
        print(f"[GenieACS] 📡 Buscando dispositivo con query optimizada (regex)...")
        
        # Construir query MongoDB que busca la IP dentro de ConnectionRequestURL
        # Escapar puntos en la IP para regex (192.168.80.107 -> 192\.168\.80\.107)
        ip_escaped = ip_buscada.replace('.', r'\.')
        
        # Query MongoDB: buscar donde ConnectionRequestURL contiene la IP
        query_dict = {
            "InternetGatewayDevice.ManagementServer.ConnectionRequestURL._value": {
                "$regex": f"http://{ip_escaped}:"
            }
        }
        
        # Convertir a JSON string para la query
        query_str = json.dumps(query_dict)
        
        url = f"{GENIEACS_API}/devices/"
        params = {
            'query': query_str
        }
        
        print(f"[GenieACS]   - Query optimizada: {query_str}")
        
        response = requests.get(url, params=params, timeout=10)
        print(f"[GenieACS]   - Status Code: {response.status_code}")
        
        response.raise_for_status()
        dispositivos = response.json()
        print(f"[GenieACS]   - Dispositivos encontrados con query: {len(dispositivos)}")
        
        # Si la query optimizada no funciona, intentar método alternativo
        if len(dispositivos) == 0:
            print(f"[GenieACS] ⚠️ Query optimizada no encontró resultados, intentando método alternativo...")
            # Intentar con formato diferente de regex
            query_dict_alt = {
                "InternetGatewayDevice.ManagementServer.ConnectionRequestURL._value": {
                    "$regex": ip_escaped,
                    "$options": "i"
                }
            }
            query_str_alt = json.dumps(query_dict_alt)
            params_alt = {'query': query_str_alt}
            response_alt = requests.get(url, params=params_alt, timeout=10)
            if response_alt.status_code == 200:
                dispositivos = response_alt.json()
                print(f"[GenieACS]   - Dispositivos encontrados (método alternativo): {len(dispositivos)}")
        
        # Si aún no hay resultados, usar método tradicional (fallback)
        if len(dispositivos) == 0:
            print(f"[GenieACS] ⚠️ Query optimizada falló, usando método tradicional (más lento)...")
            response = requests.get(f"{GENIEACS_API}/devices", timeout=10)
            response.raise_for_status()
            todos_dispositivos = response.json()
            print(f"[GenieACS]   - Total dispositivos para revisar: {len(todos_dispositivos)}")
            
            # Buscar en todos los dispositivos (método lento pero seguro)
            for i, device in enumerate(todos_dispositivos):
                if i > 0 and i % 100 == 0:
                    print(f"[GenieACS] 🔍 Revisando dispositivo {i+1}/{len(todos_dispositivos)}...")
                
                url_val = device.get("InternetGatewayDevice", {}) \
                    .get("ManagementServer", {}) \
                    .get("ConnectionRequestURL", {}) \
                    .get("_value", '')
                
                if url_val:
                    match = re.search(r"https?://([\d.]+):", url_val)
                    if match and match.group(1) == ip_buscada:
                        dispositivos = [device]  # Simular que encontramos el dispositivo
                        print(f"[GenieACS] ✅ Dispositivo encontrado en posición {i+1}")
                        break
        
        # Procesar resultados (debería ser solo 1 dispositivo o ninguno)
        for device in dispositivos:
            device_id = device.get('_id', 'N/A')
            url_val = device.get("InternetGatewayDevice", {}) \
                .get("ManagementServer", {}) \
                .get("ConnectionRequestURL", {}) \
                .get("_value", '')
            
            # Verificar que la IP coincida exactamente
            ip_actual = ''
            if url_val:
                match = re.search(r"https?://([\d.]+):", url_val)
                if match:
                    ip_actual = match.group(1)
            
            if ip_actual == ip_buscada:
                print(f"[GenieACS] ✅ ¡IP COINCIDENTE ENCONTRADA!")
                print(f"[GenieACS]   - Device ID: {device_id}")
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
                            return True, device_id
                        else:
                            print(f"[GenieACS] ❌ DISPOSITIVO OFFLINE - Fuera del límite de tiempo")
                            return False, None
                    except Exception as parse_error:
                        print(f"[GenieACS] ❌ Error al parsear fecha: {parse_error}")
                        return False, None
                else:
                    print(f"[GenieACS] ❌ DISPOSITIVO OFFLINE - No hay _lastInform")
                    return False, None
        
        # Si llegamos aquí, no se encontró el dispositivo
        print(f"[GenieACS] ❌ DISPOSITIVO NO ENCONTRADO")
        print(f"[GenieACS]   - No se encontró ningún dispositivo con IP: {ip_buscada}")
        
        return False, None
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR al validar online GenieACS: {e}")
        print(f"[GenieACS]   - Tipo de error: {type(e).__name__}")
        import traceback
        print(f"[GenieACS]   - Traceback: {traceback.format_exc()}")
        return False, None

@app.route('/verificar_sesion', methods=['POST'])
def verificar_sesion():
    if not session.get("cliente_encontrado"):
        return jsonify({'error': 'Sesión expirada'}), 401
    return jsonify({'ok': True})

@app.route('/renovar_sesion', methods=['POST'])
def renovar_sesion():
    session.modified = True  # Renueva la sesión
    return '', 204

# --- FUNCIONES DE GENIEACS ---
def diagnosticar_consulta_genieacs(device_id):
    """Diagnostica problemas con consultas a GenieACS"""
    print(f"[DIAGNÓSTICO] 🔍 ANALIZANDO CONSULTAS GENIEACS:")
    print(f"[DIAGNÓSTICO]   - Device ID original: {device_id}")
    
    try:
        # Probar diferentes formatos de device_id
        formats_to_test = [
            ("Original", device_id),
            ("Doble codificado", device_id.replace('%', '%25')),
            ("Decodificado", device_id.replace('%2D', '-').replace('%2B', '+')),
            ("Codificado simple", device_id.replace('-', '%2D').replace('+', '%2B'))
        ]
        
        for format_name, test_device_id in formats_to_test:
            print(f"[DIAGNÓSTICO] 🧪 Probando formato: {format_name}")
            print(f"[DIAGNÓSTICO]   - Device ID: {test_device_id}")
            
            query = f'{{"_id":"{test_device_id}"}}'
            url = f"{GENIEACS_API}/devices/"
            params = {'query': query}
            
            print(f"[DIAGNÓSTICO]   - Query: {query}")
            print(f"[DIAGNÓSTICO]   - URL completa: {url}?query={query}")
            
            try:
                response = requests.get(url, params=params, timeout=10)
                print(f"[DIAGNÓSTICO]   - Respuesta: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"[DIAGNÓSTICO]   - Dispositivos encontrados: {len(data)}")
                    
                    if len(data) > 0:
                        print(f"[DIAGNÓSTICO] ✅ FORMATO EXITOSO: {format_name}")
                        print(f"[DIAGNÓSTICO]   - Device ID que funciona: {test_device_id}")
                        return test_device_id
                    else:
                        print(f"[DIAGNÓSTICO] ❌ Sin resultados")
                else:
                    print(f"[DIAGNÓSTICO] ❌ Error HTTP: {response.status_code}")
                    
            except Exception as e:
                print(f"[DIAGNÓSTICO] ❌ Error en consulta: {e}")
            
            print(f"[DIAGNÓSTICO]   ---")
        
        print(f"[DIAGNÓSTICO] 💥 NINGÚN FORMATO FUNCIONÓ")
        return None
        
    except Exception as e:
        print(f"[DIAGNÓSTICO] 💥 ERROR EN DIAGNÓSTICO: {e}")
        return None

def obtener_interfaces_wifi_activas_directo(device_id):
    """Obtiene interfaces WiFi activas usando el formato correcto de GenieACS"""
    print(f"[GenieACS] 🔍 OBTENIENDO INTERFACES WIFI ACTIVAS:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - API: {GENIEACS_API}")
    
    interfaces_activas = []
    
    try:
        # Primero diagnosticar cuál formato funciona
        print(f"[GenieACS] 🔧 DIAGNOSTICANDO FORMATO CORRECTO...")
        device_id_correcto = diagnosticar_consulta_genieacs(device_id)
        
        if not device_id_correcto:
            print(f"[GenieACS] ❌ NO SE PUDO ENCONTRAR FORMATO VÁLIDO")
            return []
        
        print(f"[GenieACS] ✅ USANDO FORMATO CORRECTO: {device_id_correcto}")
        
        # Usar el formato correcto según la documentación de GenieACS
        query = f'{{"_id":"{device_id_correcto}"}}'
        
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
        # Usar el formato correcto detectado previamente
        device_id_correcto = diagnosticar_consulta_genieacs(device_id)
        
        if not device_id_correcto:
            print(f"[GenieACS] ❌ NO SE PUDO ENCONTRAR FORMATO VÁLIDO")
            return None, None
        
        # Usar el formato correcto según la documentación de GenieACS
        query = f'{{"_id":"{device_id_correcto}"}}'
        
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
    """Detecta interfaces activas y sus frecuencias. Si hay múltiples, prioriza 2.4GHz"""
    print(f"[GenieACS] 🔍 DETECTANDO INTERFACES Y FRECUENCIAS")
    
    # Obtener interfaces activas
    interfaces_activas = detectar_interfaces_wifi_activas(device_id)
    
    if not interfaces_activas:
        return [], {}
    
    interfaces_info = {}
    interfaz_24ghz = None
    ssid_24ghz = None
    
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
        
        # Guardar la interfaz de 2.4GHz si es la primera que encontramos
        if frecuencia == '2.4GHz' and interfaz_24ghz is None:
            interfaz_24ghz = interfaz
            ssid_24ghz = ssid_actual
    
    # Si hay una sola interfaz, solo esa se usa
    if len(interfaces_activas) == 1:
        primera_interfaz = interfaces_activas[0]
        ssid_primera = interfaces_info[primera_interfaz].get('ssid_actual', 'Desconocido')
        print(f"[GenieACS] ✅ Interfaz única activa (Interfaz {primera_interfaz}): {ssid_primera}")
    else:
        # Si hay múltiples interfaces, se usan TODAS
        print(f"[GenieACS] ✅ Múltiples interfaces activas: {list(interfaces_info.keys())} — se cambiarán todas")
    
    return interfaces_activas, interfaces_info

def cambiar_parametro_genieacs_sin_reinicio(device_id, parametro, valor):
    """Cambia un parámetro en GenieACS sin reiniciar automáticamente usando el formato correcto"""
    print(f"[GenieACS] 🔧 CAMBIANDO PARÁMETRO SIN REINICIO:")
    print(f"[GenieACS]   - Device ID: {device_id}")
    print(f"[GenieACS]   - Parámetro: {parametro}")
    print(f"[GenieACS]   - Valor: {valor}")
    
    try:
        from urllib.parse import quote, unquote
        
        # Probar diferentes formatos de device_id para URLs POST
        formats_to_try = [
            ("Original", device_id),
            ("Doble codificado", device_id.replace('%', '%25')),
            ("Decodificado", device_id.replace('%2D', '-').replace('%2B', '+')),
            ("Codificado simple", device_id.replace('-', '%2D').replace('+', '%2B')),
            ("Quote completo", quote(device_id, safe='')),
            ("Quote decodificado", quote(device_id.replace('%2D', '-').replace('%2B', '+'), safe=''))
        ]
        
        # Formato correcto para setParameterValues según documentación GenieACS
        payload = {
            "name": "setParameterValues",
            "parameterValues": [[parametro, valor]]
        }
        
        print(f"[GenieACS] 📡 Probando diferentes formatos de URL para POST...")
        
        for format_name, test_device_id in formats_to_try:
            print(f"[GenieACS] 🔄 Intento POST {format_name}: {test_device_id}")
            
            url = f"{GENIEACS_API}/devices/{test_device_id}/tasks?connection_request"
            
            try:
                response = requests.post(url, json=payload, timeout=30)
                print(f"[GenieACS] 📡 Respuesta POST {format_name}: {response.status_code} - {response.text[:100]}...")
                
                if response.status_code in [200, 201, 202]:
                    print(f"[GenieACS] ✅ Parámetro cambiado exitosamente con formato: {format_name}")
                    return True
                elif response.status_code == 404:
                    print(f"[GenieACS] ❌ Formato {format_name} falló con 404 - Probando siguiente...")
                    continue
                else:
                    print(f"[GenieACS] ❌ Formato {format_name} falló con {response.status_code}")
                    continue
                    
            except Exception as e:
                print(f"[GenieACS] ❌ Error en formato {format_name}: {e}")
                continue
        
        print(f"[GenieACS] 💥 TODOS LOS FORMATOS POST FALLARON")
        return False
            
    except Exception as e:
        print(f"[GenieACS] 💥 ERROR cambiando parámetro: {e}")
        return False

def cambiar_contraseña_wifi_interfaz_sin_reinicio(device_id, interfaz, nueva_password):
    """Cambia la contraseña WiFi de una interfaz específica SIN reiniciar la ONU"""
    try:
        parametro_password = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{interfaz}.PreSharedKey.1.KeyPassphrase"
        print(f"[GenieACS] 📡 Cambiando password interfaz {interfaz} SIN reinicio")
        print(f"[GenieACS]   - Parámetro: {parametro_password}")
        print(f"[GenieACS]   - Nueva contraseña: {nueva_password}")
        
        resultado = cambiar_parametro_genieacs_sin_reinicio(device_id, parametro_password, nueva_password)
        
        if resultado:
            print(f"[GenieACS] ✅ Password cambiado exitosamente en interfaz {interfaz}")
            return True
        else:
            print(f"[GenieACS] ❌ Error cambiando password en interfaz {interfaz}")
            return False
            
    except Exception as e:
        print(f"[GenieACS] ❌ Error cambiando password interfaz {interfaz}: {e}")
        return False

if __name__ == "__main__":
    app.run(debug=True)
