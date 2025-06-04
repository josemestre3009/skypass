from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import requests
import os
from dotenv import load_dotenv
import functools
from admin import admin_bp
from datetime import datetime
import random
import sqlite3

# Cargar variables desde .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Registrar Blueprint de admin
app.register_blueprint(admin_bp)

# Configuración desde .env
API_KEY = os.getenv('API_KEY_WISPHUB')
BASE_URL = 'https://api.wisphub.net/api/clientes'
GENIEACS_API = os.getenv("GENIEACS_API_URL")

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
    if request.method == "POST":
        cedula = request.form.get("cedula")
        if not cedula:
            return jsonify({'success': False, 'code': 'sin_cedula', 'message': 'Por favor ingrese su cédula'})
        cliente, error = buscar_cliente_por_cedula(cedula)
        if error:
            return jsonify({'success': False, 'code': error['code'], 'message': error['message']})
        if cliente:
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
            # Enviar código por WhatsApp usando el microservicio
            try:
                print(f"[DEPURACIÓN] Enviando código {codigo} a WhatsApp: {whatsapp}")
                resp = requests.post(
                    'http://localhost:3002/send',
                    json={
                        'telefono': whatsapp,
                        'mensaje': f'Tu código de verificación es: {codigo}'
                    },
                    timeout=7
                )
                data = resp.json()
                print(f"[DEPURACIÓN] Respuesta del microservicio: {data}")
                if not data.get('success'):
                    return jsonify({'success': False, 'code': 'error_envio', 'message': 'No se pudo enviar el código por WhatsApp. ' + data.get('message', '')})
            except Exception as e:
                print(f"[DEPURACIÓN] Excepción al enviar código: {e}")
                return jsonify({'success': False, 'code': 'error_envio', 'message': 'No se pudo enviar el código por WhatsApp. ' + str(e)})
            return jsonify({'success': True, 'ultimos4': ultimos4})
    return render_template("users/user_login.html")

@app.route('/verificar_codigo_ajax', methods=['POST'])
def verificar_codigo_ajax():
    codigo = request.form.get('codigo')
    if codigo == session.get('codigo_verificacion'):
        session.pop('_flashes', None)  # Limpiar mensajes anteriores
        flash('Sesión iniciada correctamente', 'success')
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    return jsonify({'success': False, 'message': 'Código incorrecto.'})

@app.route("/dashboard")
@cliente_requerido
def dashboard():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
    return render_template("users/user_dashboard.html", cliente=cliente, cambios_realizados=cambios_realizados)

# Función para obtener el cliente actual desde la sesión
def obtener_cliente_actual():
    return {
        'nombre': session.get('nombre', ''),
        'cedula': session.get('cedula', ''),
        'celular': session.get('telefono', ''),
        'poblacion': session.get('poblacion', ''),
        'plan_megas': session.get('plan_megas', '')
    }

@app.route("/cambiar_clave", methods=["GET", "POST"])
@cliente_requerido
def cambiar_clave():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    if request.method == "POST":
        limite_cambios = obtener_limite_cliente(cliente['cedula'])
        cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
        if cambios_realizados >= limite_cambios:
            flash(f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes.", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        nueva_clave = request.form.get("nueva_clave")
        confirmar_clave = request.form.get("confirmar_clave")
        if not nueva_clave or not confirmar_clave:
            flash("Por favor ingrese y confirme la nueva clave", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        if nueva_clave != confirmar_clave:
            flash("Las contraseñas no coinciden", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        if len(nueva_clave) < 8:
            flash("La contraseña debe tener al menos 8 caracteres", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        ip = session.get('ip')
        if not ip:
            flash("No se encontró la IP del cliente", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        device_id = obtener_device_id_por_ip(ip)
        if not device_id:
            flash("No se encontró el dispositivo del cliente", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
        ok = cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase', nueva_clave)
        if ok:
            actualizar_parametros_wisphub(cliente['cedula'], nueva_clave=nueva_clave)
            registrar_cambio_usuario(cliente['cedula'], 'Password', 'Nueva')
            flash("Clave actualizada exitosamente", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Error al cambiar la clave", "error")
            return render_template("users/user_cambiar_clave.html", cliente=cliente)
    return render_template("users/user_cambiar_clave.html", cliente=cliente)

@app.route("/cambiar_nombre_red", methods=["GET", "POST"])
@cliente_requerido
def cambiar_nombre_red():
    limpiar_historial_antiguo()
    cliente = obtener_cliente_actual()
    if request.method == "POST":
        limite_cambios = obtener_limite_cliente(cliente['cedula'])
        cambios_realizados = contar_cambios_usuario_mes(cliente['cedula'])
        if cambios_realizados >= limite_cambios:
            flash(f"Has alcanzado el límite de {limite_cambios} cambios permitidos este mes.", "error")
            return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
        nuevo_nombre = request.form.get("nuevo_nombre")
        if not nuevo_nombre:
            flash("Por favor ingrese un nuevo nombre", "error")
            return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
        ip = session.get('ip')
        if not ip:
            flash("No se encontró la IP del cliente", "error")
            return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
        device_id = obtener_device_id_por_ip(ip)
        if not device_id:
            flash("No se encontró el dispositivo del cliente", "error")
            return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
        ok = cambiar_parametro_genieacs(device_id, 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', nuevo_nombre)
        if ok:
            actualizar_parametros_wisphub(cliente['cedula'], nuevo_ssid=nuevo_nombre)
            registrar_cambio_usuario(cliente['cedula'], 'SSID', nuevo_nombre)
            flash("Nombre de red actualizado exitosamente", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Error al cambiar el nombre de la red", "error")
            return render_template("users/user_cambiar_nombre_red.html", cliente=cliente)
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

if __name__ == "__main__":
    app.run(debug=True)
