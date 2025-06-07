from flask import Blueprint, render_template, jsonify, request, session
import requests
import os
import re
import time

soporte_bp = Blueprint('soporte', __name__, template_folder='templates/soporte')

# Configuración de APIs externas
WISPHUB_API_KEY = os.getenv('API_KEY_WISPHUB')
WISPHUB_BASE_URL = 'https://api.wisphub.net/api/clientes'
GENIEACS_API = os.getenv('GENIEACS_API_URL')

# --- Utilidades ---
def admin_requerido(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_autenticado'):
            from flask import redirect, url_for, flash
            flash('Debes iniciar sesión como administrador.', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Vista principal ---
@soporte_bp.route('/soporte')
@admin_requerido
def soporte():
    return render_template('soporte/soporte.html')

cache_soporte = {
    "resultado": [],
    "estados": [],
    "segmentos": [],
    "timestamp": 0
}
CACHE_TTL = 5  # segundos

# --- API para obtener y comparar IPs ---
@soporte_bp.route('/api/soporte/ips')
@admin_requerido
def api_soporte_ips():
    global cache_soporte
    ahora = time.time()
    try:
        page_size = int(request.args.get('page_size', 20))
        if page_size < 1 or page_size > 200:
            page_size = 20
    except Exception:
        page_size = 20
    page = int(request.args.get('page', 1))

    # Si la caché es válida, usarla
    if cache_soporte["resultado"] and (ahora - cache_soporte["timestamp"] < CACHE_TTL):
        print("[CACHE] Usando datos en caché")
        resultado = cache_soporte["resultado"]
        estados = cache_soporte["estados"]
        segmentos = cache_soporte["segmentos"]
    else:
        print('--- INICIO API SOPORTE IPS ---')
        # 1. Obtener todos los clientes de Wisphub (paginando con limit/offset)
        headers = {
            'Authorization': f'Api-Key {WISPHUB_API_KEY}',
            'Content-Type': 'application/json'
        }
        clientes = []
        try:
            limit = 300
            offset = 0
            while True:
                params = {'limit': limit, 'offset': offset}
                print(f'[WISPHUB] Consultando offset {offset}...')
                resp = requests.get(WISPHUB_BASE_URL, headers=headers, params=params, timeout=15)
                print(f'[WISPHUB] Status: {resp.status_code}')
                if resp.status_code != 200:
                    print(f'[WISPHUB] Error status {resp.status_code}')
                    break
                data = resp.json()
                print(f'[WISPHUB] Respuesta keys: {list(data.keys())}')
                results = data.get('results', []) or data.get('clientes', [])
                print(f'[WISPHUB] Resultados en batch: {len(results)}')
                if not results:
                    break
                for c in results:
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            ip = s.get('ip', '')
                            if isinstance(ip, str) and ip:
                                clientes.append({
                                    'nombre': c.get('nombre', ''),
                                    'cedula': c.get('cedula', ''),
                                    'zona': c.get('zona', 'Sin zona'),
                                    'ip': ip,
                                })
                    else:
                        ip = c.get('ip') or c.get('ip_address', '')
                        if isinstance(ip, str) and ip:
                            clientes.append({
                                'nombre': c.get('nombre', ''),
                                'cedula': c.get('cedula', ''),
                                'zona': c.get('zona', 'Sin zona'),
                                'ip': ip,
                            })
                if not data.get('next'):
                    break
                offset += limit
            print(f'[WISPHUB] Total clientes obtenidos: {len(clientes)}')
        except Exception as e:
            print(f'[WISPHUB] Excepción: {e}')
            return jsonify({'success': False, 'error': f'Error al consultar Wisphub: {str(e)}'})

        # 2. Obtener dispositivos de GenieACS
        dispositivos = []
        try:
            print('[GENIEACS] Consultando dispositivos...')
            resp = requests.get(f"{GENIEACS_API}/devices", timeout=10)
            print(f'[GENIEACS] Status: {resp.status_code}')
            if resp.status_code == 200:
                data = resp.json()
                print(f'[GENIEACS] Dispositivos recibidos: {len(data)}')
                for device in data:
                    url_conexion = device.get("InternetGatewayDevice", {}) \
                        .get("ManagementServer", {}) \
                        .get("ConnectionRequestURL", {}) \
                        .get("_value", '')
                    ip_actual = ''
                    if url_conexion:
                        match = re.search(r'http://([\d\.]+):', url_conexion)
                        if match:
                            ip_actual = match.group(1)
                    if isinstance(ip_actual, str) and ip_actual:
                        dispositivos.append({
                            'device_id': device.get('_id'),
                            'ip': ip_actual,
                            'modelo': device.get("InternetGatewayDevice", {}).get("DeviceInfo", {}).get("ModelName", {}).get("_value", ''),
                            'fabricante': device.get("InternetGatewayDevice", {}).get("DeviceInfo", {}).get("Manufacturer", {}).get("_value", ''),
                        })
            print(f'[GENIEACS] Total IPs GenieACS: {len(dispositivos)}')
        except Exception as e:
            print(f'[GENIEACS] Excepción: {e}')
            return jsonify({'success': False, 'error': f'Error al consultar GenieACS: {str(e)}'})

        # 3. Comparar IPs (sin zona ni cédula)
        print(f'[COMPARA] Armando diccionarios de IPs...')
        ips_wisphub = {c['ip']: c for c in clientes if isinstance(c['ip'], str) and c['ip']}
        ips_genieacs = {d['ip']: d for d in dispositivos if isinstance(d['ip'], str) and d['ip']}
        resultado = []
        for ip, c in ips_wisphub.items():
            estado = 'Ambos' if ip in ips_genieacs else 'Solo Wisphub'
            resultado.append({
                'ip': ip,
                'nombre': c['nombre'],
                'estado': estado
            })
        for ip, d in ips_genieacs.items():
            if ip not in ips_wisphub:
                resultado.append({
                    'ip': ip,
                    'nombre': '',
                    'estado': 'Solo GenieACS'
                })
        def ip_key(ip_str):
            return tuple(int(part) for part in ip_str.split('.') if part.isdigit())
        resultado.sort(key=lambda x: ip_key(x['ip']))
        print(f'[COMPARA] Total resultado: {len(resultado)}')
        estados = ['Ambos', 'Solo Wisphub', 'Solo GenieACS']
        # --- Calcular segmentos de red (primeros 3 octetos) ---
        def get_segmento(ip):
            partes = ip.split('.')
            if len(partes) >= 3:
                return f"{partes[0]}.{partes[1]}.{partes[2]}"
            return ''
        segmentos_set = set()
        for r in resultado:
            segmento = get_segmento(r['ip'])
            r['segmento'] = segmento
            if segmento:
                segmentos_set.add(segmento)
        segmentos = sorted(segmentos_set)
        print(f'[PAGINACION] (sin paginar aún) segmentos: {segmentos}')
        cache_soporte["resultado"] = resultado
        cache_soporte["estados"] = estados
        cache_soporte["segmentos"] = segmentos
        cache_soporte["timestamp"] = ahora
        print('--- FIN API SOPORTE IPS ---')

    # --- Paginación propia (personalizable por el usuario) ---
    segmento_param = request.args.get('segmento', '').strip()
    estado_param = request.args.get('estado', '').strip()
    # Filtrar por segmento y estado antes de paginar
    filtrados = resultado
    if segmento_param:
        filtrados = [r for r in filtrados if r.get('segmento') == segmento_param]
    if estado_param:
        filtrados = [r for r in filtrados if r.get('estado') == estado_param]
    total = len(filtrados)
    total_pages = (total + page_size - 1) // page_size
    start = (page - 1) * page_size
    end = start + page_size
    resultado_pagina = filtrados[start:end]
    print(f'[PAGINACION] Página: {page} de {total_pages}, mostrando {len(resultado_pagina)} registros (page_size={page_size})')

    return jsonify({'success': True, 'ips': resultado_pagina, 'estados': estados, 'segmentos': segmentos, 'page': page, 'total_pages': total_pages, 'total': total, 'page_size': page_size})
