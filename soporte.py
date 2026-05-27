from flask import Blueprint, render_template, jsonify, request, session
import requests
import os
import re
import time
import concurrent.futures

soporte_bp = Blueprint('soporte', __name__, template_folder='templates/soporte')

# Configuración de APIs externas
WISPHUB_API_KEY = os.getenv('API_KEY_WISPHUB')
WISPHUB_BASE_URL = os.getenv('BASE_URL_WISPHUB')
GENIEACS_API = os.getenv('GENIEACS_API_URL')

# --- Utilidades ---
def admin_requerido(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_autenticado'):
            from flask import redirect, url_for, flash
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                      request.accept_mimetypes.best == 'application/json' or \
                      request.path.startswith('/api/')
            if is_ajax:
                return jsonify({'success': False, 'message': 'Sesión expirada. Inicia sesión de nuevo.'}), 401
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
CACHE_TTL = 300  # 5 minutos de caché para que sea instantáneo

# --- API para obtener y comparar IPs ---
@soporte_bp.route('/api/soporte/ips')
@admin_requerido
def api_soporte_ips():
    global cache_soporte
    ahora = time.time()
    try:
        page_size = int(request.args.get('page_size', 10)) # Por defecto 10
        if page_size < 1 or page_size > 200:
            page_size = 10
    except Exception:
        page_size = 10
    page = int(request.args.get('page', 1))
    force_refresh = request.args.get('force_refresh', '0') == '1'

    # Si la caché es válida y no se forzó actualización, usarla
    if not force_refresh and cache_soporte["resultado"] and (ahora - cache_soporte["timestamp"] < CACHE_TTL):
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
            
            def extraer_clientes(data):
                res = []
                results = data.get('results', []) or data.get('clientes', [])
                for c in results:
                    servicios = c.get('servicios', [])
                    if servicios:
                        for s in servicios:
                            ip = s.get('ip', '')
                            if isinstance(ip, str) and ip:
                                res.append({
                                    'nombre': c.get('nombre', ''),
                                    'cedula': c.get('cedula', ''),
                                    'zona': c.get('zona', 'Sin zona'),
                                    'ip': ip,
                                })
                    else:
                        ip = c.get('ip') or c.get('ip_address', '')
                        if isinstance(ip, str) and ip:
                            res.append({
                                'nombre': c.get('nombre', ''),
                                'cedula': c.get('cedula', ''),
                                'zona': c.get('zona', 'Sin zona'),
                                'ip': ip,
                            })
                return res

            print('[WISPHUB] Consultando offset 0...')
            resp = requests.get(WISPHUB_BASE_URL, headers=headers, params={'limit': limit, 'offset': 0}, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                clientes.extend(extraer_clientes(data))
                total_count = data.get('count', 0)
                
                if total_count > limit:
                    offsets = list(range(limit, total_count, limit))
                    print(f'[WISPHUB] Obteniendo en paralelo offsets: {offsets}')
                    
                    def fetch_offset(off):
                        try:
                            r = requests.get(WISPHUB_BASE_URL, headers=headers, params={'limit': limit, 'offset': off}, timeout=15)
                            if r.status_code == 200:
                                return extraer_clientes(r.json())
                        except Exception as e:
                            print(f'[WISPHUB] Error en offset {off}: {e}')
                        return []

                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        for partial_results in executor.map(fetch_offset, offsets):
                            clientes.extend(partial_results)
                            
            print(f'[WISPHUB] Total clientes obtenidos: {len(clientes)}')
        except Exception as e:
            print(f'[WISPHUB] Excepción: {e}')
            return jsonify({'success': False, 'error': f'Error al consultar Wisphub: {str(e)}'})

        # 2. Obtener dispositivos del sistema (paginado y con proyección mínima)
        dispositivos = []
        try:
            print('[GENIEACS] Consultando dispositivos (con proyección mínima)...')
            PAGE = 200
            PROJECTION = '_id,InternetGatewayDevice.ManagementServer.ConnectionRequestURL,InternetGatewayDevice.DeviceInfo.ModelName,InternetGatewayDevice.DeviceInfo.Manufacturer'
            
            def extraer_dispositivo(device):
                url_conexion = device.get("InternetGatewayDevice", {}) \
                    .get("ManagementServer", {}) \
                    .get("ConnectionRequestURL", {}) \
                    .get("_value", '')
                ip_actual = ''
                if url_conexion:
                    m = re.search(r'http://([\d\.]+):', url_conexion)
                    if m:
                        ip_actual = m.group(1)
                if isinstance(ip_actual, str) and ip_actual:
                    return {
                        'device_id': device.get('_id'),
                        'ip': ip_actual,
                        'modelo': device.get("InternetGatewayDevice", {}).get("DeviceInfo", {}).get("ModelName", {}).get("_value", ''),
                        'fabricante': device.get("InternetGatewayDevice", {}).get("DeviceInfo", {}).get("Manufacturer", {}).get("_value", ''),
                    }
                return None
            
            def fetch_genie_page(skip):
                try:
                    r = requests.get(
                        f"{GENIEACS_API}/devices",
                        params={'limit': PAGE, 'skip': skip, 'projection': PROJECTION},
                        timeout=15
                    )
                    if r.status_code == 200:
                        return r.json()
                except Exception as e:
                    print(f'[GENIEACS] Error en skip {skip}: {e}')
                return []
            
            # Primera página para conocer total
            first_page = fetch_genie_page(0)
            for dev in first_page:
                d = extraer_dispositivo(dev)
                if d:
                    dispositivos.append(d)
            
            if len(first_page) == PAGE:
                # Puede haber más páginas — cargarlas en paralelo
                skips = list(range(PAGE, 4000, PAGE))  # max 4000 para seguridad
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    for page_data in executor.map(fetch_genie_page, skips):
                        for dev in page_data:
                            d = extraer_dispositivo(dev)
                            if d:
                                dispositivos.append(d)
                        if len(page_data) < PAGE:
                            break  # última página
                            
            print(f'[GENIEACS] Total IPs dispositivos: {len(dispositivos)}')
        except Exception as e:
            print(f'[GENIEACS] Excepción: {e}')
            return jsonify({'success': False, 'error': f'Error al consultar dispositivos: {str(e)}'})

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
                    'estado': 'Solo Dispositivos'
                })
        def ip_key(ip_str):
            return tuple(int(part) for part in ip_str.split('.') if part.isdigit())
        resultado.sort(key=lambda x: ip_key(x['ip']))
        print(f'[COMPARA] Total resultado: {len(resultado)}')
        estados = ['Ambos', 'Solo Wisphub', 'Solo Dispositivos']
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

    cnt_ambos = sum(1 for r in filtrados if r['estado'] == 'Ambos')
    cnt_wisphub = sum(1 for r in filtrados if r['estado'] == 'Solo Wisphub')
    cnt_genie = sum(1 for r in filtrados if r['estado'] == 'Solo Dispositivos')

    return jsonify({
        'success': True, 
        'ips': resultado_pagina, 
        'estados': estados, 
        'segmentos': segmentos, 
        'page': page, 
        'total_pages': total_pages, 
        'total': total, 
        'page_size': page_size,
        'cnt_ambos': cnt_ambos,
        'cnt_wisphub': cnt_wisphub,
        'cnt_genie': cnt_genie
    })
