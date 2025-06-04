# Sistema de Gestión de Clientes SKY

## Descripción del Proyecto
Este proyecto desarrolla un sistema web integral para la gestión de clientes de SKY, implementado con Flask (Python 3.8+) y Bootstrap 5 para el frontend. El sistema utiliza autenticación de dos factores mediante Twilio Verify API, enviando códigos de verificación por WhatsApp. La base de datos PostgreSQL se gestiona a través de Supabase, almacenando información de clientes, historial de cambios y configuraciones de administrador. La gestión de dispositivos de red se realiza mediante la API REST de GenieACS, permitiendo modificar parámetros como SSID y contraseñas WiFi. El sistema implementa control de sesiones seguras, límites de cambios mensuales por cliente, y un panel de administración con estadísticas en tiempo real. La arquitectura sigue el patrón MVC, con blueprints de Flask para separar la lógica de administración y cliente, y utiliza variables de entorno para configuración segura.

## Características Principales
- **Verificación de Clientes**: Validación mediante cédula y código enviado por WhatsApp.
- **Dashboard de Usuario**: Interfaz para ver información del cliente y realizar cambios.
- **Cambio de Contraseña**: Permite al cliente modificar la contraseña de su red WiFi.
- **Cambio de Nombre de Red**: Permite al cliente modificar el nombre (SSID) de su red WiFi.
- **Límites de Cambios**: Control de cambios mensuales por cliente.
- **Panel de Administración**: Gestión de clientes, estadísticas y configuración del sistema.

## Requisitos
- Python 3.8+
- Flask
- Twilio (para envío de códigos por WhatsApp)
- Supabase (base de datos)
- GenieACS (API para gestión de dispositivos)

## Instalación

1. Clonar el repositorio:
```bash
git clone [URL_DEL_REPOSITORIO]
cd [NOMBRE_DEL_DIRECTORIO]
```

2. Crear y activar entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar variables de entorno:
Crear archivo `.env` con las siguientes variables:
```
SECRET_KEY=tu_clave_secreta
API_KEY_WISPHUB=tu_api_key_wisphub
TWILIO_ACCOUNT_SID=tu_sid_twilio
TWILIO_AUTH_TOKEN=tu_token_twilio
TWILIO_PHONE=tu_numero_twilio
TWILIO_VERIFY_SID=tu_verify_sid
SUPABASE_URL=tu_url_supabase
SUPABASE_KEY=tu_key_supabase
GENIEACS_API_URL=url_api_genieacs
DEBUG_VERIFICACION=false
```

## Estructura del Proyecto
```
├── app.py                 # Aplicación principal
├── admin.py              # Módulo de administración
├── requirements.txt      # Dependencias
├── .env                 # Variables de entorno
├── static/              # Archivos estáticos
│   ├── css/
│   ├── js/
│   └── img/
└── templates/           # Plantillas HTML
    ├── admin/          # Plantillas de administración
    └── users/          # Plantillas de usuario
```

## Flujos de Usuario

### Cliente
1. **Login**:
   - Ingresa cédula
   - Recibe código por WhatsApp
   - Ingresa código de verificación
   - Accede al dashboard

2. **Dashboard**:
   - Visualiza información del cliente
   - Accede a opciones de cambio de contraseña y nombre de red
   - Ve historial de cambios realizados

3. **Cambios**:
   - Cambio de contraseña WiFi
   - Cambio de nombre de red
   - Límite mensual de cambios configurable

### Administrador
1. **Panel de Control**:
   - Gestión de clientes
   - Visualización de estadísticas
   - Configuración de límites
   - Historial de cambios

## Tecnologías Utilizadas
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, Bootstrap 5
- **Base de Datos**: Supabase
- **Mensajería**: Twilio (WhatsApp)
- **Gestión de Dispositivos**: GenieACS API

## Seguridad
- Verificación de identidad mediante WhatsApp
- Límites de cambios por mes
- Sesiones seguras
- Protección de rutas

## Desarrollo
Para ejecutar en modo desarrollo:
```bash
python app.py
```
El servidor se iniciará en `http://localhost:5000`

## Producción
Para despliegue en producción:
1. Configurar servidor web (nginx/apache)
2. Usar WSGI (gunicorn/uwsgi)
3. Configurar SSL
4. Ajustar variables de entorno


## Licencia
[Especificar licencia]

## Contacto
[Información de contacto]

## Configuración

### Variables de Entorno
Crear archivo `.env` con las siguientes variables:
```
SECRET_KEY=tu_clave_secreta
API_KEY_WISPHUB=tu_api_key_wisphub
TWILIO_ACCOUNT_SID=tu_sid_twilio
TWILIO_AUTH_TOKEN=tu_token_twilio
TWILIO_PHONE=tu_numero_twilio
TWILIO_VERIFY_SID=tu_verify_sid
SUPABASE_URL=tu_url_supabase
SUPABASE_KEY=tu_key_supabase
GENIEACS_API_URL=url_api_genieacs
DEBUG_VERIFICACION=false
```

### Configuración de Servicios

1. **Twilio**
   - Cuenta activa en Twilio
   - Servicio Verify configurado
   - Número de WhatsApp verificado

2. **Supabase**
   - Proyecto creado
   - Tablas configuradas:
     - change_history
     - user_limits
     - admin_settings

3. **GenieACS**
   - API configurada y accesible
   - Endpoints disponibles:
     - /devices
     - /devices/{deviceId}/tasks

### Modo Desarrollo
Para pruebas, se puede activar el modo desarrollo configurando:
```
DEBUG_VERIFICACION=true
```
Esto simulará el envío de códigos sin usar Twilio.

### 5. Configuración de Logs
- Crear directorio `logs`
- Configurar logging en `app.py`

### 6. Configuración de SSL (Producción)
- Obtener certificado SSL
- Configurar nginx para HTTPS

### 7. Backup y Monitoreo
- Configurar backup automático de Supabase
- Programar backup de logs
- Configurar monitoreo de servicios y alertas

## Microservicio WhatsApp con Baileys (Node.js)

Este proyecto incluye un microservicio en Node.js que permite conectar un número de WhatsApp escaneando un QR desde el dashboard y enviar mensajes desde la app Flask.

### Instalación y uso

1. En la raíz del proyecto, crea la carpeta `whatsapp-baileys-bot`.
2. Dentro de esa carpeta, ejecuta:
   ```bash
   npm init -y
   npm install @whiskeysockets/baileys express cors qrcode
   ```
3. Crea el archivo `index.js` con el código proporcionado en la documentación.
4. Ejecuta el microservicio con:
   ```bash
   node index.js
   ```
5. Desde Flask, puedes consumir los endpoints:
   - `GET /qr` para mostrar el QR en el dashboard.
   - `POST /enviar` para enviar mensajes de WhatsApp.

### Notas
- Solo permite una sesión de WhatsApp a la vez (para multiusuario se requiere lógica adicional).
- El microservicio debe estar corriendo para que la integración funcione. 