# Sistema de Gestión de Clientes SKY

## Descripción General

Sistema web integral para la gestión de clientes de SKY, desarrollado con **Flask** (Python) y **Bootstrap 5**.  
Incluye autenticación de dos factores por WhatsApp, base de datos en **Supabase**, gestión de dispositivos de red con **GenieACS** y un microservicio de WhatsApp usando **Baileys** (Node.js).

---

## Características Principales

- **Verificación de clientes** por cédula y código enviado por WhatsApp.
- **Dashboard de usuario** para ver información y realizar cambios.
- **Cambio de contraseña y nombre de red WiFi** (con límites mensuales).
- **Panel de administración** para gestión de clientes, estadísticas y configuración.
- **Integración con GenieACS** para modificar parámetros de red.
- **Microservicio WhatsApp** para envío de mensajes y autenticación.

---

## Requisitos

- Python 3.8+
- Node.js 18+
- PostgreSQL (gestionada por Supabase)
- Twilio (o microservicio Baileys para WhatsApp)
- GenieACS (API para gestión de dispositivos)

---

## Instalación Paso a Paso

### 1. Clona el repositorio

```bash
git clone [URL_DEL_REPOSITORIO]
cd [NOMBRE_DEL_DIRECTORIO]
```

### 2. Configura el entorno de Python

```bash
python -m venv venv
# En Windows:
venv\Scripts\activate
# En Linux/Mac:
source venv/bin/activate
```

### 3. Instala las dependencias de Python

```bash
pip install -r requirements.txt
```

### 4. Configura las variables de entorno

Crea un archivo `.env` en la raíz con el siguiente contenido (ajusta los valores):

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

---

### 5. Configura el microservicio de WhatsApp (Baileys)

#### a) Entra a la carpeta del microservicio

```bash
cd base-baileys-memory
```

#### b) Instala las dependencias de Node.js

```bash
npm install
```

#### c) Inicia el microservicio

```bash
npm start
```

La primera vez te pedirá escanear un QR con el WhatsApp que quieres usar.

---

### 6. Inicia la aplicación principal (Flask)

Desde la raíz del proyecto (no dentro de la carpeta del bot):

```bash
python app.py
```

El servidor Flask estará disponible en:  
`http://localhost:5000`

---

### 7. (Opcional) Uso con Docker

#### Microservicio WhatsApp

Ya tienes un `Dockerfile` en `base-baileys-memory/`.  
Para construir y correr el microservicio con Docker:

```bash
cd base-baileys-memory
docker build -t whatsapp-bot .
docker run -p 3002:3002 whatsapp-bot
```

#### ¿Quieres dockerizar todo el sistema?  
Pídelo y te genero un `docker-compose.yml` para Flask + Node.js.

---

## Estructura del Proyecto

```
├── app.py                 # Aplicación principal Flask
├── admin.py               # Lógica de administración
├── requirements.txt       # Dependencias Python
├── .env                   # Variables de entorno
├── static/                # Archivos estáticos (CSS, imágenes)
├── templates/             # Plantillas HTML (admin y usuarios)
├── base-baileys-memory/   # Microservicio WhatsApp (Node.js)
│   ├── app.js             # Lógica principal del bot
│   ├── package.json       # Dependencias Node.js
│   ├── Dockerfile         # Docker para el microservicio
│   └── bot_sessions/      # Sesiones y credenciales del bot
```

---

## Flujos de Usuario

### Cliente

1. Ingresa su cédula.
2. Recibe un código por WhatsApp.
3. Ingresa el código y accede al dashboard.
4. Puede cambiar su clave o nombre de red WiFi (limitado por mes).

### Administrador

1. Accede al panel de control.
2. Gestiona clientes, ve estadísticas, historial y configura límites.

---

## Configuración de Servicios

- **Twilio**: Cuenta activa, servicio Verify y número de WhatsApp verificado.
- **Supabase**: Proyecto creado y tablas configuradas (`change_history`, `user_limits`, `admin_settings`).
- **GenieACS**: API accesible y endpoints `/devices`, `/devices/{deviceId}/tasks` disponibles.

---

## Seguridad

- Verificación de identidad por WhatsApp.
- Límites de cambios mensuales.
- Sesiones seguras y protección de rutas.

---

## Desarrollo y Producción

- **Desarrollo**:  
  Ejecuta `python app.py` y `npm start` en el microservicio.
- **Producción**:  
  Usa WSGI (gunicorn/uwsgi), configura SSL y ajusta variables de entorno.

---

## Contacto y Licencia

- [Agrega aquí tu información de contacto]
- [Especifica la licencia de tu proyecto]

---

¿Quieres agregar instrucciones para despliegue en la nube, integración continua o algo más?  
¿Te gustaría el archivo `docker-compose.yml` para levantar todo con un solo comando?  
¡Dímelo y lo agrego! 