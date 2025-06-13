# SKYPass - Sistema Integral de Gestión de Clientes y Automatización

**SKYPass** es una plataforma web desarrollada en Python (Flask) y Bootstrap, diseñada para la gestión de clientes de servicios de internet, automatización de notificaciones vía WhatsApp y administración avanzada de dispositivos (integración GenieACS). Incluye un microservicio Node.js para WhatsApp (Baileys) y utiliza SQLite para máxima portabilidad.

---

## ✨ Características principales

- **Gestión de clientes y usuarios** con panel de administración, búsqueda y filtros avanzados.
- **Visualización y control de dispositivos** conectados (routers) vía integración con GenieACS.
- **Automatización de notificaciones** y flujos conversacionales por WhatsApp (microservicio Baileys).
- **Interfaz moderna y responsiva** gracias a Bootstrap.
- **Base de datos local** (SQLite) fácil de instalar y mantener.
- **Seguridad**: control de acceso, límites de cambios y logs de auditoría.
- **Despliegue sencillo** en Linux, con soporte para Docker y servicios systemd.

---

## 📁 Estructura del proyecto

```
skypass/
│
├── app.py                # Aplicación principal Flask
├── admin.py              # Módulo de administración y utilidades
├── soporte.py            # Módulo de soporte y vistas protegidas
├── init_db.py            # Script para inicializar la base de datos
├── sqlite_schema.sql     # Esquema SQL de la base de datos
├── requirements.txt      # Dependencias Python
├── PASO_A_PRODUCCION.txt # Guía detallada de despliegue en producción
│
├── base-baileys-memory/  # Microservicio WhatsApp (Node.js/Baileys)
│   ├── app.js
│   ├── bot_sessions/
│   └── README.md
│
├── static/               # Archivos estáticos (CSS, imágenes)
├── templates/            # Plantillas HTML (usuarios, admin, soporte)
└── monitor-bot.sh        # Script de monitoreo automático del bot
```

---

## 🗄️ Esquema de la base de datos (SQLite)

- **admin_users**: Usuarios administradores (id, username, email, password)
- **admin_settings**: Configuración global clave-valor
- **change_history**: Historial de cambios realizados por usuarios/admins
- **change_limits**: Control de límites de cambios por usuario/mes
- **user_limits**: Límites personalizados por IP

> El script `init_db.py` crea automáticamente las tablas necesarias.

---

## 🚀 Instalación rápida

### 1. Requisitos previos

- Python 3.8+
- Node.js 16+ (para el bot WhatsApp)
- Git
- (Opcional) Nginx, Docker

### 2. Clona el repositorio

```bash
git clone https://github.com/tu_usuario/skypass.git
cd skypass
```

### 3. Entorno virtual e instalación de dependencias

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Inicializa la base de datos

```bash
python init_db.py
```

### 5. Configura variables de entorno

Crea un archivo `.env` en la raíz con tus claves:

```
SECRET_KEY=tu_clave_secreta
API_KEY_WISPHUB=tu_api_key
GENIEACS_API_URL=tu_url_genieacs
IP_SERVER=tu_ip
```

---

## 🤖 Microservicio WhatsApp (Baileys)

### Instalación

```bash
cd base-baileys-memory
npm install
npm start
```

- Sube tu archivo `creds.json` a `base-baileys-memory/bot_sessions/`
- Consulta la [documentación oficial de Baileys](https://bot-whatsapp.netlify.app/) para flujos avanzados.

---

## 🛡️ Despliegue en producción (Linux)

### 1. Instala dependencias del sistema

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential python3 python3-pip python3-venv git nginx
```

### 2. Configura servicios systemd

- Crea servicios para el bot y la app Flask usando Gunicorn (ver ejemplos en `PASO_A_PRODUCCION.txt`).
- Configura Nginx como proxy inverso para servir la app en producción.
- (Opcional) Configura HTTPS con Let's Encrypt.

### 3. Monitoreo automático

Utiliza `monitor-bot.sh` y cron para reiniciar el bot WhatsApp si se cae.

---

## 🐳 Docker (opcional)

Si prefieres Docker, crea un `Dockerfile` y ejecuta:

```bash
docker build -t skypass .
docker run -d -p 8000:8000 --name skypass skypass
```

---

## 📝 Notas y buenas prácticas

- Protege tu base de datos y archivos sensibles (.env, creds.json).
- Reinicia los servicios tras cualquier cambio de código.
- Consulta los logs de systemd y Nginx para depuración.
- Personaliza los límites y configuraciones desde el panel admin.

---

## 📚 Recursos útiles

- [Documentación Baileys/WhatsApp](https://bot-whatsapp.netlify.app/)
- [Roadmap y comunidad](https://github.com/orgs/codigoencasa/projects/1)
- [Discord de soporte](https://link.codigoencasa.com/DISCORD)

---

## ❓ Soporte

¿Dudas o problemas?  
Revisa este README, el archivo `PASO_A_PRODUCCION.txt` o contacta al desarrollador principal.

--- 