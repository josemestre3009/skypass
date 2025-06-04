# SKYPass - Sistema de Gestión de Clientes

**SKYPass** es una aplicación web desarrollada en Flask (Python) con Bootstrap, diseñada para la gestión de clientes de servicios de internet SKY. Permite administrar usuarios, visualizar dispositivos conectados (integración con GenieACS), y cuenta con un microservicio de WhatsApp para notificaciones automáticas. Utiliza SQLite como base de datos para facilitar la instalación y portabilidad.

---

## Características principales

- Gestión de clientes y usuarios.
- Panel de administración con búsqueda rápida y filtros.
- Visualización de dispositivos conectados (routers) vía GenieACS.
- Integración con WhatsApp (microservicio Baileys).
- Interfaz moderna y responsiva (Bootstrap).
- Base de datos local (SQLite).

---

# Instalación y despliegue en Linux (Producción)

A continuación tienes una guía paso a paso para instalar y ejecutar la aplicación en un servidor Linux.

## 1. Requisitos previos

- Python 3.8 o superior
- Git
- (Opcional) Docker y Docker Compose
- (Opcional) Servidor web como Nginx para servir en producción

---

## 2. Clonar el repositorio

```bash
git clone https://github.com/tu_usuario/skypass.git
cd skypass
```

---

## 3. Crear y activar un entorno virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 4. Instalar dependencias

```bash
pip install -r requirements.txt
```

---

## 5. Inicializar la base de datos

```bash
python init_db.py
```

Esto creará el archivo `skypass.db` con las tablas necesarias.

---

## 6. (Opcional) Configurar variables de entorno

Si necesitas variables de entorno (por ejemplo, para claves o configuraciones), crea un archivo `.env` en la raíz del proyecto.

---

## 7. Ejecutar la aplicación en modo producción

**Recomendado:** Usa un servidor WSGI como Gunicorn.

```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

Esto levantará la app en el puerto 8000 con 4 workers.

---

## 8. (Opcional) Configurar Nginx como proxy inverso

1. Instala Nginx:
   ```bash
   sudo apt update && sudo apt install nginx
   ```
2. Crea un archivo de configuración para tu sitio, por ejemplo `/etc/nginx/sites-available/skypass`:
   ```nginx
   server {
       listen 80;
       server_name tu_dominio.com;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
3. Habilita el sitio y recarga Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/skypass /etc/nginx/sites-enabled/
   sudo systemctl reload nginx
   ```

---

## 9. (Opcional) Usar Docker

Si prefieres usar Docker, asegúrate de tener el archivo `Dockerfile` y ejecuta:

```bash
docker build -t skypass .
docker run -d -p 8000:8000 --name skypass skypass
```

---

## 10. Notas adicionales

- Para ejecutar el microservicio de WhatsApp, sigue las instrucciones específicas en la carpeta correspondiente.
- Recuerda proteger tu base de datos y archivos sensibles.
- Puedes personalizar la configuración de Gunicorn y Nginx según tus necesidades.

---

¿Dudas? ¡Revisa este README o contacta al desarrollador principal. 