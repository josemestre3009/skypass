#!/bin/bash

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Función para mostrar títulos
show_title() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${CYAN}================================${NC}"
}

# Función para mostrar progreso
show_progress() {
    echo -e "${YELLOW}⏳ $1${NC}"
}

# Función para mostrar éxito
show_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Función para mostrar error
show_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Función para mostrar información
show_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Banner de inicio
clear
echo -e "${PURPLE}"
echo "  ____  _  ____   ______   _    ____ ____   "
echo " / ___|| |/ /\ \ / /  _ \ / \  / ___/ ___|  "
echo " \___ \| ' /  \ V /| |_) / _ \ \___ \___ \  "
echo "  ___) | . \   | | |  __/ ___ \ ___) |__) | "
echo " |____/|_|\_\  |_| |_| /_/   \_\____/____/  "
echo "                                            "
echo -e "${NC}"
echo -e "${WHITE}🚀 INSTALL SKYPASS 🚀${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# 1. ACTUALIZAR SISTEMA
show_title "🔄 ACTUALIZANDO SISTEMA"
show_progress "Actualizando paquetes del sistema..."
apt update > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""
show_success "Sistema actualizado correctamente"

# 2. INSTALAR DEPENDENCIAS
show_title "📦 INSTALANDO DEPENDENCIAS"
show_progress "Instalando Python, Node.js y dependencias..."

# Instalar Python y dependencias
apt install -y build-essential libcairo2-dev libjpeg-dev libpango1.0-dev libgif-dev librsvg2-dev python3 python3-pip python3-venv git > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""

# Instalar Node.js
show_progress "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash - > /dev/null 2>&1
apt install -y nodejs > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""

show_success "Dependencias instaladas correctamente"

# 3. CLONAR PROYECTO
show_title "📥 DESCARGANDO SKYPASS"
show_progress "Clonando repositorio de GitHub..."
cd ~
if [ -d "skypass" ]; then
    rm -rf skypass
fi
git clone https://github.com/josemestre3009/skypass.git > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""
cd ~/skypass
show_success "Proyecto descargado correctamente"

# 4. CONFIGURAR PYTHON
show_title "🐍 CONFIGURANDO PYTHON"
show_progress "Creando entorno virtual de Python..."
python3 -m venv venv > /dev/null 2>&1
source venv/bin/activate

show_progress "Instalando dependencias de Python..."
pip install -r requirements.txt > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""

show_progress "Instalando Gunicorn..."
pip install gunicorn > /dev/null 2>&1
show_success "Python configurado correctamente"

# 5. CONFIGURAR NODE.JS
show_title " CONFIGURANDO NODE.JS"
show_progress "Instalando dependencias de Node.js..."
cd ~/skypass/base-baileys-memory
rm -rf node_modules package-lock.json > /dev/null 2>&1
npm install > /dev/null 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo ""

show_progress "Instalando dependencias adicionales..."
npm install @bot-whatsapp/database-json > /dev/null 2>&1
rm -rf ./db ./bot_sessions > /dev/null 2>&1
show_success "Node.js configurado correctamente"

# 6. CONFIGURAR CREDENCIALES
show_title "🔐 CONFIGURANDO CREDENCIALES"
show_progress "Creando archivo .env automáticamente..."

# Generar SECRET_KEY aleatoria
SECRET_KEY=$(openssl rand -hex 32)

# Pedir API_KEY_WISPHUB al usuario
echo -e "${YELLOW}Ingresa tu API Key de Wisphub:${NC}"
read -p "API Key: " API_KEY_WISPHUB

# Crear archivo .env con localhost
cat > /root/skypass/.env << EOF
SECRET_KEY=$SECRET_KEY
API_KEY_WISPHUB=$API_KEY_WISPHUB
GENIEACS_API_URL=http://localhost:7557
IP_SERVER=localhost
QR_SERVER=localhost:3002
EOF

show_success "Archivo .env creado correctamente"

# 7. CREAR SERVICIOS SYSTEMD
show_title "⚙️ CREANDO SERVICIOS DEL SISTEMA"

# Servicio del Bot
show_progress "Creando servicio del Bot de WhatsApp..."
cat > /etc/systemd/system/bot-baileys.service << 'EOF'
[Unit]
Description=Bot Baileys Skypass
After=network.target

[Service]
User=root
WorkingDirectory=/root/skypass/base-baileys-memory
Environment=PORT=3002
ExecStart=/usr/bin/node app.js
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Servicio de la Web App
show_progress "Creando servicio de la Web App..."
cat > /etc/systemd/system/skypass-web.service << 'EOF'
[Unit]
Description=Skypass Web App
After=network.target

[Service]
User=root
WorkingDirectory=/root/skypass
Environment="PATH=/root/skypass/venv/bin"
ExecStart=/root/skypass/venv/bin/gunicorn -w 4 -b 0.0.0.0:8000 app:app
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

show_success "Servicios creados correctamente"

# 8. INICIAR SERVICIOS
show_title " INICIANDO SERVICIOS"
show_progress "Recargando configuración de systemd..."
systemctl daemon-reload > /dev/null 2>&1

show_progress "Iniciando Bot de WhatsApp..."
systemctl start bot-baileys > /dev/null 2>&1
systemctl enable bot-baileys > /dev/null 2>&1

show_progress "Iniciando Web App..."
systemctl start skypass-web > /dev/null 2>&1
systemctl enable skypass-web > /dev/null 2>&1

# Verificar servicios
sleep 3
if systemctl is-active --quiet bot-baileys && systemctl is-active --quiet skypass-web; then
    show_success "Servicios iniciados correctamente"
else
    show_error "Error al iniciar algunos servicios"
fi

# 9. MOSTRAR ESTADO FINAL
show_title " ESTADO DE LOS SERVICIOS"
echo -e "${WHITE}Bot de WhatsApp:${NC} $(systemctl is-active bot-baileys)"
echo -e "${WHITE}Web App:${NC} $(systemctl is-active skypass-web)"
echo ""

# 10. MOSTRAR ACCESO
show_title " ACCESO A LA APLICACIÓN"
echo -e "${WHITE}SkyPass Web:${NC} http://localhost:8000"
echo -e "${WHITE}Bot API:${NC} http://localhost:3002"
echo ""

# 11. MOSTRAR COMANDOS ÚTILES
show_title "🔧 COMANDOS ÚTILES"
echo -e "${WHITE}Ver logs del Bot:${NC} journalctl -u bot-baileys -f"
echo -e "${WHITE}Ver logs de la Web:${NC} journalctl -u skypass-web -f"
echo -e "${WHITE}Reiniciar Bot:${NC} systemctl restart bot-baileys"
echo -e "${WHITE}Reiniciar Web:${NC} systemctl restart skypass-web"
echo -e "${WHITE}Ver estado:${NC} systemctl status bot-baileys skypass-web"
echo ""

# 12. FINALIZACIÓN
show_title " INSTALACIÓN COMPLETADA"
echo -e "${GREEN}¡SkyPass ha sido instalado exitosamente!${NC}"
echo -e "${YELLOW}El archivo .env se creó automáticamente con tu API Key.${NC}"
echo ""
echo -e "${PURPLE}Gracias por usar SkyPass!${NC}"



