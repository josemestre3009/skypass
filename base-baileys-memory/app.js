const { createBot, createProvider, createFlow, addKeyword } = require('@bot-whatsapp/bot')
const path = require('path');
const fs = require('fs');

const QRPortalWeb = require('@bot-whatsapp/portal')
const BaileysProvider = require('@bot-whatsapp/provider/baileys')
const JsonFileAdapter = require('@bot-whatsapp/database/json')

// --- Express para microservicio ---
const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const app = express()
app.use(cors())
app.use(bodyParser.json())

// Manejo global de promesas rechazadas
process.on('unhandledRejection', (reason, promise) => {
    console.log('[ERROR] Unhandled Promise Rejection:', reason);
    console.log('[ERROR] Promise:', promise);
    // No terminar el proceso, solo loggear
});

process.on('uncaughtException', (error) => {
    console.log('[ERROR] Uncaught Exception:', error);
    // No terminar el proceso, solo loggear
});

let globalQR = null
let isConnected = false
let providerInstance = null
let estadoBot = 'iniciando' // Puede ser: iniciando, esperando_qr, conectado, desconectado, error
let reconnectAttempts = 0
let maxReconnectAttempts = 5
let reconnectTimeout = null

function setEstado(nuevoEstado) {
    estadoBot = nuevoEstado;
    console.log('[DEBUG] Estado actualizado a:', estadoBot);
}

function resetReconnectAttempts() {
    reconnectAttempts = 0;
}

function scheduleReconnect() {
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
    }
    
    if (reconnectAttempts < maxReconnectAttempts) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000); // Backoff exponencial, máximo 30 segundos
        console.log(`[RECONEXIÓN] Intentando reconectar en ${delay/1000} segundos (intento ${reconnectAttempts + 1}/${maxReconnectAttempts})`);
        
        reconnectTimeout = setTimeout(async () => {
            try {
                reconnectAttempts++;
                await initBot();
            } catch (error) {
                console.log('[ERROR] Error en reconexión:', error);
                // No incrementar intentos aquí, ya se hizo arriba
                scheduleReconnect();
            }
        }, delay);
    } else {
        console.log('[ERROR] Máximo número de intentos de reconexión alcanzado. Bot permanecerá desconectado.');
        setEstado('desconectado'); // Cambiar a 'desconectado' en lugar de 'error'
    }
}

const adapterFlow = createFlow([]) // Sin flujos automáticos

async function initBot() {
    try {
        console.log('[INICIO] Inicializando bot...');
        setEstado('iniciando');
        
        const adapterDB = new JsonFileAdapter({
            path: path.join(__dirname, 'db')
        })
        
        providerInstance = createProvider(BaileysProvider, { 
            printQRInTerminal: false, 
            generateQr: true,
            browser: ['SkyPass Bot', 'Chrome', '1.0.0'],
            markOnlineOnConnect: true
        })

        // Eventos para QR y estado
        providerInstance.on('require_action', async (ctx) => {
            console.log('[DEBUG] Evento require_action:', ctx);
            // Si trae action: 'qr', o si las instrucciones incluyen el texto de escanear QR
            if (
                (ctx.action && ctx.action === 'qr') ||
                (ctx.instructions && Array.isArray(ctx.instructions) && ctx.instructions.some(instr => instr.toLowerCase().includes('qr code')))
            ) {
                globalQR = ctx.qr || null;
                setEstado('esperando_qr');
                resetReconnectAttempts();
                console.log('[ESTADO BOT] QR recibido, esperando escaneo');
            }
        })
        
        providerInstance.on('ready', () => {
            console.log('[DEBUG] Evento ready');
            isConnected = true
            globalQR = null
            setEstado('conectado');
            resetReconnectAttempts();
            console.log('[ESTADO BOT] Cliente listo, conexión exitosa')
        })
        
        providerInstance.on('close', (closeEvent) => {
            console.log('[DEBUG] Evento close:', closeEvent);
            isConnected = false
            globalQR = null
            setEstado('desconectado');
            console.log('[ESTADO BOT] Conexión cerrada o perdida');
            
            // Programar reconexión automática
            scheduleReconnect();
        })
        
        providerInstance.on('error', (err) => {
            console.log('[DEBUG] Evento error:', err);
            isConnected = false
            globalQR = null
            console.log('[ESTADO BOT] Error inesperado:', err);
            
            // Solo reconectar para errores recuperables y no críticos
            if (err.code !== 'ERR_INVALID_CREDENTIALS' && err.code !== 'ERR_SESSION_EXPIRED') {
                setEstado('desconectado'); // Cambiar a desconectado en lugar de error
                scheduleReconnect();
            } else {
                setEstado('desconectado'); // Para errores críticos, solo marcar como desconectado
                console.log('[ESTADO BOT] Error crítico, no se intentará reconexión automática');
            }
        })

        await createBot({
            flow: adapterFlow,
            provider: providerInstance,
            database: adapterDB,
        })

        console.log('[INICIO] Bot inicializado correctamente');
        
    } catch (error) {
        console.log('[ERROR] Error al inicializar bot:', error);
        setEstado('desconectado'); // Cambiar a desconectado en lugar de error
        scheduleReconnect();
    }
}

// Inicializar el bot
initBot();

// Inicializar portal web
QRPortalWeb({ port: 5050 })

// --- Endpoints HTTP para integración Flask ---
// QR para conectar WhatsApp
app.get('/qr', (req, res) => {
    if (globalQR && !isConnected && estadoBot === 'esperando_qr') {
        // Devuelvo tanto la URL como el texto QR puro para depuración
        res.json({ 
            qr: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(globalQR)}&size=220x220`,
            qr_text: globalQR,
            estado: estadoBot
        })
        // También imprimo el QR en consola para depuración manual
        console.log('QR generado para WhatsApp:', globalQR)
    } else {
        res.json({ 
            qr: null, 
            qr_text: null,
            estado: estadoBot,
            conectado: isConnected
        })
    }
})
// Estado de conexión
app.get('/status', (req, res) => {
    res.json({ 
        conectado: isConnected, 
        estado: estadoBot,
        tiene_qr: !!globalQR,
        intentos_reconexion: reconnectAttempts,
        max_intentos: maxReconnectAttempts
    })
})

// Reiniciar bot manualmente
app.post('/restart', async (req, res) => {
    console.log('[DEPURACIÓN BOT] Reinicio manual solicitado');
    try {
        // Limpiar timeout de reconexión si existe
        if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
        }
        
        // Resetear intentos
        resetReconnectAttempts();
        
        // Reiniciar bot
        await initBot();
        
        res.json({ success: true, message: 'Bot reiniciado correctamente' });
    } catch (error) {
        console.log('[ERROR] Error al reiniciar bot:', error);
        res.json({ success: false, error: error.message });
    }
})
// Desconectar sesión
app.post('/disconnect', async (req, res) => {
    console.log('[DEPURACIÓN BOT] Petición recibida para desconectar');
    try {
        if (providerInstance && providerInstance.logout) {
            await providerInstance.logout();
        }
        
        isConnected = false;
        globalQR = null;
        setEstado('desconectado');
        
        // Limpiar timeout de reconexión si existe
        if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
        }
        
        // Reiniciar el bot para generar nuevo QR
        setTimeout(async () => {
            try {
                await initBot();
            } catch (error) {
                console.log('[ERROR] Error al reiniciar bot después de desconexión:', error);
            }
        }, 2000);
        
        console.log('[DEPURACIÓN BOT] Bot desconectado correctamente, reiniciando...');
        res.json({ success: true });
    } catch (e) {
        console.log('[DEPURACIÓN BOT] Error al desconectar:', e);
        res.json({ success: false, message: e.message });
    }
})

// Forzar reconexión
app.post('/reconnect', async (req, res) => {
    console.log('[DEPURACIÓN BOT] Petición recibida para reconectar');
    try {
        // Limpiar timeout de reconexión si existe
        if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
        }
        
        // Resetear intentos de reconexión
        resetReconnectAttempts();
        
        // Reiniciar el bot
        await initBot();
        
        console.log('[DEPURACIÓN BOT] Bot reiniciado correctamente');
        res.json({ success: true, message: 'Bot reiniciado correctamente' });
    } catch (e) {
        console.log('[DEPURACIÓN BOT] Error al reconectar:', e);
        res.json({ success: false, message: e.message });
    }
})

// Enviar mensaje/código
app.post('/send', async (req, res) => {
    let { telefono, mensaje } = req.body;
    console.log('[DEPURACIÓN BOT] Teléfono recibido:', telefono);
    console.log('[DEPURACIÓN BOT] Mensaje:', mensaje);
    // Forzar sufijo @s.whatsapp.net si no lo tiene
    if (!telefono.endsWith('@s.whatsapp.net')) {
        telefono = telefono + '@s.whatsapp.net';
    }
    console.log('[DEPURACIÓN BOT] Teléfono final a enviar:', telefono);
    if (!telefono || !mensaje) {
        return res.status(400).json({ success: false, message: 'Faltan parámetros.' });
    }
    try {
        if (!isConnected) {
            return res.status(400).json({ success: false, message: 'El bot no está conectado.' });
        }
        await providerInstance.sendText(telefono, mensaje);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Endpoint para servir la imagen QR generada localmente
app.get('/qr-image', (req, res) => {
    const qrPath = path.join(__dirname, 'bot.qr.png');
    if (fs.existsSync(qrPath)) {
        res.sendFile(qrPath);
    } else {
        res.status(404).send('QR no generado');
    }
});

const PORT = process.env.PORT || 3002
app.listen(PORT, () => {
    console.log(`WhatsApp bot escuchando en http://localhost:${PORT}`)
})

setInterval(async () => {
    if (isConnected && providerInstance && providerInstance.getInstance) {
        try {
            const sock = await providerInstance.getInstance();
            if (!sock?.user) {
                isConnected = false;
                globalQR = null;
                setEstado('desconectado');
                console.log('[DEPURACIÓN BOT] Sesión perdida, WhatsApp desconectado.');
            }
        } catch (e) {
            isConnected = false;
            globalQR = null;
            setEstado('desconectado');
            console.log('[DEPURACIÓN BOT] Error al verificar sesión, WhatsApp desconectado:', e);
        }
    }
}, 15000); // cada 15 segundos
