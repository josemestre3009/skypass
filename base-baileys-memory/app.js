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

const sessionsDir = path.join(__dirname, 'bot_sessions');
if (!fs.existsSync(sessionsDir)) {
    fs.mkdirSync(sessionsDir, { recursive: true });
}

let globalQR = null
let isConnected = false
let providerInstance = null
let estadoBot = 'iniciando' // Puede ser: iniciando, esperando_qr, conectado, desconectado, error

function setEstado(nuevoEstado) {
    estadoBot = nuevoEstado;
    console.log('[DEBUG] Estado actualizado a:', estadoBot);
}

const adapterFlow = createFlow([]) // Sin flujos automáticos

const main = async () => {
    const adapterDB = new JsonFileAdapter({
        path: path.join(__dirname, 'db')
    })
    providerInstance = createProvider(BaileysProvider, { printQRInTerminal: false, generateQr: true })

    // Eventos para QR y estado
    providerInstance.on('require_action', async (ctx) => {
        console.log('[DEBUG] Evento require_action:', ctx);
        // Si trae action: 'qr', o si las instrucciones incluyen el texto de escanear QR
        if (
            (ctx.action && ctx.action === 'qr') ||
            (ctx.instructions && Array.isArray(ctx.instructions) && ctx.instructions.some(instr => instr.toLowerCase().includes('qr code')))
        ) {
            // Forzar desconexión si estaba conectado
            if (isConnected) {
                isConnected = false;
                if (providerInstance.logout) {
                    try { await providerInstance.logout(); } catch (e) { /* ignorar error */ }
                }
            }
            globalQR = ctx.qr || null;
            setEstado('esperando_qr');
            console.log('[ESTADO BOT] QR recibido, esperando escaneo');
        }
    })
    providerInstance.on('ready', () => {
        console.log('[DEBUG] Evento ready');
        isConnected = true
        globalQR = null
        setEstado('conectado');
        console.log('[ESTADO BOT] Cliente listo, conexión exitosa')
    })
    providerInstance.on('close', () => {
        console.log('[DEBUG] Evento close');
        isConnected = false
        globalQR = null
        setEstado('desconectado');
        console.log('[ESTADO BOT] Conexión cerrada o perdida')
    })
    providerInstance.on('error', (err) => {
        console.log('[DEBUG] Evento error:', err);
        isConnected = false
        globalQR = null
        setEstado('error');
        console.log('[ESTADO BOT] Error inesperado:', err)
    })

    createBot({
        flow: adapterFlow,
        provider: providerInstance,
        database: adapterDB,
    })

    QRPortalWeb({ port: 5050 })
}

main()

// --- Endpoints HTTP para integración Flask ---
// QR para conectar WhatsApp
app.get('/qr', (req, res) => {
    if (globalQR && !isConnected) {
        // Devuelvo tanto la URL como el texto QR puro para depuración
        res.json({ 
            qr: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(globalQR)}&size=220x220`,
            qr_text: globalQR
        })
        // También imprimo el QR en consola para depuración manual
        console.log('QR generado para WhatsApp:', globalQR)
    } else {
        res.json({ qr: null, qr_text: null })
    }
})
// Estado de conexión
app.get('/status', (req, res) => {
    res.json({ conectado: isConnected, estado: estadoBot })
})
// Desconectar sesión
app.post('/disconnect', async (req, res) => {
    console.log('[DEPURACIÓN BOT] Petición recibida para desconectar');
    try {
        if (providerInstance && providerInstance.logout) {
            await providerInstance.logout();
            isConnected = false;
            globalQR = null;
            console.log('[DEPURACIÓN BOT] Bot desconectado correctamente');
            res.json({ success: true });
        } else {
            console.log('[DEPURACIÓN BOT] No se pudo desconectar: método logout no disponible');
            res.json({ success: false, message: 'No se pudo desconectar.' });
        }
    } catch (e) {
        console.log('[DEPURACIÓN BOT] Error al desconectar:', e);
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
