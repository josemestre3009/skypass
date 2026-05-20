import os
import requests

_API_URL = "https://api.ycloud.com/v2/whatsapp/messages/sendDirectly"
_PHONE_NUMBERS_URL = "https://api.ycloud.com/v2/whatsapp/phoneNumbers"


def normalizar_numero(telefono):
    """Normaliza a formato E.164 colombiano: 57XXXXXXXXXX"""
    numero = ''.join(filter(str.isdigit, str(telefono)))
    if len(numero) == 10:
        numero = '57' + numero
    if len(numero) == 12 and numero.startswith('57'):
        return numero
    return None


def _headers():
    api_key = os.getenv('YCLOUD_API_KEY')
    if not api_key:
        raise ValueError("YCLOUD_API_KEY no configurada en .env")
    return {"Content-Type": "application/json", "X-API-Key": api_key}


def _numero_envio():
    return os.getenv('YCLOUD_SENDER_NUMBER', '573127313737')


def enviar_otp(telefono, codigo):
    """Envía código OTP por WhatsApp usando la plantilla auth_skypass."""
    try:
        headers = _headers()
    except ValueError as e:
        print(f"[YCloud] {e}")
        return False

    data = {
        "from": _numero_envio(),
        "to": telefono,
        "type": "template",
        "template": {
            "name": "auth_skypass",
            "language": {"code": "es_CO", "policy": "deterministic"},
            "components": [
                {
                    "type": "body",
                    "parameters": [{"type": "text", "text": codigo}]
                },
                {
                    "type": "button",
                    "sub_type": "url",
                    "index": "0",
                    "parameters": [{"type": "text", "text": codigo}]
                }
            ]
        }
    }
    try:
        resp = requests.post(_API_URL, json=data, headers=headers, timeout=15)
        resp.raise_for_status()
        print(f"[YCloud] OTP enviado a {telefono}. ID: {resp.json().get('id')}")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"[YCloud] ERROR HTTP enviando OTP: {e.response.text}")
        return False
    except Exception as e:
        print(f"[YCloud] ERROR enviando OTP: {e}")
        return False


def enviar_confirmacion_cambio(telefono, mensaje):
    """Envía notificación de cambio WiFi usando la plantilla solicitud_cambio_skypass_v2."""
    try:
        headers = _headers()
    except ValueError as e:
        print(f"[YCloud] {e}")
        return False

    empresa = os.getenv('EMPRESA', '')
    data = {
        "from": _numero_envio(),
        "to": telefono,
        "type": "template",
        "template": {
            "name": "solicitud_cambio_skypass_v2",
            "language": {"code": "es_CO", "policy": "deterministic"},
            "components": [
                {
                    "type": "header",
                    "parameters": [{"type": "text", "text": empresa}]
                },
                {
                    "type": "body",
                    "parameters": [{"type": "text", "text": f"*{mensaje}*"}]
                }
            ]
        }
    }
    try:
        resp = requests.post(_API_URL, json=data, headers=headers, timeout=15)
        resp.raise_for_status()
        print(f"[YCloud] Confirmación enviada a {telefono}. ID: {resp.json().get('id')}")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"[YCloud] ERROR HTTP enviando confirmación: {e.response.text}")
        return False
    except Exception as e:
        print(f"[YCloud] ERROR enviando confirmación: {e}")
        return False


def verificar_estado():
    """
    Verifica el estado de conexión del número WhatsApp en YCloud.
    Returns: 'CONNECTED', 'DISCONNECTED', 'UNKNOWN', o None si hay error.
    """
    try:
        headers = _headers()
    except ValueError as e:
        print(f"[YCloud] {e}")
        return None

    sender_id = os.getenv('YCLOUD_SENDER_ID')
    try:
        resp = requests.get(_PHONE_NUMBERS_URL, headers=headers, timeout=10)
        resp.raise_for_status()
        items = resp.json().get('items', [])

        if sender_id:
            for item in items:
                if item.get('id') == sender_id:
                    estado = item.get('status', 'UNKNOWN')
                    print(f"[YCloud] Estado ({sender_id}): {estado}")
                    return estado
            print(f"[YCloud] No se encontró número con ID {sender_id}")
        elif items:
            estado = items[0].get('status', 'UNKNOWN')
            print(f"[YCloud] Estado (primer número): {estado}")
            return estado

        print("[YCloud] No se encontraron números en la cuenta")
        return None
    except Exception as e:
        print(f"[YCloud] ERROR verificando estado: {e}")
        return None
