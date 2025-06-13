import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("BREVO_API_KEY")

url = "https://api.brevo.com/v3/smtp/email"

data = {
    "sender": {"name": "Alerta Servidor", "email": "jmestresaucedo@gmail.com"},
    "to": [{"email": "jmestresaucedo@gmail.com", "name": "Jose"}],
    "subject": "Alerta: Bot WhatsApp",
    "htmlContent": "<h2>¡El bot de WhatsApp ha fallado!</h2><p>Revisa el servidor.</p>"
}

headers = {
    "accept": "application/json",
    "api-key": API_KEY,
    "content-type": "application/json"
}

response = requests.post(url, json=data, headers=headers)
print(response.status_code, response.text)