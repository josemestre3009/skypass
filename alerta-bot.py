import requests

API_KEY = 'daGnjD705T9Ips63'
url = "https://api.brevo.com/v3/smtp/email"

data = {
    "sender": {"name": "Alerta Servidor", "email": "8f8977001@smtp-brevo.com"},
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