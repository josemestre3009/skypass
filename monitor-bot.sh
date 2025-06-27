#!/bin/bash

URL="http://localhost:3002/status"
RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/status.json "$URL")
BODY=$(cat /tmp/status.json)
NOW=$(date)
LOG_FILE=~/monitor-bot.log

echo "$NOW: HTTP $RESPONSE - Respuesta: $BODY" >> "$LOG_FILE"

if [ "$RESPONSE" -eq 200 ]; then
  if echo "$BODY" | jq -e '.conectado == true' > /dev/null 2>&1; then
    echo "$NOW: Bot conectado correctamente." >> "$LOG_FILE"
  else
    echo "$NOW: Bot NO conectado. Reiniciando..." >> "$LOG_FILE"
    sudo systemctl restart bot-baileys
    sleep 15
  fi
else
  echo "$NOW: Fallo HTTP $RESPONSE. Reiniciando..." >> "$LOG_FILE"
  sudo systemctl restart bot-baileys
  sleep 15
fi
