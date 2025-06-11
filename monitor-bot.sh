#!/bin/bash
STATUS=$(curl -s http://localhost:3002/status | grep '\"conectado\":true')
if [ -z "$STATUS" ]; then
  echo "$(date): Bot caído o no responde, reiniciando..." >> ~/monitor-bot.log
  sudo systemctl restart bot-baileys
fi