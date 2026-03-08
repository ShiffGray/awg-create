#!/bin/bash
set -e

echo "╔════════════════════════════════════════╗"
echo "║   AmneziaWG + awgcreate Setup          ║"
echo "╚════════════════════════════════════════╝"

# Проверка root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Требуется sudo!"
    exit 1
fi

# 1. Установка AmneziaWG
echo ">>> Установка AmneziaWG..."
curl -sSL https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/AmneziaWG.sh | bash

# 2. Установка Python зависимостей
echo ">>> Установка Python зависимостей..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-qrcode python3-requests python3-socks

# 3. Создание папки и загрузка awgcreate.py
echo ">>> Загрузка awgcreate.py..."
mkdir -p ~/awg && cd ~/awg

curl -sSL -o awgcreate.py https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.py

# Проверка что файл не пустой
if [ ! -s awgcreate.py ]; then
    echo "❌ Ошибка загрузки awgcreate.py!"
    exit 1
fi

chmod +x awgcreate.py
echo "✅ awgcreate.py загружен!"

# 4. Проверка
echo ">>> Проверка..."
if command -v awg &> /dev/null && [ -f awgcreate.py ]; then
    echo "✅ Всё установлено!"
    echo
    echo "Следующие шаги:"
    echo "  cd ~/awg"
    echo "  python3 awgcreate.py --make awg0 -i 10.1.0.1/24 -p 51820"
    echo "  awg-quick up awg0"
else
    echo "❌ Что-то пошло не так!"
    exit 1
fi
