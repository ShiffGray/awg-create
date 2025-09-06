#!/bin/bash

set -e  # Прекращаем выполнение при ошибке

# Обновляем систему
apt update -y
#apt upgrade -y

#устанавливаем software-properties-common
apt install -y software-properties-common

#устанавливаем iptables:
apt install -y iptables

# Устанавливаем Python и утилиты
apt install -y curl wget python3 python3-pip python3-qrcode

# Добавить исходники
echo "deb-src http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse" | tee -a /etc/apt/sources.list
echo "deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse" | tee -a /etc/apt/sources.list

# Устанавливаем AmneziaWG
add-apt-repository -y ppa:amnezia/ppa
apt install -y amneziawg

# Разрешаем маршрутизацию
echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/00-amnezia.conf
sysctl --system

# Создаём директорию для AmneziaWG
mkdir -p ~/awg && cd ~/awg

# Скачиваем скрипт для работы с конфигами AWG
wget -O awgcreate.py https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.py

# Генерируем основной конфиг AWG
python3 awgcreate.py --make /etc/amnezia/amneziawg/awg0.conf -i 10.1.0.0/24 -p 44567 -l 99 --mtu 1388 --warp 3

# Генерируем шаблон конфигурации
#python3 awgcreate.py --create

# Добавляем клиентов в конфиг
for ip in $(seq 1 27); do
  python3 awgcreate.py -a "$ip"
done

# Генерируем клиентские конфигурации
python3 awgcreate.py -z

# Добавляем в автозагрузку и запускаем сервис
systemctl enable --now awg-quick@awg0
systemctl restart awg-quick@awg0.service

# Проверяем статус созданного сервиса awg-quick@awg0.service:
#systemctl status awg-quick@awg0.service

echo "Установка и настройка AmneziaWG завершена!"
