# 1. Обновление списка пакетов и установка необходимых утилит
apt update
apt install -y wget curl iptables gnupg2 dirmngr openresolv

# 2. Добавление GPG ключа Amnezia PPA
wget -qO- "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x57290828" | gpg --dearmor -o /usr/share/keyrings/amnezia-ppa.gpg
# 3. Добавление PPA репозитория в отдельный файл
echo "deb [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | tee /etc/apt/sources.list.d/amnezia.list
echo "deb-src [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | tee -a /etc/apt/sources.list.d/amnezia.list

# 4. Обновление списка пакетов и установка AmneziaWG
apt update
apt install -y amneziawg

# 5. Установка зависимостей для скрипта
apt install -y python3 python3-pip python3-qrcode python3-requests
# 6. Создаём директорию для awgcreate
mkdir -p ~/awg && cd ~/awg
# Скачиваем awgcreate для работы с конфигами AWG
wget -O awgcreate.py https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.py
