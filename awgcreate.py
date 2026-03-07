#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AmneziaWG / WireGuard Helper Script
Features:
- Multi-interface support (split system/work paths).
- Strict Fallback for DsYt IPs.
- Smart path resolution for --make.
- Selective QR generation via _allowedips.config tags.
- Automatic ZIP packaging with file directory support.
"""

from __future__ import annotations
import argparse
import datetime
import glob
import ipaddress
import logging
import math
import os
import pathlib
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
import base64
from typing import Dict, List, Optional, Tuple, Set

# ----------------- Сторонние библиотеки -----------------
try:
    import requests
except ImportError:
    print("❌ Ошибка: Библиотека 'requests' не найдена. Установите её: pip install requests")
    sys.exit(1)

try:
    import qrcode
except ImportError:
    qrcode = None

# ----------------- Настройки логирования -----------------
# Короткий формат: время (час:мин:сек) + смайлик уровня + сообщение
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("awgcreate")

# ----------------- Пути и Константы -----------------
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

# Глобальный указатель на последний активный конфиг
g_main_config_src = SCRIPT_DIR.joinpath("_main.config")

# Глобальные переменные состояния (инициализируются в init_interface_paths)
g_work_dir: pathlib.Path = SCRIPT_DIR
g_conf_dir: pathlib.Path = SCRIPT_DIR.joinpath("conf")
g_file_dir: pathlib.Path = SCRIPT_DIR.joinpath("file")
g_defclient_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_defclient.config")
g_endpoint_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_endpoint.config")
g_allowedips_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_allowedips.config")

g_main_config_fn: Optional[pathlib.Path] = None
g_main_config_type: Optional[str] = None  # 'WG' или 'AWG'
clients_for_zip: List[str] = []

# ----------------- Шаблоны -----------------

g_defserver_config = """
[Interface]
#_GenKeyTime = <SERVER_KEY_TIME>
#_PublicKey = <SERVER_PUBLIC_KEY>
Address = <SERVER_ADDR>
ListenPort = <SERVER_PORT>
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
S1 = <S1>
S2 = <S2>
H1 = <H1>
H2 = <H2>
H3 = <H3>
H4 = <H4>
MTU = <MTU>
PrivateKey = <SERVER_PRIVATE_KEY>

PostUp = bash <SERVER_UP_SCRIPT>
PostDown = bash <SERVER_DOWN_SCRIPT>
"""

g_defclient_config = """
[Interface]
Address = <CLIENT_TUNNEL_IP>
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
S1 = <S1>
S2 = <S2>
H1 = <H1>
H2 = <H2>
H3 = <H3>
H4 = <H4>
MTU = <MTU>
PrivateKey = <CLIENT_PRIVATE_KEY>

[Peer]
Endpoint = <ENDPOINT>:<SERVER_PORT>
PersistentKeepalive = <PERSISTENT_KEEPALIVE>
PresharedKey = <PRESHARED_KEY>
PublicKey = <SERVER_PUBLIC_KEY>
AllowedIPs = <ALLOWED_IPS>
"""

g_warp_config = """
[Interface]
Address = <WARP_ADDRESS>
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
H1 = 1
H2 = 2
H3 = 3
H4 = 4
MTU = <MTU>
PrivateKey = <WARP_PRIVATE_KEY>
Table = off

[Peer]
Endpoint = <WARP_ENDPOINT>
PersistentKeepalive = <PERSISTENT_KEEPALIVE>
PublicKey = <WARP_PEER_PUBLIC_KEY>
AllowedIPs = 0.0.0.0/0, ::/0
"""

# Шаблоны up/down с поддержкой WARP
up_script_template_warp = '''#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"
QUANT="4400"

# --- Подсеть ---
LOCAL_SUBNETS="<SERVER_ADDR>"                                  # Подсеть VPN (пример: 10.1.0.0/23)

# --- Ограничения скорости для подсетей ---
SUBNETS_LIMITS=(
  "<SERVER_ADDR>:<RATE_LIMIT>"
)
# --- Список WARP-интерфейсов с маршрутизацией ---
# Формат: "interface1,interface2=subnet1, subnet2" или "interface1,interface2" (для всего трафика)
# Примеры:
#   "warp0,warp1=100.24.0.0/13, 104.16.0.0/12"  # Группа WARP для конкретных подсетей
#   "warp2,warp3"                                 # Группа WARP для всего остального
#   "warp4=8.8.8.8, 1.1.1.1"                     # Одиночный WARP для DNS
#   "none=192.168.0.0/16, 10.0.0.0/8"           # Подсети для прямого маршрута (мимо WARP)
WARP_LIST=(
<WARP_LIST>
)
# --- Локальная сеть между клиентами ---
LAN_ALLOW=(
  "<SERVER_ADDR>"
)
# --- Пробросы портов ---
PORT_FORWARDING_RULES=(
  #"ЛокальныйIP:ВнешнийПорт[-Диапазон][>ВнутреннийПорт[-Диапазон]]:TCP/UDP[:Список_разрешённых_подсетей][:SNAT]"
  #"10.1.0.1:80:TCP"
  #"10.1.0.2:443:TCP:SNAT"
  #"10.1.0.3:8080:UDP:192.168.0.1:SNAT"
  #"10.1.0.4:3000>3389:TCP:SNAT"
  #"10.1.0.5:2000-2100>4000-4100:UDP"
  #"10.1.0.6:8080:TCP:192.168.0.0/20, 10.0.0.0/23, 10.1.1.1:SNAT"
  #"10.1.0.7:9000:UDP:10.1.0.0/24, 10.10.10.0/24"
)

# "Безопасное" имя туннеля для суффиксов (только буквы/цифры/_)
TUN_SAFE="$(echo "$TUN" | sed 's/[^a-zA-Z0-9]/_/g')"
# Суффиксированные/уникальные имена цепочек/ресурсов
PF_CHAIN_NAT="PORT_FORWARD_NAT_${TUN_SAFE}"
PF_CHAIN_FILTER="PORT_FORWARD_FILTER_${TUN_SAFE}"
PF_CHAIN_SNAT="PORT_FORWARD_SNAT_${TUN_SAFE}"
RANDOM_WARP_CHAIN="RANDOM_WARP_${TUN_SAFE}"
IFB_IN="ifb_${TUN_SAFE}_in"
IFB_OUT="ifb_${TUN_SAFE}_out"
INPUT_CHAIN="INPUT_${TUN_SAFE}"
HAIRPIN_CHAIN="HAIRPIN_${TUN_SAFE}"

echo "————————————————————————————————"

# --- Включаем IP forwarding если выключен ---
if [ $(sysctl -n net.ipv4.ip_forward) -eq 1 ]; then
    echo "✅ IPv4 forwarding включён"
else
    echo "❌ IPv4 forwarding ВЫКЛЮЧЕН! Включаю..."
    sysctl -w net.ipv4.ip_forward=1
fi

if [ $(sysctl -n net.ipv6.conf.all.forwarding) -eq 1 ]; then
    echo "✅ IPv6 forwarding включён"
else
    echo "❌ IPv6 forwarding ВЫКЛЮЧЕН! Включаю..."
    sysctl -w net.ipv6.conf.all.forwarding=1
fi

# --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
# Формат: "10.1.0.0/24" или "10.1.0.0/24, fd00::/120" (с пробелами и без)
# Разделяем подсети по запятой и обрезаем пробелы
LOCAL_SUBNETS_IPV4=""
LOCAL_SUBNETS_IPV6=""

IFS=',' read -ra RAW_SUBNETS <<< "$LOCAL_SUBNETS"
for subnet in "${RAW_SUBNETS[@]}"; do
  subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [ -n "$subnet" ]; then
    # Проверяем, IPv6 или IPv4 (по наличию двоеточия)
    if [[ "$subnet" == *:* ]]; then
      LOCAL_SUBNETS_IPV6="$subnet"
    else
      LOCAL_SUBNETS_IPV4="$subnet"
    fi
  fi
done

echo "📡 Подсеть: $LOCAL_SUBNETS"

# --- Вычисление первого/последнего IP и broadcast для IPv4 ---
LOCAL_SERVER_IP=""
FIRST_IP=""
LAST_IP=""
BROADCAST_ADDR=""
SERVER_OCCUPIES_FIRST=0

if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS_IPV4" | cut -d'/' -f1)"

  # Вычисляем первый, последний и broadcast через Python
  FIRST_IP=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False)
print(str(net.network_address + 1))
" 2>/dev/null) || {
    echo "❌ Ошибка: не удалось вычислить FIRST_IP для IPv4"
    exit 1
  }

  LAST_IP=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False)
print(str(net.broadcast_address - 1))
" 2>/dev/null) || {
    echo "❌ Ошибка: не удалось вычислить LAST_IP для IPv4"
    exit 1
  }

  BROADCAST_ADDR=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False)
print(str(net.broadcast_address))
" 2>/dev/null) || {
    echo "❌ Ошибка: не удалось вычислить BROADCAST_ADDR для IPv4"
    exit 1
  }

  # Проверяем, занимает ли сервер NETWORK адрес
  if [ "$LOCAL_SERVER_IP" = "$(python3 -c "import ipaddress; print(ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False).network_address)")" ]; then
    SERVER_ON_NETWORK=1
    echo "📍 IPv4: Сервер на network адресе ($LOCAL_SERVER_IP) — broadcast НЕ работает"
  else
    SERVER_ON_NETWORK=0
    echo "📍 IPv4: Сервер НЕ на network адресе ($LOCAL_SERVER_IP) — broadcast работает"
  fi
fi

# --- Вычисление первого/последнего IP для IPv6 (аналогично IPv4) ---
LOCAL_SERVER_IP_IPV6=""
FIRST_IP_IPV6=""
LAST_IP_IPV6=""
SERVER_OCCUPIES_FIRST_IPV6=0

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  LOCAL_SERVER_IP_IPV6="$(echo "$LOCAL_SUBNETS_IPV6" | cut -d'/' -f1)"

  # Вычисляем первый usable IP для IPv6
  FIRST_IP_IPV6=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False)
print(str(net.network_address + 1))
" 2>/dev/null) || {
    echo "❌ Ошибка: не удалось вычислить FIRST_IP для IPv6"
    exit 1
  }

  # Последний usable зависит от позиции сервера
  if [ "$LOCAL_SERVER_IP_IPV6" = "$FIRST_IP_IPV6" ]; then
    # Сервер на первом usable → последний зарезервирован
    LAST_IP_IPV6=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False)
print(str(net.network_address + net.num_addresses - 2))
" 2>/dev/null) || {
      echo "❌ Ошибка: не удалось вычислить LAST_IP для IPv6"
      exit 1
    }
    SERVER_OCCUPIES_FIRST_IPV6=1
    echo "📍 IPv6: Сервер на первом usable IP ($LOCAL_SERVER_IP_IPV6)"
  else
    # Сервер на network/другом адресе → все доступны
    LAST_IP_IPV6=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False)
print(str(net.network_address + net.num_addresses - 1))
" 2>/dev/null) || {
      echo "❌ Ошибка: не удалось вычислить LAST_IP для IPv6"
      exit 1
    }
    SERVER_OCCUPIES_FIRST_IPV6=0
    echo "📍 IPv6: Сервер на network/другом адресе ($LOCAL_SERVER_IP_IPV6)"
  fi
  
  # Проверяем, занимает ли сервер NETWORK адрес для IPv6
  if [ "$LOCAL_SERVER_IP_IPV6" = "$(python3 -c "import ipaddress; print(ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False).network_address)")" ]; then
    SERVER_ON_NETWORK_IPV6=1
    echo "📍 IPv6: Сервер на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast НЕ работает"
  else
    SERVER_ON_NETWORK_IPV6=0
    echo "📍 IPv6: Сервер НЕ на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast работает"
  fi
fi

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
# Диапазон MARK: 1000-9990 (максимум 900 уникальных значений для tc)
# Используем cksum (более доступен чем od) или md5sum как fallback
TUN_HASH=$(echo -n "$TUN" | cksum 2>/dev/null | cut -d' ' -f1)
if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
  # Fallback на md5sum если cksum не доступен
  TUN_HASH=$(echo -n "$TUN" | md5sum 2>/dev/null | cut -c1-8)
  TUN_HASH=$((16#$TUN_HASH))  # Конвертация из hex в decimal
fi
if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
  # Последний fallback — используем длину имени
  TUN_HASH=${#TUN}
fi
MARK_BASE=$((1000 + (TUN_HASH % 900) * 10))

# Функция: найти или зарезервировать TABLE_ID для данного TABLE_NAME (201..400)
find_table_id() {
  local tname="$1"
  local tid
  tid=$(awk -v name="$tname" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
  if [ -n "$tid" ]; then
    echo "$tid"
    return
  fi
  for id in $(seq 201 400); do
    if ! grep -q "^${id}[[:space:]]" /etc/iproute2/rt_tables 2>/dev/null; then
      echo "$id"
      return
    fi
  done
  echo "0"
}

# --- Функция: определить версию IP и вернуть команду iptables/ip6tables ---
# Использование: IPT_CMD="$(get_ipt_cmd "$subnet")"
#              $IPT_CMD -t mangle -A ... -d "$subnet" ...
get_ipt_cmd() {
  local addr="$1"
  # Проверяем, содержит ли адрес двоеточие (IPv6)
  if [[ "$addr" == *:* ]]; then
    echo "ip6tables"
  else
    echo "iptables"
  fi
}

# --- Helper функции для парсинга WARP_LIST ---
# Использование: interfaces="$(parse_warp_interfaces "$entry")"
#              subnets="$(parse_warp_subnets "$entry")"
parse_warp_interfaces() {
  local entry="$1"
  # Если есть "=" — возвращаем часть до "=", иначе всю запись
  if [[ "$entry" == *"="* ]]; then
    echo "${entry%%=*}"
  else
    echo "$entry"
  fi
}

parse_warp_subnets() {
  local entry="$1"
  # Если есть "=" — возвращаем часть после "=", иначе пусто
  if [[ "$entry" == *"="* ]]; then
    echo "${entry#*=}"
  else
    echo ""
  fi
}

# --- Helper функция для применения правил к IPv4 и IPv6 ---
# Использование: apply_rule_both "$CHAIN" "-j RETURN" "$IPV4_SUBNET" "$IPV6_SUBNET"
apply_rule_both() {
  local chain="$1"
  local rule="$2"
  local ipv4_subnet="$3"
  local ipv6_subnet="$4"
  
  # Применяем правило для IPv4 если подсеть указана
  if [ -n "$ipv4_subnet" ]; then
    iptables -t mangle -A "$chain" -s "$ipv4_subnet" $rule 2>/dev/null || true
  fi
  
  # Применяем правило для IPv6 если подсеть указана
  if [ -n "$ipv6_subnet" ]; then
    ip6tables -t mangle -A "$chain" -s "$ipv6_subnet" $rule 2>/dev/null || true
  fi
}

# --- Helper функция для очистки правил IPv4 и IPv6 ---
# Использование: cleanup_rule_both "$CHAIN" "-j RETURN" "$IPV4_SUBNET" "$IPV6_SUBNET"
cleanup_rule_both() {
  local chain="$1"
  local rule="$2"
  local ipv4_subnet="$3"
  local ipv6_subnet="$4"
  
  # Очищаем правило для IPv4 если подсеть указана
  if [ -n "$ipv4_subnet" ]; then
    iptables -t mangle -D "$chain" -s "$ipv4_subnet" $rule 2>/dev/null || true
  fi
  
  # Очищаем правило для IPv6 если подсеть указана
  if [ -n "$ipv6_subnet" ]; then
    ip6tables -t mangle -D "$chain" -s "$ipv6_subnet" $rule 2>/dev/null || true
  fi
}

# --- Запуск WARP-интерфейсов (дополнительные WireGuard-интерфейсы для мульти-WARP) ---
# Пропускаем, если WARP_LIST пустой или содержит только "none"
# Используем счётчик ссылок для поддержки общих WARP между туннелями
# Парсим формат: "warp0,warp1=subnet1, subnet2" или "warp0,warp1"
WARP_ACTIVE=0

# Создаём ОБЩУЮ папку для всех WARP файлов (ОБЩАЯ ДЛЯ ВСЕХ ИНТЕРФЕЙСОВ!)
# Файлы хранятся рядом с up.sh/down.sh скриптом в .state/.warp/
STATE_BASE_DIR="$(dirname "$(readlink -f "$0")")/.state"
mkdir -p "$STATE_BASE_DIR" 2>/dev/null || true
mkdir -p "$STATE_BASE_DIR/.warp" 2>/dev/null || true

# Сохраняем WARP_LIST для down скрипта (чтобы не дублировать в конфиге)
printf '%s\n' "${WARP_LIST[@]}" > "$STATE_BASE_DIR/.warp/${TUN}_warp_list.conf"

# Собираем все уникальные WARP интерфейсы из всех записей WARP_LIST
declare -A ALL_WARP_INTERFACES
for entry in "${WARP_LIST[@]}"; do
  # Пропускаем "none" и пустые записи
  if [ "$entry" = "none" ] || [ -z "$entry" ]; then
    continue
  fi
  
  # Используем helper функцию для парсинга интерфейсов
  interfaces_part="$(parse_warp_interfaces "$entry")"
  
  # Разбиваем интерфейсы по запятой и обрезаем пробелы
  IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
  for iface in "${RAW_INTERFACES[@]}"; do
    iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ -n "$iface" ] && [ "$iface" != "none" ]; then
      ALL_WARP_INTERFACES["$iface"]=1
    fi
  done
done

# Запускаем каждый уникальный WARP интерфейс
# Используем файлы для отслеживания активных WARP (переменные в subshell не работают)
WARP_ACTIVE=0
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  echo "🚀 Запуск WARP-туннеля: $warp"
  WARP_REF_FILE="$STATE_BASE_DIR/.warp/warp_${warp}.ref"
  WARP_LOCK_FILE="$STATE_BASE_DIR/.warp/warp_${warp}.lock"
  WARP_ACTIVE_FILE="$STATE_BASE_DIR/.warp/warp_${warp}.active"

  # Используем flock для предотвращения race condition
  (
    flock -x -w 10 200 || {
      echo "Ошибка: не удалось получить блокировку для $warp"
      exit 1
    }

    # Проверяем, запущен ли уже этот WARP
    if [ -f "$WARP_REF_FILE" ]; then
      # WARP уже запущен, увеличиваем счётчик
      ref_count=$(cat "$WARP_REF_FILE" 2>/dev/null || echo "0")
      echo $((ref_count + 1)) > "$WARP_REF_FILE"
    else
      # Запускаем WARP впервые
      if awg-quick up "$warp"; then
        echo "1" > "$WARP_REF_FILE"
      else
        echo "Ошибка запуска $warp: $?"
      fi
    fi
  ) 200>"$WARP_LOCK_FILE"
  
  # Проверяем, удалось ли запустить WARP (файл .ref существует)
  if [ -f "$WARP_REF_FILE" ]; then
    touch "$WARP_ACTIVE_FILE"
    WARP_ACTIVE=1
  fi
done

# --- WARP-маршрутизация и балансировка трафика через WARP интерфейсы ---
if [ "$WARP_ACTIVE" -eq 1 ]; then
  # --- Создаём таблицы маршрутизации для каждого WARP интерфейса ---
  declare -A WARP_TABLE_IDS
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    TABLE_ID=$(find_table_id "$warp")
    if [ "$TABLE_ID" = "0" ]; then
      echo "Ошибка: не удалось найти свободный TABLE_ID для $warp"
    else
      grep -q "^$TABLE_ID[[:space:]]$warp$" /etc/iproute2/rt_tables || echo "$TABLE_ID $warp" >> /etc/iproute2/rt_tables
      ip route replace default dev "$warp" table "$TABLE_ID"
      WARP_TABLE_IDS["$warp"]="$TABLE_ID"
    fi
  done

  # --- iptables для маркировки трафика ---
  # Создаём цепочку в ОБЕИХ таблицах (iptables и ip6tables)
  iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -N "$RANDOM_WARP_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || ip6tables -t mangle -N "$RANDOM_WARP_CHAIN" 2>/dev/null || true
  
  # Добавляем правила PREROUTING для ВСЕХ интерфейсов (чтобы WARP работал для клиентов всех туннелей!)
  iptables -t mangle -C PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -A PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -C PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || ip6tables -t mangle -A PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true

  # --- Исключение подсетей из маркировки (идут напрямую через IFACE, мимо WARP) ---
  # Собираем все IP/подсети для исключения из WARP:
  # 1. none= из WARP_LIST (ручные исключения)
  # 2. LAN_ALLOW (автоматически для локальной сети)
  ALL_WARP_EXCLUSIONS=()
  
  # Добавляем none= из WARP_LIST
  for entry in "${WARP_LIST[@]}"; do
    if [[ "$entry" =~ ^none[[:space:]]*= ]]; then
      subnets_part="${entry#*=}"
      IFS=',' read -ra RAW_SUBNETS <<< "$subnets_part"
      for subnet in "${RAW_SUBNETS[@]}"; do
        subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$subnet" ] && ALL_WARP_EXCLUSIONS+=("$subnet")
      done
    fi
  done
  
  # Добавляем LAN_ALLOW (автоматически)
  if [ ${#LAN_ALLOW[@]} -gt 0 ]; then
    for rule in "${LAN_ALLOW[@]}"; do
      IFS=',' read -ra PARTS <<< "$rule"
      for part in "${PARTS[@]}"; do
        part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$part" ] && ALL_WARP_EXCLUSIONS+=("$part")
      done
    done
  fi
  
  # Применяем все исключения
  if [ ${#ALL_WARP_EXCLUSIONS[@]} -gt 0 ]; then
    echo "🔒 Исключение ${#ALL_WARP_EXCLUSIONS[@]} IP/подсетей из WARP (локальная сеть + none=)"
    for subnet in "${ALL_WARP_EXCLUSIONS[@]}"; do
      IPT_CMD="$(get_ipt_cmd "$subnet")"
      $IPT_CMD -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d "$subnet" -j RETURN 2>/dev/null || true
    done
  fi

  # --- Сначала собираем все интерфейсы БЕЗ подсетей в одну группу для балансировки всего остального трафика ---
  DEFAULT_WARP_GROUP=()
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi
    # Если нет "=" — это интерфейсы для всего остального трафика
    if [[ "$entry" != *"="* ]]; then
      IFS=',' read -ra RAW_INTERFACES <<< "$entry"
      for iface in "${RAW_INTERFACES[@]}"; do
        iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ -n "$iface" ] && [ "$iface" != "none" ]; then
          DEFAULT_WARP_GROUP+=("$iface")
        fi
      done
    fi
  done

  # --- Собираем все подсети из записей с подсетями (для RETURN) ---
  # Исключаем "none=" записи — они уже добавлены в RETURN выше
  ALL_SPECIFIC_SUBNETS=()
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi
    # Пропускаем "none=subnets" (с поддержкой пробелов вокруг =) — они не нужны в ALL_SPECIFIC_SUBNETS
    if [[ "$entry" =~ ^none[[:space:]]*= ]]; then
      continue
    fi
    if [[ "$entry" == *"="* ]]; then
      subnets_part="${entry#*=}"
      IFS=',' read -ra RAW_SUBNETS <<< "$subnets_part"
      for s in "${RAW_SUBNETS[@]}"; do
        s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$s" ] && ALL_SPECIFIC_SUBNETS+=("$s")
      done
    fi
  done

  # --- Обработка каждой записи WARP_LIST ---
  # Формат: "warp0,warp1=subnet1, subnet2" или "warp0,warp1" (для всего трафика)
  MARK_OFFSET=0
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi

    # Разбираем запись
    if [[ "$entry" == *"="* ]]; then
      # Есть подсети: разделяем по "="
      interfaces_part="${entry%%=*}"
      subnets_part="${entry#*=}"
      HAS_SUBNETS=1
    else
      # Нет подсетей: пропускаем, обработаем отдельно в конце
      continue
    fi

    # Разбиваем интерфейсы по запятой и обрезаем пробелы
    WARP_GROUP=()
    IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
    for iface in "${RAW_INTERFACES[@]}"; do
      iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ -n "$iface" ] && [ "$iface" != "none" ]; then
        WARP_GROUP+=("$iface")
      fi
    done

    # Пропускаем пустые группы
    WARP_GROUP_COUNT=${#WARP_GROUP[@]}
    if [ "$WARP_GROUP_COUNT" -eq 0 ]; then
      continue
    fi

    # Разбиваем подсети по запятой и обрезаем пробелы (если есть)
    SUBNET_GROUP=()
    if [ "$HAS_SUBNETS" -eq 1 ]; then
      IFS=',' read -ra RAW_SUBNETS <<< "$subnets_part"
      for subnet in "${RAW_SUBNETS[@]}"; do
        subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$subnet" ] && SUBNET_GROUP+=("$subnet")
      done
    fi

    # --- Создаём правила маркировки для этой группы WARP ---
    # Если есть подсети — маркируем только трафик на эти подсети
    # Используем get_ipt_cmd для поддержки IPv4/IPv6

    if [ "$HAS_SUBNETS" -eq 1 ] && [ ${#SUBNET_GROUP[@]} -gt 0 ]; then
      # --- Трафик на конкретные подсети через эту группу WARP ---
      for subnet in "${SUBNET_GROUP[@]}"; do
        # Определяем версию IP (iptables или ip6tables)
        IPT_CMD="$(get_ipt_cmd "$subnet")"
        # Балансировка между интерфейсами в группе (nth statistic)
        for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
          MARK=$((MARK_BASE + MARK_OFFSET + i))
          # Маркируем только новые соединения на эту подсеть
          $IPT_CMD -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -m conntrack --ctstate NEW \
            -m statistic --mode nth --every $WARP_GROUP_COUNT --packet $i \
            -j CONNMARK --set-mark $MARK
        done
      done
    fi

    # Увеличиваем MARK_OFFSET для следующей группы
    MARK_OFFSET=$((MARK_OFFSET + WARP_GROUP_COUNT))
  done

  # --- Обработка всех интерфейсов БЕЗ подсетей (для всего остального трафика) ---
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    # Сначала создаём RETURN для всех специфичных подсетей
    # Используем get_ipt_cmd для поддержки IPv4/IPv6
    for subnet in "${ALL_SPECIFIC_SUBNETS[@]}"; do
      IPT_CMD="$(get_ipt_cmd "$subnet")"
      $IPT_CMD -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -j RETURN 2>/dev/null || true
    done

    # Балансировка для всего остального трафика между ВСЕМИ интерфейсами без подсетей
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      iptables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW \
        -m statistic --mode nth --every $DEFAULT_WARP_COUNT --packet $i \
        -j CONNMARK --set-mark $MARK
    done
    MARK_OFFSET=$((MARK_OFFSET + DEFAULT_WARP_COUNT))
  fi

  # --- Восстанавливаем mark для всех пакетов ---
  iptables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark
  ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark

  # --- Добавляем ip rule для каждого MARK -> TABLE ---
  # Сначала обрабатываем записи с подсетями
  MARK_OFFSET=0
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi

    # Разбираем запись
    if [[ "$entry" == *"="* ]]; then
      interfaces_part="${entry%%=*}"
    else
      continue  # Без подсетей обработаем потом
    fi

    # Разбиваем интерфейсы
    WARP_GROUP=()
    IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
    for iface in "${RAW_INTERFACES[@]}"; do
      iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ -n "$iface" ] && [ "$iface" != "none" ]; then
        WARP_GROUP+=("$iface")
      fi
    done

    WARP_GROUP_COUNT=${#WARP_GROUP[@]}
    if [ "$WARP_GROUP_COUNT" -eq 0 ]; then
      continue
    fi

    # Добавляем ip rule для каждого MARK в группе
    for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${WARP_GROUP[$i]}"
      TABLE_ID="${WARP_TABLE_IDS[$warp_iface]}"
      if [ -n "$TABLE_ID" ]; then
        # Проверяем, существует ли уже правило (с проверкой что ip rule show выполнился успешно)
        if ip rule show 2>/dev/null | grep -q "fwmark $MARK table $TABLE_ID"; then
          : # Правило уже существует
        else
          ip rule add fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        fi
      fi
    done

    MARK_OFFSET=$((MARK_OFFSET + WARP_GROUP_COUNT))
  done

  # --- Обработка интерфейсов БЕЗ подсетей (для всего остального трафика) ---
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${DEFAULT_WARP_GROUP[$i]}"
      TABLE_ID="${WARP_TABLE_IDS[$warp_iface]}"
      if [ -n "$TABLE_ID" ]; then
        if ip rule show 2>/dev/null | grep -q "fwmark $MARK table $TABLE_ID"; then
          : # Правило уже существует
        else
          ip rule add fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        fi
      fi
    done
  fi

  # --- Настройка FORWARD и NAT для трафика через WARP ---
  # IPv4 правила
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    # Разрешаем FORWARD для ВСЕХ туннелей на WARP (не только текущего!)
    iptables -C FORWARD -o "$warp" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$warp" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -i "$warp" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$warp" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -C POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
  done

  # IPv6 правила (с NAT, так как WARP поддерживает IPv6)
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    # Разрешаем FORWARD для ВСЕХ туннелей на WARP (не только текущего!)
    ip6tables -C FORWARD -o "$warp" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -o "$warp" -j ACCEPT 2>/dev/null || true
    ip6tables -C FORWARD -i "$warp" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$warp" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    ip6tables -t nat -C POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
  done
fi

# --- Настройка FORWARD и NAT для трафика напрямую через внешний интерфейс ---
# Если WARP активен — это для подсетей из "none=..." в WARP_LIST, если нет — для всего трафика
# Используем суффиксированную цепочку для избежания конфликтов между туннелями

# IPv4 правила
iptables -t filter -N "$INPUT_CHAIN" 2>/dev/null || true
iptables -t filter -C INPUT -j "$INPUT_CHAIN" 2>/dev/null || iptables -t filter -A INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
iptables -t filter -C "$INPUT_CHAIN" -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -t filter -A "$INPUT_CHAIN" -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true
# Разрешаем ICMP (пинг) из VPN подсети на сервер (IPv4)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t filter -C "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -p icmp -j ACCEPT 2>/dev/null || iptables -t filter -A "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -p icmp -j ACCEPT 2>/dev/null || true
fi
iptables -C FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# IPv6 правила (С NAT!)
ip6tables -t filter -N "$INPUT_CHAIN" 2>/dev/null || true
ip6tables -t filter -C INPUT -j "$INPUT_CHAIN" 2>/dev/null || ip6tables -t filter -A INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
ip6tables -t filter -C "$INPUT_CHAIN" -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || ip6tables -t filter -A "$INPUT_CHAIN" -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true
# Разрешаем ICMPv6 (пинг) из VPN подсети на сервер (IPv6)
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t filter -C "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -p icmpv6 -j ACCEPT 2>/dev/null || ip6tables -t filter -A "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -p icmpv6 -j ACCEPT 2>/dev/null || true
fi
ip6tables -C FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
ip6tables -C FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
ip6tables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# --- Hairpin NAT ---
# Используем суффиксированную цепочку для избежания конфликтов между туннелями
# Создаём цепочку в ОБЕИХ таблицах (iptables и ip6tables)
iptables -t nat -N "$HAIRPIN_CHAIN" 2>/dev/null || true
ip6tables -t nat -N "$HAIRPIN_CHAIN" 2>/dev/null || true

# IPv4 Hairpin NAT
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t nat -C "$HAIRPIN_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -d "$LOCAL_SUBNETS_IPV4" -j MASQUERADE 2>/dev/null || iptables -t nat -A "$HAIRPIN_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -d "$LOCAL_SUBNETS_IPV4" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -C POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || iptables -t nat -A POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
fi

# IPv6 Hairpin NAT (нужен для проброса портов через внешний IPv6 адрес)
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t nat -C "$HAIRPIN_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -d "$LOCAL_SUBNETS_IPV6" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A "$HAIRPIN_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -d "$LOCAL_SUBNETS_IPV6" -j MASQUERADE 2>/dev/null || true
  ip6tables -t nat -C POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || ip6tables -t nat -A POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
fi

# --- Проброс портов через отдельные цепочки (DNAT + SNAT + ACCEPT) ---
# ВАЖНО: Должно быть ДО LAN_ALLOW + DROP чтобы проброс портов работал для всех клиентов!
echo "🔌 Проброс портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_FILTER, $PF_CHAIN_SNAT)"
# Создаём цепочки в ОБЕИХ таблицах (iptables и ip6tables)
iptables -t nat -N "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t filter -N "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t nat -N "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -N "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t filter -N "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t nat -N "$PF_CHAIN_SNAT" 2>/dev/null || true

# Добавляем правила PREROUTING для ВСЕХ интерфейсов (универсально, без привязки к туннелям!)
# Это позволяет клиентам любых VPN (и не-VPN) подключаться к проброшенным портам
iptables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || iptables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || ip6tables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true

# FORWARD и POSTROUTING для текущего туннеля
iptables -t filter -C FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || iptables -t filter -A FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t nat -C POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || iptables -t nat -A POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t filter -C FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || ip6tables -t filter -A FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t nat -C POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || ip6tables -t nat -A POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true

# --- Локальная сеть между клиентами ---
# Расширенная сегментация: каждый элемент массива — это группа IP/подсетей которые могут общаться ДРУГ С ДРУГОМ
# Формат: "IP1, IP2, IP3, ..." — все участники могут общаться со всеми остальными в этой группе
# Пример: "10.0.1.11, 10.0.1.0/30, 10.1.1.1" — все трое могут общаться между собой в обе стороны

# СНАЧАЛА запрещаем ВСЁ межклиентское общение (DROP в КОНЕЦ цепи)
iptables -A FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
ip6tables -A FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true

# --- Функция: найти туннель для IP/подсети ---
# Возвращает имя туннеля (например, "awg0") или пустую строку если не найден
find_tun_for_ip() {
  local ip_or_subnet="$1"
  
  # Перебираем ВСЕ запущенные интерфейсы (не только awg*)
  for test_tun in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    
    # Получаем все адреса этого интерфейса
    local addrs=$(ip -o addr show "$test_tun" 2>/dev/null | awk '{print $4}')
    
    # Проверяем каждый адрес
    for addr in $addrs; do
      if python3 -c "
import ipaddress
try:
    ip = ipaddress.ip_network('$ip_or_subnet', strict=False)
    tun_net = ipaddress.ip_network('$addr', strict=False)
    if ip.subnet_of(tun_net) or tun_net.subnet_of(ip) or ip.overlaps(tun_net):
        exit(0)
    exit(1)
except:
    exit(1)
" 2>/dev/null; then
        echo "$test_tun"
        return 0
      fi
    done
  done
  
  # Не нашли туннель для этого IP
  echo ""
  return 1
}

if [ ${#LAN_ALLOW[@]} -gt 0 ]; then
  echo "🏠 Локальная сеть: РАЗРЕШЕНА для ${#LAN_ALLOW[@]} групп сегментации"

  # Проходим по каждому правилу в LAN_ALLOW
  for rule in "${LAN_ALLOW[@]}"; do
    # Разбиваем правило по запятой и обрезаем пробелы
    IFS=',' read -ra PARTS <<< "$rule"
    PARTS_CLEAN=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -n "$part" ] && PARTS_CLEAN+=("$part")
    done

    # Если частей нет — пропускаем
    [ ${#PARTS_CLEAN[@]} -eq 0 ] && continue

    # Если часть всего одна — разрешаем только внутри себя (для подсетей)
    if [ ${#PARTS_CLEAN[@]} -eq 1 ]; then
      SOURCE="${PARTS_CLEAN[0]}"

      # Определяем тип (IPv4 или IPv6)
      if [[ "$SOURCE" == *:* ]]; then
        IPT_CMD="ip6tables"
      else
        IPT_CMD="iptables"
      fi

      echo "  $SOURCE → только внутри (сам с собой)"
      $IPT_CMD -I FORWARD -i "$TUN" -o "$TUN" -s "$SOURCE" -d "$SOURCE" -j ACCEPT 2>/dev/null || true
    else
      # Если частей несколько — разрешаем ВСЕМ общаться со ВСЕМИ в обе стороны
      echo "  Группа: ${PARTS_CLEAN[*]} (все ↔ все)"

      # Проходим по каждой паре участников и создаём правила в обе стороны
      for ((i=0; i<${#PARTS_CLEAN[@]}; i++)); do
        for ((j=0; j<${#PARTS_CLEAN[@]}; j++)); do
          # Пропускаем если это один и тот же участник
          [ $i -eq $j ] && continue

          SRC="${PARTS_CLEAN[$i]}"
          DST="${PARTS_CLEAN[$j]}"

          # Автоматически определяем туннель для источника
          SRC_TUN=$(find_tun_for_ip "$SRC")
          
          # Если не нашли туннель для SRC — пропускаем эту пару
          if [ -z "$SRC_TUN" ]; then
            echo "    ⚠️  Пропущено: $SRC (туннель не найден)"
            continue
          fi
          
          # Автоматически определяем туннель для получателя
          DST_TUN=$(find_tun_for_ip "$DST")
          
          # Если не нашли туннель для DST — пропускаем эту пару
          if [ -z "$DST_TUN" ]; then
            echo "    ⚠️  Пропущено: $DST (туннель не найден)"
            continue
          fi

          # Разрешаем SRC → DST (в НАЧАЛО цепи, поверх DROP!)
          # Используем найденные туннели (поддержка межтуннельного трафика!)
          echo "    $SRC ($SRC_TUN) → $DST ($DST_TUN)"
          $IPT_CMD -I FORWARD -i "$SRC_TUN" -o "$DST_TUN" -s "$SRC" -d "$DST" -j ACCEPT 2>/dev/null || true
        done
      done
    fi
  done
else
  echo "🚫 Локальная сеть: ЗАПРЕЩЕНА"
  # DROP уже добавлен выше — клиенты изолированы
fi

# Сохраняем LAN_ALLOW в файл для последующей очистки в down.sh
# Файл хранится в .state/ вместе с другими временными файлами туннеля
LAN_ALLOW_FILE="$STATE_BASE_DIR/.lan_allow_${TUN}.conf"

# Собираем карту интерфейсов и подсетей для всех IP в LAN_ALLOW
# Это нужно чтобы down.sh мог очистить правила даже если интерфейс больше не существует
INTERFACE_MAP=()
for rule in "${LAN_ALLOW[@]}"; do
  IFS=',' read -ra PARTS <<< "$rule"
  for part in "${PARTS[@]}"; do
    part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$part" ] && continue
    
    # Находим туннель для этого IP/подсети
    tun_name=$(find_tun_for_ip "$part")
    if [ -n "$tun_name" ]; then
      # Получаем подсеть этого туннеля
      tun_subnet=$(ip -o addr show "$tun_name" 2>/dev/null | awk '{print $4}' | head -1)
      if [ -n "$tun_subnet" ]; then
        INTERFACE_MAP+=("$tun_name=$tun_subnet")
      fi
    fi
  done
done

# Удаляем дубликаты из INTERFACE_MAP
INTERFACE_MAP_UNIQUE=($(printf '%s\n' "${INTERFACE_MAP[@]}" | sort -u))

# Записываем в файл: сначала карта интерфейсов, потом правила LAN_ALLOW
{
  echo "# INTERFACE_MAP: ${INTERFACE_MAP_UNIQUE[*]}"
  printf '%s\n' "${LAN_ALLOW[@]}"
} > "$LAN_ALLOW_FILE" 2>/dev/null || true

# --- Broadcast/Multicast трафик (для игр и service discovery) ---
# Работает ТОЛЬКО если сервер НЕ занимает ПЕРВЫЙ IP в подсети
# Broadcast/Multicast разрешается ТОЛЬКО между участниками ОДНОЙ группы LAN_ALLOW
# Используем mark для полной изоляции — broadcast доходит только до участников группы
# Mark уникальны для каждого туннеля (на основе MARK_BASE) чтобы избежать коллизий
# Диапазон: MARK_BASE+1000 до MARK_BASE+1099 (не пересекается с WARP mark)

# IPv4 Broadcast
if [ -n "$LOCAL_SUBNETS_IPV4" ] && [ -n "$BROADCAST_ADDR" ] && [ "$SERVER_ON_NETWORK" -eq 0 ]; then
    # Для каждой группы в LAN_ALLOW создаём уникальные mark
    # Используем MARK_BASE чтобы mark были уникальны для каждого туннеля
    MARK=$((MARK_BASE + 1000))
    for rule in "${LAN_ALLOW[@]}"; do
      IFS=',' read -ra PARTS <<< "$rule"
      
      # Собираем только IPv4 участников этой группы
      IPV4_PARTS=()
      for part in "${PARTS[@]}"; do
        part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$part" ] && continue
        [[ "$part" != *:* ]] && IPV4_PARTS+=("$part")
      done
      
      # Если в группе есть IPv4 участники — настраиваем broadcast
      if [ ${#IPV4_PARTS[@]} -gt 0 ]; then
        # 1. Маркируем broadcast от каждого участника группы
        for src in "${IPV4_PARTS[@]}"; do
          iptables -t mangle -A FORWARD -s "$src" -d "$BROADCAST_ADDR" -j MARK --set-mark $MARK 2>/dev/null || true
          iptables -t mangle -A FORWARD -s "$src" -d 255.255.255.255 -j MARK --set-mark $MARK 2>/dev/null || true
        done

        # 2. Разрешаем получать broadcast ТОЛЬКО участникам этой группы (В НАЧАЛО цепи, поверх DROP!)
        for dst in "${IPV4_PARTS[@]}"; do
          iptables -I FORWARD -i "$TUN" -o "$TUN" -m mark --mark $MARK -d "$dst" -j ACCEPT 2>/dev/null || true
        done

        # Увеличиваем mark для следующей группы
        MARK=$((MARK + 1))
      fi
    done
    
    # DROP не нужен — если mark не разрешён через ACCEPT, он блокируется автоматически
fi

# IPv6 Multicast (работает аналогично IPv4 broadcast)
# ff02::1 - all nodes multicast (аналог 255.255.255.255)
# Используем mark для полной изоляции — multicast доходит только до участников группы
# Используем ТЕ ЖЕ mark что и для IPv4 (на основе MARK_BASE), так как это разные таблицы (ip6tables)
# ВАЖНО: Multicast работает ТОЛЬКО если сервер НЕ на network адресе (как и broadcast)
if [ -n "$LOCAL_SUBNETS_IPV6" ] && [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
    # Для каждой группы в LAN_ALLOW создаём уникальные mark (те же что и для IPv4)
    # Используем MARK_BASE чтобы mark были уникальны для каждого туннеля
    MARK=$((MARK_BASE + 1000))
    for rule in "${LAN_ALLOW[@]}"; do
      IFS=',' read -ra PARTS <<< "$rule"

      # Собираем только IPv6 участников этой группы
      IPV6_PARTS=()
      for part in "${PARTS[@]}"; do
        part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$part" ] && continue
        [[ "$part" == *:* ]] && IPV6_PARTS+=("$part")
      done

      # Если в группе есть IPv6 участники — настраиваем multicast
      if [ ${#IPV6_PARTS[@]} -gt 0 ]; then
        # 1. Маркируем multicast от каждого участника группы
        for src in "${IPV6_PARTS[@]}"; do
          ip6tables -t mangle -A FORWARD -s "$src" -d "ff02::1" -j MARK --set-mark $MARK 2>/dev/null || true
        done

        # 2. Разрешаем получать multicast ТОЛЬКО участникам этой группы (В НАЧАЛО цепи, поверх DROP!)
        for dst in "${IPV6_PARTS[@]}"; do
          ip6tables -I FORWARD -i "$TUN" -o "$TUN" -m mark --mark $MARK -d "$dst" -j ACCEPT 2>/dev/null || true
        done

        # Увеличиваем mark для следующей группы
        MARK=$((MARK + 1))
      fi
    done

    # DROP не нужен — если mark не разрешён через ACCEPT, он блокируется автоматически
fi

# --- Добавление правил для каждого проброса ---
for rule in "${PORT_FORWARDING_RULES[@]}"; do
  # Разбор правила: парсим с конца, чтобы поддержать IPv6 адреса
  # Формат: CLIENT_IP:PORT[>PORT]:PROTO[:SNAT][;SUBNETS]
  # IPv6 адреса содержат ':', поэтому SUBNETS отделяется ';' от остальных полей
  # Примеры:
  #   "10.1.0.5:80:TCP:SNAT" — без подсетей
  #   "10.1.0.5:80:TCP:SNAT;192.168.0.0/24" — с IPv4 подсетями
  #   "10.1.0.5:80:TCP:SNAT;2a01:e5c0:52cc::/48" — с IPv6 подсетями
  #   "10.1.0.5:80:TCP;192.168.0.0/24, 2a01:e5c0:52cc::/48" — с несколькими подсетями без SNAT

  # Сначала разделяем по ';' чтобы отделить SUBNETS от остальных полей
  if [[ "$rule" == *";"* ]]; then
    # Есть разделитель ';' — разделяем основную часть и SUBNETS
    MAIN_PART="${rule%%;*}"
    ALLOWED_SUBNETS="${rule#*;}"
  else
    # Нет разделителя ';' — всё правило в основной части
    MAIN_PART="$rule"
    ALLOWED_SUBNETS=""
  fi

  # Считаем количество ':' в основной части (без SUBNETS)
  colon_count=$(echo "$MAIN_PART" | tr -cd ':' | wc -c)

  # Определяем позиции полей с конца
  # Последние поле: SNAT (опционально)
  # Предпоследнее: PROTO (TCP/UDP)
  # Пред-предпоследнее: PORT[>PORT]
  # Всё остальное в начале: CLIENT_IP (может быть IPv6)

  if [ "$colon_count" -lt 2 ]; then
    echo "Ошибка: неверный формат правила '$rule' (минимум CLIENT_IP:PORT:PROTO)"
    continue
  fi

  # Извлекаем поля из основной части (без SUBNETS)
  last_field=$(echo "$MAIN_PART" | rev | cut -d':' -f1 | rev)
  second_last=$(echo "$MAIN_PART" | rev | cut -d':' -f2 | rev)

  # Определяем где PROTO и SNAT
  if [ "${last_field^^}" = "SNAT" ]; then
    # :SNAT в конце основной части
    PF_PROTO="$second_last"
    PF_PORT_PROTO=$(echo "$MAIN_PART" | rev | cut -d':' -f3 | rev)
    CLIENT_IP=$(echo "$MAIN_PART" | rev | cut -d':' -f4- | rev)
    SNAT_FLAG="SNAT"
  else
    # Нет SNAT, PROTO = последнее
    PF_PROTO="$last_field"
    PF_PORT_PROTO="$second_last"
    CLIENT_IP=$(echo "$MAIN_PART" | rev | cut -d':' -f3- | rev)
    SNAT_FLAG=""
  fi
  
  # Проверяем протокол
  PF_PROTO_UPPER="${PF_PROTO^^}"
  if [ "$PF_PROTO_UPPER" != "TCP" ] && [ "$PF_PROTO_UPPER" != "UDP" ]; then
    echo "Ошибка: неверный протокол '$PF_PROTO' в правиле '$rule' (должен быть TCP или UDP)"
    continue
  fi

  # Поддержка списка CLIENT_IP через запятую (IPv4, IPv6 или оба)
  # Формат: "10.1.0.5" или "fd00::5" или "10.1.0.5, fd00::5"
  CLIENT_IP_ARRAY=()
  IFS=',' read -ra RAW_CLIENT_IPS <<< "$CLIENT_IP"
  for cip in "${RAW_CLIENT_IPS[@]}"; do
    cip="$(echo "$cip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -n "$cip" ] && CLIENT_IP_ARRAY+=("$cip")
  done
  
  # Если не указан ни один IP — ошибка
  if [ ${#CLIENT_IP_ARRAY[@]} -eq 0 ]; then
    echo "Ошибка: не указан клиентский IP в правиле '$rule'"
    continue
  fi
  
  # Подготовка массива подсетей; если пусто — будем работать без фильтра -s/-d
  if [ -z "$ALLOWED_SUBNETS" ]; then
    USE_SUBNETS=0
    ALLOWED_SUBNETS_DISPLAY="ALL"
  else
    USE_SUBNETS=1
    # Разбиваем по запятой и обрезаем пробелы
    SUBNETS_ARRAY=()
    IFS=',' read -ra RAW_SUBNETS <<< "$ALLOWED_SUBNETS"
    for s in "${RAW_SUBNETS[@]}"; do
      s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -n "$s" ] && SUBNETS_ARRAY+=("$s")
    done
    ALLOWED_SUBNETS_DISPLAY="$ALLOWED_SUBNETS"
  fi

  # Разбор внешнего/внутреннего портов с опцией диапазонов
  IFS='>' read -r PF_PORT_EXT PF_PORT_INT <<< "$PF_PORT_PROTO"
  [ -z "$PF_PORT_INT" ] && PF_PORT_INT="$PF_PORT_EXT"

  # Собираем уникальные SNAT правила (чтобы не дублировать)
  declare -A SNAT_RULES_ADDED

  # Проходим по всем CLIENT_IP (IPv4, IPv6 или оба)
  for CLIENT_IP in "${CLIENT_IP_ARRAY[@]}"; do
    # Определяем тип CLIENT_IP (IPv4 или IPv6)
    if [[ "$CLIENT_IP" == *:* ]]; then
      IPT_CMD="ip6tables"
      IP_VERSION="ipv6"
      # Для IPv6 используем IPv6 серверный IP
      SERVER_IP="$LOCAL_SERVER_IP_IPV6"
      # Фильтруем только IPv6 подсети
      FILTERED_SUBNETS=()
      for subnet in "${SUBNETS_ARRAY[@]}"; do
        [[ "$subnet" == *:* ]] && FILTERED_SUBNETS+=("$subnet")
      done

      # Если IPv6 серверный IP пустой — используем IPv4 (для SNAT)
      [ -z "$SERVER_IP" ] && SERVER_IP="$LOCAL_SERVER_IP"
      
      # Для DNAT IPv6 адреса нужно оборачивать в квадратные скобки: [IPv6]:port
      CLIENT_IP_DNAT="[$CLIENT_IP]"
    else
      IPT_CMD="iptables"
      IP_VERSION="ipv4"
      # Для IPv4 используем IPv4 серверный IP
      SERVER_IP="$LOCAL_SERVER_IP"
      # Фильтруем только IPv4 подсети
      FILTERED_SUBNETS=()
      for subnet in "${SUBNETS_ARRAY[@]}"; do
        [[ "$subnet" != *:* ]] && FILTERED_SUBNETS+=("$subnet")
      done
      
      # Для IPv4 квадратные скобки не нужны
      CLIENT_IP_DNAT="$CLIENT_IP"
    fi

    # Поддержка диапазонов портов: ext и int могут быть single или start-end
    # 1. Оба диапазона
    if [[ "$PF_PORT_EXT" == *"-"* ]] && [[ "$PF_PORT_INT" == *"-"* ]]; then
        PF_PORT_EXT_START="${PF_PORT_EXT%-*}"
        PF_PORT_EXT_END="${PF_PORT_EXT#*-}"
        PF_PORT_INT_START="${PF_PORT_INT%-*}"
        PF_PORT_INT_END="${PF_PORT_INT#*-}"
        RANGE_LEN=$((PF_PORT_EXT_END - PF_PORT_EXT_START))
        if [ $RANGE_LEN -ne $((PF_PORT_INT_END - PF_PORT_INT_START)) ]; then
          echo "Ошибка: диапазоны портов должны быть одинаковой длины для правила '$rule'"
          continue
        fi
        for ((i=0; i<=RANGE_LEN; i++)); do
          EXT_PORT=$((PF_PORT_EXT_START + i))
          INT_PORT=$((PF_PORT_INT_START + i))
          if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
            for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$EXT_PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$INT_PORT"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO
              snat_key="${CLIENT_IP}:${INT_PORT}:${PF_PROTO}"
              if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$SERVER_IP"
                SNAT_RULES_ADDED[$snat_key]=1
              fi
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            # доступ всем — без -s / -d
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$EXT_PORT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$INT_PORT"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO
            snat_key="${CLIENT_IP}:${INT_PORT}:${PF_PROTO}"
            if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$SERVER_IP"
              SNAT_RULES_ADDED[$snat_key]=1
            fi
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -j ACCEPT
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "${SNAT_FLAG^^}" = "SNAT" ]; then
            echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
          else
            echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
          fi
        done
        # После обработки обоих диапазонов — завершаем обработку этого CLIENT_IP
        continue
    fi
    # 2. Внешний диапазон
    if [[ "$PF_PORT_EXT" == *"-"* ]] && [[ "$PF_PORT_INT" != *"-"* ]]; then
        PF_PORT_START="${PF_PORT_EXT%-*}"
        PF_PORT_END="${PF_PORT_EXT#*-}"
        for ((PORT_NUM=PF_PORT_START; PORT_NUM<=PF_PORT_END; PORT_NUM++)); do
          if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
            for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PORT_NUM" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
              snat_key="${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
              if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
                SNAT_RULES_ADDED[$snat_key]=1
              fi
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -s "$ALLOWED_SUBNET" -j ACCEPT
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PORT_NUM" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
            snat_key="${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
            if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
              SNAT_RULES_ADDED[$snat_key]=1
            fi
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -j ACCEPT
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "${SNAT_FLAG^^}" = "SNAT" ]; then
            echo "$PF_PROTO порт $PORT_NUM на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
          else
            echo "$PF_PROTO порт $PORT_NUM на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
          fi
        done
        # После обработки внешнего диапазона — завершаем обработку этого CLIENT_IP
        continue
    fi
    # 3. Внутренний диапазон
    if [[ "$PF_PORT_INT" == *"-"* ]] && [[ "$PF_PORT_EXT" != *"-"* ]]; then
        PF_PORT_START="${PF_PORT_INT%-*}"
        PF_PORT_END="${PF_PORT_INT#*-}"
        for ((PORT_NUM=PF_PORT_START; PORT_NUM<=PF_PORT_END; PORT_NUM++)); do
          if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
            for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
              snat_key="${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
              if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
                SNAT_RULES_ADDED[$snat_key]=1
              fi
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -s "$ALLOWED_SUBNET" -j ACCEPT
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
            snat_key="${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
            if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
              SNAT_RULES_ADDED[$snat_key]=1
            fi
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -j ACCEPT
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "${SNAT_FLAG^^}" = "SNAT" ]; then
            echo "$PF_PROTO порт $PF_PORT_EXT->$PORT_NUM на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
          else
            echo "$PF_PROTO порт $PF_PORT_EXT->$PORT_NUM на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
          fi
        done
        # После обработки внутреннего диапазона — завершаем обработку этого CLIENT_IP
        continue
    fi
    # 4. Оба не диапазоны (single-port)
    if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
          for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:PF_PORT_INT:PROTO
            snat_key="${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
            if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
              SNAT_RULES_ADDED[$snat_key]=1
            fi
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
          done
        else
          $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
          # SNAT добавляем только один раз для комбинации CLIENT_IP:PF_PORT_INT:PROTO
          snat_key="${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
          if [ "${SNAT_FLAG^^}" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${SNAT_RULES_ADDED[$snat_key]}" ]; then
            $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
            SNAT_RULES_ADDED[$snat_key]=1
          fi
          $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -j ACCEPT
          $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -m state --state RELATED,ESTABLISHED -j ACCEPT
        fi

        if [ "${SNAT_FLAG^^}" = "SNAT" ]; then
          echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
        else
          echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
        fi
    # Конец обработки всех вариантов портов
  done
  # Конец цикла по CLIENT_IP_ARRAY
  unset SNAT_RULES_ADDED
done
# Конец цикла по PORT_FORWARDING_RULES

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
# Применяется только если SUBNETS_LIMITS не пустой
# Примечание: для больших подсетей (/16 и больше) этот цикл может работать долго
# Если лимит = 0 для подсети — эта подсеть пропускается (лимит отключен)
# Формат: "subnet1, subnet2:limit" или "subnet:limit" (поддержка IPv4+IPv6)
if [ ${#SUBNETS_LIMITS[@]} -gt 0 ]; then
  echo "⚡ Настройка лимитов скорости"
  
  # --- Проверка диапазона масок подсетей (IPv4: /8-/32, IPv6: /104-/128) ---
  VALID_SUBNETS_LIMITS=()
  for entry in "${SUBNETS_LIMITS[@]}"; do
    # Извлекаем подсети (всё до последнего :)
    subnets_part=$(echo "$entry" | rev | cut -d':' -f2- | rev)
    limit_part=$(echo "$entry" | rev | cut -d':' -f1 | rev)
    
    entry_valid=1
    IFS=',' read -ra RAW_SUBNETS <<< "$subnets_part"
    for subnet in "${RAW_SUBNETS[@]}"; do
      subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$subnet" ] && continue
      
      # Проверяем маску через Python
      if ! python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network('$subnet', strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen < 8 or net.prefixlen > 32:
            print(f'IPv4 подсеть /{net.prefixlen} вне диапазона /8-/32', file=sys.stderr)
            sys.exit(1)
    else:
        if net.prefixlen < 104 or net.prefixlen > 128:
            print(f'IPv6 подсеть /{net.prefixlen} вне диапазона /104-/128', file=sys.stderr)
            sys.exit(1)
    sys.exit(0)
except Exception as e:
    print(f'Ошибка: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        echo "⚠️  Пропущено: '$subnet' (недопустимая подсеть)"
        entry_valid=0
        break
      fi
    done
    
    # Если все подсети в правиле валидны — добавляем в список
    if [ "$entry_valid" -eq 1 ]; then
      VALID_SUBNETS_LIMITS+=("$entry")
    fi
  done
  
  # Если все правила отфильтрованы — выходим
  if [ ${#VALID_SUBNETS_LIMITS[@]} -eq 0 ]; then
    echo "ℹ️  Лимиты скорости отключены (нет валидных правил)"
    return
  fi
  
  # Используем валидные правила вместо исходных
  SUBNETS_LIMITS=("${VALID_SUBNETS_LIMITS[@]}")
  
  if ! modprobe ifb; then
    echo "Ошибка: не удалось загрузить модуль ifb"
    exit 1
  fi

  ip link set "$IFB_IN" down 2>/dev/null || true
  ip link delete "$IFB_IN" 2>/dev/null || true
  ip link set "$IFB_OUT" down 2>/dev/null || true
  ip link delete "$IFB_OUT" 2>/dev/null || true
  ip link add "$IFB_OUT" type ifb 2>/dev/null || true
  ip link set "$IFB_OUT" up
  ip link add "$IFB_IN" type ifb 2>/dev/null || true
  ip link set "$IFB_IN" up

  tc qdisc del dev "$TUN" root 2>/dev/null || true
  tc qdisc del dev "$TUN" handle ffff: ingress 2>/dev/null || true
  tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
  tc qdisc del dev "$IFB_IN" root 2>/dev/null || true

  tc qdisc add dev "$TUN" root handle 1: htb
  # Перенаправляем IPv4 трафик на ifb для ограничения
  tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT"
  # Перенаправляем IPv6 трафик на ifb для ограничения
  tc filter add dev "$TUN" parent 1: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT"
  tc qdisc add dev "$IFB_OUT" root handle 1: htb default 2
  tc qdisc add dev "$TUN" handle ffff: ingress
  # Перенаправляем входящий IPv4 трафик на ifb
  tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN"
  # Перенаправляем входящий IPv6 трафик на ifb
  tc filter add dev "$TUN" parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN"
  tc qdisc add dev "$IFB_IN" root handle 1: htb default 2

  # Функция для создания новой иерархии tc классов при переполнении minor_id
  # ВАЖНО: 1: используется ТОЛЬКО для BRIDGE (1:2 до 1:9999)
  # Клиенты создаются в 2:, 3:, ... до 9999: (по 9999 клиентов на иерархию)
  # ИТОГО: 9998 иерархий × 9999 клиентов = ~100 миллионов клиентов!
  create_tc_hierarchy() {
    major_class=$((major_class + 1))
    minor_id=1  # ← Начинаем с 1 для 2:, 3:, etc. (экономим 999 классов!)
    tc class add dev "$IFB_OUT" parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
    tc class add dev "$IFB_OUT" parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
    tc qdisc add dev "$IFB_OUT" parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
    tc class add dev "$IFB_IN" parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
    tc class add dev "$IFB_IN" parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
    tc qdisc add dev "$IFB_IN" parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
  }

  major_class=1
  minor_id=10000  # ← СРАЗУ > 9999 чтобы создать первую иерархию (2:) для клиентов!
  echo "📊 Установка лимитов скорости для подсетей"
  
  for entry in "${SUBNETS_LIMITS[@]}"; do
      # Парсим с конца: последнее поле после : это лимит
      # Формат: "subnet1, subnet2:limit" или "subnet:limit"
      LIM=$(echo "$entry" | rev | cut -d':' -f1 | rev)
      # Всё остальное — это список подсетей
      SUBNETS_PART=$(echo "$entry" | rev | cut -d':' -f2- | rev)
      
      # Разбиваем подсети по запятой и обрезаем пробелы
      SUBNET_ARRAY=()
      IFS=',' read -ra RAW_SUBNETS <<< "$SUBNETS_PART"
      for s in "${RAW_SUBNETS[@]}"; do
        s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$s" ] && SUBNET_ARRAY+=("$s")
      done
      
      # Если лимит = 0, пропускаем эту группу подсетей (лимит отключен)
      if [ "$LIM" -eq 0 ] 2>/dev/null; then
          echo "$SUBNETS_PART -> лимит отключен (0)"
          continue
      fi
      
      # Если только одна подсеть — используем старую логику
      if [ ${#SUBNET_ARRAY[@]} -eq 1 ]; then
          SUBNET="${SUBNET_ARRAY[0]}"
          
          # Определяем версию IP (IPv4 или IPv6)
          if [[ "$SUBNET" == *:* ]]; then
              IP_VERSION="ipv6"
              PROTO_MATCH="ip6"
          else
              IP_VERSION="ip"
              PROTO_MATCH="ip"
          fi
          
          IPS=$(python3 - <<PY
import ipaddress, sys
try:
    net = ipaddress.ip_network('${SUBNET}', strict=False)
    for ip in net:
        print(ip)
except Exception as e:
    sys.exit(1)
PY
)
          for ip in $IPS; do
              if [ "$minor_id" -gt 9999 ]; then
                  create_tc_hierarchy
              fi
              classid="${major_class}:${minor_id}"
              major="${major_class}:"
              tc class add dev "$IFB_OUT" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
              # Используем prio 1 для IPv4 и prio 2 для IPv6 (tc не разрешает одинаковый prio для разных протоколов)
              if [ "$IP_VERSION" = "ipv6" ]; then
                  tc filter add dev "$IFB_OUT" protocol $IP_VERSION parent ${major_class}: prio 2 u32 match $PROTO_MATCH dst $ip flowid $classid 2>/dev/null || true
                  tc filter add dev "$IFB_IN" protocol $IP_VERSION parent ${major_class}: prio 2 u32 match $PROTO_MATCH src $ip flowid $classid 2>/dev/null || true
              else
                  tc filter add dev "$IFB_OUT" protocol $IP_VERSION parent ${major_class}: prio 1 u32 match $PROTO_MATCH dst $ip flowid $classid
                  tc filter add dev "$IFB_IN" protocol $IP_VERSION parent ${major_class}: prio 1 u32 match $PROTO_MATCH src $ip flowid $classid
              fi
              tc qdisc add dev "$IFB_OUT" parent $classid fq_codel
              tc class add dev "$IFB_IN" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
              tc qdisc add dev "$IFB_IN" parent $classid fq_codel
              minor_id=$((minor_id + 1))
          done
          echo "$SUBNET -> ${LIM}mbit"
      else
          # Несколько подсетей — поддерживаем кратные соотношения
          # Сначала получаем количество адресов и префиксы каждой подсети
          SUBNET_INFO=()
          for subnet in "${SUBNET_ARRAY[@]}"; do
              INFO=$(python3 -c "
import ipaddress
try:
    net = ipaddress.ip_network('${subnet}', strict=False)
    print(f'{net.num_addresses}:{net.prefixlen}')
except:
    print('0:0')
")
              SUBNET_INFO+=("$INFO")
          done

          # Определяем типы подсетей (IPv4 или IPv6)
          SUBNET_TYPES=()
          for subnet in "${SUBNET_ARRAY[@]}"; do
              if [[ "$subnet" == *:* ]]; then
                  SUBNET_TYPES+=("ipv6")
              else
                  SUBNET_TYPES+=("ipv4")
              fi
          done

          # Вычисляем соотношение подсетей через Python
          # Возвращает: ipv4_count, ipv6_count, ipv4_client_mask, ipv6_client_mask, ratio_step
          SHAPING_INFO=$(python3 - <<PY
import ipaddress, math

subnets = '${SUBNETS_PART}'.split(',')
ipv4_nets = []
ipv6_nets = []

for s in subnets:
    s = s.strip()
    if not s:
        continue
    net = ipaddress.ip_network(s, strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        ipv4_nets.append(net)
    else:
        ipv6_nets.append(net)

# Если есть и IPv4 и IPv6
if ipv4_nets and ipv6_nets:
    # Берём первую IPv4 и первую IPv6 для расчёта соотношения
    ipv4_net = ipv4_nets[0]
    ipv6_net = ipv6_nets[0]
    
    ipv4_total = 2 ** (32 - ipv4_net.prefixlen)
    ipv6_total = 2 ** (128 - ipv6_net.prefixlen)
    ratio = ipv6_total / ipv4_total
    
    if ratio >= 1:
        # 1 IPv4 : N IPv6
        ipv4_client_mask = 32
        ipv6_bits = int(math.log2(ratio))
        ipv6_client_mask = 128 - ipv6_bits
        ipv4_step = 1
        ipv6_step = int(ratio)
        # Количество классов = количество IPv4 адресов
        num_classes = ipv4_total
    else:
        # N IPv4 : 1 IPv6
        ipv6_client_mask = 128
        ipv4_bits = int(math.log2(1 / ratio))
        ipv4_client_mask = 32 - ipv4_bits
        ipv4_step = int(1 / ratio)
        ipv6_step = 1
        # Количество классов = количество IPv6 адресов
        num_classes = ipv6_total
    
    print(f'{num_classes}:{ipv4_step}:{ipv6_step}:{ipv4_client_mask}:{ipv6_client_mask}')
else:
    # Только один тип подсетей
    print('0:1:1:32:128')
PY
)
          NUM_CLASSES=$(echo "$SHAPING_INFO" | cut -d':' -f1)
          IPV4_STEP=$(echo "$SHAPING_INFO" | cut -d':' -f2)
          IPV6_STEP=$(echo "$SHAPING_INFO" | cut -d':' -f3)
          IPV4_CLIENT_MASK=$(echo "$SHAPING_INFO" | cut -d':' -f4)
          IPV6_CLIENT_MASK=$(echo "$SHAPING_INFO" | cut -d':' -f5)

          # Генерируем IP для каждой подсети
          ALL_IPS_ARRAYS=()
          declare -a ALL_IPS_ARRAYS
          for i in "${!SUBNET_ARRAY[@]}"; do
              subnet="${SUBNET_ARRAY[$i]}"
              IPS=$(python3 - <<PY
import ipaddress, sys
try:
    net = ipaddress.ip_network('${subnet}', strict=False)
    for ip in net:
        print(str(ip))
except Exception as e:
    sys.exit(1)
PY
)
              ALL_IPS_ARRAYS[$i]="$IPS"
          done

          # Проходим по всем классам с учётом шага
          # IP с соответствующими индексами получают один лимит
          for idx in $(seq 0 $((NUM_CLASSES - 1))); do
              if [ "$minor_id" -gt 9999 ]; then
                  create_tc_hierarchy
              fi

              classid="${major_class}:${minor_id}"
              major="${major_class}:"

              # Создаём класс с общим лимитом
              tc class add dev "$IFB_OUT" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
              tc class add dev "$IFB_IN" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"

              # Добавляем фильтры для каждой подсети
              for i in "${!SUBNET_ARRAY[@]}"; do
                  subnet="${SUBNET_ARRAY[$i]}"
                  ip_type="${SUBNET_TYPES[$i]}"
                  ips_str="${ALL_IPS_ARRAYS[$i]}"

                  # Определяем шаг для этого типа подсети
                  if [ "$ip_type" = "ipv6" ]; then
                      STEP="$IPV6_STEP"
                  else
                      STEP="$IPV4_STEP"
                  fi

                  # Вычисляем индекс с учётом шага
                  REAL_IDX=$((idx * STEP + 1))

                  # Получаем IP по индексу
                  target_ip=$(echo "$ips_str" | sed -n "${REAL_IDX}p")

                  # Выравниваем по границе блока (как в Python скрипте)
                  if [ -n "$target_ip" ]; then
                      if [ "$ip_type" = "ipv6" ] && [ "$IPV6_CLIENT_MASK" -lt 128 ]; then
                          # Выравниваем IPv6 по границе блока
                          target_ip=$(python3 -c "
import ipaddress
ip = ipaddress.IPv6Address('$target_ip')
mask = $IPV6_CLIENT_MASK
block_size = 2 ** (128 - mask)
aligned_int = int(ip) & ~(block_size - 1)
aligned = ipaddress.IPv6Address(aligned_int)
print(aligned)
")
                      elif [ "$ip_type" = "ipv4" ] && [ "$IPV4_CLIENT_MASK" -lt 32 ]; then
                          # Выравниваем IPv4 по границе блока
                          target_ip=$(python3 -c "
import ipaddress
ip = ipaddress.IPv4Address('$target_ip')
mask = $IPV4_CLIENT_MASK
block_size = 2 ** (32 - mask)
aligned_int = int(ip) & ~(block_size - 1)
aligned = ipaddress.IPv4Address(aligned_int)
print(aligned)
")
                      fi
                  fi

                  if [ -n "$target_ip" ]; then
                      if [ "$ip_type" = "ipv6" ]; then
                          tc filter add dev "$IFB_OUT" protocol ipv6 parent ${major_class}: prio 2 u32 match ip6 dst $target_ip flowid $classid 2>/dev/null || true
                          tc filter add dev "$IFB_IN" protocol ipv6 parent ${major_class}: prio 2 u32 match ip6 src $target_ip flowid $classid 2>/dev/null || true
                      else
                          tc filter add dev "$IFB_OUT" protocol ip parent ${major_class}: prio 1 u32 match ip dst $target_ip flowid $classid
                          tc filter add dev "$IFB_IN" protocol ip parent ${major_class}: prio 1 u32 match ip src $target_ip flowid $classid
                      fi
                  fi
              done
              
              tc qdisc add dev "$IFB_OUT" parent $classid fq_codel
              tc qdisc add dev "$IFB_IN" parent $classid fq_codel
              minor_id=$((minor_id + 1))
          done
          
          unset ALL_IPS_ARRAYS
          echo "$SUBNETS_PART -> ${LIM}mbit (общий лимит)"
      fi
  done
  echo "✅ Лимиты скорости настроены"
else
  echo "ℹ️  Лимиты скорости отключены (SUBNETS_LIMITS пуст)"
fi
echo "————————————————————————————————"
'''

down_script_template_warp = '''#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"

LOCAL_SUBNETS="<SERVER_ADDR>"

# STATE_BASE_DIR — папка для временных файлов (рядом со скриптом)
STATE_BASE_DIR="$(dirname "$(readlink -f "$0")")/.state"

# WARP_LIST будет прочитан из файла в .warp/ при остановке интерфейса

# --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
LOCAL_SUBNETS_IPV4=""
LOCAL_SUBNETS_IPV6=""

IFS=',' read -ra RAW_SUBNETS <<< "$LOCAL_SUBNETS"
for subnet in "${RAW_SUBNETS[@]}"; do
  subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [ -n "$subnet" ]; then
    if [[ "$subnet" == *:* ]]; then
      LOCAL_SUBNETS_IPV6="$subnet"
    else
      LOCAL_SUBNETS_IPV4="$subnet"
    fi
  fi
done

# Извлекаем IPv4 серверный IP
LOCAL_SERVER_IP=""
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS_IPV4" | cut -d'/' -f1)"
fi

# Извлекаем IPv6 серверный IP
LOCAL_SERVER_IP_IPV6=""
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  LOCAL_SERVER_IP_IPV6="$(echo "$LOCAL_SUBNETS_IPV6" | cut -d'/' -f1)"
fi

# "Безопасное" имя туннеля для суффиксов (только буквы/цифры/_)
TUN_SAFE="$(echo "$TUN" | sed 's/[^a-zA-Z0-9]/_/g')"
# Суффиксированные/уникальные имена цепочек/ресурсов
PF_CHAIN_NAT="PORT_FORWARD_NAT_${TUN_SAFE}"
PF_CHAIN_FILTER="PORT_FORWARD_FILTER_${TUN_SAFE}"
PF_CHAIN_SNAT="PORT_FORWARD_SNAT_${TUN_SAFE}"
RANDOM_WARP_CHAIN="RANDOM_WARP_${TUN_SAFE}"
IFB_IN="ifb_${TUN_SAFE}_in"
IFB_OUT="ifb_${TUN_SAFE}_out"
INPUT_CHAIN="INPUT_${TUN_SAFE}"
HAIRPIN_CHAIN="HAIRPIN_${TUN_SAFE}"

echo "————————————————————————————————"

# --- Функция: определить версию IP и вернуть команду iptables/ip6tables ---
# Использование: IPT_CMD="$(get_ipt_cmd "$subnet")"
#              $IPT_CMD -t mangle -A ... -d "$subnet" ...
get_ipt_cmd() {
  local addr="$1"
  # Проверяем, содержит ли адрес двоеточие (IPv6)
  if [[ "$addr" == *:* ]]; then
    echo "ip6tables"
  else
    echo "iptables"
  fi
}

# --- Helper функции для парсинга WARP_LIST (те же что в up.sh) ---
parse_warp_interfaces() {
  local entry="$1"
  if [[ "$entry" == *"="* ]]; then
    echo "${entry%%=*}"
  else
    echo "$entry"
  fi
}

parse_warp_subnets() {
  local entry="$1"
  if [[ "$entry" == *"="* ]]; then
    echo "${entry#*=}"
  else
    echo ""
  fi
}

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
# Должен совпадать с расчётом из up скрипта (диапазон 1000-9990)
# Используем cksum (более доступен чем od) или md5sum как fallback
TUN_HASH=$(echo -n "$TUN" | cksum 2>/dev/null | cut -d' ' -f1)
if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
  # Fallback на md5sum если cksum не доступен
  TUN_HASH=$(echo -n "$TUN" | md5sum 2>/dev/null | cut -c1-8)
  TUN_HASH=$((16#$TUN_HASH))  # Конвертация из hex в decimal
fi
if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
  # Последний fallback — используем длину имени
  TUN_HASH=${#TUN}
fi
MARK_BASE=$((1000 + (TUN_HASH % 900) * 10))

# --- Остановка WARP-туннелей ---
# Читаем WARP_LIST из файла сохранённого up скриптом
# Файлы хранятся рядом с up.sh/down.sh скриптом
WARP_LIST=()
if [ -f "$STATE_BASE_DIR/.warp/${TUN}_warp_list.conf" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && WARP_LIST+=("$line")
  done < "$STATE_BASE_DIR/.warp/${TUN}_warp_list.conf"
else
  echo "Ошибка: файл $STATE_BASE_DIR/.warp/${TUN}_warp_list.conf не найден!"
  echo "Правила iptables и ip rule не будут очищены автоматически!"
  echo "Очищаем только WARP интерфейсы через reference counting..."
fi

# Пропускаем, если WARP_LIST пустой или содержит только "none"
# Используем счётчик ссылок для поддержки общих WARP между туннелями
# Парсим формат: "warp0,warp1=subnet1, subnet2" или "warp0,warp1"
WARP_ACTIVE=0

# Собираем все уникальные WARP интерфейсы из всех записей WARP_LIST
declare -A ALL_WARP_INTERFACES
for entry in "${WARP_LIST[@]}"; do
  # Пропускаем "none" и пустые записи
  if [ "$entry" = "none" ] || [ -z "$entry" ]; then
    continue
  fi
  
  # Используем helper функцию для парсинга интерфейсов
  interfaces_part="$(parse_warp_interfaces "$entry")"
  
  # Разбиваем интерфейсы по запятой и обрезаем пробелы
  IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
  for iface in "${RAW_INTERFACES[@]}"; do
    iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ -n "$iface" ] && [ "$iface" != "none" ]; then
      ALL_WARP_INTERFACES["$iface"]=1
    fi
  done
done

# Останавливаем каждый уникальный WARP интерфейс
# Используем файлы для отслеживания активных WARP (переменные в subshell не работают)
WARP_ACTIVE=0
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  echo "🛑 Остановка WARP-туннеля: $warp"
  WARP_REF_FILE="$STATE_BASE_DIR/.warp/warp_${warp}.ref"
  WARP_LOCK_FILE="$STATE_BASE_DIR/.warp/warp_${warp}.lock"

  # Используем flock для предотвращения race condition
  (
    flock -x -w 10 200 || {
      echo "Ошибка: не удалось получить блокировку для $warp"
      exit 1
    }

    # Проверяем счётчик ссылок
    if [ -f "$WARP_REF_FILE" ]; then
      ref_count=$(cat "$WARP_REF_FILE" 2>/dev/null || echo "0")
      if [ "$ref_count" -le 1 ]; then
        # Последний пользователь, закрываем WARP
        if awg-quick down "$warp" 2>/dev/null; then
          : # WARP остановлен
        else
          echo "Ошибка остановки $warp: $?"
        fi
        rm -f "$WARP_REF_FILE"
      else
        # Уменьшаем счётчик
        echo $((ref_count - 1)) > "$WARP_REF_FILE"
      fi
    else
      # Файла нет, пробуем закрыть (на случай если счётчик потерялся)
      if awg-quick down "$warp" 2>/dev/null; then
        : # WARP остановлен
      else
        echo "Ошибка остановки $warp: $?"
      fi
    fi
  ) 200>"$WARP_LOCK_FILE"

  # Проверяем, удалось ли остановить WARP (файл .ref не существует)
  if [ ! -f "$WARP_REF_FILE" ]; then
    WARP_ACTIVE=1
    
    # Очищаем маршруты и правила для этого WARP (только если ref=0!)
    TABLE_ID=$(awk -v name="$warp" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
    if [ -n "$TABLE_ID" ]; then
      ip route flush table "$TABLE_ID" 2>/dev/null || true
    fi
    
    # Очищаем NAT правила для этого WARP
    iptables -t nat -D POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
    ip6tables -t nat -D POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
  fi
done

# Удаляем файлы активности WARP
rm -f "$STATE_BASE_DIR/.warp/warp_*.active" 2>/dev/null || true

# Удаляем файл со списком WARP_LIST (он больше не нужен)
rm -f "$STATE_BASE_DIR/.warp/${TUN}_warp_list.conf"

# Удаляем файл LAN_ALLOW (он больше не нужен)
rm -f "$STATE_BASE_DIR/.lan_allow_${TUN}.conf"

# --- Очистка маршрутизации и таблиц для WARP ---
if [ "$WARP_ACTIVE" -eq 1 ] && [ ${#ALL_WARP_INTERFACES[@]} -gt 0 ]; then
  # --- Сначала собираем все интерфейсы БЕЗ подсетей в одну группу ---
  DEFAULT_WARP_GROUP=()
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi
    if [[ "$entry" != *"="* ]]; then
      IFS=',' read -ra RAW_INTERFACES <<< "$entry"
      for iface in "${RAW_INTERFACES[@]}"; do
        iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ -n "$iface" ] && [ "$iface" != "none" ]; then
          DEFAULT_WARP_GROUP+=("$iface")
        fi
      done
    fi
  done

  # --- Собираем все подсети из записей с подсетями ---
  # Исключаем "none=" записи — они не нужны в ALL_SPECIFIC_SUBNETS
  ALL_SPECIFIC_SUBNETS=()
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi
    # Пропускаем "none=subnets" (с поддержкой пробелов вокруг =) — они не нужны в ALL_SPECIFIC_SUBNETS
    if [[ "$entry" =~ ^none[[:space:]]*= ]]; then
      continue
    fi
    if [[ "$entry" == *"="* ]]; then
      subnets_part="${entry#*=}"
      IFS=',' read -ra RAW_SUBNETS <<< "$subnets_part"
      for s in "${RAW_SUBNETS[@]}"; do
        s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$s" ] && ALL_SPECIFIC_SUBNETS+=("$s")
      done
    fi
  done

  # --- Удаляем ip rule для записей с подсетями ---
  MARK_OFFSET=0
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi

    if [[ "$entry" == *"="* ]]; then
      interfaces_part="${entry%%=*}"
    else
      continue
    fi

    # Разбиваем интерфейсы
    WARP_GROUP=()
    IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
    for iface in "${RAW_INTERFACES[@]}"; do
      iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ -n "$iface" ] && [ "$iface" != "none" ]; then
        WARP_GROUP+=("$iface")
      fi
    done

    WARP_GROUP_COUNT=${#WARP_GROUP[@]}
    if [ "$WARP_GROUP_COUNT" -eq 0 ]; then
      continue
    fi

    # Удаляем ip rule для каждого MARK в группе
    for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${WARP_GROUP[$i]}"
      ip rule del fwmark $MARK table "$warp_iface" 2>/dev/null || true
      ip route del default dev "$warp_iface" table "$warp_iface" 2>/dev/null || true
    done

    MARK_OFFSET=$((MARK_OFFSET + WARP_GROUP_COUNT))
  done

  # --- Удаляем ip rule для интерфейсов БЕЗ подсетей ---
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${DEFAULT_WARP_GROUP[$i]}"
      # Получаем TABLE_ID из rt_tables
      TABLE_ID=$(awk -v name="$warp_iface" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
      if [ -n "$TABLE_ID" ]; then
        ip rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        ip route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
      fi
    done
  fi
fi

# --- Очистка iptables/ip6tables для балансировки WARP (цепочка специфична для туннеля) ---
# Очищаем всегда, даже если WARP не активен (на случай если правила остались)
# Используем обе команды для поддержки IPv4 и IPv6
iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -D PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$RANDOM_WARP_CHAIN" 2>/dev/null || true

ip6tables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
ip6tables -t mangle -X "$RANDOM_WARP_CHAIN" 2>/dev/null || true

# --- Очистка FORWARD для трафика через WARP (IPv4) ---
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  iptables -D FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
done

# --- Очистка FORWARD для трафика через WARP (IPv6) ---
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  ip6tables -D FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  ip6tables -D FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
done

# --- Удаляем Hairpin NAT (IPv4 + IPv6) ---
iptables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
iptables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
iptables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true

ip6tables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
ip6tables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
ip6tables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true

# --- Очистка broadcast/multicast правил (mangle + filter) ---
# Очищаем mark правила для broadcast (IPv4) и multicast (IPv6)
# Используем избирательную очистку по интерфейсу чтобы не затронуть другие туннели
# Используем одинаковые mark (100-199) для IPv4 и IPv6 так как это разные таблицы

# IPv4 Broadcast очистка (mangle mark) - только для этого туннеля
iptables -t mangle -D FORWARD -i "$TUN" -d "$BROADCAST_ADDR" -j MARK --set-mark 100 2>/dev/null || true
iptables -t mangle -D FORWARD -i "$TUN" -d 255.255.255.255 -j MARK --set-mark 100 2>/dev/null || true
# Очищаем все mark для этого туннеля (перебор от 100 до 199)
for mark in $(seq 100 199); do
  iptables -t mangle -D FORWARD -i "$TUN" -j MARK --set-mark $mark 2>/dev/null || true
done
# Очищаем ACCEPT правила для broadcast (filter таблица)
for mark in $(seq 100 199); do
  iptables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $mark -j ACCEPT 2>/dev/null || true
done

# IPv6 Multicast очистка (mangle mark) - только для этого туннеля
# Используем те же mark (100-199) так как это разные таблицы
ip6tables -t mangle -D FORWARD -i "$TUN" -d "ff02::1" -j MARK --set-mark 100 2>/dev/null || true
# Очищаем все mark для этого туннеля (перебор от 100 до 199)
for mark in $(seq 100 199); do
  ip6tables -t mangle -D FORWARD -i "$TUN" -j MARK --set-mark $mark 2>/dev/null || true
done
# Очищаем ACCEPT правила для multicast (filter таблица)
for mark in $(seq 100 199); do
  ip6tables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $mark -j ACCEPT 2>/dev/null || true
done

# --- Полное удаление цепочек проброса портов (специфично для туннеля) ---
# IPv4 + IPv6 очистка
echo "🧹 Очистка проброса портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_SNAT, $PF_CHAIN_FILTER)"

# IPv4 проброс портов (очищаем правило БЕЗ -i так как добавляли без него!)
iptables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true

iptables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
iptables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
iptables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true

iptables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true

# IPv6 проброс портов (очищаем правило БЕЗ -i так как добавляли без него!)
ip6tables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true

ip6tables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true

ip6tables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true

# --- Очистка FORWARD и NAT для трафика напрямую через внешний интерфейс ---
# Очищаем суффиксированную цепочку INPUT (IPv4 + IPv6)

# IPv4 INPUT
iptables -t filter -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
iptables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
iptables -t filter -X "$INPUT_CHAIN" 2>/dev/null || true

# IPv6 INPUT
ip6tables -t filter -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
ip6tables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
ip6tables -t filter -X "$INPUT_CHAIN" 2>/dev/null || true

# Очищаем правило локальной сети (из up скрипта) (IPv4 + IPv6)
# Читаем LAN_ALLOW из сохранённого файла в .state/
LAN_ALLOW_FILE="$STATE_BASE_DIR/.lan_allow_${TUN}.conf"
LAN_ALLOW=()
INTERFACE_MAP=()

if [ -f "$LAN_ALLOW_FILE" ]; then
  while IFS= read -r line; do
    # Читаем карту интерфейсов из комментария
    if [[ "$line" =~ ^#.*INTERFACE_MAP: ]]; then
      # Извлекаем карту интерфейсов: "# INTERFACE_MAP: awg0=10.0.0.0/24 awg1=10.1.0.0/24"
      map_part="${line#*INTERFACE_MAP: }"
      for mapping in $map_part; do
        INTERFACE_MAP+=("$mapping")
      done
    elif [ -n "$line" ]; then
      # Читаем правила LAN_ALLOW
      LAN_ALLOW+=("$line")
    fi
  done < "$LAN_ALLOW_FILE"
fi

# Функция: найти имя интерфейса из INTERFACE_MAP по IP/подсети
find_tun_from_map() {
  local ip_or_subnet="$1"
  
  # Ищем в сохранённой карте интерфейсов
  for mapping in "${INTERFACE_MAP[@]}"; do
    tun_name="${mapping%%=*}"      # awg0 из "awg0=10.0.0.0/24"
    tun_subnet="${mapping#*=}"     # 10.0.0.0/24 из "awg0=10.0.0.0/24"
    
    # Проверяем попадает ли IP в эту подсеть
    if python3 -c "
import ipaddress
try:
    ip = ipaddress.ip_network('$ip_or_subnet', strict=False)
    tun_net = ipaddress.ip_network('$tun_subnet', strict=False)
    if ip.subnet_of(tun_net) or tun_net.subnet_of(ip) or ip.overlaps(tun_net):
        exit(0)
    exit(1)
except:
    exit(1)
" 2>/dev/null; then
      echo "$tun_name"
      return 0
    fi
  done
  
  # Не нашли в карте — возвращаем пусто
  echo ""
  return 1
}

# Очищаем правила локальная сети если они есть
if [ ${#LAN_ALLOW[@]} -gt 0 ]; then
  echo "Очистка правил локальной сети (${#LAN_ALLOW[@]} групп сегментации)"

  # Проходим по каждому правилу в LAN_ALLOW и удаляем созданные правила
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"
    PARTS_CLEAN=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -n "$part" ] && PARTS_CLEAN+=("$part")
    done

    [ ${#PARTS_CLEAN[@]} -eq 0 ] && continue

    # Если часть всего одна — очищаем только внутри себя
    if [ ${#PARTS_CLEAN[@]} -eq 1 ]; then
      SOURCE="${PARTS_CLEAN[0]}"
      SOURCE_TUN=$(find_tun_from_map "$SOURCE")
      [ -z "$SOURCE_TUN" ] && continue

      if [[ "$SOURCE" == *:* ]]; then
        IPT_CMD="ip6tables"
      else
        IPT_CMD="iptables"
      fi

      $IPT_CMD -D FORWARD -i "$SOURCE_TUN" -o "$SOURCE_TUN" -s "$SOURCE" -d "$SOURCE" -j ACCEPT 2>/dev/null || true
    else
      # Если частей несколько — очищаем ВСЕ пары (все ↔ все)
      for ((i=0; i<${#PARTS_CLEAN[@]}; i++)); do
        for ((j=0; j<${#PARTS_CLEAN[@]}; j++)); do
          [ $i -eq $j ] && continue

          SRC="${PARTS_CLEAN[$i]}"
          DST="${PARTS_CLEAN[$j]}"

          # Находим туннели из сохранённой карты (даже если интерфейс не существует!)
          SRC_TUN=$(find_tun_from_map "$SRC")
          DST_TUN=$(find_tun_from_map "$DST")

          # Пропускаем если туннель не найден в карте
          [ -z "$SRC_TUN" ] && continue
          [ -z "$DST_TUN" ] && continue

          if [[ "$SRC" == *:* ]]; then
            IPT_CMD="ip6tables"
          else
            IPT_CMD="iptables"
          fi

          # Пытаемся удалить правило (даже если интерфейс не существует)
          $IPT_CMD -D FORWARD -i "$SRC_TUN" -o "$DST_TUN" -s "$SRC" -d "$DST" -j ACCEPT 2>/dev/null || true
        done
      done
    fi
  done

  # Удаляем файл
  rm -f "$LAN_ALLOW_FILE"
fi

# Удаляем DROP правило межклиентского трафика (оно было добавлено в up.sh)
iptables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true

# Очищаем старые универсальные правила (если вдруг они есть)
iptables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true

# Очищаем правила FORWARD для трафика напрямую через внешний интерфейс
iptables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

ip6tables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# POSTROUTING MASQUERADE не удаляем — он общий для всех туннелей (IPv4 и IPv6)

# --- Откат лимитов скорости (tc и ifb) ---
# Очищаем всё, что могло быть создано для этого туннеля
# tc работает на уровне устройств, поэтому очистка универсальна для IPv4 + IPv6
echo "🧹 Очистка лимитов скорости"
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" handle ffff: ingress 2>/dev/null || true
tc qdisc del dev "$IFB_IN" root 2>/dev/null || true
ip link set "$IFB_IN" down 2>/dev/null || true
ip link delete "$IFB_IN" 2>/dev/null || true
tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
ip link set "$IFB_OUT" down 2>/dev/null || true
ip link delete "$IFB_OUT" 2>/dev/null || true

echo "————————————————————————————————"
'''

# ----------------- Утилиты -----------------


def atomic_write_text(path: pathlib.Path, text: str, encoding: str = "utf-8") -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as f:
            f.write(text)
        os.replace(tmpname, str(path))
    finally:
        try:
            if os.path.exists(tmpname):
                os.remove(tmpname)
        except Exception:
            pass


def exec_cmd(cmd, input: Optional[str] = None, shell: bool = False, timeout: Optional[int] = None) -> Tuple[int, str]:
    try:
        use_shell = shell
        if isinstance(cmd, str) and not shell:
            use_shell = True
        proc = subprocess.run(
            cmd,
            input=input,
            shell=use_shell,
            check=False,
            timeout=timeout,
            encoding="utf8",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        rc = proc.returncode
        out = proc.stdout or ""
        return rc, out
    except subprocess.TimeoutExpired as e:
        return 124, getattr(e, "output", "") or ""
    except Exception as e:
        return 1, f"exec_cmd failed: {e}"


def gen_pair_keys(cfg_type: Optional[str] = None) -> Tuple[str, str]:
    global g_main_config_type
    if not cfg_type:
        cfg_type = g_main_config_type
    if not cfg_type:
        raise RuntimeError("Неизвестный тип конфига для генерации ключей")
    wgtool = "wg" if cfg_type.lower().startswith("w") else "awg"
    rc, out = exec_cmd([wgtool, "genkey"])
    if rc != 0 or not out:
        # Fallback
        if wgtool == "awg":
            logger.warning("⚠  awg не найден, пробую wg...")
            rc, out = exec_cmd(["wg", "genkey"])
            wgtool = "wg"
    if rc != 0 or not out:
        raise RuntimeError(f"Не удалось сгенерировать приватный ключ через {wgtool}: {out.strip()}")
    priv = out.strip()
    rc, out = exec_cmd([wgtool, "pubkey"], input=priv + "\n")
    if rc != 0 or not out:
        raise RuntimeError(f"Не удалось сгенерировать публичный ключ через {wgtool}: {out.strip()}")
    pub = out.strip()
    return priv, pub


def gen_preshared_key() -> str:
    rc, out = exec_cmd(["openssl", "rand", "-base64", "32"])
    if rc == 0 and out:
        return out.strip()
    try:
        return base64.b64encode(os.urandom(32)).decode("ascii")
    except Exception:
        raise RuntimeError("Не удалось сгенерировать preshared key")


def get_main_iface() -> Optional[str]:
    rc, out = exec_cmd(["ip", "link", "show"])
    if rc != 0:
        logger.warning("⚠  Не удалось выполнить 'ip link show': %s", out.strip())
        return None
    for line in out.splitlines():
        if "<BROADCAST" in line and "state UP" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[1].strip()
    return None


def get_ext_ipaddr() -> str:
    try:
        r = requests.get("https://icanhazip.com", timeout=6)
        r.raise_for_status()
        ip = r.text.strip()
        ipaddress.ip_address(ip)
        return ip
    except Exception as e:
        raise RuntimeError(f"Не удалось получить внешний IP: {e}")


class IPAddr:
    def __init__(self, ipaddr: Optional[str] = None):
        self.ip = [0, 0, 0, 0]
        self.mask: Optional[int] = None
        if ipaddr:
            self.init(ipaddr)

    def init(self, ipaddr: str) -> None:
        _ipaddr = ipaddr
        if not ipaddr:
            raise RuntimeError(f'Некорректный IP: "{_ipaddr}"')
        if '/' in ipaddr:
            try:
                self.mask = int(ipaddr.split('/')[1])
            except Exception:
                raise RuntimeError(f'Некорректный IP: "{_ipaddr}"')
            ipaddr = ipaddr.split('/')[0]
        parts = ipaddr.split('.')
        if len(parts) != 4:
            raise RuntimeError(f'Некорректный IP: "{_ipaddr}"')
        for i, p in enumerate(parts):
            try:
                self.ip[i] = int(p)
            except Exception:
                raise RuntimeError(f'Некорректный IP: "{_ipaddr}"')

    def __str__(self) -> str:
        out = f'{self.ip[0]}.{self.ip[1]}.{self.ip[2]}.{self.ip[3]}'
        if self.mask:
            out += '/' + str(self.mask)
        return out


# ----------------- WGConfig (Original Logic) -----------------

class WGConfig:
    def __init__(self, filename: Optional[str] = None):
        self.lines: List[str] = []
        self.iface: Dict[str, str] = {}
        self.peer: Dict[str, Dict[str, str]] = {}
        self.idsline: Dict[str, int] = {}
        self.cfg_fn: Optional[pathlib.Path] = None
        if filename:
            self.load(filename)

    def load(self, filename: str) -> int:
        self.cfg_fn = pathlib.Path(filename)
        self.lines = []
        self.iface = {}
        self.peer = {}
        self.idsline = {}
        with open(self.cfg_fn, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        iface = None
        secdata = []
        secline = []
        secitem = None
        lineitem = None
        for n, raw in enumerate(lines):
            line = raw.rstrip("\n").rstrip("\r")
            self.lines.append(line)
            if line.strip() == '' or (line.startswith('#') and not line.startswith('#_')):
                continue
            if line.startswith('[') and line.endswith(']'):
                name = line[1:-1]
                secitem = {"_section_name": name.lower()}
                lineitem = {"_section_name": n}
                secdata.append(secitem)
                secline.append(lineitem)
                if name.lower() == 'interface':
                    if iface:
                        raise RuntimeError("Найдены несколько секций Interface")
                    iface = secitem
                continue
            parsed = line
            if parsed.startswith('#_') and '=' in parsed:
                parsed = parsed[2:]
            if parsed.startswith('#'):
                continue
            if '=' not in parsed:
                continue
            xv = parsed.find('=')
            vname = parsed[:xv].strip()
            value = parsed[xv + 1 :].strip()
            if not secitem or not lineitem:
                continue
            secitem[vname] = value
            lineitem[vname] = n
        if not iface:
            raise RuntimeError("Не найдена секция Interface")
        for i, item in enumerate(secdata):
            lineinfo = secline[i]
            if item['_section_name'] == 'interface':
                self.iface = item
                pname = "__this_server__"
            else:
                if 'Name' in item:
                    pname = item['Name']
                elif 'PublicKey' in item:
                    pname = item['PublicKey']
                else:
                    continue
                if 'AllowedIPs' not in item:
                    continue
                if pname in self.peer:
                    raise RuntimeError(f'Дублирование peer {pname}')
                self.peer[pname] = item
            if pname in self.idsline:
                raise RuntimeError(f'Дублирование\tidline для {pname}')
            min_line = lineinfo['_section_name']
            max_line = min_line
            self.idsline[pname] = min_line
            for v in item:
                if v in lineinfo:
                    self.idsline[f'{pname}|{v}'] = lineinfo[v]
                    if lineinfo[v] > max_line:
                        max_line = lineinfo[v]
            item['_lines_range'] = (min_line, max_line)
        self.cfg_fn = pathlib.Path(filename)
        return len(self.peer)

    def save(self, filename: Optional[str] = None) -> None:
        if not filename:
            if not self.cfg_fn:
                raise RuntimeError('Нет данных для сохранения: файл не указан')
            filename = str(self.cfg_fn)
        if not self.lines:
            raise RuntimeError('Нет данных для сохранения')
        atomic_write_text(pathlib.Path(filename), "\n".join(self.lines) + "\n")

    def del_client(self, c_name: str) -> str:
        if c_name not in self.peer:
            raise RuntimeError(f'Клиент не найден: {c_name}')
        client = self.peer[c_name]
        ipaddr = client['AllowedIPs']
        min_line, max_line = client['_lines_range']
        del self.lines[min_line : max_line + 1]
        del self.peer[c_name]
        secsize = max_line - min_line + 1
        del_list = []
        for k, v in list(self.idsline.items()):
            if v >= min_line and v <= max_line:
                del_list.append(k)
            elif v > max_line:
                self.idsline[k] = v - secsize
        for k in del_list:
            if k in self.idsline:
                del self.idsline[k]
        return ipaddr

    def set_param(self, c_name: str, param_name: str, param_value: str, force: bool = False, offset: int = 0) -> None:
        if c_name not in self.peer:
            raise RuntimeError(f'Клиент не найден: {c_name}')
        line_prefix = "" if not param_name.startswith('_') else "#_"
        param_key = param_name[1:] if param_name.startswith('_') else param_name
        client = self.peer[c_name]
        min_line, max_line = client['_lines_range']
        if param_key in client:
            nline = self.idsline[f'{c_name}|{param_key}']
            line = self.lines[nline]
            if line.startswith('#_'):
                line_prefix = "#_"
            self.lines[nline] = f'{line_prefix}{param_key} = {param_value}'
            client[param_key] = param_value
            return
        if not force:
            raise RuntimeError(f'Параметр не найден: {param_key} для {c_name}')
        new_line = f'{line_prefix}{param_key} = {param_value}'
        client[param_key] = param_value
        secsize = max_line - min_line + 1
        if offset >= secsize or offset < 0:
            offset = 0
        pos = max_line + 1 if offset <= 0 else min_line + offset
        for k, v in list(self.idsline.items()):
            if v >= pos:
                self.idsline[k] = v + 1
        self.idsline[f'{c_name}|{param_key}'] = pos
        self.lines.insert(pos, new_line)
        client['_lines_range'] = (min_line, max_line + 1)


# ----------------- Проверка endpoint'ов WARP и генерация -----------------

CANDIDATE_WARP_ENDPOINTS = [
    # Domain-based (Cloudflare автоматически выберет IPv4 или IPv6)
    "engage.cloudflareclient.com:2408",
    "engage.cloudflareclient.com:4500",
    "engage.cloudflareclient.com:500",
    "engage.cloudflareclient.com:1002",
    "engage.cloudflareclient.com:1701",
    "engage.cloudflareclient.com:3138",
    "engage.cloudflareclient.com:3581",
    "engage.cloudflareclient.com:7559",
    "engage.cloudflareclient.com:8080",
    "engage.cloudflareclient.com:8443",
    
    # IPv4 Endpoints (162.159.192.x range)
    "162.159.192.1:500",
    "162.159.192.1:1002",
    "162.159.192.1:2408",
    "162.159.192.1:3138",
    "162.159.192.1:4500",
    "162.159.192.1:7559",
    "162.159.192.9:500",
    "162.159.192.9:1002",
    "162.159.192.9:2408",
    "162.159.192.9:3138",
    "162.159.192.9:4500",
    "162.159.192.9:7559",
    
    # IPv4 Endpoints (162.159.193.x range)
    "162.159.193.1:500",
    "162.159.193.1:1002",
    "162.159.193.1:2408",
    "162.159.193.1:4500",
    
    # IPv4 Endpoints (188.114.96-99.x range - Europe)
    "188.114.96.1:500",
    "188.114.96.1:1002",
    "188.114.96.1:2408",
    "188.114.97.1:500",
    "188.114.97.1:2408",
    "188.114.98.124:3581",
    "188.114.98.36:7559",
    "188.114.99.1:500",
    "188.114.99.1:2408",
    "188.114.99.224:1002",
    
    # IPv6 Endpoints (Cloudflare IPv6 ranges)
    "[2606:4700:d0::a29f:c001]:2408",
    "[2606:4700:d0::a29f:c001]:4500",
    "[2606:4700:d1::a29f:c001]:2408",
    "[2606:4700:d1::a29f:c001]:4500",
    "[2a06:98c0:3600::103]:2408",
    "[2a06:98c0:3600::103]:4500",
]

FALLBACK_DSYT_ALLOWEDIPS = (
    "1.0.0.0/9, 1.192.0.0/10, 100.24.0.0/13, 101.64.0.0/10, 103.0.0.0/14, 103.100.128.0/19, 103.101.0.0/18, 103.103.128.0/17, 103.105.0.0/16, 103.106.192.0/18, 103.107.128.0/17, 103.108.0.0/17, 103.111.128.0/17, 103.111.64.0/19, 103.112.48.0/21, 103.118.64.0/18, 103.119.0.0/16, 103.12.0.0/16, 103.120.0.0/16, 103.122.0.0/15, 103.124.0.0/16, 103.132.16.0/20, 103.132.64.0/18, 103.137.0.0/17, 103.139.128.0/17, 103.14.16.0/20, 103.140.0.0/16, 103.141.64.0/22, 103.144.0.0/16, 103.146.0.0/15, 103.148.0.0/14, 103.15.0.0/16, 103.152.0.0/13, 103.160.0.0/11, 103.17.128.0/17, 103.192.0.0/17, 103.193.0.0/17, 103.196.128.0/17, 103.199.0.0/18, 103.199.192.0/19, 103.199.224.0/21, 103.199.64.0/20, 103.20.0.0/16, 103.200.28.0/22, 103.200.32.0/19, 103.206.128.0/18, 103.21.0.0/17, 103.21.128.0/18, 103.211.104.0/21, 103.211.16.0/20, 103.214.160.0/20, 103.214.192.0/18, 103.218.0.0/16, 103.221.128.0/17, 103.224.0.0/16, 103.225.176.0/20, 103.225.96.0/19, 103.226.128.0/18, 103.226.224.0/19, 103.228.130.0/23, 103.230.0.0/17, 103.232.128.0/19, 103.233.0.0/16, 103.234.0.0/17, 103.240.180.0/22, 103.242.0.0/19, 103.242.128.0/17, 103.243.0.0/18, 103.243.112.0/21, 103.246.240.0/21, 103.249.0.0/16, 103.25.128.0/17, 103.251.0.0/17, 103.251.192.0/18, 103.252.96.0/19, 103.26.208.0/20, 103.27.0.0/17, 103.28.0.0/15, 103.38.0.0/16, 103.39.128.0/17, 103.39.64.0/18, 103.40.0.0/16, 103.41.0.0/19, 103.42.0.0/16, 103.44.0.0/16, 103.52.0.0/16, 103.54.32.0/19, 103.56.0.0/17, 103.58.64.0/18, 103.59.128.0/17, 103.62.128.0/17, 103.66.64.0/18, 103.7.0.0/17, 103.70.0.0/16, 103.73.160.0/21, 103.73.64.0/18, 103.76.192.0/18, 103.80.0.0/17, 103.85.128.0/17, 103.85.64.0/18, 103.88.192.0/19, 103.89.0.0/16, 103.94.128.0/17, 103.97.0.0/18, 103.97.128.0/18, 104.16.0.0/12, 104.237.160.0/19, 104.244.40.0/21, 104.36.192.0/21, 105.0.0.0/8, 106.0.0.0/8, 107.181.160.0/19, 108.136.0.0/14, 108.156.0.0/14, 108.160.160.0/20, 108.177.0.0/17, 109.224.41.0/24, 109.239.184.0/21, 110.0.0.0/10, 110.128.0.0/10, 110.64.0.0/12, 110.93.128.0/17, 111.0.0.0/8, 112.0.0.0/8, 113.128.0.0/10, 113.192.0.0/13, 113.64.0.0/10, 114.0.0.0/9, 114.136.0.0/13, 114.250.63.0/24, 114.250.64.0/23, 114.250.67.0/24, 114.250.69.0/24, 114.250.70.0/24, 115.126.0.0/15, 115.164.0.0/15, 115.176.0.0/12, 115.64.0.0/11, 116.204.128.0/18, 116.206.0.0/18, 116.206.128.0/19, 116.212.128.0/19, 116.56.0.0/13, 116.64.0.0/10, 117.0.0.0/12, 117.128.0.0/9, 117.52.0.0/15, 117.55.224.0/19, 117.96.0.0/12, 118.107.180.0/22, 118.128.0.0/9, 118.68.0.0/14, 118.96.0.0/13, 119.0.0.0/13, 119.152.0.0/13, 119.16.0.0/12, 119.160.0.0/11, 119.32.0.0/11, 120.0.0.0/8, 121.64.0.0/12, 122.0.0.0/10, 122.144.0.0/14, 122.152.0.0/13, 122.192.0.0/11, 122.248.0.0/14, 122.252.0.0/15, 123.104.0.0/13, 123.128.0.0/10, 123.192.0.0/11, 123.240.0.0/13, 123.253.0.0/18, 124.0.0.0/9, 124.192.0.0/11, 124.248.0.0/14, 125.128.0.0/9, 125.64.0.0/10, 128.0.0.0/16, 128.121.0.0/16, 128.242.0.0/16, 128.75.0.0/16, 13.224.0.0/12, 13.248.0.0/14, 13.32.0.0/12, 130.211.0.0/16, 132.245.0.0/16, 137.59.16.0/20, 137.59.32.0/20, 137.59.64.0/18, 138.128.136.0/21, 139.5.64.0/19, 14.102.128.0/18, 14.128.0.0/9, 140.213.0.0/16, 142.161.0.0/16, 142.250.0.0/15, 143.204.0.0/16, 144.48.128.0/18, 145.236.72.0/23, 145.255.0.0/20, 146.75.0.0/16, 148.163.0.0/17, 148.64.96.0/20, 148.69.0.0/16, 149.154.160.0/20, 149.54.0.0/17, 15.196.0.0/14, 15.204.0.0/16, 150.107.0.0/18, 150.107.204.0/22, 150.129.0.0/21, 150.129.32.0/19, 150.129.96.0/19, 151.101.0.0/16, 154.0.0.0/13, 154.64.0.0/10, 156.233.0.0/16, 157.20.0.0/16, 157.240.0.0/16, 157.8.0.0/14, 159.106.0.0/16, 159.138.0.0/16, 159.192.0.0/16, 159.65.0.0/16, 161.49.0.0/17, 162.125.0.0/16, 162.158.0.0/15, 162.210.192.0/21, 162.220.8.0/21, 162.252.180.0/22, 163.40.0.0/13, 163.53.64.0/18, 164.215.0.0/16, 165.165.0.0/16, 165.21.0.0/16, 166.117.0.0/16, 166.70.0.0/16, 168.143.0.0/16, 170.149.0.0/16, 170.178.160.0/19, 170.238.0.0/16, 171.128.0.0/9, 171.96.0.0/11, 172.217.0.0/16, 172.241.208.0/21, 172.253.0.0/16, 172.64.0.0/13, 173.194.0.0/16, 173.208.128.0/17, 173.208.64.0/18, 173.231.0.0/18, 173.234.144.0/20, 173.234.32.0/19, 173.236.128.0/17, 173.244.192.0/19, 173.252.192.0/18, 173.252.64.0/18, 173.255.192.0/18, 174.143.0.0/16, 174.36.0.0/15, 175.104.0.0/14, 175.112.0.0/12, 175.96.0.0/13, 176.28.128.0/17, 177.64.0.0/12, 178.128.240.0/20, 178.151.230.0/24, 178.176.156.0/24, 178.22.168.0/24, 179.32.0.0/12, 179.60.0.0/16, 179.64.0.0/10, 18.128.0.0/9, 18.64.0.0/10, 180.149.224.0/19, 180.149.48.0/20, 180.149.64.0/18, 180.160.0.0/11, 180.192.0.0/11, 181.0.0.0/11, 181.208.0.0/14, 182.0.0.0/9, 182.176.0.0/12, 182.192.0.0/10, 183.0.0.0/8, 184.150.0.0/17, 184.150.128.0/18, 184.172.0.0/15, 184.72.0.0/15, 185.100.209.0/24, 185.107.56.0/24, 185.158.208.0/23, 185.192.248.0/26, 185.192.249.0/24, 185.192.251.192/26, 185.23.124.0/23, 185.45.4.0/22, 185.48.9.0/24, 185.5.161.0/26, 185.60.216.0/22, 185.61.94.0/23, 185.76.151.0/24, 186.128.0.0/9, 187.0.0.0/11, 187.128.0.0/9, 188.114.96.0/22, 188.120.127.0/24, 188.166.0.0/17, 188.21.9.0/24, 188.43.61.0/24, 188.43.68.0/23, 188.93.174.0/24, 189.128.0.0/9, 190.0.0.0/10, 190.224.0.0/11, 192.133.76.0/22, 192.135.88.0/21, 192.157.48.0/20, 192.178.0.0/15, 192.248.0.0/17, 192.86.0.0/24, 193.109.164.0/22, 193.126.242.0/26, 194.78.0.0/24, 194.9.24.0/24, 194.9.25.0/24, 195.12.177.0/26, 195.176.255.192/26, 195.187.0.0/16, 195.87.177.0/24, 195.95.178.0/24, 196.1.128.0/17, 196.128.0.0/9, 196.32.0.0/11, 197.0.0.0/8, 198.27.64.0/18, 198.44.160.0/19, 199.115.112.0/21, 199.16.156.0/22, 199.193.112.0/21, 199.232.0.0/16, 199.59.148.0/22, 199.85.224.0/21, 199.96.56.0/21, 200.96.0.0/11, 201.0.0.0/11, 201.160.0.0/11, 201.48.0.0/16, 202.128.0.0/14, 202.136.0.0/13, 202.148.0.0/14, 202.152.0.0/13, 202.160.0.0/15, 202.163.0.0/16, 202.165.0.0/16, 202.166.0.0/15, 202.168.0.0/15, 202.182.0.0/15, 202.184.0.0/13, 202.24.0.0/13, 202.39.0.0/16, 202.51.64.0/21, 202.51.72.0/22, 202.51.79.0/24, 202.52.0.0/14, 202.60.0.0/16, 202.64.0.0/14, 202.68.0.0/15, 202.70.0.0/16, 202.72.0.0/14, 202.79.0.0/17, 202.80.0.0/13, 202.88.0.0/14, 202.93.0.0/16, 203.101.0.0/16, 203.110.0.0/15, 203.112.0.0/12, 203.128.0.0/12, 203.144.0.0/13, 203.162.0.0/15, 203.167.0.0/16, 203.170.0.0/16, 203.171.128.0/17, 203.176.0.0/13, 203.184.0.0/14, 203.189.0.0/17, 203.192.0.0/10, 203.64.0.0/13, 203.76.0.0/15, 203.78.0.0/17, 203.80.0.0/13, 204.11.56.0/23, 204.145.2.0/23, 204.212.0.0/14, 204.79.196.0/23, 204.84.0.0/15, 205.186.128.0/18, 206.144.0.0/14, 207.231.168.0/21, 207.244.64.0/18, 208.0.0.0/11, 208.101.0.0/18, 208.110.64.0/19, 208.115.192.0/18, 208.187.128.0/17, 208.192.0.0/10, 208.43.0.0/16, 208.54.0.0/17, 208.77.40.0/21, 208.84.220.0/22, 208.91.196.0/23, 208.98.128.0/18, 209.115.128.0/17, 209.141.112.0/20, 209.145.96.0/19, 209.146.0.0/17, 209.148.128.0/17, 209.191.192.0/19, 209.52.0.0/15, 209.85.128.0/17, 209.91.64.0/18, 209.95.32.0/19, 209.97.0.0/18, 210.0.0.0/7, 212.106.200.0/21, 212.113.52.0/24, 212.156.0.0/16, 212.188.10.0/24, 212.188.34.0/24, 212.188.35.0/24, 212.188.37.0/24, 212.188.49.0/24, 212.20.18.0/24, 212.32.224.0/19, 212.39.86.0/24, 212.43.1.0/24, 212.43.8.0/21, 212.55.184.0/22, 212.7.208.0/22, 212.90.48.0/20, 212.92.104.0/21, 213.152.1.64/27, 213.180.193.0/24, 213.202.0.0/21, 213.55.64.0/18, 213.59.192.0/18, 216.105.64.0/20, 216.123.192.0/18, 216.137.32.0/19, 216.19.176.0/20, 216.239.32.0/19, 216.245.192.0/19, 216.58.192.0/19, 217.119.118.64/26, 217.130.7.0/25, 217.175.200.64/26, 217.197.248.0/23, 217.73.128.0/22, 218.0.0.0/7, 220.0.0.0/9, 220.160.0.0/11, 221.0.0.0/8, 222.0.0.0/8, 223.128.0.0/9, 223.25.128.0/17, 223.27.128.0/17, 223.32.0.0/11, 23.142.48.0/24, 23.152.160.0/24, 23.192.0.0/11, 23.224.0.0/15, 23.227.32.0/19, 23.234.0.0/18, 23.82.0.0/16, 23.96.0.0/13, 24.244.0.0/18, 27.112.0.0/13, 27.128.0.0/9, 27.2.0.0/15, 27.64.0.0/11, 27.96.0.0/12, 3.128.0.0/9, 31.13.64.0/18, 31.145.0.0/16, 34.0.0.0/15, 34.192.0.0/10, 34.2.0.0/15, 34.64.0.0/10, 35.184.0.0/13, 35.192.0.0/12, 35.208.0.0/12, 35.224.0.0/12, 35.240.0.0/13, 36.0.0.0/9, 37.1.216.0/21, 37.152.0.0/22, 37.48.64.0/18, 38.0.0.0/7, 4.0.0.0/9, 40.136.0.0/15, 40.96.0.0/12, 41.0.0.0/8, 42.0.0.0/8, 43.224.0.0/16, 43.226.16.0/20, 43.228.0.0/16, 43.230.128.0/21, 43.245.128.0/20, 43.245.144.0/21, 43.245.192.0/20, 43.245.96.0/20, 43.250.0.0/16, 43.252.16.0/21, 44.192.0.0/10, 45.112.128.0/18, 45.113.128.0/18, 45.114.8.0/21, 45.116.192.0/19, 45.116.224.0/20, 45.118.240.0/21, 45.121.128.0/17, 45.124.0.0/18, 45.127.0.0/17, 45.134.10.0/24, 45.14.108.0/22, 45.249.0.0/16, 45.253.0.0/16, 45.54.0.0/17, 45.64.0.0/16, 45.76.0.0/15, 46.134.192.0/18, 46.32.101.0/24, 46.36.112.0/20, 46.61.0.0/16, 47.88.0.0/14, 49.192.0.0/11, 49.224.0.0/13, 49.32.0.0/11, 5.195.0.0/16, 5.200.14.128/25, 5.21.228.0/22, 5.30.0.0/15, 5.32.175.0/24, 5.79.64.0/18, 50.0.0.0/15, 50.117.0.0/17, 50.128.0.0/9, 50.22.0.0/15, 50.87.0.0/16, 51.39.0.0/16, 51.81.0.0/16, 52.0.0.0/10, 52.160.0.0/11, 52.222.0.0/16, 52.84.0.0/14, 52.96.0.0/12, 54.144.0.0/12, 54.224.0.0/11, 54.64.0.0/11, 58.0.0.0/10, 58.112.0.0/12, 58.128.0.0/9, 58.64.0.0/11, 59.0.0.0/9, 59.152.0.0/18, 59.152.96.0/20, 59.153.128.0/17, 59.160.0.0/11, 61.0.0.0/13, 61.128.0.0/9, 61.16.0.0/12, 61.32.0.0/11, 61.64.0.0/10, 62.0.0.0/16, 62.149.96.0/20, 62.212.240.0/20, 62.231.75.0/24, 63.64.0.0/10, 64.120.0.0/18, 64.13.192.0/18, 64.15.112.0/20, 64.233.160.0/19, 64.31.0.0/18, 64.4.224.0/20, 64.53.128.0/17, 65.192.0.0/11, 65.240.0.0/13, 65.49.0.0/17, 65.8.0.0/14, 66.102.0.0/20, 66.112.176.0/20, 66.151.176.0/20, 66.22.192.0/18, 66.220.144.0/20, 66.248.254.0/24, 66.58.128.0/17, 66.96.224.0/19, 67.15.0.0/16, 67.204.128.0/18, 67.228.0.0/16, 67.230.160.0/19, 67.50.0.0/17, 69.162.128.0/18, 69.162.64.0/18, 69.171.224.0/19, 69.197.128.0/18, 69.30.0.0/18, 69.48.216.0/21, 69.50.192.0/19, 69.51.64.0/18, 69.59.192.0/19, 69.63.176.0/20, 70.32.0.0/20, 72.19.32.0/19, 72.234.0.0/15, 74.125.0.0/16, 74.63.192.0/18, 74.86.0.0/16, 75.126.0.0/16, 75.2.0.0/17, 75.98.144.0/20, 76.223.0.0/17, 77.120.12.0/22, 77.247.183.144/28, 77.37.252.0/23, 79.133.76.0/23, 8.0.0.0/13, 8.32.0.0/11, 80.253.29.0/24, 80.77.172.0/22, 80.87.198.0/23, 80.87.64.0/19, 80.97.192.0/18, 81.130.96.0/20, 81.17.16.0/20, 81.171.0.0/19, 81.192.0.0/16, 81.200.2.0/24, 81.23.16.0/21, 81.23.24.0/21, 81.27.242.128/27, 82.114.162.0/23, 82.147.133.128/26, 82.148.96.0/19, 82.192.64.0/19, 82.76.231.64/26, 83.219.145.0/24, 83.224.64.0/20, 84.15.64.0/24, 84.235.64.0/22, 84.235.77.0/24, 84.235.78.0/24, 85.112.112.0/20, 86.120.7.128/27, 86.62.126.64/27, 87.245.192.0/20, 87.245.216.0/21, 88.191.249.0/24, 88.201.0.0/17, 89.27.128.0/17, 90.180.0.0/14, 90.200.0.0/14, 91.105.192.0/23, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.4.0/22, 91.108.56.0/22, 91.108.8.0/22, 91.185.2.0/24, 92.204.208.0/20, 92.80.0.0/13, 93.123.23.0/24, 93.179.96.0/21, 94.142.38.0/24, 94.203.108.0/23, 94.229.72.112/28, 94.24.192.0/18, 94.31.189.0/24, 94.96.0.0/14, 95.142.107.0/27, 95.161.64.0/20, 95.167.73.0/24, 95.168.192.0/19, 95.59.170.0/24, 95.66.0.0/18, 96.30.64.0/18, 96.44.128.0/18, 96.63.128.0/19, 96.9.128.0/19, 98.159.96.0/20, 99.83.128.0/17, 99.84.0.0/16, 99.86.0.0/16"
)


def check_endpoint(host_port: str, timeout: float = 1.5) -> bool:
    """
    Эвристическая проверка доступности endpoint'а:
    - пробуем TCP соединение
    - если не получилось — пробуем UDP "подключение" и посылку одного байта
    Возвращаем True если хотя бы один метод сработал.
    """
    try:
        host, sport = host_port.rsplit(":", 1)
        port = int(sport)
    except Exception:
        return False
    # Попытка TCP
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            s = socket.socket(af, socktype, proto)
            s.settimeout(timeout)
            try:
                s.connect(sa)
                s.close()
                return True
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
    except Exception:
        pass
    # Попытка UDP
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM):
            af, socktype, proto, canonname, sa = res
            s = socket.socket(af, socktype, proto)
            s.settimeout(timeout)
            try:
                s.connect(sa)
                s.send(b"\x00")
                s.close()
                return True
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
    except Exception:
        pass
    return False


def _select_endpoint_from_api_result(result: dict) -> Optional[str]:
    """
    Попытаться извлечь endpoint из различных возможных структур ответа API.
    """
    try:
        cfg = result.get("config") or {}
        peers = cfg.get("peers") or []
        if peers and isinstance(peers, list):
            ep = peers[0].get("endpoint")
            if ep:
                return ep
    except Exception:
        pass
    try:
        ep = result.get("endpoint")
        if ep:
            return ep
    except Exception:
        pass
    try:
        endpoints = result.get("endpoints") or result.get("servers")
        if isinstance(endpoints, list) and endpoints:
            first = endpoints[0]
            if isinstance(first, str):
                return first
            if isinstance(first, dict):
                return first.get("endpoint")
    except Exception:
        pass
    return None


def generate_warp_config(tun_name: str, index: int, mtu: int, proxy: str = "") -> Tuple[str, str]:
    """
    Генерация одного WARP-конфига.
    """
    api = "https://api.cloudflareclient.com/v0i1909051800"
    headers = {"user-agent": "amneziawg-script/1.0", "content-type": "application/json"}

    # Настройка proxy если указан
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        priv_key, pub_key = gen_pair_keys("AWG")
        data = {
            "install_id": "",
            "tos": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "key": pub_key,
            "fcm_token": "",
            "type": "ios",
            "locale": "en_US",
        }
        resp = requests.post(
            f"{api}/reg",
            headers=headers,
            json=data,
            timeout=10,  # Оптимальный таймаут для proxy
            proxies=proxies,
        )
        resp.raise_for_status()
        res = resp.json().get("result")
        if not res:
            raise RuntimeError("В ответе регистрации отсутствует result")
        reg_id = res.get("id")
        token = res.get("token")
        if not reg_id or not token:
            raise RuntimeError("В ответе регистрации отсутствует id/token")
        resp2 = requests.patch(
            f"{api}/reg/{reg_id}",
            headers={**headers, "authorization": f"Bearer {token}"},
            json={"warp_enabled": True},
            timeout=10,  # Оптимальный таймаут для proxy
            proxies=proxies,
        )
        resp2.raise_for_status()
        result_obj = resp2.json().get("result", {})
        cfg = result_obj.get("config", {})
        peers = cfg.get("peers", [])
        if not peers:
            raise RuntimeError("В конфиге Cloudflare отсутствуют peers")
        peer_pub = peers[0].get("public_key", "")
        client_ipv4 = cfg.get("interface", {}).get("addresses", {}).get("v4", "")
        client_ipv6 = cfg.get("interface", {}).get("addresses", {}).get("v6", "")
        api_endpoint = _select_endpoint_from_api_result(result_obj)
    except Exception as e:
        raise RuntimeError(f"Ошибка WARP API: {e}")

    candidates = []
    if api_endpoint:
        candidates.append(api_endpoint)
    candidates.extend(CANDIDATE_WARP_ENDPOINTS)

    chosen = None
    total_endpoints = len(candidates)
    for idx, ep in enumerate(candidates, 1):
        try:
            logger.info("🔍 Проверка endpoint %d/%d: %s ...", idx, total_endpoints, ep)
            if check_endpoint(ep, timeout=0.6):  # Уменьшено с 1.5 до 0.6 сек
                chosen = ep
                logger.info("✅ Endpoint найден: %s", chosen)
                break
            else:
                logger.info("❌ Endpoint не доступен: %s", ep)
        except Exception as e:
            logger.info("❌ Endpoint ошибка: %s (%s)", ep, e)
            continue

    if not chosen:
        raise RuntimeError("Не найден доступный endpoint для WARP (проверено %d endpoint'ов)" % total_endpoints)

    jc = random.randint(80, 120)
    jmin = random.randint(48, 64)
    jmax = random.randint(jmin + 8, 80)
    persistent_keepalive = random.randint(1, 9)
    out = g_warp_config
    out = out.replace("<WARP_PRIVATE_KEY>", priv_key)
    out = out.replace("<JC>", str(jc))
    out = out.replace("<JMIN>", str(jmin))
    out = out.replace("<JMAX>", str(jmax))
    out = out.replace("<MTU>", str(mtu))
    out = out.replace("<WARP_ADDRESS>", ", ".join([x for x in (client_ipv4, client_ipv6) if x]))
    out = out.replace("<WARP_PEER_PUBLIC_KEY>", peer_pub)
    out = out.replace("<PERSISTENT_KEEPALIVE>", str(persistent_keepalive))
    out = out.replace("<WARP_ENDPOINT>", chosen)
    filename = f"{tun_name}warp{index}.conf"
    return out, filename


def generate_warp_configs(tun_name: str, num_warps: int, mtu: int, proxy: str = "") -> List[str]:
    """
    Генерация N WARP-конфигов с попытками и откатом при неудаче.
    """
    warp_configs: List[str] = []
    for i in range(num_warps):
        success = False
        for attempt in range(3):  # 3 попытки достаточно
            try:
                conf_text, fname = generate_warp_config(tun_name, i, mtu, proxy)
                path = pathlib.Path(g_main_config_fn).parent.joinpath(fname)
                atomic_write_text(path, conf_text)
                warp_configs.append(fname)
                success = True
                break
            except requests.exceptions.HTTPError as he:
                status = getattr(he.response, "status_code", None)
                if status == 429:
                    backoff = 2 + attempt * 2  # 2, 4, 6 сек
                    logger.warning("⚠  Cloudflare API rate-limited; ожидаю %d сек", backoff)
                    time.sleep(backoff)
                    continue
                else:
                    logger.warning("⚠  HTTP ошибка при генерации WARP: %s", he)
                    break
            except Exception as e:
                logger.warning("⚠  Попытка генерации WARP %d не удалась: %s", attempt + 1, e)
                time.sleep(1 + attempt)
                continue
        if not success:
            logger.warning("⚠  Отмена генерации WARP.")
            for created in warp_configs:
                try:
                    p = pathlib.Path(g_main_config_fn).parent.joinpath(created)
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
            raise RuntimeError("WARP конфиги не сгенерированы")
    return warp_configs


# ----------------- fetch DsYt с fallback -----------------


def fetch_allowed_dsyt() -> str:
    """
    Загружает CIDR-листы для набора сайтов. Если не удалось получить ХОТЯ БЫ ОДИН —
    сразу возвращает FALLBACK_DSYT_ALLOWEDIPS.
    """
    sites = [
        "youtube.com",
        "discord.com",
        "discord.gg",
        "discord.media",
        "telegram.org"
    ]
    protocols = ["cidr4", "cidr6"]
    ip_set = set()
    
    # Сначала собираем все IPs во временное хранилище
    for site in sites:
        site_ips = set()
        for proto in protocols:
            url = f"https://iplist.opencck.org/?format=comma&data={proto}&site={site}"
            try:
                r = requests.get(url, timeout=8)
                if r.status_code != 200:
                    logger.warning("⚠  Не удалось получить IPs для %s (%s). Код ответа: %s. Используется Fallback.", site, proto, r.status_code)
                    return FALLBACK_DSYT_ALLOWEDIPS
                
                data = r.text.strip()
                if not data:
                    # Если вернулся пустой список для сайта — это подозрительно, считаем за ошибку
                    logger.warning("⚠  Пустой ответ для %s (%s). Используется Fallback.", site, proto)
                    return FALLBACK_DSYT_ALLOWEDIPS
                
                for item in data.split(","):
                    item = item.strip()
                    if not item: continue
                    try:
                        ipaddress.ip_network(item, strict=False)
                        site_ips.add(item)
                    except Exception:
                        continue
            except Exception as e:
                logger.warning("⚠  Ошибка соединения при получении %s (%s): %s. Используется Fallback.", site, proto, e)
                return FALLBACK_DSYT_ALLOWEDIPS
        
        # Если для сайта вообще ничего не нашлось (даже если 200 OK)
        if not site_ips:
             logger.warning("⚠  Не найдено ни одного IP для %s. Используется Fallback.", site)
             return FALLBACK_DSYT_ALLOWEDIPS
             
        ip_set.update(site_ips)

    return ", ".join(sorted(ip_set))


# ----------------- Парсеры конфигов -----------------


def _sanitize_label(lbl: str) -> str:
    if not lbl:
        return ""
    lbl2 = re.sub(r'[^A-Za-z0-9_\-]', '_', lbl)
    return lbl2


def parse_endpoints_config(text: str, default_port: str) -> List[Dict[str, str]]:
    out = []
    if not text:
        return out
    tokens: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '#' in line:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
        parts = [p.strip() for p in line.split(",") if p.strip()]
        tokens.extend(parts)

    for p in tokens:
        raw = p
        label = ""
        hostport = p
        if hostport.startswith('['):
            try:
                close = hostport.index(']')
                host_section = hostport[1:close]
                rest = hostport[close + 1 :].strip()
                port = default_port
                label = ""
                if rest.startswith(':'):
                    rest2 = rest[1:]
                    if '-' in rest2:
                        port_part, lbl_part = rest2.split('-', 1)
                        port = port_part.strip() or default_port
                        label = _sanitize_label(lbl_part.strip())
                    else:
                        port = rest2.strip() or default_port
                elif rest.startswith('-'):
                    label = _sanitize_label(rest[1:].strip())
                host = host_section.strip()
                if not host:
                    continue
                if not str(port).isdigit():
                    port = default_port
                else:
                    try:
                        port_int = int(port)
                        if not (1 <= port_int <= 65535):
                            port = default_port
                    except Exception:
                        port = default_port
                out.append({"host": host, "port": str(port), "label": label})
                continue
            except ValueError:
                hostport = p

        hostpart = hostport
        lbl = ""
        if '-' in hostpart:
            head, sep, tail = hostpart.rpartition('-')
            if sep and tail and re.match(r'^[A-Za-z0-9_\-]+$', tail) and head.strip():
                head_strip = head.strip()
                head_has_dot = '.' in head_strip
                head_has_colon = ':' in head_strip
                raw_has_colon = ':' in raw
                ipv4_match = re.match(r'^\d+\.\d+\.\d+\.\d+$', head_strip) is not None
                if head_has_dot or head_has_colon or raw_has_colon or ipv4_match:
                    hostpart = head_strip
                    lbl = _sanitize_label(tail.strip())
                else:
                    hostpart = hostpart
                    lbl = ""
            else:
                hostpart = hostpart
                lbl = ""

        if hostpart.count(':') >= 2:
            out.append({"host": hostpart.strip(), "port": default_port, "label": lbl})
            continue

        if ':' in hostpart:
            h, prt = hostpart.rsplit(":", 1)
            if prt.isdigit():
                prt_val = prt.strip()
                try:
                    prt_int = int(prt_val)
                    if 1 <= prt_int <= 65535:
                        out.append({"host": h.strip(), "port": str(prt_int), "label": lbl})
                    else:
                        out.append({"host": h.strip(), "port": default_port, "label": lbl})
                except Exception:
                    out.append({"host": h.strip(), "port": default_port, "label": lbl})
                continue
            else:
                out.append({"host": hostpart.strip(), "port": default_port, "label": lbl})
                continue
        else:
            h = hostpart.strip()
            out.append({"host": h, "port": default_port, "label": lbl})
    return out

def get_server_public_address(cfg) -> str:
    iface = getattr(cfg, "iface", {}) or getattr(cfg, "interface", {})
    for key in ("Endpoint", "PublicEndpoint", "ExternalAddress"):
        val = iface.get(key)
        if val:
            return val.split("/")[0].strip()
    env_ip = os.getenv("AWG_PUBLIC_ADDR")
    if env_ip:
        return env_ip.strip()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip:
            return ip
    except Exception:
        pass
    addr = iface.get("Address", "")
    return addr.split("/")[0] if addr else ""

def parse_allowedips_config(text: str, server_addr: str = "") -> Tuple[Dict[str, str], Set[str]]:
    """
    Парсит _allowedips.config. 
    Возвращает кортеж: (словарь {Имя: IPs}, множество имен для QR {Имя1, Имя2})
    """
    out_ips: Dict[str, str] = {}
    out_qr: Set[str] = set()
    
    if not text:
        return out_ips, out_qr
        
    if server_addr:
        text = text.replace("<SERVER_ADDR>", str(server_addr))
        
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
            
        # Разбиваем строку по ';'. Обычно ожидаем: Name = IPs; [qr]
        parts = [p.strip() for p in line.split(';')]
        
        # Первая часть должна содержать определение
        def_part = parts[0]
        if '=' not in def_part:
            continue
            
        name, ips = def_part.split('=', 1)
        name = name.strip()
        out_ips[name] = ips.strip()
        
        # Проверяем флаг qr в остальных частях
        if len(parts) > 1:
            for p in parts[1:]:
                if p.lower() == 'qr':
                    out_qr.add(name)
                    
    return out_ips, out_qr


def ensure_allowedips_config(path: pathlib.Path) -> None:
    if path.exists():
        return
    logger.info("📦 Создание файла %s с загрузкой списков IP (единоразово)...", path)
    dsyt_ips = fetch_allowed_dsyt()
    content = [
        "# Format: Name = IP, IP, IP; [qr]",
        "All = 0.0.0.0/0, ::/0; qr", # По умолчанию All с QR
        f"DsYt = {dsyt_ips};"
    ]
    atomic_write_text(path, "\n".join(content) + "\n")


# ----------------- Обработчики -----------------

def init_interface_paths(interface_name: str):
    global g_work_dir, g_conf_dir, g_file_dir
    global g_defclient_config_fn, g_endpoint_config_fn, g_allowedips_config_fn
    
    g_work_dir = SCRIPT_DIR.joinpath(interface_name)
    g_work_dir.mkdir(parents=True, exist_ok=True)
    
    g_conf_dir = g_work_dir.joinpath("conf")
    g_conf_dir.mkdir(parents=True, exist_ok=True)
    
    g_file_dir = g_work_dir.joinpath("file")
    g_file_dir.mkdir(parents=True, exist_ok=True)
    
    g_defclient_config_fn = g_work_dir.joinpath("_defclient.config")
    g_endpoint_config_fn = g_work_dir.joinpath("_endpoint.config")
    g_allowedips_config_fn = g_work_dir.joinpath("_allowedips.config")


def _ensure_endpoint_file_exists(default_addr: str) -> None:
    try:
        if not g_endpoint_config_fn.exists():
            if default_addr and default_addr.strip():
                atomic_write_text(g_endpoint_config_fn, (default_addr or "") + "\n")
                logger.info("✅ _endpoint.config создан: %s", g_endpoint_config_fn)
    except Exception as e:
        logger.warning("⚠  Не удалось создать _endpoint.config: %s", e)


def calculate_client_masks(ipv4_net: ipaddress.IPv4Network, ipv6_net: Optional[ipaddress.IPv6Network]) -> Tuple[int, int, float]:
    """
    Вычисляет маски клиентов и коэффициент кратности на основе соотношения объёмов подсетей.
    
    Возвращает кортеж: (ipv4_client_mask, ipv6_client_mask, ratio)
    где:
    - ipv4_client_mask: маска для IPv4 адреса клиента (например, /32, /30, /31)
    - ipv6_client_mask: маска для IPv6 адреса клиента (например, /128, /126, /125)
    - ratio: коэффициент кратности (сколько IPv6 адресов на 1 IPv4, или наоборот)
    
    Примеры:
    - /24 + /120 → ratio=1.0 → (32, 128, 1.0) — 1 IPv4 : 1 IPv6
    - /24 + /119 → ratio=2.0 → (32, 127, 2.0) — 1 IPv4 : 2 IPv6
    - /24 + /118 → ratio=4.0 → (32, 126, 4.0) — 1 IPv4 : 4 IPv6
    - /22 + /120 → ratio=0.25 → (30, 128, 0.25) — 4 IPv4 : 1 IPv6
    """
    if not ipv6_net:
        # Только IPv4
        return 32, 128, 1.0
    
    # Количество адресов в подсетях
    ipv4_total = 2 ** (32 - ipv4_net.prefixlen)
    ipv6_total = 2 ** (128 - ipv6_net.prefixlen)
    
    # Соотношение
    ratio = ipv6_total / ipv4_total
    
    if ratio >= 1:
        # 1 IPv4 : N IPv6 (IPv6 подсеть шире)
        ipv4_client_mask = 32  # 1 адрес
        ipv6_bits = int(math.log2(ratio))
        ipv6_client_mask = 128 - ipv6_bits
    else:
        # N IPv4 : 1 IPv6 (IPv4 подсеть шире)
        ipv6_client_mask = 128  # 1 адрес
        ipv4_bits = int(math.log2(1 / ratio))
        ipv4_client_mask = 32 - ipv4_bits
    
    return ipv4_client_mask, ipv6_client_mask, ratio


def validate_ipv4_ipv6_pair(ipv4_net: ipaddress.IPv4Network, ipv6_net: Optional[ipaddress.IPv6Network], ipv4_server_ip: str = "", ipv6_server_ip: str = "") -> bool:
    """
    Проверяет что IPv4 и IPv6 подсети совместимы.
    
    Проверки:
    1. Позиция сервера: оба на network или оба не на network
    2. Соотношение подсетей: не экстремальное (от 1:65536 до 65536:1)
    
    Возвращает True если валидация пройдена, иначе бросает RuntimeError.
    """
    if not ipv6_net:
        return True  # IPv6 опционален

    # Вычисляем маски клиентов и коэффициент кратности
    ipv4_client_mask, ipv6_client_mask, ratio = calculate_client_masks(ipv4_net, ipv6_net)
    
    # --- Проверка 1: Позиция сервера ---
    # Сервер должен занимать одинаковую позицию в обеих подсетях
    # (либо network address в обеих, либо не network address в обеих)
    ipv4_is_network = (ipv4_server_ip == str(ipv4_net.network_address)) if ipv4_server_ip else True
    ipv6_is_network = (ipv6_server_ip == str(ipv6_net.network_address)) if ipv6_server_ip else True
    
    if ipv4_is_network != ipv6_is_network:
        raise RuntimeError(
            f'Позиция сервера в IPv4 и IPv6 должна совпадать. '
            f'IPv4: сервер на {"network" if ipv4_is_network else "не network"}, '
            f'IPv6: сервер на {"network" if ipv6_is_network else "не network"}. '
            f'Пример: 10.1.0.0/24,fd00::/120 (оба на network) или 10.1.0.1/24,fd00::1/120 (оба не на network)'
        )
    
    # --- Проверка 2: Разумное соотношение ---
    # Максимальное соотношение основано на диапазонах масок (/8-/30 и /104-/126)
    # Максимум: IPv4 /30 + IPv6 /104 = 1:4194304 или IPv4 /8 + IPv6 /126 = 4194304:1
    # 2^22 = 4194304 (разница между мин/масками: 30-8=22 или 126-104=22)
    MAX_RATIO = 4194304  # 2^22 (максимум 1:4194304 или 4194304:1)
    MIN_RATIO = 1 / MAX_RATIO

    if ratio > MAX_RATIO:
        raise RuntimeError(
            f'Соотношение подсетей слишком большое: 1 IPv4 = {ratio:,.0f} IPv6. '
            f'Максимальное соотношение: 1:{MAX_RATIO:,}. '
            f'Пример: IPv4 /24 + IPv6 /112 (1:256)'
        )

    if ratio < MIN_RATIO:
        raise RuntimeError(
            f'Соотношение подсетей слишком маленькое: 1 IPv4 = {ratio:.10f} IPv6 (1:{1/ratio:,.0f}). '
            f'Минимальное соотношение: 1:{MAX_RATIO:,} ({MIN_RATIO:.10f}). '
            f'Пример: IPv4 /16 + IPv6 /120 (256:1)'
        )
    
    return True


def parse_ipaddr_argument(ipaddr_str: str) -> Tuple[ipaddress.IPv4Network, Optional[ipaddress.IPv6Network], str, str]:
    """
    Парсит аргумент --ipaddr с поддержкой IPv4 или IPv4+IPv6 через запятую.

    Формат: "10.1.0.1/24" или "10.1.0.1/24, fd00::1/120"

    Возвращает кортеж: (ipv4_net, ipv6_net, display_string, original_string)
    где original_string — оригинальная строка для валидации
    """
    original_string = ipaddr_str.strip()

    ipaddr_ipv4 = None
    ipaddr_ipv6 = None

    # Разбиваем по запятой и обрезаем пробелы
    raw_subnets = [s.strip() for s in ipaddr_str.split(',')]

    for subnet_str in raw_subnets:
        if not subnet_str:
            continue

        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as e:
            raise RuntimeError(f'Некорректный IP адрес "{subnet_str}": {e}')

        # Проверка размера подсети
        if isinstance(net, ipaddress.IPv4Network):
            # IPv4: от /8 до /30 (практичные размеры для VPN)
            if net.prefixlen < 8:
                raise RuntimeError(f'IPv4 подсеть /{net.prefixlen} слишком большая (минимум /8)')
            if net.prefixlen > 30:
                raise RuntimeError(f'IPv4 подсеть /{net.prefixlen} слишком маленькая (максимум /30)')
        else:
            # IPv6: от /104 до /126 (практичные размеры для VPN)
            if net.prefixlen < 104:
                raise RuntimeError(f'IPv6 подсеть /{net.prefixlen} слишком большая (минимум /104)')
            if net.prefixlen > 126:
                raise RuntimeError(f'IPv6 подсеть /{net.prefixlen} слишком маленькая (максимум /126)')

        # Определяем версию IP
        if isinstance(net, ipaddress.IPv4Network):
            if ipaddr_ipv4 is not None:
                raise RuntimeError(f'Указано несколько IPv4 подсетей: {ipaddr_ipv4} и {subnet_str}')
            ipaddr_ipv4 = net
        else:  # IPv6
            if ipaddr_ipv6 is not None:
                raise RuntimeError(f'Указано несколько IPv6 подсетей: {ipaddr_ipv6} и {subnet_str}')
            ipaddr_ipv6 = net

    # IPv4 обязателен, IPv6 опционален
    if ipaddr_ipv4 is None:
        raise RuntimeError('IPv4 подсеть обязательна (например, 10.1.0.1/24)')

    # Извлекаем IP сервера из оригинальной строки (ДО нормализации!)
    ipv4_server_ip = ""
    ipv6_server_ip = ""
    for subnet_str in raw_subnets:
        if not subnet_str:
            continue
        # Берём IP адрес до / (например, "10.10.0.1" из "10.10.0.1/16")
        ip_part = subnet_str.split('/')[0].strip()
        try:
            ip = ipaddress.ip_address(ip_part)
            if isinstance(ip, ipaddress.IPv4Address):
                ipv4_server_ip = ip_part
            else:
                ipv6_server_ip = ip_part
        except:
            pass

    # Валидация одинакового размера и позиции сервера
    validate_ipv4_ipv6_pair(ipaddr_ipv4, ipaddr_ipv6, ipv4_server_ip, ipv6_server_ip)

    # Формируем строку для up.sh (нормализованный формат с пробелом)
    if ipaddr_ipv6:
        ipaddr_display = f"{ipv4_server_ip}/{ipaddr_ipv4.prefixlen}, {ipv6_server_ip}/{ipaddr_ipv6.prefixlen}"
    else:
        ipaddr_display = f"{ipv4_server_ip}/{ipaddr_ipv4.prefixlen}"

    return ipaddr_ipv4, ipaddr_ipv6, ipaddr_display, ipaddr_display


def handle_makecfg(opt) -> None:
    global g_main_config_fn, g_main_config_type

    raw_input = opt.makecfg

    # Логика "умного пути"
    if os.sep not in raw_input:
        # Если слэшей нет, считаем это именем файла в /etc/amnezia/amneziawg/
        name = raw_input
        if not name.endswith('.conf'):
            name += '.conf'
        target_path = pathlib.Path("/etc/amnezia/amneziawg").joinpath(name)
    else:
        # Если слэши есть, используем как путь
        target_path = pathlib.Path(raw_input)

    tun_name = target_path.stem

    init_interface_paths(tun_name)

    # Создаем родительскую директорию (например /etc/amnezia/amneziawg), если её нет
    if not target_path.parent.exists():
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"Не удалось создать директорию {target_path.parent}: {e}")

    g_main_config_fn = target_path.resolve()

    if g_main_config_fn.exists():
        raise RuntimeError(f'Файл уже существует: {g_main_config_fn}')

    mtype = "AWG" if g_main_config_fn.name.startswith("a") else "WG"

    # Используем указанный интерфейс или определяем автоматически
    if opt.iface:
        main_iface = opt.iface
        logger.info("🌐 Используем указанный интерфейс: %s", main_iface)
    else:
        main_iface = get_main_iface()
        if not main_iface:
            raise RuntimeError("Не удалось определить основной сетевой интерфейс (попробуйте --iface)")

    if not opt.ipaddr:
        raise RuntimeError("Укажите --ipaddr")

    # Используем новую функцию для парсинга и валидации
    ipaddr_ipv4_net, ipaddr_ipv6_net, ipaddr_display, normalized_string = parse_ipaddr_argument(opt.ipaddr)

    # --- СНАЧАЛА ГЕНЕРИРУЕМ WARP (если нужен) ---
    warp_configs: List[str] = []
    if opt.warp > 0:
        logger.info("🌀 Генерация %d WARP конфигов...", opt.warp)
        try:
            warp_configs = generate_warp_configs(tun_name, opt.warp, opt.mtu, opt.proxy)
        except RuntimeError as e:
            error_msg = str(e)

            # Проверяем тип ошибки
            if "Ошибка WARP API" in error_msg:
                # Проблема с доступом к API
                logger.error("❌ Не удалось сгенерировать WARP: проблема с доступом к Cloudflare API")
                if not opt.proxy:
                    logger.info("💡 Попробуйте использовать прокси для обхода блокировок через флаг --proxy \"адрес прокси\"")
                else:
                    logger.info("💡 Попробуйте использовать другой прокси для обхода блокировок через флаг --proxy \"адрес прокси\"")
            elif "Не найден доступный endpoint" in error_msg:
                # Проблема с доступностью endpoint'ов
                logger.error("❌ Не удалось сгенерировать WARP: проблема с доступом к Cloudflare Endpoint")
                logger.info("💡 Похоже WARP у вас не будет работать и лучше не используйте его, генерируйте интерфейс без флага --warp")
            else:
                # Неизвестная ошибка
                logger.error("❌ Не удалось сгенерировать WARP: что-то пошло не так")
                logger.error("📝 Детали: %s", error_msg)
                logger.info("💡 Попробуйте использовать прокси через флаг --proxy \"адрес прокси\", если не выйдет то без --warp")

            raise RuntimeError("Генерация WARP не удалась — интерфейс не создан")

        for c in warp_configs:
            logger.info("📄 WARP конфиг: %s", c)
        logger.info("✅ WARP конфиги сгенерированы")

    # --- ТЕПЕРЬ СОЗДАЁМ СЕРВЕРНЫЙ КОНФИГ И СКРИПТЫ ---
    priv, pub = gen_pair_keys(mtype)
    random.seed()
    jc = random.randint(80, 120)
    jmin = random.randint(48, 64)
    jmax = random.randint(jmin + 8, 80)

    up_path = g_main_config_fn.parent.joinpath(f"{tun_name}up.sh")
    down_path = g_main_config_fn.parent.joinpath(f"{tun_name}down.sh")

    out = g_defserver_config
    out = out.replace("<SERVER_KEY_TIME>", datetime.datetime.now().isoformat())
    out = out.replace("<SERVER_PRIVATE_KEY>", priv)
    out = out.replace("<SERVER_PUBLIC_KEY>", pub)
    out = out.replace("<SERVER_ADDR>", normalized_string)
    out = out.replace("<SERVER_PORT>", str(opt.port))
    if mtype == "AWG":
        out = out.replace("<JC>", str(jc))
        out = out.replace("<JMIN>", str(jmin))
        out = out.replace("<JMAX>", str(jmax))
        out = out.replace("<S1>", str(random.randint(3, 127)))
        out = out.replace("<S2>", str(random.randint(3, 127)))
        out = out.replace("<H1>", str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace("<H2>", str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace("<H3>", str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace("<H4>", str(random.randint(0x10000011, 0x7FFFFF00)))
    else:
        out = out.replace("\nJc = <", "\n# ")
        out = out.replace("\nJmin = <", "\n# ")
        out = out.replace("\nJmax = <", "\n# ")
        out = out.replace("\nS1 = <", "\n# ")
        out = out.replace("\nS2 = <", "\n# ")
        out = out.replace("\nH1 = <", "\n# ")
        out = out.replace("\nH2 = <", "\n# ")
        out = out.replace("\nH3 = <", "\n# ")
        out = out.replace("\nH4 = <", "\n# ")
    out = out.replace("<SERVER_IFACE>", main_iface)
    out = out.replace("<SERVER_TUN>", tun_name)
    out = out.replace("<SERVER_UP_SCRIPT>", str(up_path))
    out = out.replace("<SERVER_DOWN_SCRIPT>", str(down_path))
    out = out.replace("<MTU>", str(opt.mtu))

    atomic_write_text(g_main_config_fn, out)
    logger.info("✅ Серверный конфиг создан: %s", g_main_config_fn)

    if warp_configs:
        warp_list_str = "\n".join([f'  \"{pathlib.Path(cfg).stem}\"' for cfg in warp_configs])
    else:
        warp_list_str = '  "none=0.0.0.0/0,::/0"'

    replacements = {
        "<SERVER_PORT>": str(opt.port),
        "<SERVER_IFACE>": main_iface,
        "<SERVER_TUN>": tun_name,
        "<SERVER_ADDR>": normalized_string,
        "<RATE_LIMIT>": f"{opt.limit}",
        "<WARP_LIST>": warp_list_str,
    }
    up_script = up_script_template_warp
    down_script = down_script_template_warp
    for k, v in replacements.items():
        up_script = up_script.replace(k, v)
        down_script = down_script.replace(k, v)

    # Резервное копирование существующих .sh файлов
    if up_path.exists():
        backup_path = up_path.with_suffix('.sh.bak')
        import shutil
        shutil.copy2(up_path, backup_path)
        logger.info("📦 Создана резервная копия: %s", backup_path)
    if down_path.exists():
        backup_path = down_path.with_suffix('.sh.bak')
        import shutil
        shutil.copy2(down_path, backup_path)
        logger.info("📦 Создана резервная копия: %s", backup_path)

    atomic_write_text(up_path, up_script)
    atomic_write_text(down_path, down_script)
    os.chmod(str(up_path), 0o755)
    os.chmod(str(down_path), 0o755)
    
    atomic_write_text(g_main_config_src, str(g_main_config_fn))
    
    try:
        _ensure_endpoint_file_exists(str(get_ext_ipaddr()))
        ensure_allowedips_config(g_allowedips_config_fn)
    except Exception as e:
        logger.warning("⚠  Не удалось создать вспомогательные файлы: %s", e)
        
    sys.exit(0)


def handle_add(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)

    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    c_name = opt.addcl
    logger.info('👤 Создание нового пользователя "%s"...', c_name)
    if c_name.lower() in (x.lower() for x in cfg.peer.keys()):
        raise RuntimeError(f'Пользователь "{c_name}" уже существует')
    
    # --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
    # Формат: "10.1.0.0/24" или "10.1.0.0/24, fd00::/120"
    raw_subnets = [s.strip() for s in srv['Address'].split(',')]
    
    net_ipv4 = None
    net_ipv6 = None
    
    for subnet_str in raw_subnets:
        if not subnet_str:
            continue
        net = ipaddress.ip_network(subnet_str, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            net_ipv4 = net
        else:
            net_ipv6 = net
    
    if net_ipv4 is None:
        raise RuntimeError('IPv4 подсеть обязательна')

    # Проверка размера подсети
    # IPv4: от /8 до /30 (практичные размеры для VPN)
    if net_ipv4.prefixlen < 8:
        raise RuntimeError(f'IPv4 подсеть /{net_ipv4.prefixlen} слишком большая (минимум /8)')
    if net_ipv4.prefixlen > 30:
        raise RuntimeError(f'IPv4 подсеть /{net_ipv4.prefixlen} слишком маленькая (максимум /30)')

    # IPv6: от /104 до /126 (практичные размеры для VPN)
    if net_ipv6 is not None:
        if net_ipv6.prefixlen < 104:
            raise RuntimeError(f'IPv6 подсеть /{net_ipv6.prefixlen} слишком большая (минимум /104)')
        if net_ipv6.prefixlen > 126:
            raise RuntimeError(f'IPv6 подсеть /{net_ipv6.prefixlen} слишком маленькая (максимум /126)')

    # --- Собираем используемые IPv4 адреса ---
    used_ips_ipv4 = set()
    used_ips_ipv6 = set()

    for peer in cfg.peer.values():
        try:
            peer_ips = peer['AllowedIPs']
            # Поддержка формата "10.1.0.5/32, fd00::5/128"
            for peer_ip_str in [s.strip() for s in peer_ips.split(',')]:
                peer_ip = ipaddress.ip_network(peer_ip_str, strict=False)
                if isinstance(peer_ip, ipaddress.IPv4Network):
                    used_ips_ipv4.add(int(peer_ip.network_address))
                else:
                    used_ips_ipv6.add(int(peer_ip.network_address))
        except Exception:
            continue

    # Читаем конфиг сервера чтобы узнать реальный IP сервера
    srv_path = pathlib.Path(g_main_config_fn)
    srvcfg = srv_path.read_text(encoding='utf-8')

    # --- Вычисляем первый/последний IP для IPv4 ---
    first_usable_int_ipv4 = int(net_ipv4.network_address) + 1
    broadcast_int_ipv4 = int(net_ipv4.broadcast_address)

    # Реальный IP сервера из конфига (Address = ...)
    # Парсим "10.10.0.0/16" → 10.10.0.0
    server_addr_ipv4 = srvcfg.split('[Peer]')[0]  # Только [Interface] секция
    for line in server_addr_ipv4.split('\n'):
        if line.strip().startswith('Address = '):
            addr_part = line.split('=')[1].strip().split(',')[0].strip()
            server_ip_int_ipv4 = int(ipaddress.IPv4Address(addr_part.split('/')[0]))
            break
    else:
        # Не нашли Address, используем network
        server_ip_int_ipv4 = int(net_ipv4.network_address)

    # Определяем: занимает ли сервер NETWORK адрес (а не первый usable!)
    # Это важно для определения доступности broadcast адреса
    server_on_network_ipv4 = (server_ip_int_ipv4 == int(net_ipv4.network_address))

    # Добавляем IP сервера в занятые!
    used_ips_ipv4.add(server_ip_int_ipv4)

    # Последний usable зависит от позиции сервера
    if server_on_network_ipv4:
        # Сервер на network → broadcast НЕ работает → можно выдать
        last_usable_int_ipv4 = broadcast_int_ipv4
    else:
        # Сервер НЕ на network (на первом usable или другом) → broadcast РАБОТАЕТ → зарезервирован
        last_usable_int_ipv4 = broadcast_int_ipv4 - 1
    
    # --- Вычисляем первый/последний IP для IPv6 ---
    first_usable_int_ipv6 = None
    last_usable_int_ipv6 = None

    if net_ipv6:
        first_usable_int_ipv6 = int(net_ipv6.network_address) + 1

        # Реальный IP сервера из конфига (Address = ...)
        # Парсим "fd00::/112" → fd00::
        server_addr_ipv6 = srvcfg.split('[Peer]')[0]  # Только [Interface] секция
        for line in server_addr_ipv6.split('\n'):
            if line.strip().startswith('Address = '):
                addr_part = line.split('=')[1].strip()
                # Ищем IPv6 адрес (после запятой если есть)
                if ',' in addr_part:
                    addr_part = addr_part.split(',')[1].strip()
                ipv6_server_ip_str = addr_part.split('/')[0]
                ipv6_server_ip_int = int(ipaddress.IPv6Address(ipv6_server_ip_str))
                break
        else:
            # Не нашли Address, используем network
            ipv6_server_ip_int = int(net_ipv6.network_address)

        # Определяем: занимает ли сервер NETWORK адрес (а не первый usable!)
        server_on_network_ipv6 = (ipv6_server_ip_int == int(net_ipv6.network_address))

        # Добавляем IP сервера в занятые!
        used_ips_ipv6.add(ipv6_server_ip_int)

        # Последний usable зависит от позиции сервера
        if server_on_network_ipv6:
            # Сервер на network → "broadcast" НЕ работает → можно выдать
            last_usable_int_ipv6 = int(net_ipv6.network_address) + net_ipv6.num_addresses - 1
        else:
            # Сервер НЕ на network → "broadcast" РАБОТАЕТ → зарезервирован
            last_usable_int_ipv6 = int(net_ipv6.network_address) + net_ipv6.num_addresses - 2

    # --- Обработка ручного IP ---
    ipaddr_ipv4 = None
    ipaddr_ipv6 = None
    
    if opt.ipaddr:
        # Поддержка формата "10.1.0.5/32" или "10.1.0.5/32, fd00::5/128"
        raw_manual_ips = [s.strip() for s in opt.ipaddr.split(',')]
        
        for manual_ip_str in raw_manual_ips:
            manual_ip = ipaddress.ip_network(manual_ip_str, strict=False)

            if isinstance(manual_ip, ipaddress.IPv4Network):
                # Проверяем что IPv4 клиента в подсети сервера
                if not manual_ip.subnet_of(net_ipv4):
                    raise RuntimeError(f'IPv4 адрес {manual_ip_str} не в подсети сервера {net_ipv4}')
                
                ip_int = int(manual_ip.network_address)
                if ip_int in used_ips_ipv4:
                    raise RuntimeError(f'IPv4 адрес {manual_ip_str} уже используется')

                # Проверка: если сервер НЕ на network, broadcast работает и зарезервирован
                if not server_on_network_ipv4 and ip_int == broadcast_int_ipv4:
                    raise RuntimeError(f'IPv4 адрес {manual_ip_str} зарезервирован для broadcast')

                ipaddr_ipv4 = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
            else:
                # Проверяем что IPv6 клиента в подсети сервера (если IPv6 подсеть есть)
                if net_ipv6 and not manual_ip.subnet_of(net_ipv6):
                    raise RuntimeError(f'IPv6 адрес {manual_ip_str} не в подсети сервера {net_ipv6}')
                
                ip_int = int(manual_ip.network_address)
                if ip_int in used_ips_ipv6:
                    raise RuntimeError(f'IPv6 адрес {manual_ip_str} уже используется')
                
                ipaddr_ipv6 = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
    else:
        # --- Автоматический выбор IP с учётом кратности подсетей ---
        # Вычисляем маски клиентов и коэффициент кратности
        ipv4_client_mask, ipv6_client_mask, ratio = calculate_client_masks(net_ipv4, net_ipv6)
        
        # Определяем шаг для IPv4 и IPv6
        # Если ratio > 1: 1 IPv4 : N IPv6 → IPv6 шаг = ratio
        # Если ratio < 1: N IPv4 : 1 IPv6 → IPv4 шаг = 1/ratio
        if ratio >= 1:
            ipv4_step = 1
            ipv6_step = int(ratio)
        else:
            ipv4_step = int(1 / ratio)
            ipv6_step = 1
        
        # IPv4
        chosen_ipv4 = None
        chosen_ipv6 = None
        # range_end_ipv4 = последний usable + 1 (для range() не включительно)
        range_end_ipv4 = last_usable_int_ipv4 + 1

        # Проходим по всем IPv4 адресам с учётом шага
        for ip_int in range(first_usable_int_ipv4, range_end_ipv4, ipv4_step):
            if ip_int not in used_ips_ipv4:
                # Нашли свободный IPv4, теперь ищем соответствующий IPv6
                if net_ipv6 and first_usable_int_ipv6 is not None:
                    # Вычисляем индекс IPv6 по индексу IPv4 с учётом шага
                    ipv4_idx = (ip_int - first_usable_int_ipv4) // ipv4_step
                    ipv6_int = first_usable_int_ipv6 + (ipv4_idx * ipv6_step)

                    # Проверяем что IPv6 не занят и в пределах диапазона
                    if ipv6_int not in used_ips_ipv6 and ipv6_int <= last_usable_int_ipv6:
                        chosen_ipv4 = ip_int
                        chosen_ipv6 = ipv6_int
                        break
                else:
                    # IPv6 подсети нет, выдаём только IPv4
                    chosen_ipv4 = ip_int
                    break

        if chosen_ipv4 is None:
            raise RuntimeError('Нет свободных IPv4 адресов')

        # Вычисляем первый IP в блоке для IPv4 (выравнивание по границе маски)
        # ВАЖНО: блок должен полностью попадать в диапазон usable адресов
        if ipv4_client_mask < 32:
            ipv4_block_size = 2 ** (32 - ipv4_client_mask)
            # Выравниваем вниз до границы блока
            chosen_ipv4_aligned = chosen_ipv4 & ~(ipv4_block_size - 1)
            
            # Проверяем что блок не начинается с network адреса
            if chosen_ipv4_aligned == int(net_ipv4.network_address):
                # Блок начинается с network — сдвигаем на следующий блок
                chosen_ipv4_aligned += ipv4_block_size
            
            # Проверяем что блок не заканчивается на broadcast
            block_end = chosen_ipv4_aligned + ipv4_block_size - 1
            if block_end == int(net_ipv4.broadcast_address):
                # Блок заканчивается на broadcast — сдвигаем на предыдущий блок
                chosen_ipv4_aligned -= ipv4_block_size
        else:
            chosen_ipv4_aligned = chosen_ipv4

        # Вычисляем первый IP в блоке для IPv6 (выравнивание по границе маски)
        if ipv6_client_mask < 128 and chosen_ipv6 is not None:
            ipv6_block_size = 2 ** (128 - ipv6_client_mask)
            # Выравниваем вниз до границы блока
            chosen_ipv6_aligned = chosen_ipv6 & ~(ipv6_block_size - 1)
            
            # Проверяем что блок не начинается с network адреса
            if chosen_ipv6_aligned == int(net_ipv6.network_address):
                # Блок начинается с network — сдвигаем на следующий блок
                chosen_ipv6_aligned += ipv6_block_size
            
            # Проверяем что блок не заканчивается на последний адрес (аналог broadcast)
            block_end = chosen_ipv6_aligned + ipv6_block_size - 1
            if block_end == int(net_ipv6.broadcast_address):
                # Блок заканчивается на broadcast — сдвигаем на предыдущий блок
                chosen_ipv6_aligned -= ipv6_block_size
        else:
            chosen_ipv6_aligned = chosen_ipv6 if chosen_ipv6 else 0

        # Формируем адрес с маской клиента
        ipaddr_ipv4 = f"{str(ipaddress.IPv4Address(chosen_ipv4_aligned))}/{ipv4_client_mask}"

        # IPv6 (если есть подсеть и мы нашли пару)
        if net_ipv6 and chosen_ipv6 is not None:
            ipaddr_ipv6 = f"{str(ipaddress.IPv6Address(chosen_ipv6_aligned))}/{ipv6_client_mask}"
        elif net_ipv6:
            # IPv6 подсеть есть, но не нашли пару — выдаём только IPv4 с предупреждением
            logger.warning('⚠  Нет свободных пар IPv4+IPv6, выдаём только IPv4')
            ipaddr_ipv6 = None
    
    # Формируем итоговый AllowedIPs
    if ipaddr_ipv6:
        ipaddr = f"{ipaddr_ipv4}, {ipaddr_ipv6}"
    else:
        ipaddr = ipaddr_ipv4
    
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()
    persistent_keepalive = random.randint(1, 9)
    srv_path = pathlib.Path(g_main_config_fn)
    srvcfg = srv_path.read_text(encoding='utf-8')
    srvcfg += f'\n'
    srvcfg += f'[Peer]\n'
    srvcfg += f'#_Name = {c_name}\n'
    srvcfg += f'#_GenKeyTime = {datetime.datetime.now().isoformat()}\n'
    srvcfg += f'#_PrivateKey = {priv_key}\n'
    srvcfg += f'PublicKey = {pub_key}\n'
    srvcfg += f'PresharedKey = {psk}\n'
    srvcfg += f'PersistentKeepalive = {persistent_keepalive}\n'
    srvcfg += f'AllowedIPs = {ipaddr}\n'
    atomic_write_text(srv_path, srvcfg)
    logger.info('✅ Пользователь "%s" создан. IP=%s PersistentKeepalive=%s', c_name, ipaddr, persistent_keepalive)


def handle_update(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.update
    logger.info('🔄 Сброс ключей для "%s"...', p_name)
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()
    cfg.set_param(p_name, '_PrivateKey', priv_key, force=True, offset=2)
    cfg.set_param(p_name, 'PublicKey', pub_key)
    cfg.set_param(p_name, 'PresharedKey', psk)
    gentime = datetime.datetime.now().isoformat()
    cfg.set_param(p_name, '_GenKeyTime', gentime, force=True, offset=2)
    new_pk = random.randint(1, 9)
    cfg.set_param(p_name, 'PersistentKeepalive', str(new_pk), force=True, offset=3)
    ipaddr = cfg.peer[p_name]['AllowedIPs']
    cfg.save()
    logger.info('✅ Ключи сброшены для "%s". IP=%s NewPK=%s', p_name, ipaddr, new_pk)


def handle_delete(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.delete
    logger.info('🗑️  Удаление пользователя "%s"...', p_name)
    ipaddr = cfg.del_client(p_name)
    cfg.save()
    logger.info('✅ Удалён "%s". Освобождён IP=%s', p_name, ipaddr)


def handle_confgen(opt) -> Set[str]:
    """
    Генерирует конфиги.
    Возвращает множество имен (например {'All', 'Tg'}), для которых нужно сгенерировать QR.
    """
    global clients_for_zip
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    logger.info('📝 Генерация клиентских конфигов...')
    
    if not g_defclient_config_fn.exists():
        logger.info('Шаблон не найден, создаю стандартный шаблон в %s...', g_defclient_config_fn)
        out = g_defclient_config
        if g_main_config_type != 'AWG':
            out = out.replace('\nJc = <', '\n# ')
            out = out.replace('\nJmin = <', '\n# ')
            out = out.replace('\nJmax = <', '\n# ')
            out = out.replace('\nS1 = <', '\n# ')
            out = out.replace('\nS2 = <', '\n# ')
            out = out.replace('\nH1 = <', '\n# ')
            out = out.replace('\nH2 = <', '\n# ')
            out = out.replace('\nH3 = <', '\n# ')
            out = out.replace('\nH4 = <', '\n# ')
        atomic_write_text(g_defclient_config_fn, out)
    
    tmpcfg = g_defclient_config_fn.read_text(encoding='utf-8')

    # Очистка
    for fn in glob.glob(str(g_conf_dir.joinpath("*.conf"))):
        if fn.endswith(g_main_config_fn.name): continue
        try:
            os.remove(fn)
        except Exception: pass
    for fn in glob.glob(str(g_conf_dir.joinpath("*.png"))):
        try:
            os.remove(fn)
        except Exception: pass
    
    random.seed()
    
    # Загрузка и парсинг AllowedIPs с поддержкой QR-флага
    ensure_allowedips_config(g_allowedips_config_fn)
    try:
        server_addr = srv.get("Address", "")
        # allowed_ips_dict: { "All": "0.0.0...", "DsYt": "1.1.1..." }
        # qr_enabled_names: { "All", "Tg" }
        allowed_ips_dict, qr_enabled_names = parse_allowedips_config(
            g_allowedips_config_fn.read_text(encoding='utf-8'),
            server_addr
        )
    except Exception as e:
        logger.error("⚠  Ошибка чтения %s: %s", g_allowedips_config_fn, e)
        allowed_ips_dict = {"All": "0.0.0.0/0, ::/0"}
        qr_enabled_names = {"All"} # Fallback

    only_list = get_only_list()
    peers = list(cfg.peer.items())
    if only_list:
        peers = [(name, peer) for name, peer in peers if name.lower() in [x.lower() for x in only_list]]
        if not peers:
            raise RuntimeError('Ни одного клиента не найдено для --only')

    clients_for_zip.clear()

    endpoint_text = ""
    if g_endpoint_config_fn.exists():
        try:
            endpoint_text = g_endpoint_config_fn.read_text(encoding='utf-8').strip()
        except Exception:
            endpoint_text = ""
    else:
        try:
            public_addr = get_server_public_address(cfg)
            _ensure_endpoint_file_exists(public_addr)
            endpoint_text = g_endpoint_config_fn.read_text(encoding='utf-8').strip() if g_endpoint_config_fn.exists() else ""
        except Exception as e:
            logger.error("❌ Не удалось определить публичный IP сервера: %s", e)
            logger.error("Укажите Endpoint вручную в файле %s", g_endpoint_config_fn)
            logger.error("Пример: %s", get_ext_ipaddr() if get_ext_ipaddr() else "203.0.113.1")
            raise RuntimeError("Не удалось создать _endpoint.config — укажите Endpoint вручную")

    raw_listen = srv.get('ListenPort', '') or ""
    default_port = str(opt.port)
    if raw_listen and str(raw_listen).strip().isdigit():
        default_port = str(raw_listen).strip()
    else:
        if raw_listen:
            logger.warning("⚠  ListenPort в server.cfg некорректен ('%s') — используется опция --port=%s", raw_listen, default_port)
        default_port = str(opt.port)

    endpoints = parse_endpoints_config(endpoint_text, default_port)
    endpoints = [e for e in endpoints if e.get("host") and str(e.get("host")).strip()]
    if not endpoints:
        logger.info("ℹ️  Не найден _endpoint.config или он пуст; использую адрес из server.cfg")
        raw_srv_addr = srv.get('Address', '')
        if raw_srv_addr and '/' in raw_srv_addr:
            raw_srv_addr = raw_srv_addr.split('/')[0]
        endpoints = [{"host": raw_srv_addr, "port": default_port, "label": ""}]

    single_endpoint = len(endpoints) == 1
    psk_added = False

    for peer_name, peer in peers:
        if 'Name' not in peer or 'PrivateKey' not in peer:
            logger.info('Пропуск peer с публичным ключом %s', peer.get("PublicKey", "<no>"))
            continue
        psk = peer.get('PresharedKey', gen_preshared_key())
        if 'PresharedKey' not in peer:
            cfg.set_param(peer_name, 'PresharedKey', psk)
            psk_added = True
        jc = random.randint(80, 120)
        jmin = random.randint(48, 64)
        jmax = random.randint(jmin + 8, 80)
        persistent_keepalive = random.randint(1, 9)
        mtu = srv.get('MTU', str(opt.mtu))

        for idx, ep in enumerate(endpoints, start=1):
            host = ep.get('host', '')
            port = ep.get('port', default_port)
            raw_label = ep.get('label', '')
            
            if single_endpoint:
                ep_label = "" if not raw_label else raw_label
            else:
                ep_label = raw_label if raw_label else str(idx)

            out_base = tmpcfg[:]
            out_base = out_base.replace('<MTU>', mtu)
            out_base = out_base.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])
            out_base = out_base.replace('<CLIENT_TUNNEL_IP>', peer['AllowedIPs'])
            out_base = out_base.replace('<JC>', str(jc))
            out_base = out_base.replace('<JMIN>', str(jmin))
            out_base = out_base.replace('<JMAX>', str(jmax))
            out_base = out_base.replace('<S1>', srv.get('S1', ''))
            out_base = out_base.replace('<S2>', srv.get('S2', ''))
            out_base = out_base.replace('<H1>', srv.get('H1', ''))
            out_base = out_base.replace('<H2>', srv.get('H2', ''))
            out_base = out_base.replace('<H3>', srv.get('H3', ''))
            out_base = out_base.replace('<H4>', srv.get('H4', ''))
            
            host_for_cfg = host
            if ':' in host and not host.startswith('['):
                host_for_cfg = f'[{host}]'
            out_base = out_base.replace('<ENDPOINT>', host_for_cfg)
            out_base = out_base.replace('<SERVER_PORT>', str(port))
            out_base = out_base.replace('<SERVER_PUBLIC_KEY>', srv.get('PublicKey', ''))
            out_base = out_base.replace('<PRESHARED_KEY>', psk)
            out_base = out_base.replace('<SERVER_ADDR>', srv.get('Address', ''))
            out_base = out_base.replace('<PERSISTENT_KEEPALIVE>', str(persistent_keepalive))

            for ip_list_name, ip_list_value in allowed_ips_dict.items():
                conf_name = f"{peer_name}{ip_list_name}{ep_label}.conf"
                final_conf = out_base.replace('<ALLOWED_IPS>', ip_list_value)
                try:
                    with open(g_conf_dir.joinpath(conf_name), 'w', newline='\n', encoding='utf-8') as file:
                        file.write(final_conf)
                except Exception as e:
                    logger.warning("⚠  Не удалось записать conf-файл %s: %s", conf_name, e)
                    continue

            if peer_name not in clients_for_zip:
                clients_for_zip.append(peer_name)

    if psk_added:
        try:
            cfg.save()
        except Exception as e:
            logger.warning("⚠  Не удалось сохранить server config после добавления PresharedKey: %s", e)
    
    return qr_enabled_names


def generate_qr_codes(qr_filter: Optional[Set[str]] = None) -> None:
    """
    Генерирует QR.
    qr_filter: множество имен IP-списков, для которых генерировать QR (например {'All', 'Tg'}).
    """
    logger.info('📱 Генерация QR-кодов...')
    if qrcode is None:
        raise RuntimeError('Пакет qrcode не установлен')
        
    # Если фильтр не передан (например, вызван только -q), попробуем прочитать из файла
    if qr_filter is None:
        try:
            # Читаем конфиг, чтобы узнать какие списки помечены как qr
            if g_allowedips_config_fn.exists():
                _, qr_filter = parse_allowedips_config(g_allowedips_config_fn.read_text('utf-8'))
            else:
                qr_filter = {'All'} # Default fallback
        except Exception:
            qr_filter = {'All'}

    # Очистка старых PNG
    for fn in glob.glob(str(g_conf_dir.joinpath("*.png"))):
        try: os.remove(fn)
        except Exception: pass
    
    # Поиск подходящих конфигов.
    # Файлы именуются: {Peer}{IPList}{EpLabel}.conf
    # Нам нужно найти в имени файла вхождение одного из ключей qr_filter.
    
    flst = []
    for p in g_conf_dir.glob("*.conf"):
        if p.name == g_main_config_fn.name: continue
        
        # Проверяем, содержит ли имя файла одну из разрешенных подстрок
        stem = p.stem
        # Логика: если фильтр {'All', 'Tg'}, то берем sniffAll.conf, sniffTgMSK.conf
        # но НЕ sniffDsYt.conf
        
        is_target = False
        for tag in qr_filter:
            if tag in stem:
                is_target = True
                break
        
        if is_target:
            flst.append(str(p))
            
    if not flst:
        logger.warning('⚠  Нет файлов, подходящих под QR фильтр: %s', qr_filter)
        return
    
    def generate_qr(conf, fn):
        if os.path.getsize(fn) > 2048:
            logger.warning('⚠  Конфиг %s >2KB, возможно QR не получится', fn)
        max_version = 40
        error_correction = qrcode.constants.ERROR_CORRECT_L
        for version in range(1, max_version + 1):
            try:
                qr = qrcode.QRCode(version=version, error_correction=error_correction, box_size=10, border=4)
                qr.add_data(conf)
                qr.make(fit=False)
                return qr.make_image(fill="black", back_color="white")
            except (qrcode.exceptions.DataOverflowError, ValueError):
                continue
        raise ValueError("⚠  Данных слишком много для QR")

    for fn in flst:
        with open(fn, 'r', encoding='utf-8') as file:
            conf = file.read()
        name = os.path.splitext(os.path.basename(fn))[0]
        png_path = g_conf_dir.joinpath(f"{name}.png")
        try:
            img = generate_qr(conf, fn)
            img.save(str(png_path))
        except Exception as e:
            logger.error('❌ Ошибка генерации QR для %s: %s', fn, e)


def zip_client_files(client_name: str) -> None:
    zip_filename = g_conf_dir.joinpath(f"{client_name}.zip")
    
    suffixes = []
    if g_allowedips_config_fn.exists():
        try:
            ips_dict, _ = parse_allowedips_config(g_allowedips_config_fn.read_text('utf-8'))
            suffixes = list(ips_dict.keys())
        except Exception: pass

    if suffixes:
        suffixes.sort(key=len, reverse=True)
        suffixes_pattern = "|".join([re.escape(s) for s in suffixes])
        pattern_str = rf'^{re.escape(client_name)}({suffixes_pattern}).*\.(conf|png)$'
    else:
        pattern_str = rf'^{re.escape(client_name)}[A-Za-z0-9_\-]*\.(conf|png)$'

    pattern_file = re.compile(pattern_str)
    
    with zipfile.ZipFile(str(zip_filename), 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for file in sorted(g_conf_dir.iterdir()):
            if not file.is_file():
                continue
            if pattern_file.match(file.name):
                try:
                    zipf.write(str(file), arcname=file.name)
                except Exception as e:
                    logger.warning("⚠  Не удалось добавить %s в %s: %s", file, zip_filename, e)
        
        if g_file_dir.exists() and g_file_dir.is_dir():
            for root, dirs, files in os.walk(g_file_dir):
                rel_root = os.path.relpath(root, g_file_dir)
                if rel_root == ".":
                    rel_root = ""
                else:
                    dir_arcname = rel_root.rstrip("/") + "/"
                    try:
                        zinfo = zipfile.ZipInfo(dir_arcname)
                        zipf.writestr(zinfo, "")
                    except Exception:
                        pass
                for fname in files:
                    full_path = os.path.join(root, fname)
                    if rel_root:
                        arcname = os.path.join(rel_root, fname)
                    else:
                        arcname = fname
                    try:
                        zipf.write(full_path, arcname=arcname)
                    except Exception as e:
                        logger.warning("⚠  Не удалось добавить %s в %s: %s", full_path, zip_filename, e)


def zip_all() -> None:
    logger.info('📦 Упаковка конфигов в ZIP...')
    names = list(dict.fromkeys(clients_for_zip))
    for name in names:
        zip_client_files(name)


def clean_confdir_types(keep_conf: bool = False, keep_qr: bool = False, keep_zip: bool = False,
                        allowed_names: Optional[List[str]] = None) -> None:
    keep_files = set()
    if allowed_names:
        for name in allowed_names:
            for f in os.listdir(g_conf_dir):
                if not f.startswith(name):
                    continue
                if keep_conf and f.endswith('.conf'):
                    keep_files.add(f)
                if keep_qr and f.endswith('.png'):
                    keep_files.add(f)
                if keep_zip and f == f"{name}.zip":
                    keep_files.add(f)
    else:
        for f in os.listdir(g_conf_dir):
            if keep_conf and f.endswith('.conf'):
                keep_files.add(f)
            if keep_qr and f.endswith('.png'):
                keep_files.add(f)
            if keep_zip and f.endswith('.zip'):
                keep_files.add(f)
    
    for f in os.listdir(g_conf_dir):
        if f not in keep_files and (f.endswith('.conf') or f.endswith('.png') or f.endswith('.zip')):
            try:
                os.remove(g_conf_dir.joinpath(f))
            except Exception:
                pass


# ----------------- CLI -----------------

parser = argparse.ArgumentParser(description="AmneziaWG инструмент для конфигов")
parser.add_argument("-s", "--serv-cfg", dest="server_cfg", default="", help="Server config (awg0/conf или путь)")
parser.add_argument("-a", "--add", dest="addcl", default="", help="Добавить клиента")
parser.add_argument("-u", "--update", default="", help="Сбросить ключи")
parser.add_argument("-d", "--delete", default="", help="Удалить клиента")
parser.add_argument("-c", "--conf", dest="confgen", action="store_true", help="Сгенерировать конфиги")
parser.add_argument("-q", "--qrcode", action="store_true", help="QR-коды")
parser.add_argument("-z", "--zip", action="store_true", help="ZIP-архивы")
parser.add_argument("-o", "--only", help="Только указанные клиенты", default="")
parser.add_argument("-i", "--ipaddr", default="", help="IP адрес")
parser.add_argument("-p", "--port", type=int, default=4455, help="Порт")
parser.add_argument("-l", "--limit", type=int, default=0, help="Limit (Mbit)")
parser.add_argument("-f", "--iface", default="", help="Сетевой интерфейс (например ens3)")
parser.add_argument("--make", dest="makecfg", default="", help="Создать серверный конфиг")
parser.add_argument("--mtu", type=int, default=1388, help="MTU")
parser.add_argument("--warp", type=int, default=0, help="WARP конфиги")
parser.add_argument("--proxy", default="", help="Proxy сервер для WARP API (например http://proxy:8080 или socks5://127.0.0.1:9050)")
opt = parser.parse_args()


def get_only_list() -> List[str]:
    if not opt.only:
        return []
    return [x.strip() for x in opt.only.split(",") if x.strip()]


xopt = [opt.addcl, opt.update, opt.delete]
copt = [x for x in xopt if len(x) > 0]
if copt and len(copt) >= 2:
    raise RuntimeError('Слишком много действий одновременно')


def resolve_server_config_candidate(name: Optional[str]) -> Optional[str]:
    if not name:
        return None

    def resolve_file(p: pathlib.Path) -> Optional[str]:
        if p.is_file():
            return str(p.resolve())
        if p.is_dir():
            conf = p.joinpath(p.name + ".conf")
            if conf.is_file():
                return str(conf.resolve())
        return None

    p = pathlib.Path(name)
    if p.is_absolute():
        r = resolve_file(p)
        if r:
            return r
    r = resolve_file(p)
    if r:
        return r
    candidates = []
    if not name.endswith(".conf"):
        candidates.append(name + ".conf")
    candidates.append(name)

    standard_dir = pathlib.Path("/etc/amnezia/amneziawg")
    for cand in candidates:
        r = resolve_file(standard_dir.joinpath(cand))
        if r:
            return r
    base_name = name.replace(".conf", "")
    r = resolve_file(SCRIPT_DIR.joinpath(base_name))
    if r:
        return r
    for cand in candidates:
        r = resolve_file(pathlib.Path.cwd().joinpath(cand))
        if r:
            return r
        r = resolve_file(pathlib.Path(cand))
        if r:
            return r
    return None


def get_main_config_path(check: bool = True, override: Optional[str] = None) -> Optional[str]:
    global g_main_config_fn, g_main_config_type
    
    if override:
        resolved = resolve_server_config_candidate(override)
        if resolved:
            g_main_config_fn = pathlib.Path(resolved)
            init_interface_paths(g_main_config_fn.stem)

            g_main_config_type = "AWG" if g_main_config_fn.name.startswith("a") else "WG"
            return str(g_main_config_fn)
        else:
            if check:
                raise RuntimeError(f'Не найден серверный конфиг "{override}"')
            g_main_config_fn = None
            return None
            
    if not g_main_config_src.exists():
        if check:
            raise RuntimeError(f'{g_main_config_src} не найден')
        g_main_config_fn = None
        return None
        
    content = g_main_config_src.read_text(encoding="utf-8").strip()
    if not content:
        if check:
            raise RuntimeError(f'{g_main_config_src} пустой')
        g_main_config_fn = None
        return None
        
    g_main_config_fn = pathlib.Path(content.splitlines()[0].strip())
    cfg_exists = g_main_config_fn.exists()
    
    if check and not cfg_exists:
        raise RuntimeError(f'Основной конфиг "{g_main_config_fn}" не найден')
        
    init_interface_paths(g_main_config_fn.stem)
    g_main_config_type = "AWG" if g_main_config_fn.name.startswith("a") else "WG"
    return str(g_main_config_fn)


def main() -> None:
    # Проверка на Windows
    if sys.platform == "win32":
        logger.error("❌ Этот скрипт работает только на Linux. Windows не поддерживается.")
        sys.exit(1)

    if not (1280 <= opt.mtu <= 1420):
        raise ValueError("MTU должен быть в диапазоне 1280..1420")

    want_conf = opt.confgen
    want_qr = opt.qrcode
    want_zip = opt.zip
    need_conf = want_conf or want_qr or want_zip
    need_qr = want_qr or want_zip

    if opt.makecfg:
        handle_makecfg(opt)
        return

    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)

    if opt.addcl:
        handle_add(opt)
        return
    if opt.update:
        handle_update(opt)
        return
    if opt.delete:
        handle_delete(opt)
        return
        
    # Сначала генерируем конфиги (если нужно),
    # и получаем список имен для QR
    qr_filter = None
    if need_conf:
        qr_filter = handle_confgen(opt)
        
    if need_qr:
        # Передаем полученный фильтр
        generate_qr_codes(qr_filter)
        
    if want_zip:
        zip_all()
        
    only_list = get_only_list()
    allowed_names = None
    if only_list:
        allowed_names = clients_for_zip if clients_for_zip else only_list
        
    clean_confdir_types(
        keep_conf=want_conf,
        keep_qr=want_qr,
        keep_zip=want_zip,
        allowed_names=allowed_names
    )
    logger.info('✅ Готово')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Фатальная ошибка: %s", e)
        sys.exit(1)
