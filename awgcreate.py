#!/usr/bin/env python3
"""
AmneziaWG Helper Script
"""

from __future__ import annotations

import argparse
import base64
import datetime
import glob
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import pathlib
import random
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import types
import zipfile
import zlib

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

try:
    import cryptography
except ImportError:
    cryptography = None

if cryptography is not None:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.x509.oid import NameOID

try:
    import aioquic
except ImportError:
    aioquic = None

if aioquic is not None:
    from aioquic._buffer import Buffer
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.packet import pull_quic_header

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

# Ставится True после первой неудачной попытки собрать сайдкар (чтобы не спамить warning)
_IMITAT_SIDECAR_MISSING = False
_WARP_PROBE_MISSING = False
# Бэкофф-таймстампы пересборки сайдкаров (фикс аудита-A4: транзитные сбои
# сети не блокируют навсегда, а откладывают повторную попытку на 5 минут)
_SIDECAR_RETRY_AT: dict[str, float] = {}

# Глобальный указатель на последний активный конфиг
g_main_config_src = SCRIPT_DIR.joinpath("_main.config")

# Глобальные переменные состояния (инициализируются в init_interface_paths)
g_work_dir: pathlib.Path = SCRIPT_DIR
g_conf_dir: pathlib.Path = SCRIPT_DIR.joinpath("conf")
g_file_dir: pathlib.Path = SCRIPT_DIR.joinpath("file")
g_defclient_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_defclient.config")
g_endpoint_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_endpoint.config")
g_allowedips_config_fn: pathlib.Path = SCRIPT_DIR.joinpath("_allowedips.config")

g_main_config_fn: pathlib.Path | None = None
clients_for_zip: list[str] = []


# ----------------- Шаблоны -----------------

g_defserver_config = """# Protocol: <PROTOCOL>
[Interface]
#_GenKeyTime = <SERVER_KEY_TIME>
#_PublicKey = <SERVER_PUBLIC_KEY>
Address = <SERVER_ADDR>
ListenPort = <SERVER_PORT>
<JC_LINE><JMIN_LINE><JMAX_LINE><S1_LINE><S2_LINE><S3_LINE><S4_LINE><H1_LINE><H2_LINE><H3_LINE><H4_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE><HEADERPROTECTIONKEY_LINE><CONTENTPADDINGADDITION_LINE><REKEYAFTERTIME_LINE><REKEYTIMEOUT_LINE><REJECTAFTERTIME_LINE><KEEPALIVETIMEOUT_LINE><MAXHANDSHAKEATTEMPTS_LINE><RANDOMTRAILERS_LINE><DISABLECOOKIES_LINE>MTU = <MTU>
PrivateKey = <SERVER_PRIVATE_KEY>

PostUp = bash <SERVER_UP_SCRIPT>
PostDown = bash <SERVER_DOWN_SCRIPT>
"""

g_defclient_config = """
[Interface]
Address = <CLIENT_TUNNEL_IP>
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
<JC_LINE><JMIN_LINE><JMAX_LINE><S1_LINE><S2_LINE><S3_LINE><S4_LINE><H1_LINE><H2_LINE><H3_LINE><H4_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE><HEADERPROTECTIONKEY_LINE><CONTENTPADDINGADDITION_LINE><REKEYAFTERTIME_LINE><REKEYTIMEOUT_LINE><REJECTAFTERTIME_LINE><KEEPALIVETIMEOUT_LINE><MAXHANDSHAKEATTEMPTS_LINE><RANDOMTRAILERS_LINE><DISABLECOOKIES_LINE>MTU = <MTU>
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
<JC_LINE><JMIN_LINE><JMAX_LINE><REKEYAFTERTIME_LINE><REKEYTIMEOUT_LINE><REJECTAFTERTIME_LINE><KEEPALIVETIMEOUT_LINE><MAXHANDSHAKEATTEMPTS_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE><TABLE_LINE>MTU = <MTU>
PrivateKey = <WARP_PRIVATE_KEY>

[Peer]
Endpoint = <WARP_ENDPOINT>
PersistentKeepalive = <PERSISTENT_KEEPALIVE>
PublicKey = <WARP_PEER_PUBLIC_KEY>
AllowedIPs = 0.0.0.0/0, ::/0
"""

# Шаблон для файла параметров (awg.sh), так же это тестовый скрипт
params_script_template = r'''#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"
LOCAL_SUBNETS="<SERVER_ADDR>"

# --- Лимиты скорости ---
SUBNETS_LIMITS=(
  "<SERVER_ADDR>:<RATE_LIMIT>"
)
BRIDGE="FFFF:10000mbit:4400"

# --- WARP маршрутизация ---
WARP_LIST=(
<WARP_LIST>
)

# --- Группы локальных сетей ---
LAN_ALLOW=(
  "<SERVER_ADDR>"
)

# --- Пробросы портов ---
PORT_FORWARDING_RULES=(
  #"ЛокальныйIPv4'/+'[,v6]:ВнешнийПорт[-Диапазон][>ВнутреннийПорт[-Диапазон]][:[TCP]'/+'[,UDP]][:[SNAT]'/+'[,IFACE]][:[Список_IPv4]'/+'[,v6_подсетей]]"
  #"10.1.0.1:80:TCP"
  #"10.1.0.2:443:TCP:SNAT"
)

# --- DDoS защита ---
PORT_FORWARDING_DDOS=(
  #"Порт[-Диапазон][&Список][=Shared][,v6][/Протокол]:Rate/Период[+Burst][>EstRate/Период[+EstBurst]][<Connlimit[,NewRate/Период]][^EstPackets][_МинДлина-МаксДлина][~Полоса][!Бан/Секунд][@Интерфейс][=>ReplyRate/Период+Burst][=_ReplyМин-Макс][=~ReplyПолоса]"
  #"80/tcp:100/10+50>500/5+100<20,5/30^10_32-1500~100mbit!3/60"
  #"22:10/60<3!5/300"
  "<SERVER_PORT>/udp:50/10+100>1000/10+2000<10,2/10^50_32-1500~<RATE_LIMIT>=>1000/10+2000=_32-1500=~<RATE_LIMIT>"
)

# --- Квоты трафика ---
TRAFFIC_QUOTAS=(
  #"10.77.0.0/24:5g:day"
)
#Часовой пояс
QUOTA_TIMEZONE="UTC"


# --- Режим логирования ---
# 0 = выключен, 1 = включён
# UPLOG=1 — включить лог для up скрипта
# DOWNLOG=1 — включить лог для down скрипта
# TESTLOG=1 — включить лог для проверочного скрипта
UPLOG=0
DOWNLOG=0
TESTLOG=0


# ==========================================
# === Python Helpers (вся работа с IP) ===
# ==========================================

# Проверка: перекрывается ли подсеть с локальными подсетями туннеля
local_subnet_overlaps() {
    [ -n "$LOCAL_SUBNETS_IPV4" ] && overlaps_py "$1" "$LOCAL_SUBNETS_IPV4" && return 0
    [ -n "$LOCAL_SUBNETS_IPV6" ] && overlaps_py "$1" "$LOCAL_SUBNETS_IPV6" && return 0
    return 1
}

overlaps_py() {
    python3 - "$1" "$2" <<'PYEOF'
import ipaddress, sys
ip1 = ipaddress.ip_network(sys.argv[1], strict=False)
ip2 = ipaddress.ip_network(sys.argv[2], strict=False)
sys.exit(0 if ip1.overlaps(ip2) else 1)
PYEOF
}

# Проверка: является ли IP адресом сети (network address)
is_network_address() {
    python3 - "$1" "$2" <<'PYEOF'
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    net = ipaddress.ip_network(sys.argv[2], strict=False)
    print(1 if ip == net.network_address else 0)
except:
    print(0)
PYEOF
}
check_server_network() {
    is_network_address "$1" "$2"
}

# Проверка ip rule по диапазону MARK
# $1 = MARK_BASE
check_ip_rules() {
    local mark_base_val="$1"
    MARK_BASE="$mark_base_val" python3 << 'PYEOF'
import subprocess, sys
import os

mark_base = int(os.environ.get('MARK_BASE', '1000'))

warp_start = mark_base
warp_end = warp_start + 999
bc_start = mark_base + 1000
bc_end = mark_base + 1099

def get_rules(ip_ver):
    try:
        cmd = ['ip'] + (['-6'] if ip_ver == 6 else []) + ['rule', 'show']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        lines = []
        for line in result.stdout.strip().split('\n'):
            if not line: continue
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'fwmark' and i+1 < len(parts):
                    v = parts[i+1]
                    # fwmark может быть "0x3e8/0x3e8" (с маской; фикс аудита:
                    # int(v,0) падал на такой строке и обнулял ВСЮ выборку)
                    m = int(v.split('/')[0], 0) if v.startswith('0x') else int(v)
                    lines.append((line, m))
        return lines
    except:
        return []

def print_matching(rules, start, end, label_v4, label_v6):
    for ip_ver, label in [(4, label_v4), (6, label_v6)]:
        if ip_ver in rules:
            print(f'   {label}:')
            found = False
            for line, m in rules[ip_ver]:
                if start <= m <= end:
                    print(f'       {line}')
                    found = True
            if not found:
                print('       (нет правил)')

rules = {4: get_rules(4), 6: get_rules(6)}
print_matching(rules, warp_start, warp_end, 'WARP марки (маркировка + маршрутизация) IPv4', 'WARP марки (маркировка + маршрутизация) IPv6')
print_matching(rules, bc_start, bc_end, 'Broadcast/Multicast марки IPv4', 'Broadcast/Multicast марки IPv6')
PYEOF
}

# Расчёт всех параметров IPv4 подсети
calc_ipv4_info() {
    eval $(LOCAL_SUBNETS_IPV4="$LOCAL_SUBNETS_IPV4" LOCAL_SERVER_IP="$LOCAL_SERVER_IP" python3 <<'PYEOF'
import ipaddress, os
try:
    net = ipaddress.ip_network(os.environ['LOCAL_SUBNETS_IPV4'], strict=False)
    srv = ipaddress.ip_address(os.environ['LOCAL_SERVER_IP'])
    print(f'BROADCAST_ADDR="{net.broadcast_address}"')
    print(f'SERVER_ON_NETWORK={int(srv == net.network_address)}')
except:
    print('BROADCAST_ADDR=""')
    print('SERVER_ON_NETWORK=0')
PYEOF
)
}

# Проверка статуса IPv6 подсети
calc_ipv6_status() {
    eval $(LOCAL_SUBNETS_IPV6="$LOCAL_SUBNETS_IPV6" LOCAL_SERVER_IP_IPV6="$LOCAL_SERVER_IP_IPV6" python3 <<'PYEOF'
import ipaddress, os
try:
    net = ipaddress.ip_network(os.environ['LOCAL_SUBNETS_IPV6'], strict=False)
    srv = ipaddress.ip_address(os.environ['LOCAL_SERVER_IP_IPV6'])
    print(f'SERVER_ON_NETWORK_IPV6={int(srv == net.network_address)}')
except:
    print('SERVER_ON_NETWORK_IPV6=0')
PYEOF
)
}

# Валидация маски подсети для лимитов скорости
validate_subnet_mask() {
    python3 - "$1" <<'PYEOF'
import ipaddress, sys
ip_str = sys.argv[1].strip()
net = ipaddress.ip_network(ip_str, strict=False)
if isinstance(net, ipaddress.IPv4Network):
    ok = 8 <= net.prefixlen <= 32
else:
    # Для IPv6 разрешаем /96 до /128, но /112 допустима
    ok = 96 <= net.prefixlen <= 128
sys.exit(0 if ok else 1)
PYEOF
}

# Расчёт broadcast адреса
get_broadcast_addr() {
    python3 - "$1" <<'PYEOF'
import ipaddress, sys
try:
    print(ipaddress.ip_network(sys.argv[1], strict=False).broadcast_address)
except: pass
PYEOF
}

net_contains_ip() {
    # Пропуск серверной группы в лимитах: лежит ли IP внутри сети/блока (0=да)
    NET_ARG="$1" IP_ARG="$2" python3 -c "import ipaddress,os,sys; \
n=ipaddress.ip_network(os.environ['NET_ARG'],strict=False); \
sys.exit(0 if ipaddress.ip_address(os.environ['IP_ARG']) in n else 1)"
}

net_is_last_block() {
    # Broadcast-группа: блок заканчивается на последний адрес подсети (0=да)
    NET_ARG="$1" BLOCK_ARG="$2" python3 -c "import ipaddress,os,sys; \
b=ipaddress.ip_network(os.environ['BLOCK_ARG'],strict=False); \
n=ipaddress.ip_network(os.environ['NET_ARG'],strict=False); \
sys.exit(0 if int(b.broadcast_address)==int(n.broadcast_address) else 1)"
}

subnets_equal() {
    # Одна ли СЕТЬ (network+prefix), независимо от записи адреса: «10.77.0.1/24»
    # == «10.77.0.0/24». Используется флагом «правило содержит главную сеть».
    A_ARG="$1" B_ARG="$2" python3 -c '
import ipaddress, os, sys
try:
    a = ipaddress.ip_network(os.environ["A_ARG"], strict=False)
    b = ipaddress.ip_network(os.environ["B_ARG"], strict=False)
    sys.exit(0 if (a.prefixlen == b.prefixlen and a.network_address == b.network_address) else 1)
except Exception:
    sys.exit(1)'
}

# Поиск туннеля по подсети в .conf файлах и активных интерфейсах
find_tunnel_for_subnet() {
  local target_subnet="$1"
  local script_dir="$(dirname "$(readlink -f "$0")")"

  for conf_file in "$script_dir"/*.conf; do
    [ -f "$conf_file" ] || continue
    local conf_name="$(basename "$conf_file" .conf)"
    [[ "$conf_name" == *warp* ]] && continue
    local conf_subnet_raw=$(grep -E "^Address = " "$conf_file" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
    [ -z "$conf_subnet_raw" ] && continue
    IFS=',' read -ra SUBNETS <<< "$conf_subnet_raw"
    for subnet in "${SUBNETS[@]}"; do
      subnet="$(echo "$subnet" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$subnet" ] && continue
      local overlaps
      overlaps=$(overlaps_py "$target_subnet" "$subnet")
      if [ $? -eq 0 ]; then
        echo "$conf_name"
        return 0
      fi
    done
  done

  for iface in $(ip -br link show 2>/dev/null | awk '{print $1}'); do
    [ "$iface" = "${TUN:-}" ] && continue
    for addr in $(ip -o addr show "$iface" 2>/dev/null | awk '{print $4}'); do
      local overlaps
      overlaps=$(overlaps_py "$target_subnet" "$addr")
      if [ $? -eq 0 ]; then
        echo "$iface"
        return 0
      fi
    done
  done

  return 1
}

# Поиск туннеля из INTERFACE_MAP по IP/подсети
find_tun_from_map() {
  local ip_or_subnet="$1"

  for mapping in "${INTERFACE_MAP[@]}"; do
    tun_name="${mapping%%=*}"
    tun_subnet="${mapping#*=}"

    local overlaps
    overlaps=$(overlaps_py "$ip_or_subnet" "$tun_subnet")
    if [ $? -eq 0 ]; then
      echo "$tun_name"
      return 0
    fi
  done

  echo ""
  return 1
}

# Атомарное обновление reference count с PID-based mkdir блокировкой
# Безопасная версия: проверяем жив ли процесс перед удалением lock
atomic_ref_update() {
  local ref_file="$1"
  local operation="$2"
  local value="${3:-}"
  local my_pid="${BASHPID:-$$}"
  local my_lock="${ref_file}.d.${my_pid}"
  local max_attempts=90
  local attempt=0

  local result=""
  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))
    if mkdir "$my_lock" 2>/dev/null; then
      # Заодно убираем только МЁРТВЫЕ чужие lock-каталоги
      for other in "${ref_file}.d."*; do
        [ -e "$other" ] || continue
        [ "$other" = "$my_lock" ] && continue
        local opid="${other##*.d.}"
        if ! kill -0 "$opid" 2>/dev/null; then
          rm -rf "$other" 2>/dev/null || true
        fi
      done
      case "$operation" in
        "inc")
          local cur=$(cat "$ref_file" 2>/dev/null || echo "0")
          result=$((cur + 1))
          echo "$result" > "$ref_file"
          ;;
        "dec")
          local cur=$(cat "$ref_file" 2>/dev/null || echo "0")
          result=$((cur - 1))
          echo "$result" > "$ref_file"
          ;;
        "get_inc")
          local cur=$(cat "$ref_file" 2>/dev/null || echo "0")
          result="$cur:$((cur + 1))"
          echo "$((cur + 1))" > "$ref_file"
          ;;
        "get_dec")
          local cur=$(cat "$ref_file" 2>/dev/null || echo "0")
          result="$cur:$((cur - 1))"
          echo "$((cur - 1))" > "$ref_file"
          ;;
        "set")
          echo "$value" > "$ref_file"
          result="$value"
          ;;
        "get")
          result=$(cat "$ref_file" 2>/dev/null || echo "0")
          ;;
      esac
      rmdir "$my_lock" 2>/dev/null || rm -rf "$my_lock" 2>/dev/null || true
      echo "$result"
      return 0
    fi
    sleep 0.1
  done

  echo "⚠️ Lock для $ref_file занят более ${max_attempts}x0.1с — операция не выполнена" >&2
  return 1
}

# Парсинг WARP интерфейсов из записи WARP_LIST
parse_warp_interfaces() {
  local entry="$1"
  if [[ "$entry" == *"="* ]]; then
    echo "${entry%%=*}"
  else
    echo "$entry"
  fi
}

warp_specific_layout() {
  # Агрегация WARP-групп по подсетям: одна подсеть в нескольких записях
  # WARP_LIST сливается в одну группу интерфейсов (трафик делится по всем).
  local -A _sif
  local -a _sorder=() _difs=()
  local entry i part s if ifs
  for entry in "${WARP_LIST[@]}"; do
    [ "$entry" = "none" ] || [ -z "$entry" ] && continue
    # none=subnets — исключения, в маркировку НЕ попадают (как в down-сборе)
    [[ "$entry" =~ ^none[[:space:]]*= ]] && continue
    if [[ "$entry" == *"="* ]]; then
      # Интерфейсы из части до "="
      part="${entry%%=*}"
      local -a _ifs=()
      IFS=',' read -ra _ri <<< "$part"
      for if in "${_ri[@]}"; do
        if="$(echo "$if" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$if" ] && [ "$if" != "none" ] && _ifs+=("$if")
      done
      # Подсети из части после "="
      part="${entry#*=}"
      IFS=',' read -ra _rs <<< "$part"
      for s in "${_rs[@]}"; do
        s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$s" ] || continue
        if [ -z "${_sif[$s]+x}" ]; then
          _sorder+=("$s")
          _sif[$s]=""
        fi
        for if in "${_ifs[@]}"; do
          if [[ ",${_sif[$s]}," != *",$if,"* ]]; then
            [ -n "${_sif[$s]}" ] && _sif[$s]="${_sif[$s]},"
            _sif[$s]="${_sif[$s]}$if"
          fi
        done
      done
    else
      # Без подсетей — в default-группу (дедупликация)
      IFS=',' read -ra _ri <<< "$entry"
      for if in "${_ri[@]}"; do
        if="$(echo "$if" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$if" ] && [ "$if" != "none" ] || continue
        local _dup=0
        for i in "${_difs[@]}"; do [ "$i" = "$if" ] && _dup=1 && break; done
        [ "$_dup" -eq 0 ] && _difs+=("$if")
      done
    fi
  done

  local _off=0 _cnt=0
  for s in "${_sorder[@]}"; do
    IFS=',' read -ra _g <<< "${_sif[$s]}"
    _cnt=${#_g[@]}
    echo "S|${_off}|${_cnt}|${s}|${_sif[$s]}"
    _off=$((_off + _cnt))
  done
  local _dc=${#_difs[@]}
  if [ "$_dc" -gt 0 ]; then
    ifs=""
    for if in "${_difs[@]}"; do
      [ -n "$ifs" ] && ifs="$ifs,"
      ifs="$ifs$if"
    done
    # 5 полей как у S-строк (4-е поле — подсеть — пустое для D)
    echo "D|${_off}|${_dc}||${ifs}"
  fi
}

# Парсинг флагов (SNAT + интерфейс)
parse_flags() {
  local s="$1"
  PARSED_SNAT=""
  PARSED_IFACE=""
  IFS=',' read -ra flag_parts <<< "$s"
  for part in "${flag_parts[@]}"; do
    part="${part// /}"
    local part_upper
    part_upper=$(printf '%s' "$part" | tr '[:lower:]' '[:upper:]')
    if [ "$part_upper" = "SNAT" ]; then
      PARSED_SNAT="SNAT"
    elif [ -n "$part" ]; then
      PARSED_IFACE="$part"
    fi
  done
}

# Проверка протокола (поддержка пробелов: "TCP, UDP")
is_proto_field() {
  local f="$1"
  local f_clean="${f// /}"
  local f_upper
  f_upper=$(printf '%s' "$f_clean" | tr '[:lower:]' '[:upper:]')
  [ "$f_upper" = "TCP" ] || [ "$f_upper" = "UDP" ] || [ "$f_upper" = "TCP,UDP" ] || [ "$f_upper" = "UDP,TCP" ]
}

# Проверка флагов (SNAT, интерфейс)
is_flags_field() {
  local f="$1"
  local f_upper
  f_upper=$(printf '%s' "$f" | tr '[:lower:]' '[:upper:]')
  [ "$f_upper" = "SNAT" ] && return 0
  [[ "$f" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] && return 0
  [[ "$f_upper" == *"SNAT"* ]] && [[ "$f" =~ [a-zA-Z] ]] && return 0
  return 1
}

# Получение информации о подсети (кол-во адресов + префикс)
get_subnet_info() {
    SUBNET_ARG="$1" python3 << PYEOF
import ipaddress, os
try:
    net = ipaddress.ip_network(os.environ.get('SUBNET_ARG', ''), strict=False)
    print(f'{net.num_addresses}:{net.prefixlen}')
except:
    print('0:0')
PYEOF
 2>/dev/null
}

# Перечисление IP в подсети с предупреждением для больших подсетей
# /8 для IPv4 (16M адресов), /96 для IPv6
# tc создаёт 1 класс на каждый IP подсети
list_subnet_ips() {
    local subnet="$1"
    local max_prefixlen_ipv4=8
    local max_prefixlen_ipv6=96
    SUBNET_ARG="$subnet" MAX_V4="$max_prefixlen_ipv4" MAX_V6="$max_prefixlen_ipv6" python3 << PYEOF
import ipaddress, os, sys
try:
    subnet = os.environ.get('SUBNET_ARG', '')
    max_v4 = int(os.environ.get('MAX_V4', 8))
    max_v6 = int(os.environ.get('MAX_V6', 96))
    net = ipaddress.ip_network(subnet, strict=False)
    num_ips = net.num_addresses
    
    if ':' in subnet:
        effective_limit = max_v6
        limit_type = 'IPv6'
    else:
        effective_limit = max_v4
        limit_type = 'IPv4'
    if net.prefixlen < effective_limit:
        print(f"# Подсеть {subnet} слишком большая (/{net.prefixlen} < /{effective_limit} для {limit_type})", file=sys.stderr)
        print(f"# Минимум: /{effective_limit} ({num_ips} адресов)", file=sys.stderr)
        sys.exit(1)
    if num_ips > 65536:
        print(f"# {subnet}: слишком много адресов ({num_ips}) — максимум 65536 (фикс аудита: /96 вешал up на 2^32 классах); минимум: /112 для IPv6, /16 для IPv4", file=sys.stderr)
        sys.exit(1)
    for ip in net:
        print(ip)
except Exception as e:
    print(f"Ошибка: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# Вычисление соотношений подсетей
calc_subnet_ratios() {
    SUBNETS_ARG="$1" python3 << PYEOF
import ipaddress, os, sys
subnets = os.environ.get('SUBNETS_ARG', '').split(',')
nets = []
counts = []
for s in subnets:
    s = s.strip()
    if not s: continue
    net = ipaddress.ip_network(s, strict=False)
    # Проверка размера подсети
    if ':' in s:
        # IPv6: минимум /96
        if net.prefixlen < 96:
            print(f"# Подсеть {s} слишком большая (/96 минимум)", file=sys.stderr)
            sys.exit(1)
    else:
        # IPv4: минимум /8
        if net.prefixlen < 8:
            print(f"# Подсеть {s} слишком большая (/8 минимум)", file=sys.stderr)
            sys.exit(1)
    nets.append((net.num_addresses, net.prefixlen, 'ipv6' if ':' in s else 'ipv4'))
    counts.append(net.num_addresses)
min_count = min(counts)
ratios = [c // min_count for c in counts]
result = [str(min_count)]
for (cnt, pre, ip_type), r in zip(nets, ratios):
    result.append(f"{cnt}:{pre}:{ip_type}:{r}:{cnt}")
print('|'.join(result))
PYEOF
}

# Вычисление базового IP блока
get_block_ip() {
    SUBNET_ARG="$1" RATIO_ARG="$2" IDX_ARG="$3" python3 << PYEOF
import ipaddress, os
subnet = os.environ.get('SUBNET_ARG', '')
net = ipaddress.ip_network(subnet, strict=False)
start_int = int(net.network_address)
ratio = int(os.environ.get('RATIO_ARG', '1'))
idx = int(os.environ.get('IDX_ARG', '0'))
block_size = ratio
block_start = start_int + (idx * block_size)
if ':' in subnet:
    start = ipaddress.IPv6Address(block_start)
    prefix = net.prefixlen
    mask = max(prefix, 128 - (ratio - 1).bit_length())
    print(f'{start}/{mask}')
else:
    start = ipaddress.IPv4Address(block_start)
    prefix = net.prefixlen
    mask = max(prefix, 32 - (ratio - 1).bit_length())
    print(f'{start}/{mask}')
PYEOF
}

# Парсинг подсети из .conf файла
parse_conf_subnet() {
    python3 - "$1" <<'PYEOF'
import ipaddress, sys
print(ipaddress.ip_network(sys.argv[1], strict=False))
PYEOF
}

# Парсинг строки SUBNETS_LIMITS (subnet1,subnet2:LIM или subnet1:LIM_D:LIM_U или просто подсеть)
# Формат вывода: subnet|rate|type
#   type = "none" (нет лимита), "mix" (одно значение), "separate" (down:up)
parse_entry() {
  PARSED_ENTRY="$1" python3 - <<'PYEOF'
import os
entry = os.environ.get('PARSED_ENTRY', '')
last_slash = entry.rfind('/')
if last_slash >= 0:
    rate_part = entry[last_slash+1:]
    colon_pos = rate_part.find(':')
    if colon_pos >= 0:
        prefix = rate_part[:colon_pos]
        subnet = entry[:last_slash] + '/' + prefix
        rate = rate_part[colon_pos+1:]
    else:
        subnet = entry
        rate = ''
else:
    colon_pos = entry.find(':')
    if colon_pos >= 0:
        subnet = entry[:colon_pos]
        rate = entry[colon_pos+1:]
    else:
        subnet = entry
        rate = ''
if not rate:
    print(f'{subnet}|{rate}|none')
elif ':' in rate:
    print(f'{subnet}|{rate}|separate')
else:
    print(f'{subnet}|{rate}|mix')
PYEOF
}

# Проверка: входит ли IP в одну из подсетей группы (python, как остальные IP-хелперы).
# Перенесено из up.sh — все Python-хелперы живут в скрипте параметров (source у up/down).
ip_in_subnets() {
  ARG_IP="$1" ARG_SUBNETS="$2" python3 - << 'PYEOF'
import ipaddress, os, sys
try:
    ip = ipaddress.ip_address(os.environ.get('ARG_IP', ''))
except ValueError:
    sys.exit(1)
for s in os.environ.get('ARG_SUBNETS', '').split(','):
    s = s.strip()
    if not s:
        continue
    try:
        if ip in ipaddress.ip_network(s, strict=False):
            sys.exit(0)
    except ValueError:
        continue
sys.exit(1)
PYEOF
}

# Отделяет максимальный правый хвост подсетей (содержат '/') от остальной части
# правила проброса PORT_FORWARDING_RULES (остальное — клиент:порты[:флаги]).
# Вывод: "MAIN_PART|SUBNETS" (фикс бага 1.19: левомайстовый re-search до '$').
# Перенесено из up.sh — единое место для Python-хелперов.
split_rule_subnets() {
  RULE_ARG="$1" python3 - << 'PYEOF'
import os, re
rule = os.environ.get('RULE_ARG', '')
m = re.search(r'((?:[0-9A-Fa-f]+(?:[.:][0-9A-Fa-f]*)*/[0-9]{1,3})(?:,[ \t]*[0-9A-Fa-f]+(?:[.:][0-9A-Fa-f]*)*/[0-9]{1,3})*)$', rule)
if m:
    sub = m.group(1)
    print(f"{rule[:len(rule)-len(sub)]}|{sub}")
else:
    print(f"{rule}|")
PYEOF
}

# --- Секции клиентов конфига (для квот per-client) ---
# Выводит по строке «имя|адреса» на секцию [Peer] (имя из #_Name),
# адреса через запятую. Нужно для квот: набор ipset на клиента.
parse_peer_sections() {
  local conf_file="$1"
  [ -f "$conf_file" ] || return 0
  awk '
    /^\[Peer\]/ { in_peer=1; name=""; ips=""; next }
    in_peer && /^#_Name[[:space:]]*=/ { sub(/^#_Name[[:space:]]*=[[:space:]]*/, ""); name=$0; next }
    in_peer && /^AllowedIPs[[:space:]]*=/ { sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); ips=$0; next }
    in_peer && /^\[/ && !/^\[Peer\]/ { print name "|" ips; in_peer=0 }
    in_peer && /^$/ { print name "|" ips; in_peer=0 }
    END { if (in_peer) print name "|" ips }
  ' "$conf_file" 2>/dev/null
}
# --- Конец: секции клиентов конфига ---

# === Конец Python Helpers ===


# ==========================================
# === Bash Helpers  ===
# ==========================================

# Вычисление MARK_BASE из имени туннеля
calc_mark_base() {
  local tun_name="$1"
  local tun_hash tun_hash_hex
  tun_hash=$(echo -n "$tun_name" | cksum 2>/dev/null | cut -d' ' -f1)
  if [ -z "$tun_hash" ] || [ "$tun_hash" = "0" ]; then
    tun_hash_hex=$(echo -n "$tun_name" | md5sum 2>/dev/null | cut -c1-8)
    tun_hash=$((16#$tun_hash_hex))
  fi
  if [ -z "$tun_hash" ] || [ "$tun_hash" = "0" ]; then
    tun_hash=${#tun_name}
  fi
  # Шаг +11 (взаимно прост с 900): слоты идут циклически со сдвигом
  # 11...880, 891, 2, 13, ... 893, 4, 15 ... — соседние хэши не садятся
  # рядом, и аллокатор при коллизиях не толпится на соседних слотах.
  echo "$((1000 + ((tun_hash % 900) * 11 % 900) * 10))"
}

mark_range_occupied() {
  # stdout: найденные чужие марки в диапазоне (пусто = свободен)
  local base_val="$1"
  MARK_BASE="$base_val" python3 << 'PYEOF'
import os, subprocess
try:
    base = int(os.environ.get('MARK_BASE', '1000'))
except ValueError:
    base = 1000
lo, hi = base, base + 1099
extra = base + 9000
marks = set()
for extra_args in ([], ['-6']):
    try:
        out = subprocess.run(['ip'] + extra_args + ['rule', 'show'],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        continue
    for tok in out.split():
        if not tok.startswith('0x'):
            continue
        h = tok.split('/')[0]
        try:
            m = int(h, 16)
        except ValueError:
            continue
        if m != 0:
            marks.add(m)
for m in sorted(marks):
    if lo <= m <= hi or m == extra:
        print(m)
PYEOF
}

alloc_mark_base() {
  local tun_safe="$1"
  local saved_file="${SCRIPT_DIR}/.data/mark_base_${tun_safe}"
  if [ -f "$saved_file" ]; then
    cat "$saved_file"
    return 0
  fi
  local base new_base k occupied i
  base=$(calc_mark_base "$tun_safe")
  new_base="$base"
  i=0
  while [ "$i" -lt 900 ]; do
    occupied=$(mark_range_occupied "$new_base")
    if [ -z "$occupied" ]; then
      mkdir -p "$SCRIPT_DIR/.data" 2>/dev/null || true
      echo "$new_base" > "$saved_file" 2>/dev/null || true
      echo "$new_base"
      return 0
    fi
    new_base=$(( 1000 + ((((new_base - 1000) / 10 ) + 11) % 900) * 10 ))
    i=$((i + 1))
  done
  echo "⚠️  Не удалось найти свободный диапазон марк для $tun_safe (900+ туннелей?) — расчётный" >&2
  echo "$base"
}

# "Безопасное" имя туннеля для суффиксов
safe_tun_name() {
  echo "$1" | sed 's/[^a-zA-Z0-9]/_/g'
}

# Парсинг LOCAL_SUBNETS на IPv4 и IPv6
parse_local_subnets() {
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
}

quota_value_bytes() {
    # Объём в байты: "5g" → 5368709120; голое число — байты.
    # Входы > 2^63-1 (напр. 10000000t) НЕ выразимы в int64: насыщаем к максимуму
    # (строгая сторона — огромная квота, а не арифметический мусор/0; фикс
    # волны-2 аудита). Для bare-чисел сравниваем по длине строки.
    local _v="$1" _n="" _dig _mul=1
    case "$_v" in
      *[bB]) _dig="${_v%[bB]}" ;;
      *[kK]) _dig="${_v%[kK]}"; _mul=1024 ;;
      *[mM]) _dig="${_v%[mM]}"; _mul=1048576 ;;
      *[gG]) _dig="${_v%[gG]}"; _mul=1073741824 ;;
      *[tT]) _dig="${_v%[tT]}"; _mul=1099511627776 ;;
      *) _dig="${_v:-0}" ;;
    esac
    # насыщение: цифровая строка > 9223372036854775807 или результат > 2^63-1
    if [ "${#_dig}" -gt 19 ] || { [ "${#_dig}" -eq 19 ] && [ "$_dig" \> "9223372036854775807" ]; }; then
      echo "9223372036854775807"; return 0
    fi
    if [ "$_mul" -eq 1 ]; then _n="$_dig"
    else
      _n=$(( _dig * _mul ))
      [ "$_n" -lt 0 ] && _n="9223372036854775807"
    fi
    echo "${_n:-0}"
}

quota_throttle_bits() {
    # Скорость после превышения квоты (4-е поле правила, mbit-стиль как у
    # лимитов: "2m"=2 Мбит/с, "64k"=64 кбит/с, "100mbit"/"64kbit"; голое
    # число = бит/с). Суффикс "bit" снимается (фикс волны-2 аудита: раньше
    # "100mbit" молча превращался в 0 → строгий DROP вместо 100 Мбит/с).
    local _v="$1" _n=""
    _v="${_v%bit}"; _v="${_v%BIT}"
    case "$_v" in
      *[kK]) _n=$(( ${_v%[kK]} * 1000 )) ;;
      *[mM]) _n=$(( ${_v%[mM]} * 1000000 )) ;;
      *[gG]) _n=$(( ${_v%[gG]} * 1000000000 )) ;;
      *) _n="${_v:-0}" ;;
    esac
    case "$_n" in
      ''|*[!0-9]*) _n=0 ;;   # битые значения → 0 (строгий DROP; фикс волны-2)
    esac
    echo "${_n:-0}"
}

net_count_addrs() {
    # Число адресов сети/блока: v4: 2^(32-p); v6: 2^(128-p).
    # Bash int64 не умеет 2^(≥63): для блоков v6 /66 и шире вес невыразим —
    # раньше 1<<(128-p) при p<64 давал 0/мусор (маскирование счётчика) и квота
    # v6 молча исчезала. Отдаём максимальный выразимый вес (2^62); произведение
    # с объёмом затем насыщается в quota_client_plan (фикс аудита-T1).
    local _n="$1" _p="${1##*/}"
    if [[ "$_n" == *:* ]]; then
        local _s=$(( 128 - _p ))
        if [ "$_s" -ge 63 ]; then
            echo "4611686018427387904"   # 2^62 — положительное, в int64
        else
            echo "$(( 1 << _s ))"
        fi
    else
        echo "$(( 1 << (32 - _p) ))"
    fi
}

quota_mul_sat() {
    # Насыщенное умножение int64 (защита от молчаливого переполнения: если
    # a*b > 2^63-1, отдаём максимум, а не мусор/0). Штатные комбинации
    # (вес ≤2^24, объём ≤16G) не доходят до порога — поведение без изменений.
    local _a="$1" _b="$2"
    if [ "$_a" -le 0 ] || [ "$_b" -le 0 ]; then echo 0; return; fi
    if [ "$_a" -gt $(( 9223372036854775807 / _b )) ]; then
        echo "9223372036854775807"
    else
        echo "$(( _a * _b ))"
    fi
}

period_is_point() {
    # «Чистая» календарная точка: буква+_T без кратности (D_T20, W_T5).
    # Составные (D3_T20 — окно с точкой-фазой) считаются ОКНАМИ (сброс через
    # N×длина; фаза-точка задаёт час/день старта: +N дней сохраняет его).
    case "$1" in
      [A-Z]_T*) return 0 ;;
      *) return 1 ;;
    esac
}

period_len() {
    # Длина цикла ОКНА в секундах: [N]<unit>; тупые единицы:
    # hour=3600, day=86400, week=604800, month=2592000 (30 дней).
    local _k="$1" _u="${1:0:1}" _n="${1%%_*}" _b=0
    case "$_u" in
      H) _b=3600 ;; D) _b=86400 ;; W) _b=604800 ;; M) _b=2592000 ;;
      *) echo 0; return 1 ;;
    esac
    _n="${_n#?}"; [ -z "$_n" ] && _n=1
    [ "$_n" = "0" ] && _n=1   # защита от D0/H0 (см. quota_period_key)
    echo $(( _b * _n ))
}

period_next() {
    # Следующая граница строго ПОСЛЕ ts. Окно: ts + длина. Точка: календарная
    # (TZ=QUOTA_TIMEZONE); переполнение точки («day30», «week9», «month35») —
    # конец единицы.
    local ts="$1" k="$2" u p cand d m0 uu
    if period_is_point "$k"; then
      u="${k:0:1}"; p="${k#*_T}"
      case "$u" in
        D) d=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%F)
           if [ "$p" -ge 24 ]; then
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d +1 day 00:00" +%s)
           else
             # Локальное время через date, а не m0+p*3600: в день DST-перехода
             # арифметика по эпохе съезжала на час (фикс аудита-5x5)
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d $(printf '%02d' "$p"):00" +%s)
             [ "$cand" -le "$ts" ] && cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d +1 day $(printf '%02d' "$p"):00" +%s)
           fi ;;
        W) d=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%F)
           uu=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%u)
           if [ "$p" -ge 8 ]; then
             # переполнение: понедельник следующей недели (00:00 локально)
             wd0=$(TZ="$QUOTA_TIMEZONE" date -d "$d -$((uu - 1)) days 00:00" +%s)
             cand=$(( wd0 + 7 * 86400 ))
             [ "$cand" -le "$ts" ] && cand=$(( cand + 7 * 86400 ))
           else
             # день p недели (1=пн..7=вс), локальная полночь
             delta=$(( ( p - uu + 7 ) % 7 ))
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d +$delta days 00:00" +%s)
             [ "$cand" -le "$ts" ] && cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d +$((delta + 7)) days 00:00" +%s)
           fi ;;
        M) local ym din tgt
           ym=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%Y-%m)
           din=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 +1 month -1 day" +%-d)
           tgt=$p; [ "$tgt" -gt "$din" ] && tgt=$din
           cand=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-$(printf '%02d' "$tgt") 00:00" +%s)
           if [ "$cand" -le "$ts" ]; then
             ym=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 +1 month" +%Y-%m)
             din=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 +1 month -1 day" +%-d)
             tgt=$p; [ "$tgt" -gt "$din" ] && tgt=$din
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-$(printf '%02d' "$tgt") 00:00" +%s)
           fi ;;
        *) cand=$(( ts + 1 )) ;;
      esac
      [ -z "$cand" ] && cand=$(( ts + 1 ))
      echo "$cand"
    else
      echo $(( ts + $(period_len "$k") ))
    fi
}

period_last() {
    # Последняя граница <= ts (календарно; для окон просто ts — сдвиг на
    # k×длина выполняет вызывающий код от старого reset_ts).
    local ts="$1" k="$2" u p cand d m0 uu
    if [[ "$k" == *_T* ]]; then
      u="${k:0:1}"; p="${k#*_T}"
      case "$u" in
        D) d=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%F)
           if [ "$p" -ge 24 ]; then
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d 00:00" +%s)
           else
             # локальное время через date (DST-переходы; фикс аудита-5x5)
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d $(printf '%02d' "$p"):00" +%s)
             [ "$cand" -gt "$ts" ] && cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d -1 day $(printf '%02d' "$p"):00" +%s)
           fi ;;
        W) d=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%F)
           uu=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%u)
           if [ "$p" -ge 8 ]; then
             wd0=$(TZ="$QUOTA_TIMEZONE" date -d "$d -$((uu - 1)) days 00:00" +%s)
             cand="$wd0"
             [ "$cand" -gt "$ts" ] && cand=$(( cand - 7 * 86400 ))
           else
             delta=$(( ( p - uu + 7 ) % 7 ))
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d -$(((7 - delta) % 7)) days 00:00" +%s)
             [ "$cand" -gt "$ts" ] && cand=$(TZ="$QUOTA_TIMEZONE" date -d "$d -$(((7 - delta) % 7) + 7) days 00:00" +%s)
           fi ;;
        M) local ym din tgt
           ym=$(TZ="$QUOTA_TIMEZONE" date -d "@$ts" +%Y-%m)
           din=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 +1 month -1 day" +%-d)
           tgt=$p; [ "$tgt" -gt "$din" ] && tgt=$din
           cand=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-$(printf '%02d' "$tgt") 00:00" +%s)
           if [ "$cand" -gt "$ts" ]; then
             ym=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 -1 day" +%Y-%m)
             din=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-01 +1 month -1 day" +%-d)
             tgt=$p; [ "$tgt" -gt "$din" ] && tgt=$din
             cand=$(TZ="$QUOTA_TIMEZONE" date -d "$ym-$(printf '%02d' "$tgt") 00:00" +%s)
           fi ;;
        *) cand="$ts" ;;
      esac
      [ -z "$cand" ] && cand="$ts"
      echo "$cand"
    else
      echo "$ts"
    fi
}

snapshot_spent() {
    # Израсходованность по счётчику xt_quota. Арг: set период НАПРАВЛЕНИЕ.
    # НАПРАВЛЕНИЕ: SRC (аплоад) | DST (даунлоад) | ALL (общий пул).
    # Для SEP читаем байты правила в SRC/DST-цепочке периода; для ALL —
    # счётчик единственного правила -m quota общей цепочки клиента.
    local _est="$1" _suf="$2" _dir="$3" _b=0 _allc
    case "$_est" in
      *_V4)
        if [ "$_dir" = "ALL" ]; then
          _allc=$(quota_all_name "$_est" "$_suf")
          _b=$(iptables -L "$_allc" -n -v -x 2>/dev/null | awk '$0 ~ /quota/ {print $2; exit}')
        else
          # index($0,s) — строковое вхождение, не regex: имя набора допускает
          # '.' (санитайзер tr -c 'A-Za-z0-9_.-'), а $0 ~ s трактовал бы
          # «A.B» как «A.B»-regex → мог прочитать чужой счётчик (фикс аудита).
          # Суффикс src/dst — граница имени: иначе имя-префикс другого набора
          # (клиенты a и a_V4) читал бы чужой счётчик (фикс аудита-5x5).
          _ank="dst"; [ "$_dir" = "SRC" ] && _ank="src"
          _b=$(iptables -L "QUOTA_${TUN_SAFE}_${_suf}_${_dir}" -n -v -x 2>/dev/null | awk -v s="$_est $_ank" 'index($0,s) {print $2; exit}')
        fi
        ;;
      *_V6)
        if [ "$_dir" = "ALL" ]; then
          _allc=$(quota_all_name "$_est" "$_suf")
          _b=$(ip6tables -L "$_allc" -n -v -x 2>/dev/null | awk '$0 ~ /quota/ {print $2; exit}')
        else
          _ank="dst"; [ "$_dir" = "SRC" ] && _ank="src"
          _b=$(ip6tables -L "QUOTA_${TUN_SAFE}_${_suf}_${_dir}" -n -v -x 2>/dev/null | awk -v s="$_est $_ank" 'index($0,s) {print $2; exit}')
        fi
        ;;
    esac
    echo "${_b:-0}"
}

quota_thr_pref_of() {
    # pref набора из журнала throttle (.thr: set|DIR|class|pref); пусто — не назначен
    # Имя набора экранируется: клиентские имена допускают '.' (regex-метасимвол;
    # фикс регресса: «msk.office» алиасил «mskXoffice» и крал его pref)
    local _set="$1" _dir="$2"
    local _qd="${QUOTA_DIR:-${SCRIPT_DIR%/}/.data/quota}" _se
    _se="$(printf '%s' "$_set" | sed 's/[][\.*^$+?()|{}]/\\&/g')"
    grep "^$_se|$_dir|" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null | cut -d'|' -f4 | head -1
}

quota_thr_pref_pick() {
    # pref для набора: свой из .thr (межпроходовая стабильность), иначе первый
    # свободный в 5..99 — диапазон НИЖЕ prio 100 per-subnet mirred лимитов
    # скорости (фикс аудита-5x5: префы ≥101 проигрывали лимитам на TUN).
    # Зачем свой pref: на nft-бэкенде `tc filter del` с u32-ключами сносит
    # ВЕСЬ prio (ключи игнорируются) — удаление по паттерну адреса выносило
    # чужие throttle-фильтры того же pref (проверено живьём: переживали только
    # фильтры последнего вооружённого набора). Свой pref делает удаление точным.
    local _set="$1"
    local _qd="${QUOTA_DIR:-${SCRIPT_DIR%/}/.data/quota}" _p _busy
    _p=$(quota_thr_pref_of "$_set" U)
    [ -n "$_p" ] || _p=$(quota_thr_pref_of "$_set" D)
    if [ -n "$_p" ]; then echo "$_p"; return 0; fi
    _p=5
    while [ "$_p" -lt 100 ]; do
      _busy=$(grep -E "^[^|]+\|[UD]\|[0-9a-f]+\|$_p$" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null | head -1)
      [ -z "$_busy" ] && { echo "$_p"; return 0; }
      _p=$(( _p + 1 ))
    done
    echo ""
}

quota_period_thr() {
    # Вооружённость ПЕРИОДА набора: "armed|tu|td" — armed=1 если период
    # исчерпан И у него положительный throttle (tu>0 или td>0); tu/td —
    # скорости сторон ЭТОГО периода (THR_MAP). Per-period вооружённость нужна
    # хвостам DROP: исчерпание throttle-периода не должно снимать строгий
    # DROP no-throttle периода того же клиента (фикс волны-2 аудита).
    local _s="$1" _p="$2" _a _m _u _d
    _a="${THR_PERIOD[$_s|$_p]:-0}"
    _m="${THR_MAP[$_s|$_p]:-0}"
    _u=0; _d=0
    if [ -n "$_m" ] && [ "$_m" != "0" ]; then
      _u="${_m#*|}"; _u="${_u%%|*}"
      _d="${_m##*|}"
    fi
    echo "$_a|$_u|$_d"
}

quota_throttle_on() {
    # Послеквотный лимит клиенту (БЕЗ марок: совместимо с WARP и всем остальным).
    # Реализация e2e-проверена (аудит-2026-09): прежняя схема «mirred egress
    # redirect в ifb_<tun>_mix» НЕ работала — download зацикливался (egress TUN →
    # ifb → стек → снова egress TUN), а upload возвращался в стек с интерфейсом
    # ifb_* и все правила с «-i TUN» (квоты, пробросы) переставали матчить.
    # Новая схема:
    #   download (к клиенту) — HTB-класс на root qdisc САМОГО TUN (egress):
    #     flowid-фильтры по dst адресам клиента; интерфейс не меняется.
    #   upload (от клиента) — police на ingress qdisc TUN по src адресам
    #     (отброс сверх скорости); интерфейс не меняется.
    # Арг: set upRate downRate v4blk v6blk iface
    #   upRate==downRate>0 — одинаковая скорость на оба направления;
    #   upRate>0,downRate==0 — только аплоад (клиент шлёт);
    #   downRate>0,upRate==0 — только даунлоад (клиенту);
    #   оба>0 и разные — разные скорости.
    # Фильтры ставятся на СВОЙ pref набора (см. quota_thr_pref_pick) — иначе
    # удаление по ключам на nft-бэкенде выносит чужие фильтры того же pref.
    local _set="$1" _ur="${2:-0}" _dr="${3:-0}" _v4="${4:-}" _v6="${5:-}" _ifc="$6"
    local _cxh _ux _dx p m _tp
    local _qd="${QUOTA_DIR:-${SCRIPT_DIR%/}/.data/quota}"
    [ -z "$_ifc" ] && return 0
    [ "$_ur" -gt 0 ] || [ "$_dr" -gt 0 ] || return 0
    # pref выбираем ДО off(): журнал ещё содержит СВОЮ запись → возвращается
    # стабильный pref (pick-после-off выдавал бы наименьший свободный каждый
    # проход; фикс аудита-5x5). Пустой pref (пул исчерпан) → отказ от
    # вооружения с предупреждением — безопаснее, чем коллизия pref.
    _tp=$(quota_thr_pref_pick "$_set")
    [ -n "$_tp" ] || { echo "⚠️ quota_throttle_on: нет свободного pref (пул 5..99 исчерпан) — throttle пропущен, остаётся строгий DROP" >&2; return 1; }
    quota_throttle_off "$_set" "$_ifc" "$_v4" "$_v6"
    # Корень TUN: HTB (для классов download). Если root — prio/noqueue —
    # заменяем на HTB 1:. (При активных лимитах root уже htb — только
    # добавляем классы.) default 1 + класс 1:1 — «безлимит по умолчанию»:
    # иначе неклассифицированный download (другие клиенты) дропался бы
    # (htb без default = dropout; фикс аудита e2e-2026-09).
    if ! tc qdisc show dev "$_ifc" 2>/dev/null | grep -qE 'qdisc htb [0-9a-f]*: root'; then
      tc qdisc del dev "$_ifc" root 2>/dev/null || true
      tc qdisc add dev "$_ifc" root handle 1: htb default 1 2>/dev/null || true
      tc class add dev "$_ifc" parent 1: classid 1:1 htb rate 10gbit ceil 10gbit quantum 65535 2>/dev/null || true
    else
      # htb уже есть: гарантируем default != 0 и класс 1:1 (безлимит-фолбэк)
      tc class add dev "$_ifc" parent 1: classid 1:1 htb rate 10gbit ceil 10gbit quantum 65535 2>/dev/null || true
    fi
    tc qdisc show dev "$_ifc" 2>/dev/null | grep -q 'ingress' || tc qdisc add dev "$_ifc" handle ffff: ingress 2>/dev/null || true
    _next_cid() {
      # свободный leaf-класс в верхней зоне (1:F000..1:FFFF — вне основных)
      local _cid=61440 _h="f000"
      while [ "$_cid" -lt 65534 ] && tc class show dev "$_ifc" 2>/dev/null | grep -q "class htb 1:${_h} "; do
        _cid=$(( _cid + 1 ))
        _h=$(printf '%x' "$_cid")
      done
      echo "$_cid"
    }
    if [ "$_ur" -gt 0 ] && [ "$_dr" -gt 0 ] && [ "$_ur" -eq "$_dr" ]; then
      # Один класс на оба направления: download-класс + upload-police той же ставкой
      _cxh=$(printf '%x' "$(_next_cid)")
      tc class add dev "$_ifc" parent 1: classid "1:$_cxh" htb rate "${_ur}bit" ceil "${_ur}bit" quantum 3000 2>/dev/null || true
      for _a in $(echo "${_v4:-}" | tr ',' ' '); do
        [ -z "$_a" ] && continue
        p=$(echo "$_a" | cut -d'/' -f1); m=$(echo "$_a" | cut -d'/' -f2); [ -z "$m" ] && m=32
        tc filter add dev "$_ifc" parent 1: protocol ip pref "$_tp" u32 match ip dst "$p/$m" flowid "1:$_cxh" 2>/dev/null || true
        tc filter add dev "$_ifc" parent ffff: protocol ip pref "$_tp" u32 match ip src "$p/$m" action police rate "${_ur}bit" burst 32768 conform-exceed drop/ok 2>/dev/null || true
      done
      for _a in $(echo "${_v6:-}" | tr ',' ' '); do
        [ -z "$_a" ] && continue
        p=$(echo "$_a" | cut -d'/' -f1); m=$(echo "$_a" | cut -d'/' -f2); [ -z "$m" ] && m=128
        tc filter add dev "$_ifc" parent 1: protocol ipv6 pref "$_tp" u32 match ip6 dst "$p/$m" flowid "1:$_cxh" 2>/dev/null || true
        tc filter add dev "$_ifc" parent ffff: protocol ipv6 pref "$_tp" u32 match ip6 src "$p/$m" action police rate "${_ur}bit" burst 32768 conform-exceed drop/ok 2>/dev/null || true
      done
      echo "$_set|U|$_cxh|$_tp" >> "${_qd}/${TUN_SAFE}.thr" 2>/dev/null
      echo "$_set|D|$_cxh|$_tp" >> "${_qd}/${TUN_SAFE}.thr" 2>/dev/null
      # Проверка фактического вооружения ПО СТОРОНАМ (фикс волны-2 + регресс):
      # суммарный счётчик позволял «вооружиться» при вставленной только одной
      # стороне (police не встал — нет ingress qdisc) — upload/ download без
      # ограничения при снятом DROP-хвосте. Нужны ОБЕ стороны.
      _fc1=$(tc filter show dev "$_ifc" parent 1: 2>/dev/null | grep -cE "pref $_tp ")
      _fcf=$(tc filter show dev "$_ifc" parent ffff: 2>/dev/null | grep -cE "pref $_tp ")
      if [ "$_fc1" -le 0 ] || [ "$_fcf" -le 0 ]; then
        echo "⚠️ quota_throttle_on: фильтры встали неполностью (pref $_tp: 1:=$_fc1 ffff:=$_fcf) — throttle не вооружён" >&2
        return 1
      fi
    else
      # Раздельно: U — upload-police (по src), D — download-класс (по dst)
      _ux=""; _dx=""
      if [ "$_ur" -gt 0 ]; then
        _ux=$(printf '%x' "$(_next_cid)")
        # Только-upload: класс материализуем, чтобы id был занят в ядре —
        # иначе следующий набор прохода получил бы тот же id и его класс был
        # удалён off() этого набора (фикс аудита-5x5)
        if [ "$_dr" -eq 0 ]; then
          tc class add dev "$_ifc" parent 1: classid "1:$_ux" htb rate "${_ur}bit" ceil "${_ur}bit" quantum 3000 2>/dev/null || true
        fi
      fi
      if [ "$_dr" -gt 0 ]; then
        _dx=$(printf '%x' "$(_next_cid)")
        tc class add dev "$_ifc" parent 1: classid "1:$_dx" htb rate "${_dr}bit" ceil "${_dr}bit" quantum 3000 2>/dev/null || true
      fi
      for _a in $(echo "${_v4:-}" | tr ',' ' '); do
        [ -z "$_a" ] && continue
        p=$(echo "$_a" | cut -d'/' -f1); m=$(echo "$_a" | cut -d'/' -f2); [ -z "$m" ] && m=32
        [ -n "$_dx" ] && tc filter add dev "$_ifc" parent 1: protocol ip pref "$_tp" u32 match ip dst "$p/$m" flowid "1:$_dx" 2>/dev/null || true
        [ -n "$_ux" ] && tc filter add dev "$_ifc" parent ffff: protocol ip pref "$_tp" u32 match ip src "$p/$m" action police rate "${_ur}bit" burst 32768 conform-exceed drop/ok 2>/dev/null || true
      done
      for _a in $(echo "${_v6:-}" | tr ',' ' '); do
        [ -z "$_a" ] && continue
        p=$(echo "$_a" | cut -d'/' -f1); m=$(echo "$_a" | cut -d'/' -f2); [ -z "$m" ] && m=128
        [ -n "$_dx" ] && tc filter add dev "$_ifc" parent 1: protocol ipv6 pref "$_tp" u32 match ip6 dst "$p/$m" flowid "1:$_dx" 2>/dev/null || true
        [ -n "$_ux" ] && tc filter add dev "$_ifc" parent ffff: protocol ipv6 pref "$_tp" u32 match ip6 src "$p/$m" action police rate "${_ur}bit" burst 32768 conform-exceed drop/ok 2>/dev/null || true
      done
      [ -n "$_ux" ] && echo "$_set|U|$_ux|$_tp" >> "${_qd}/${TUN_SAFE}.thr" 2>/dev/null
      [ -n "$_dx" ] && echo "$_set|D|$_dx|$_tp" >> "${_qd}/${TUN_SAFE}.thr" 2>/dev/null
      # Проверка фактического вооружения по сторонам (см. combined-ветку)
      _fc1=$(tc filter show dev "$_ifc" parent 1: 2>/dev/null | grep -cE "pref $_tp ")
      _fcf=$(tc filter show dev "$_ifc" parent ffff: 2>/dev/null | grep -cE "pref $_tp ")
      { [ -n "$_dx" ] && [ "$_fc1" -le 0 ]; } && { echo "⚠️ quota_throttle_on: download-фильтры не встали (pref $_tp)" >&2; return 1; }
      { [ -n "$_ux" ] && [ "$_fcf" -le 0 ]; } && { echo "⚠️ quota_throttle_on: upload-фильтры не встали (pref $_tp)" >&2; return 1; }
    fi
}

quota_throttle_off() {
    # Выключить: удалить police-фильтры (upload) и flowid-фильтры+класс
    # (download) СВОЕГО pref набора (см. quota_thr_pref_pick; на nft-бэкенде
    # tc filter del с u32-ключами сносит весь prio — чужие фильтры того же
    # pref; фикс аудита-e2e), затем .thr-записи клиента. Для старых .thr без
    # pref — фолбэк на удаление по адресному паттерну.
    local _set="$1" _ifc="$2" _v4="${3:-}" _v6="${4:-}" p m _u="" _d="" _cl _tp
    local _qd="${QUOTA_DIR:-${SCRIPT_DIR%/}/.data/quota}"
    [ -z "$_ifc" ] && return 0
    # Экранирование имени набора ('.' в клиентских именах; фикс регресса)
    _se="$(printf '%s' "$_set" | sed 's/[][\.*^$+?()|{}]/\\&/g')"
    _u=$(grep "^$_se|U|" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null | cut -d'|' -f3 | head -1)
    _d=$(grep "^$_se|D|" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null | cut -d'|' -f3 | head -1)
    _tp=$(quota_thr_pref_of "$_set" U)
    [ -n "$_tp" ] || _tp=$(quota_thr_pref_of "$_set" D)
    if [ -n "$_tp" ]; then
      # Свой pref набора: удаляем весь pref (это ТОЛЬКО наши фильтры)
      tc filter del dev "$_ifc" parent 1: protocol ip pref "$_tp" 2>/dev/null || true
      tc filter del dev "$_ifc" parent ffff: protocol ip pref "$_tp" 2>/dev/null || true
      tc filter del dev "$_ifc" parent 1: protocol ipv6 pref "$_tp" 2>/dev/null || true
      tc filter del dev "$_ifc" parent ffff: protocol ipv6 pref "$_tp" 2>/dev/null || true
    elif grep -qE "^${_se}\|[UD]\|[0-9a-f]*$" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null; then
      # Legacy .thr (3 поля, дофиксовый формат): тот код ставил pref 5
      # фиксированно — сносим pref 5 целиком (миграция; шаблонные удаления
      # по ключам на nft-бэкенде всё равно сносят весь pref, а адресные
      # паттерны здесь не нужны).
      tc filter del dev "$_ifc" parent 1: protocol ip pref 5 2>/dev/null || true
      tc filter del dev "$_ifc" parent ffff: protocol ip pref 5 2>/dev/null || true
      tc filter del dev "$_ifc" parent 1: protocol ipv6 pref 5 2>/dev/null || true
      tc filter del dev "$_ifc" parent ffff: protocol ipv6 pref 5 2>/dev/null || true
    fi
    for _cl in "$_u" "$_d"; do
      [ -n "$_cl" ] || continue
      tc class del dev "$_ifc" classid "1:$_cl" 2>/dev/null || true
    done
    sed -i "/^$_se|/d" "${_qd}/${TUN_SAFE}.thr" 2>/dev/null || true
}

quota_rule_parse() {
    # Парсер правила квоты: "подсети : [up][:down] : срок : [throttle..]".
    # Период — первое поле с единицей времени; объёмы — 1-2 поля перед ним;
    # throttle — 0-2 поля после; подсети — ВСЁ до объёмов (может содержать ':',
    # IPv6!). Вывод: "SUBS|MODE|upVol|downVol|periodKey|thrMode|thrUp|thrDown"
    local _r="$1" _k _mode upv downv tmode tup tdn _subs
    local -a _fa=()
    IFS=':' read -ra _fa <<< "$_r"
    local n=${#_fa[@]} i pi=-1 f
    for ((i=0;i<n;i++)); do
      case "${_fa[$i]}" in
        *hour*|*day*|*week*|*month*) pi=$i; break ;;
        # Новый стиль ключей: D3_T20/W_T5/M_T15/D_T24/D3/D (фикс аудита-5x5:
        # раньше молча игнорировались — квота не строилась вовсе)
        [HDWM]*) if [[ "${_fa[$i]}" =~ ^[HDWM]([0-9]*)(_T[0-9]+)?$ ]]; then pi=$i; break; fi ;;
      esac
    done
    [ "$pi" -lt 0 ] && { echo "N|N|0|0|N|0|0|0"; return 0; }
    _k=$(quota_period_key "${_fa[$pi]}")
    [ "$_k" = "N" ] && { echo "N|N|0|0|N|0|0|0"; return 0; }
    # throttle справа (0..2 непустых)
    declare -a _R=()
    for ((i=pi+1;i<n;i++)); do [ -n "${_fa[$i]}" ] && _R+=("${_fa[$i]}"); done
    if [ "${#_R[@]}" -gt 2 ]; then echo "N|N|0|0|N|0|0|0"; return 0; fi
    # объёмы слева (1..2, числовые с суффиксом); _L[0]=ближний к периоду
    declare -a _L=()
    for ((i=pi-1; i>=0 && ${#_L[@]}<2; i--)); do
      f="${_fa[$i]}"
      if [[ "$f" =~ ^[0-9]+$ || "$f" =~ ^[0-9]+[bkmgtBKMGT]$ ]]; then _L+=("$f"); else break; fi
    done
    local nl=${#_L[@]}
    if [ "$nl" -lt 1 ]; then echo "N|N|0|0|N|0|0|0"; return 0; fi
    if [ "$nl" -eq 2 ]; then
      _mode="SEP"; upv=$(quota_value_bytes "${_L[1]}"); downv=$(quota_value_bytes "${_L[0]}")
    else
      _mode="ALL"; upv=$(quota_value_bytes "${_L[0]}"); downv=0
      if [ "$upv" -le 0 ]; then echo "N|N|0|0|N|0|0|0"; return 0; fi
    fi
    # подсети: сегменты до первого объёма, склеенные ':' (ПУСТЫЕ сегменты
    # сохраняем — IPv6 '::' режется по ':' на пустые, их пропуск ломал v6:
    # fd00::/104 → fd00:/104 и весь v6-план молча исчезал)
    local firstvol=$(( pi - nl ))
    if [ "$firstvol" -lt 1 ]; then echo "N|N|0|0|N|0|0|0"; return 0; fi
    _subs=""
    for ((i=0;i<firstvol;i++)); do
      [ "$i" -gt 0 ] && _subs="$_subs:"
      _subs="$_subs${_fa[$i]}"
    done
    tmode=0; tup=0; tdn=0
    local nr=${#_R[@]}
    if [ "$nr" -eq 1 ]; then
      tmode=1; tup=$(quota_throttle_bits "${_R[0]}"); tdn=0
    elif [ "$nr" -eq 2 ]; then
      tmode=2; tup=$(quota_throttle_bits "${_R[0]}"); tdn=$(quota_throttle_bits "${_R[1]}")
    fi
    echo "$_subs|$_mode|$upv|$downv|$_k|$tmode|$tup|$tdn"
}

quota_period_key() {
    # Разбор строки периода → ключ (H/D/W/M + кратность/точка); N если невалидно.
    # Строгие проверки: префикс/суффикс — только цифры; суффикс у hour — ошибка.
    local _per="$1" _plet="" _pre _punit _suf _pN _ppt
    # Новый стиль ключей напрямую: D3_T20 / W_T5 / M_T15 / D_T24 / D_T20 / D3 / D
    # (фикс аудита-5x5: список форматов из README теперь парсится, а не молча
    # отбрасывается).
    if [[ "$_per" =~ ^([HDWM])([0-9]*)(_T([0-9]+))?$ ]]; then
      # Кратность 0 (D0/H0) и точка 0 (D_T0) невалидны: period_len(D0)=0 давал
      # «всегда истёкший» период — квота сбрасывалась каждый час (bypass по
      # опечатке; фикс волны-2 аудита).
      if [ "${BASH_REMATCH[2]}" = "0" ] || [ "${BASH_REMATCH[4]}" = "0" ]; then echo "N"; return 1; fi
      _plet="${BASH_REMATCH[1]}"
      if [ -n "${BASH_REMATCH[2]}" ]; then _plet="${_plet}$((10#${BASH_REMATCH[2]}))"; fi
      if [ -n "${BASH_REMATCH[4]}" ]; then _plet="${_plet}_T$((10#${BASH_REMATCH[4]}))"; fi
      # H-точка с суффиксом — как и в legacy-ветке: час не имеет «точки»
      if [ "${BASH_REMATCH[1]}" = "H" ] && [ -n "${BASH_REMATCH[4]}" ]; then echo "N"; return 1; fi
      echo "$_plet"
      return 0
    fi
    _pre="${_per%%[A-Za-z]*}"
    case "$_pre" in
      *[!0-9]*) [ -n "$_pre" ] && { echo "N"; return 1; } ;;
    esac
    if [ -n "$_pre" ]; then _punit="${_per#"$_pre"}"; else _punit="$_per"; fi
    _punit="${_punit%%[0-9]*}"
    _suf="${_per#"$_pre$_punit"}"
    case "$_suf" in
      *[!0-9]*) [ -n "$_suf" ] && { echo "N"; return 1; } ;;
    esac
    _pN="$_pre"; _ppt="$_suf"
    case "$_punit" in
      hour) _plet=H; [ -n "$_ppt" ] && { echo "N"; return 1; } ;;
      day) _plet=D ;;
      week) _plet=W ;;
      month) _plet=M ;;
      *) echo "N"; return 1 ;;
    esac
    # нормализация к десятичным (ведущие нули: 08day/08 не должны читаться как 8-ричные)
    local _pn10=0 _pt10=0
    [ -n "$_pN" ] && _pn10=$((10#$_pN))
    [ -n "$_ppt" ] && _pt10=$((10#$_ppt))
    if [ -n "$_ppt" ]; then
      if [ -n "$_pN" ]; then _plet="${_plet}${_pn10}_T${_pt10}"; else _plet="${_plet}_T${_pt10}"; fi
    elif [ -n "$_pN" ] && [ "$_pn10" -gt 1 ]; then
      _plet="${_plet}${_pn10}"
    fi
    echo "$_plet"
}

quota_client_plan() {
    # План квоты клиента: $1 — v4-блок, $2 — v6-блок. Вывод — строки
    # "КЛЮЧ MODE v4u v4d v6u v6d thrMode thrUp thrDown" по ВСЕМ совпавшим
    # правилам (НАЛОЖЕНИЕ периодов; первый на период-ключ).
    # MODE: ALL (общий пул) | SEP (раздельно up/down); thrMode 0|1|2.
    local _v4="$1" _v6="$2" _ip4 _ip6 _r _rp _subs _rest _mode upv downv _k tmode tup tdn
    local _w4 _w6 _rsub _s2 _dupe _pp _found
    _ip4="${_v4%%/*}"; _ip6="${_v6%%/*}"
    local -a _seen=()
    _found=0
    for _r in "${TRAFFIC_QUOTAS[@]}"; do
      _rp=$(quota_rule_parse "$_r")
      _subs="${_rp%%|*}"; _rest="${_rp#*|}"
      [ "$_subs" = "N" ] && continue
      _mode="${_rest%%|*}"; _rest="${_rest#*|}"
      upv="${_rest%%|*}"; _rest="${_rest#*|}"
      downv="${_rest%%|*}"; _rest="${_rest#*|}"
      _k="${_rest%%|*}"; _rest="${_rest#*|}"
      tmode="${_rest%%|*}"; _rest="${_rest#*|}"
      tup="${_rest%%|*}"; _rest="${_rest#*|}"
      tdn="${_rest%%|*}"
      _w4=0; _w6=0
      if [ -n "$_v4" ]; then
        IFS=',' read -ra _rsub <<< "$_subs"
        for _s2 in "${_rsub[@]}"; do
          _s2="$(echo "$_s2" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
          [[ "$_s2" == *:* ]] && continue
          if net_contains_ip "$_s2" "$_ip4"; then _w4=$(( $(net_count_addrs "$_v4") )); break; fi
        done
      fi
      if [ -n "$_v6" ]; then
        IFS=',' read -ra _rsub <<< "$_subs"
        for _s2 in "${_rsub[@]}"; do
          _s2="$(echo "$_s2" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
          [[ "$_s2" == *:* ]] || continue
          if net_contains_ip "$_s2" "$_ip6"; then _w6=$(( $(net_count_addrs "$_v6") )); break; fi
        done
      fi
      if [ "$_w4" -gt 0 ] || [ "$_w6" -gt 0 ]; then
        _dupe=""
        for _pp in "${_seen[@]}"; do [ "$_pp" = "$_k" ] && _dupe=1 && break; done
        if [ -z "$_dupe" ]; then
          _seen+=("$_k")
          if [ "$_mode" = "SEP" ]; then
            echo "$_k SEP $(quota_mul_sat "$upv" "$_w4") $(quota_mul_sat "$downv" "$_w4") $(quota_mul_sat "$upv" "$_w6") $(quota_mul_sat "$downv" "$_w6") $tmode $tup $tdn"
          else
            echo "$_k ALL $(quota_mul_sat "$upv" "$_w4") $(quota_mul_sat "$upv" "$_w4") $(quota_mul_sat "$upv" "$_w6") $(quota_mul_sat "$upv" "$_w6") $tmode $tup $tdn"
          fi
          _found=1
        fi
      fi
    done
    [ "$_found" = "0" ] && echo "N N 0 0 0 0 0 0 0"
}

quota_all_name() {
    # Имя ОБЩЕЙ (ALL) цепочки клиента для периода: Q_<tun>_<клиент>_<период>_A.
    # $1 = set-имя (Q_<tun>_<клиент>_V4/V6), $2 = periodKey. Имена цепочек
    # iptables ≤ 28 символов: при переполнении клиента ужимаем (начало + md5).
    # Детерминированно — snapshot/rebuild восстанавливают то же имя.
    # Суффикс 6 hex (24 бита; фикс волны-2 аудита: 4 hex давали ~1/65k коллизию
    # имён при длинных общих префиксах — два клиента делили бы квоту/throttle).
    local _set="$1" _per="$2" _tn _cn _base _room _keep
    _tn="${_set#Q_}"; _tn="${_tn%%_*}"
    _cn="${_set#Q_${_tn}_}"; _cn="${_cn%_V4}"; _cn="${_cn%_V6}"
    _base="Q_${_tn}_${_cn}_${_per}_A"
    if [ ${#_base} -gt 28 ]; then
      _room=$(( 28 - ${#_tn} - ${#_per} - 8 ))   # "Q_", "_", "_A" + 6-хэш
      [ "$_room" -lt 5 ] && _room=5
      _keep=$(( _room - 6 )); [ "$_keep" -lt 1 ] && _keep=1
      _cn="$(printf '%s' "$_cn" | cut -c1-$_keep)$(printf '%s' "$_cn" | md5sum | cut -c1-6)"
      _base="Q_${_tn}_${_cn}_${_per}_A"
    fi
    echo "$_base"
}

# === Конец Bash Helpers ===


# ================================================================
# === ПРОВЕРОЧНЫЙ СКРИПТ (запускается при прямом вызове bash) ===
# ================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] || [[ -n "$AWG_CHECK_MODE" ]]; then
  # --- Настройка логирования ---
  SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
  LOG_DIR="$SCRIPT_DIR/.data/log"
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  LOG_FILE="$LOG_DIR/${TUN}.log"
  
  # Логирование включается если TESTLOG=1
  if [ "$TESTLOG" = "1" ]; then
    exec 1> >(tee "$LOG_FILE")
    exec 2>&1
  fi

  echo "═══════════════════════════════════════════════════════════"
  echo "🔍 Проверка правил для интерфейса: $TUN ($(date '+%Y-%m-%d %H:%M:%S'))"
  echo "═══════════════════════════════════════════════════════════"
  echo ""

  # "Безопасное" имя туннеля для суффиксов
  TUN_SAFE=$(safe_tun_name "$TUN")

  # Вычисляем MARK_BASE (так же как в up.sh)
  MARK_BASE=$(calc_mark_base "$TUN")

  # Суффиксированные имена цепочек
  PF_CHAIN_NAT="PORT_FORWARD_NAT_${TUN_SAFE}"
  PF_CHAIN_FILTER="PORT_FORWARD_FILTER_${TUN_SAFE}"
  PF_CHAIN_SNAT="PORT_FORWARD_SNAT_${TUN_SAFE}"
  RANDOM_WARP_CHAIN="RANDOM_WARP_${TUN_SAFE}"
  INPUT_CHAIN="INPUT_${TUN_SAFE}"
  HAIRPIN_CHAIN="HAIRPIN_${TUN_SAFE}"

  # --- Парсинг LOCAL_SUBNETS на IPv4 и IPv6 (точно как в up.sh) ---
  parse_local_subnets

  # --- Вычисление BROADCAST_ADDR (только из IPv4, как в up.sh) ---
  BROADCAST_ADDR=""
  if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
    BROADCAST_ADDR=$(get_broadcast_addr "$LOCAL_SUBNETS_IPV4")
  fi

  # --- 1. INPUT цепочка (IPv4 + IPv6) ---
  echo "📥 INPUT цепочка ($INPUT_CHAIN):"
  echo "   Порт: $PORT/UDP"
  echo "   IPv4 правила:"
  iptables -t filter -L "$INPUT_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6 правила:"
  ip6tables -t filter -L "$INPUT_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  # --- 1.1. DDoS проверка hashlimit статистики ---
  echo "🛡️  DDoS защита:"
  echo "   Rate limit AWG порт ($PORT/UDP):"
  echo "   IPv4:"
  iptables -t filter -L "$INPUT_CHAIN" -n -v 2>/dev/null | grep -E "hashlimit|DROP.*$PORT" | head -6 || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t filter -L "$INPUT_CHAIN" -n -v 2>/dev/null | grep -E "hashlimit|DROP.*$PORT" | head -6 || echo "     (нет правил)"
  echo "   Per-port DDOS (PORT_FORWARDING_DDOS):"
  if [ ${#PORT_FORWARDING_DDOS[@]} -gt 0 ]; then
    for _de in "${PORT_FORWARDING_DDOS[@]}"; do
      echo "     • $_de"
    done
  else
    echo "     (не настроено)"
  fi
  echo "   Правила PF_CHAIN_FILTER (hashlimit/connlimit/DROP):"
  echo "   IPv4:"
  iptables -t filter -L "$PF_CHAIN_FILTER" -n -v 2>/dev/null | grep -E "hashlimit|connlimit|DROP" | head -10 || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t filter -L "$PF_CHAIN_FILTER" -n -v 2>/dev/null | grep -E "hashlimit|connlimit|DROP" | head -10 || echo "     (нет правил)"
  echo ""

  # --- 2. FORWARD цепочки (IPv4 + IPv6) ---
  echo "🔄 FORWARD цепочки:"
  echo "   Hairpin NAT ($HAIRPIN_CHAIN):"
  echo "   IPv4:"
  iptables -t nat -L "$HAIRPIN_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6:"
  ip6tables -t nat -L "$HAIRPIN_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  echo "   Проброс портов (NAT: $PF_CHAIN_NAT):"
  echo "   IPv4:"
  iptables -t nat -L "$PF_CHAIN_NAT" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6:"
  ip6tables -t nat -L "$PF_CHAIN_NAT" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  echo "   Проброс портов (FILTER: $PF_CHAIN_FILTER):"
  echo "   IPv4:"
  iptables -t filter -L "$PF_CHAIN_FILTER" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6:"
  ip6tables -t filter -L "$PF_CHAIN_FILTER" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  echo "   Проброс портов (SNAT: $PF_CHAIN_SNAT):"
  echo "   IPv4:"
  iptables -t nat -L "$PF_CHAIN_SNAT" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6:"
  ip6tables -t nat -L "$PF_CHAIN_SNAT" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  echo "   Random WARP ($RANDOM_WARP_CHAIN):"
  echo "   IPv4:"
  iptables -t mangle -L "$RANDOM_WARP_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo "   IPv6:"
  ip6tables -t mangle -L "$RANDOM_WARP_CHAIN" -n -v 2>/dev/null || echo "   ❌ Цепочка не найдена"
  echo ""

  # --- 2.1. Общие правила PREROUTING и FORWARD ---
  echo "🔗 Общие правила (ссылки на цепочки):"
  echo "   PREROUTING → $RANDOM_WARP_CHAIN (WARP маркировка):"
  echo "   IPv4:"
  iptables -t mangle -L PREROUTING -n -v 2>/dev/null | grep -E "$RANDOM_WARP_CHAIN" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t mangle -L PREROUTING -n -v 2>/dev/null | grep -E "$RANDOM_WARP_CHAIN" || echo "     (нет правил)"
  echo "   PREROUTING → $PF_CHAIN_NAT (проброс портов NAT):"
  echo "   IPv4:"
  iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep -E "$PF_CHAIN_NAT" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t nat -L PREROUTING -n -v 2>/dev/null | grep -E "$PF_CHAIN_NAT" || echo "     (нет правил)"
  echo "   FORWARD → $PF_CHAIN_FILTER (проброс портов FILTER):"
  echo "   IPv4:"
  iptables -t filter -L FORWARD -n -v 2>/dev/null | grep -E "$PF_CHAIN_FILTER" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t filter -L FORWARD -n -v 2>/dev/null | grep -E "$PF_CHAIN_FILTER" || echo "     (нет правил)"
  echo "   POSTROUTING → $PF_CHAIN_SNAT (проброс портов SNAT):"
  echo "   IPv4:"
  iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "$PF_CHAIN_SNAT" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "$PF_CHAIN_SNAT" || echo "     (нет правил)"
  echo "   POSTROUTING → $HAIRPIN_CHAIN (Hairpin NAT):"
  echo "   IPv4:"
  iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "$HAIRPIN_CHAIN" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "$HAIRPIN_CHAIN" || echo "     (нет правил)"
  echo "   INPUT → $INPUT_CHAIN (вход):"
  echo "   IPv4:"
  iptables -t filter -L INPUT -n -v 2>/dev/null | grep -E "$INPUT_CHAIN" || echo "     (нет правил)"
  echo "   IPv6:"
  ip6tables -t filter -L INPUT -n -v 2>/dev/null | grep -E "$INPUT_CHAIN" || echo "     (нет правил)"
  echo ""

  # --- 3. Таблицы маршрутизации и ip rule ---
  echo "📊 Маршрутизация (ip rule + ip route):"
  echo "   Таблицы для $TUN:"
  if [ -f /etc/iproute2/rt_tables ]; then
    grep -E "^[0-9]+[[:space:]]+.*${TUN}" /etc/iproute2/rt_tables 2>/dev/null || echo "   (нет таблиц)"
  fi
  echo ""
  echo "   ip rule (fwmark → table):"
  # MARK_BASE используется для WARP маркировки (CONNMARK) и ip rule
  # Проверяем все диапазоны через helper функцию
  check_ip_rules "$MARK_BASE"
  echo ""
  echo "   Маршруты по таблицам WARP:"
  for warp_entry in "${WARP_LIST[@]}"; do
    if [ "$warp_entry" != "none" ] && [ -n "$warp_entry" ]; then
      warp_iface=$(echo "$warp_entry" | cut -d'=' -f1 | sed 's/[[:space:]]//g')
      if [[ "$warp_iface" != *","* ]]; then
        # Одиночный интерфейс
        table_id=$(grep -E "^[0-9]+[[:space:]]+${warp_iface}$" /etc/iproute2/rt_tables 2>/dev/null | cut -d' ' -f1)
        if [ -n "$table_id" ]; then
          echo "   $warp_iface (table $table_id):"
          echo "     IPv4:"
          ip route show table "$table_id" 2>/dev/null | head -5 || echo "     (нет маршрутов)"
          echo "     IPv6:"
          ip -6 route show table "$table_id" 2>/dev/null | head -5 || echo "     (нет маршрутов)"
        fi
      fi
    fi
  done
  echo ""

  # --- 4. IFB устройства и tc ---
  echo "🚦 Лимиты скорости (tc + IFB):"
  IFB_IN="ifb_${TUN_SAFE}_in"
  IFB_OUT="ifb_${TUN_SAFE}_out"
  IFB_MIX="ifb_${TUN_SAFE}_mix"
  echo "   IFB устройства:"
  if ip link show "$IFB_IN" &>/dev/null; then
    echo "   ✅ $IFB_IN активен"
    ip -br link show "$IFB_IN" 2>/dev/null
  else
    echo "   ❌ $IFB_IN не найден"
  fi
  if ip link show "$IFB_OUT" &>/dev/null; then
    echo "   ✅ $IFB_OUT активен"
    ip -br link show "$IFB_OUT" 2>/dev/null
  else
    echo "   ❌ $IFB_OUT не найден"
  fi
  if ip link show "$IFB_MIX" &>/dev/null; then
    echo "   ✅ $IFB_MIX активен"
    ip -br link show "$IFB_MIX" 2>/dev/null
  else
    echo "   ❌ $IFB_MIX не найден"
  fi
  echo ""
  
  # Проверка tc фильтров на TUN (перенаправление на IFB)

  # Проверка фильтров на root 1: (маршрутизация в мосты)
  echo "   🔍 Фильтры на root 1: (маршрутизация в мосты):"
  for _ifb_check in "$IFB_MIX" "$IFB_OUT" "$IFB_IN"; do
    if ip link show "$_ifb_check" &>/dev/null; then
      root_filter_count=$(tc filter show dev "$_ifb_check" parent 1: 2>/dev/null | grep -c "flowid")
      root_filter_count=${root_filter_count:-0}
      if [ "$root_filter_count" -gt 0 ]; then
        echo "   ✅ $_ifb_check: найдено $root_filter_count фильтров на root 1:"
        tc filter show dev "$_ifb_check" parent 1: 2>/dev/null | grep -E "match|flowid" | head -10
      else
        echo "   ❌ $_ifb_check: фильтры на root 1: НЕ созданы!"
      fi
    fi
  done
  echo ""
  echo "   🔍 Фильтры перенаправления (на $TUN):"
  echo "   IPv4 фильтры:"
  ipv4_filter_count=$(tc -s filter show dev "$TUN" parent 1: protocol ip 2>/dev/null | grep -c "mirred")
  ipv4_filter_count=${ipv4_filter_count:-0}
  if [ "$ipv4_filter_count" -gt 0 ]; then
    echo "   ✅ Найдено $ipv4_filter_count IPv4 фильтров"
    tc -s filter show dev "$TUN" parent 1: protocol ip 2>/dev/null | grep -E "mirred|Sent|rule hit" | head -6
  else
    echo "   ❌ IPv4 фильтры не найдены"
  fi
  echo "   IPv6 фильтры:"
  ipv6_filter_count=$(tc -s filter show dev "$TUN" parent 1: protocol ipv6 2>/dev/null | grep -c "mirred")
  ipv6_filter_count=${ipv6_filter_count:-0}
  if [ "$ipv6_filter_count" -gt 0 ]; then
    echo "   ✅ Найдено $ipv6_filter_count IPv6 фильтров"
    tc -s filter show dev "$TUN" parent 1: protocol ipv6 2>/dev/null | grep -E "mirred|Sent|rule hit" | head -6
  else
    echo "   ❌ IPv6 фильтры не найдены"
  fi
  echo ""

  # Проверка tc классов на IFB (для всех режимов)
  echo "   📊 Классы HTB:"
  for _ifb_check in "$IFB_MIX" "$IFB_OUT" "$IFB_IN"; do
    if ip link show "$_ifb_check" &>/dev/null; then
      _total=$(tc class show dev "$_ifb_check" 2>/dev/null | grep -c "rate" || echo "0")
      _active=$(tc -s class show dev "$_ifb_check" 2>/dev/null | grep -cE "Sent [1-9]")
      _overlimits=$(tc -s class show dev "$_ifb_check" 2>/dev/null | grep "overlimits" | grep -oE "[0-9]+" | awk '{sum+=$1} END {print sum+0}')
      echo "   $_ifb_check: $_total классов, $_active активных, $_overlimits ограничений"
      if [ "$_active" -gt 0 ]; then
        tc -s class show dev "$_ifb_check" 2>/dev/null | grep -B1 "Sent [1-9]" | grep -E "class htb|Sent" | head -6
      fi
      # Компактная структура иерархии
      echo "     ─ Структура:"
      # Мосты (1:X parent 1:1)
      tc class show dev "$_ifb_check" 2>/dev/null | grep "parent 1:1" | while IFS= read -r _bline; do
        echo "     ├─ $_bline"
      done
      # Первые 3 листовых класса (не bridge, не root 1:1)
      tc class show dev "$_ifb_check" 2>/dev/null | grep -v "parent 1:1" | grep -v "1:1 root" | head -3 | while IFS= read -r _lline; do
        echo "     └─ $_lline"
      done
    fi
  done
  echo ""
  
  # Проверка ingress фильтров (для входящего трафика)
  echo "   🔍 Ingress фильтры (на $TUN):"
  ingress_filter_count=$(tc -s filter show dev "$TUN" parent ffff: 2>/dev/null | grep -c "mirred")
  ingress_filter_count=${ingress_filter_count:-0}
  if [ "$ingress_filter_count" -gt 0 ]; then
    echo "   ✅ Найдено $ingress_filter_count ingress фильтров"
  else
    echo "   ⚠️  Ingress фильтры не найдены (это нормально если лимиты только на исходящий трафик)"
  fi
  echo ""

  # Проверка per-client фильтров на внутренних qdisc
  echo "   🔍 Per-client фильтры (внутренние qdisc):"
  for _ifb_check in "$IFB_MIX" "$IFB_OUT" "$IFB_IN"; do
    if ip link show "$_ifb_check" &>/dev/null; then
      for _inner_handle in $(tc qdisc show dev "$_ifb_check" 2>/dev/null | grep "htb" | grep -v "root" | awk '{print $3}' | sed 's/://'); do
        [ -z "$_inner_handle" ] && continue
        _v4=$(tc filter show dev "$_ifb_check" parent ${_inner_handle}: protocol ip 2>/dev/null | grep -c "flowid" || echo "0")
        _v6=$(tc filter show dev "$_ifb_check" parent ${_inner_handle}: protocol ipv6 2>/dev/null | grep -c "flowid" || echo "0")
        _unclass=$(tc -s qdisc show dev "$_ifb_check" 2>/dev/null | grep "htb ${_inner_handle}:" | grep -oP 'direct_packets_stat \K[0-9]+' || echo "?")
        _classes=$(tc class show dev "$_ifb_check" 2>/dev/null | grep -c "rate" || echo "0")
        echo "   $_ifb_check parent ${_inner_handle}:"
        echo "     IPv4 per-client: $_v4 (ожидается N*2)"
        echo "     IPv6 per-client: $_v6 (ожидается N*2)"
        echo "     Unclassified с момента запуска: $_unclass (0 = ок)"
        echo "     HTB классов: $_classes"
        if [ "$_v4" -eq 0 ] && [ "$_v6" -eq 0 ]; then
          echo "     ⚠️  Per-client фильтры ОТСУТСТВУЮТ — весь трафик идёт в дефолтный класс!"
        fi
      done
    fi
  done
  echo ""

  # Топ классов по трафику (мосты + пиры отдельно)
  echo "   📊 Топ bridge классов (1:X):"
  for _ifb_check in "$IFB_MIX" "$IFB_OUT" "$IFB_IN"; do
    if ip link show "$_ifb_check" &>/dev/null; then
      tc -s class show dev "$_ifb_check" 2>/dev/null | awk '/^class htb 1:/{c=$0} /^class / && !/^class htb 1:/{c=""} /^ Sent/{if(c) print c" | "$2}' | sort -t'|' -k2 -rnu 2>/dev/null | head -5 | while IFS= read -r _line; do echo "     $_line"; done
    fi
  done
  echo ""
  echo "   📊 Топ per-client классов (2+:):"
  for _ifb_check in "$IFB_MIX" "$IFB_OUT" "$IFB_IN"; do
    if ip link show "$_ifb_check" &>/dev/null; then
      tc -s class show dev "$_ifb_check" 2>/dev/null | awk '/^class htb [2-9]/{c=$0} /^class / && !/^class htb [2-9]/{c=""} /^ Sent/{if(c) print c" | "$2}' | sort -t'|' -k2 -rnu 2>/dev/null | head -10 | while IFS= read -r _line; do echo "     $_line"; done
    fi
  done
  echo ""
  echo ""

  # Проверка ip rules WARP (fwmark → таблица; фикс WARP-аудита: раньше гнался
  # мифический «prio 100», которого код не создаёт — self-test всегда врал ❌)
  echo "   📋 ip rules fwmark→table (WARP-маршрутизация):"
  _ip4_rules=$(ip rule show 2>/dev/null | grep -E "fwmark|mark" || true)
  if [ -n "$_ip4_rules" ]; then
    echo "   ✅ IPv4:"
    echo "$_ip4_rules" | while IFS= read -r _rline; do echo "        $_rline"; done
  else
    echo "   ❌ IPv4: WARP fwmark-правила не созданы"
  fi
  _ip6_rules=$(ip -6 rule show 2>/dev/null | grep -E "fwmark|mark" || true)
  if [ -n "$_ip6_rules" ]; then
    echo "   ✅ IPv6:"
    echo "$_ip6_rules" | while IFS= read -r _rline; do echo "        $_rline"; done
  else
    echo "   ❌ IPv6: WARP fwmark-правила не созданы"
  fi
  echo ""

  # --- 5. WARP интерфейсы ---
  echo "🌀 WARP интерфейсы:"
  if [ ${#WARP_LIST[@]} -gt 0 ]; then
    for entry in "${WARP_LIST[@]}"; do
      echo "   • $entry"
    done
  else
    echo "   (нет WARP)"
  fi
  echo ""

  # --- 5. LAN_ALLOW группы ---
  echo "🏠 LAN_ALLOW группы:"
  if [ ${#LAN_ALLOW[@]} -gt 0 ]; then
    for rule in "${LAN_ALLOW[@]}"; do
      echo "   • $rule"
    done
  else
    echo "   (нет LAN_ALLOW)"
  fi
  echo ""

  # --- 6. Лимиты скорости (конфиг) ---
  echo "📋 Лимиты скорости (конфиг SUBNETS_LIMITS):"
  if [ ${#SUBNETS_LIMITS[@]} -gt 0 ]; then
    for entry in "${SUBNETS_LIMITS[@]}"; do
      echo "   • $entry"
    done
  else
    echo "   (нет лимитов)"
  fi
  echo ""

  # --- 7. Пробросы портов (конфиг) ---
  echo "🔌 Пробросы портов (конфиг PORT_FORWARDING_RULES):"
  if [ ${#PORT_FORWARDING_RULES[@]} -gt 0 ]; then
    for rule in "${PORT_FORWARDING_RULES[@]}"; do
      echo "   • $rule"
    done
  else
    echo "   (нет пробросов)"
  fi
  echo ""

  # --- 8. MARK диапазоны ---
  echo "📈 MARK диапазоны:"
  echo "   MARK_BASE: $MARK_BASE (база для всех марок туннеля)"
  echo "   WARP марки (CONNMARK + ip rule): $MARK_BASE .. $((MARK_BASE + 999))"
  echo "   Broadcast/Multicast марки: $((MARK_BASE + 1000)) .. $((MARK_BASE + 1099))"
  echo "   Примечание: tc/htb использует classid (major:minor), НЕ fwmark"
  echo ""

  # --- 9. Состояние интерфейса TUN ---
  echo "📡 Состояние интерфейса $TUN:"
  if ip link show "$TUN" &>/dev/null; then
    echo "   ✅ Интерфейс активен"
    ip -br addr show "$TUN" 2>/dev/null | head -3
  else
    echo "   ❌ Интерфейс не активен"
  fi
  echo ""

  # --- 10. WARP reference count + active status ---
  echo "🔢 WARP Reference Count + Active Status:"
  WARP_DIR="$(dirname "$(readlink -f "$0")")/.data/warp"
  if [ -d "$WARP_DIR" ]; then
    # Показываем все .ref файлы с ref count и active статусом
    for ref_file in "$WARP_DIR"/*.ref; do
      if [ -f "$ref_file" ]; then
        warp_name=$(basename "$ref_file" .ref)
        ref_count=$(cat "$ref_file" 2>/dev/null)
        active_file="$WARP_DIR/${warp_name}.active"
        if [ -f "$active_file" ]; then
          active_status="✅ active"
        else
          active_status="❌ не active"
        fi
        # Проверяем реальный статус интерфейса
        if ip link show "$warp_name" &>/dev/null; then
          iface_status="✅ интерфейс поднят"
        else
          iface_status="❌ интерфейс не найден"
        fi
        echo "   • $warp_name: ref=$ref_count | $active_status | $iface_status"
      fi
    done
  else
    echo "   (нет WARP файлов)"
  fi
  echo ""

  # --- 11. Дополнительные проверки ---
  echo "🔍 Дополнительные проверки:"
  echo "   FORWARD DROP между клиентами:"
  iptables -L FORWARD -n -v 2>/dev/null | grep -E "DROP.*$TUN" || echo "   (нет правил)"
  echo ""

  echo "   FORWARD для WARP интерфейсов:"
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" != "none" ] && [ -n "$entry" ]; then
      # Разбиваем группу интерфейсов (точно как parse_warp_interfaces в up.sh)
      interfaces_part="$entry"
      if [[ "$entry" == *"="* ]]; then
        interfaces_part="${entry%%=*}"
      fi
      IFS=',' read -ra RAW_IFACES <<< "$interfaces_part"
      for warp_iface in "${RAW_IFACES[@]}"; do
        warp_iface="$(echo "$warp_iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$warp_iface" ] && continue
        echo "   IPv4: $TUN → $warp_iface:"
        iptables -L FORWARD -n -v 2>/dev/null | grep -E "$TUN.*$warp_iface" || echo "     (нет правил)"
        echo "   IPv6: $TUN → $warp_iface:"
        ip6tables -L FORWARD -n -v 2>/dev/null | grep -E "$TUN.*$warp_iface" || echo "     (нет правил)"
      done
    fi
  done
  echo ""

  echo "   FORWARD для IFACE (прямой маршрут):"
  echo "   IPv4:"
  iptables -L FORWARD -n -v 2>/dev/null | grep -E "$TUN.*$IFACE|$IFACE.*$TUN" || echo "   (нет правил)"
  echo "   IPv6:"
  ip6tables -L FORWARD -n -v 2>/dev/null | grep -E "$TUN.*$IFACE|$IFACE.*$TUN" || echo "   (нет правил)"
  echo ""

  echo "   LAN_ALLOW правила (разрешения между клиентами):"
  echo "   IPv4:"
  iptables -L FORWARD -n -v 2>/dev/null | grep -E "ACCEPT.*$TUN.*$TUN" | head -10 || echo "   (нет правил)"
  echo "   IPv6:"
  ip6tables -L FORWARD -n -v 2>/dev/null | grep -E "ACCEPT.*$TUN.*$TUN" | head -10 || echo "   (нет правил)"
  echo ""

  echo "   Broadcast/Multicast mark правила:"
  echo "   IPv4 (mangle):"
  if [ -n "$BROADCAST_ADDR" ]; then
    iptables -t mangle -L FORWARD -n -v 2>/dev/null | grep -E "MARK.*$BROADCAST_ADDR|MARK.*255.255.255.255" | head -5 || echo "     (нет правил)"
  else
    echo "     (broadcast не вычислен — нет IPv4 подсети)"
  fi
  echo "   IPv6 (mangle):"
  ip6tables -t mangle -L FORWARD -n -v 2>/dev/null | grep -E "MARK.*ff02::1" | head -5 || echo "     (нет правил)"
  echo ""

  echo "   NAT POSTROUTING (MASQUERADE):"
  echo "   IPv4:"
  iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "MASQUERADE.*$IFACE|MASQUERADE.*warp" | head -10 || echo "   (нет правил)"
  echo "   IPv6:"
  ip6tables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "MASQUERADE.*$IFACE|MASQUERADE.*warp" | head -10 || echo "   (нет правил)"
  echo ""

  # --- Проверочный режим: квоты трафика и relay (дополнение рефакторинга) ---
  _qtun="$(safe_tun_name "$TUN")"
  echo "📊 Квоты трафика (xt_quota + cron):"
  if [ "${#TRAFFIC_QUOTAS[@]}" -gt 0 ]; then
    echo "   правила (массив TRAFFIC_QUOTAS): ${#TRAFFIC_QUOTAS[@]}"
    for _qr in "${TRAFFIC_QUOTAS[@]}"; do echo "     $_qr"; done
    echo "   наборы ipset (per-клиент): $(ipset list -name 2>/dev/null | grep -cE "^Q_${_qtun}_" || echo 0)"
    # Проверяем ЛЮБУЮ существующую цепочку периода (ключи периодов динамические:
    # H/D/W/M/D3/D3_T20/...; раньше фиксированный H давал ложное «не созданы» —
    # фикс аудита-5x5)
    _qfirst=$(iptables-save 2>/dev/null | grep -oE "QUOTA_${_qtun}_[A-Za-z0-9_]+_SRC" | head -1 | sed 's/^QUOTA_//;s/_SRC$//')
    if [ -n "$_qfirst" ]; then
      for _qp in H D W M; do
        echo "   Период $_qp (правила клиентов):"
        iptables -L "QUOTA_${_qtun}_${_qp}_SRC" -n -v 2>/dev/null | grep -E "match-set" | head -10 | sed 's/^/     /'
      done
      echo "   период(ы) в цепочках: $(iptables-save 2>/dev/null | grep -oE "QUOTA_${_qtun}_[A-Za-z0-9_]+_SRC" | sed 's/^QUOTA_//;s/_SRC$//' | sort -u | tr '\n' ' ')"
      echo "   cron: $(crontab -l 2>/dev/null | grep -c "awg-quota-${_qtun}" || echo 0) задача(и)"
      echo "   state: $(cat "$(dirname "$(readlink -f "$0")")/.data/quota/${_qtun}.last" 2>/dev/null || echo 'нет файла')"
    else
      echo "   ⚠  Цепочки QUOTA_${_qtun}_* не созданы (туннель не поднят или квоты не применились)"
    fi
  else
    echo "   (квоты выключены: TRAFFIC_QUOTAS пуст)"
  fi
  echo ""

  echo "🚀 Relay broadcast (bc_relay_${_qtun}):"
  if [ -f "$(dirname "$(readlink -f "$0")")/.data/bc_relay_${_qtun}.pid" ]; then
    _rpid="$(cat "$(dirname "$(readlink -f "$0")")/.data/bc_relay_${_qtun}.pid" 2>/dev/null)"
    if [ -n "$_rpid" ] && kill -0 "$_rpid" 2>/dev/null; then
      echo "   ✅ запущен (pid $_rpid)"
    else
      echo "   ❌ pid-файл есть, но процесс не живёт (pid: $_rpid)"
    fi
  else
    echo "   (не запущен — нет .data/bc_relay_${_qtun}.pid; broadcast-группы не заданы/туннель не поднят)"
  fi
  echo ""
  # --- Конец проверочного режима: квоты и relay ---

  echo "═══════════════════════════════════════════════════════════"
  echo "✅ Проверка завершена"
  echo "═══════════════════════════════════════════════════════════"
  echo ""
  if [ "$TESTLOG" = "1" ]; then
    echo "📄 Лог сохранён: $LOG_FILE"
  fi
fi
'''

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################


# Шаблоны up/down с поддержкой WARP, пробросов портов и лимитов скорости
up_script_template_warp = r'''#!/bin/bash

# --- Определение пути и имени---
UP_SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$UP_SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$UP_SCRIPT_PATH" up.sh)"

# Путь к файлу параметров
PARAMS_FILE="$SCRIPT_DIR/${SCRIPT_NAME}.sh"

# Читаем параметры
if [ -f "$PARAMS_FILE" ]; then
  source "$PARAMS_FILE"
else
  echo "❌ Ошибка: файл параметров не найден: $PARAMS_FILE"
  exit 1
fi

# --- Настройка логирования ---
LOG_DIR="$SCRIPT_DIR/.data/log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Загружаем conntrack helpers для Active FTP, SIP, TFTP - для работы PORT_FORWARD
# Игнорируем ошибки если модули уже загружены или недоступны
modprobe nf_conntrack_ftp 2>/dev/null || true
modprobe nf_conntrack_sip 2>/dev/null || true
modprobe nf_conntrack_tftp 2>/dev/null || true

# Включаем логирование только если UPLOG=1
if [ "$UPLOG" = "1" ]; then
  LOG_FILE="$LOG_DIR/${TUN}up.log"
  exec 3>"$LOG_FILE"
  BASH_XTRACEFD=3
  set -x
fi

# "Безопасное" имя туннеля для суффиксов (только буквы/цифры/_)
TUN_SAFE=$(safe_tun_name "$TUN")
# Суффиксированные/уникальные имена цепочек/ресурсов
PF_CHAIN_NAT="PORT_FORWARD_NAT_${TUN_SAFE}"
PF_CHAIN_FILTER="PORT_FORWARD_FILTER_${TUN_SAFE}"
PF_CHAIN_SNAT="PORT_FORWARD_SNAT_${TUN_SAFE}"
RANDOM_WARP_CHAIN="RANDOM_WARP_${TUN_SAFE}"
IFB_IN="ifb_${TUN_SAFE}_in"
IFB_OUT="ifb_${TUN_SAFE}_out"
IFB_MIX="ifb_${TUN_SAFE}_mix"
INPUT_CHAIN="INPUT_${TUN_SAFE}"
HAIRPIN_CHAIN="HAIRPIN_${TUN_SAFE}"

echo "————————————————————————————————"

# Python helper функции загружаются через source "$PARAMS_FILE" выше
# Все функции доступны: ip_overlaps, calc_ipv4_info, get_broadcast_addr, и т.д.

# --- DDoS: конвертация N/период в формат iptables hashlimit ---
# hashlimit понимает только X/second, X/minute, X/hour, X/day (и X/s, X/m...)
# Наш DSL: 50/10 = 50 пакетов за 10 секунд → конвертируем в 5/second
# Если не делится нацело — конвертируем в /minute
ddos_rate_str() {
  local _rate="$1" _unit="$2"
  # Нормализация единиц: iptables hashlimit принимает только
  # second|minute|hour|day (префиксы не понимает) — «100/hr» молча ронял
  # правило, и порт оставался под голым хвостовым DROP (полный аут;
  # фикс аудита-DDoS-24).
  case "$_unit" in
    hr|h|hrs|H) _unit="hour" ;;
    min|m|mins) _unit="minute" ;;
    sec|s|secs) _unit="second" ;;
    d|D) _unit="day" ;;
  esac
  # Валидация: rate и unit должны быть числами
  case "$_unit" in
    ""|second|minute|hour|day)
      [[ "$_rate" =~ ^[0-9]+$ ]] || { echo "0"; return; }
      echo "${_rate}/${_unit:-second}"
      ;;
    *)
      [[ "$_rate" =~ ^[0-9]+$ ]] && [[ "$_unit" =~ ^[0-9]+$ ]] || { echo "0"; return; }
      # Выбираем наименьшую единицу, где округлённый результат >= 1
      # Округление к ближайшему целому: (N + period/2) / period
      if [ $(((_rate + _unit / 2) / _unit)) -ge 1 ]; then
        echo "$(((_rate + _unit / 2) / _unit))/second"
      elif [ $(((_rate * 60 + _unit / 2) / _unit)) -ge 1 ]; then
        echo "$(((_rate * 60 + _unit / 2) / _unit))/minute"
      elif [ $(((_rate * 3600 + _unit / 2) / _unit)) -ge 1 ]; then
        echo "$(((_rate * 3600 + _unit / 2) / _unit))/hour"
      else
        echo "$(((_rate * 86400 + _unit / 2) / _unit))/day"
      fi
      ;;
  esac
}

# --- DDoS: конвертация bandwidth в формат iptables hashlimit (byte mode) ---
# hashlimit понимает только Xkb/s и Xmb/s (байты). НЕ поддерживает mbit/kbit/gbit!
# mbit → kb (×125: 1 mbit = 125 kb), kbit → kb (÷8), gb → mb (×1000), mb/kb — как есть
ddos_bw_str() {
  local _val="$1"
  # Извлекаем число и суффикс
  local _num="${_val%%[a-zA-Z]*}"
  local _suf="${_val##*[0-9]}"
  # Валидация: число обязательно
  [[ "$_num" =~ ^[0-9]+$ ]] || { echo "0"; return; }
  case "$_suf" in
    ""|mbit)
      echo "$((_num * 125))kb/s"
      ;;
    kbit)
      local _kbits="$(((_num + 4) / 8))"
      # Минимум 1kb/s (иначе 1-7 kbit дали бы 0 и потушили бы интернет)
      [ "$_kbits" -lt 1 ] && _kbits="1"
      echo "${_kbits}kb/s"
      ;;
    mb)
      echo "${_num}mb/s"
      ;;
    kb)
      echo "${_num}kb/s"
      ;;
    gb)
      echo "$((_num * 1000))mb/s"
      ;;
    gbit)
      echo "$((_num * 125000))kb/s"
      ;;
    *)
      # Неизвестный суффикс — оставляем как есть
      echo "${_val}/s"
      ;;
  esac
}

# --- DDoS: парсинг одной строки PORT_FORWARDING_DDOS ---
# Символьный формат: 443/tcp:100/10+50>200/5+100<10,2/5^20_32-720~10mbit!5/300=>500/10+2000=~20mbit=_64-1500
#   443/tcp     — порт + протокол (tcp/udp/tcp,udp или без)
#   :100/10+50  — rate=100, период=10, burst=50 (период и burst опциональны)
#   >200/5+100  — est_rate=200, период=5, est_burst=100 (блок опционален)
#   <10,2/5     — connlimit=10, rate на новые=2 за 5 сек (оба опциональны)
#   ^20         — est_packets=20 (опционально)
#   _32-720     — length_min=32, length_max=720 (опционально)
#   ~10mbit     — bandwidth 10 mbit/s для ESTABLISHED (опционально)
#   !5/300      — ban после 5 нарушений на 300 сек (опционально)
#   @eth0       — привязка к интерфейсу (опционально, без @ — все интерфейсы)
#   =>500/10+2000 =~20mbit =_64-1500 — параметры для reply (сервер→клиент)
#     По умолчанию reply без защиты. Указал = — применяются отдельные параметры.
parse_ddos_entry() {
  local _entry="$1"
  DDOS_PORT=""; DDOS_PROTO=""; DDOS_FAMILY=""; DDOS_RATE=""; DDOS_RATE_UNIT=""; DDOS_BURST=""
  DDOS_EST_RATE=""; DDOS_EST_RATE_UNIT=""; DDOS_EST_BURST=""
  DDOS_CONNLIMIT=""; DDOS_NEW_RATE=""; DDOS_NEW_RATE_UNIT=""
  DDOS_EST_PACKETS=""; DDOS_LENGTH_MIN=""; DDOS_LENGTH_MAX=""
  DDOS_BW=""; DDOS_BAN_HITS=""; DDOS_BAN_SEC=""
  DDOS_REPLY_EST_RATE=""; DDOS_REPLY_EST_RATE_UNIT=""; DDOS_REPLY_EST_BURST=""
  DDOS_REPLY_LENGTH_MIN=""; DDOS_REPLY_LENGTH_MAX=""; DDOS_REPLY_BW=""
  DDOS_IFACE=""

  # Извлекаем порт, протокол и семейство из начала строки (до первого маркера : > < ^ _ ~ !)
  # Формат: ПОРТ[/ПРОТОКОЛ[,v4|v6]]
  # Порт может быть:
  #   - числом: 443
  #   - диапазоном: 8100-8110 (одно правило --dport 8100:8110, «per-port»)
  #   - shared-диапазоном: 8100=-8110 (разворачивается в список → ОБЩИЙ счётчик)
  #   - списком: 8100&8105&8110 (любой список = ОБЩИЙ счётчик, «shared»; `=`
  #     после портов не меняет семантику; per-port задаётся только диапазоном)
  local _rest="$_entry"
  DDOS_PORT=""; DDOS_PORT_LIST=""; DDOS_PORT_RAW=""

  # Извлекаем порт/диапазон/список
  local _port_match=""
  if [[ "$_rest" =~ ^([0-9]+)(=-?[0-9]+|-[0-9]+|=)? ]]; then
    DDOS_PORT="${BASH_REMATCH[1]}"
    # Добавляем диапазон/знак равенства к порту
    if [ -n "${BASH_REMATCH[2]}" ]; then
      DDOS_PORT="${DDOS_PORT}${BASH_REMATCH[2]}"
    fi
    DDOS_PORT_RAW="$DDOS_PORT"
    _port_match="${BASH_REMATCH[0]}"
    _rest="${_rest:${#_port_match}}"
    # Проверяем: если после числа идёт & — это список
    if [[ "$_rest" == "&"* ]]; then
      # Список портов: 8100&8105&8110 или 8100=&8105=&8110
      local _list="$DDOS_PORT"
      local _shared=false
      # Проверяем shared-режим (число=)
      if [[ "$DDOS_PORT" == *= ]]; then
        _shared=true
        DDOS_PORT="${DDOS_PORT%=}"
        _list="${_list%=}"
      fi
      while [[ "$_rest" == "&"* ]]; do
        _rest="${_rest:1}"
        # Снимаем опциональный = после & (для &= синтаксиса)
        [[ "$_rest" == "="* ]] && _rest="${_rest:1}"
        # Элемент списка: число, диапазон (8300-8400), или с = (shared)
        if [[ "$_rest" =~ ^([0-9]+(-[0-9]+)?)(=?)(-?[0-9]*)(.*) ]]; then
          local _next="${BASH_REMATCH[1]}"
          local _next_sep="${BASH_REMATCH[3]}"
          # Если есть продолжение диапазона (-8800) — добавляем
          if [ -n "${BASH_REMATCH[4]}" ]; then
            _next="${_next}${BASH_REMATCH[4]}"
          fi
          _rest="${BASH_REMATCH[5]}"
          if [ "$_shared" = true ] || [ "$_next_sep" = "=" ]; then
            _shared=true
          fi
          _list="${_list},${_next}"
        else
          return 1
        fi
      done
      DDOS_PORT_RAW="${_list//,/_}"
      if [ "$_shared" = true ]; then
        DDOS_PORT_LIST="$_list"
        DDOS_PORT=""
      else
        DDOS_PORT_LIST="$_list"
        DDOS_PORT=""
      fi
    elif [[ "$DDOS_PORT" == *=* ]]; then
      # Диапазон с shared: 8100=-8110
      local _start="${DDOS_PORT%=*}"
      local _end="${DDOS_PORT#*=}"
      _end="${_end#-}"
      DDOS_PORT_LIST=""
      for ((_p=_start; _p<=_end; _p++)); do
        [ -n "$DDOS_PORT_LIST" ] && DDOS_PORT_LIST="${DDOS_PORT_LIST},"
        DDOS_PORT_LIST="${DDOS_PORT_LIST}${_p}"
      done
      DDOS_PORT=""
    fi
  else
    return 1
  fi

  # Опционально: /протокол[,семейство]
  if [[ "$_rest" == /* ]]; then
    _rest="${_rest:1}"
    # Извлекаем до первого маркера
    local _pm_end=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
    local _proto_raw=""
    if [ -n "$_pm_end" ]; then
      _proto_raw="${_rest:0:$_pm_end}"
      _rest="${_rest:$_pm_end}"
    else
      _proto_raw="$_rest"
      _rest=""
    fi
    # Парсим протоколы и семейство
    IFS=',' read -ra _parts <<< "$_proto_raw"
    local _proto_seen=""
    local _family_seen=""
    for _p in "${_parts[@]}"; do
      _p="${_p^^}"
      case "$_p" in
          TCP|UDP)
            [ -z "$_proto_seen" ] && _proto_seen="$_p" || _proto_seen="${_proto_seen},${_p}"
            ;;
          V4|IPV4)
            [ -z "$_family_seen" ] && _family_seen="v4" || _family_seen="${_family_seen},v4"
            ;;
          V6|IPV6)
            [ -z "$_family_seen" ] && _family_seen="v6" || _family_seen="${_family_seen},v6"
            ;;
          *)
            # Невалидный токен — игнорируем
            ;;
        esac
      done
      DDOS_PROTO="$_proto_seen"
      DDOS_FAMILY="$_family_seen"
    fi

  # Разбиваем строку по маркерам — любой порядок
  # Сначала двухсимвольные (=>, =_, =~), потом односимвольные (: > < ^ _ ~ !)
  local _rate_block="" _est_block="" _conn_block="" _packets="" _length=""
  local _has_est=false

  while [[ -n "$_rest" ]]; do
    # Двухсимвольные
    if [[ "$_rest" == "=>"* ]]; then
      _rest="${_rest:2}"
      local _rep_end=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      local _rep_block=""
      if [ -n "$_rep_end" ]; then
        _rep_block="${_rest:0:$_rep_end}"
        _rest="${_rest:$_rep_end}"
      else
        _rep_block="$_rest"
        _rest=""
      fi
      if [[ "$_rep_block" == *+* ]]; then
        DDOS_REPLY_EST_BURST="${_rep_block##*+}"
        _rep_block="${_rep_block%+*}"
      fi
      if [[ "$_rep_block" == */* ]]; then
        DDOS_REPLY_EST_RATE="${_rep_block%/*}"
        DDOS_REPLY_EST_RATE_UNIT="${_rep_block#*/}"
      else
        DDOS_REPLY_EST_RATE="$_rep_block"
      fi
    elif [[ "$_rest" == "=_"* ]]; then
      _rest="${_rest:2}"
      local _rep_len_end=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      local _rep_len=""
      if [ -n "$_rep_len_end" ]; then
        _rep_len="${_rest:0:$_rep_len_end}"
        _rest="${_rest:$_rep_len_end}"
      else
        _rep_len="$_rest"
        _rest=""
      fi
      if [[ "$_rep_len" == *-* ]]; then
        DDOS_REPLY_LENGTH_MIN="${_rep_len%-*}"
        DDOS_REPLY_LENGTH_MAX="${_rep_len#*-}"
      else
        DDOS_REPLY_LENGTH_MIN="$_rep_len"
      fi
    elif [[ "$_rest" == "=~"* ]]; then
      _rest="${_rest:2}"
      local _rep_bw_end=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      local _rep_bw_val=""
      if [ -n "$_rep_bw_end" ]; then
        _rep_bw_val="${_rest:0:$_rep_bw_end}"
        _rest="${_rest:$_rep_bw_end}"
      else
        _rep_bw_val="$_rest"
        _rest=""
      fi
      DDOS_REPLY_BW="$_rep_bw_val"
      local _rep_bw_num="${DDOS_REPLY_BW%%[a-zA-Z]*}"
      if [ "$_rep_bw_num" = "0" ]; then
        DDOS_REPLY_BW="0"
      else
        local _rep_bw_unit="${DDOS_REPLY_BW##*[0-9]}"
        [ -n "$_rep_bw_unit" ] || DDOS_REPLY_BW="${_rep_bw_num}mbit"
      fi
    # Односимвольные
    elif [[ "$_rest" == ":"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        _rate_block="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        _rate_block="$_rest"
        _rest=""
      fi
    elif [[ "$_rest" == ">"* ]]; then
      _has_est=true
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        _est_block="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        _est_block="$_rest"
        _rest=""
      fi
    elif [[ "$_rest" == "<"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        _conn_block="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        _conn_block="$_rest"
        _rest=""
      fi
    elif [[ "$_rest" == "^"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        _packets="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        _packets="$_rest"
        _rest=""
      fi
    elif [[ "$_rest" == "_"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        _length="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        _length="$_rest"
        _rest=""
      fi
    elif [[ "$_rest" == "~"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        DDOS_BW="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        DDOS_BW="$_rest"
        _rest=""
      fi
      local _bw_num="${DDOS_BW%%[a-zA-Z]*}"
      if [ "$_bw_num" = "0" ]; then
        DDOS_BW="0"
      else
        local _bw_unit="${DDOS_BW##*[0-9]}"
        [ -n "$_bw_unit" ] || DDOS_BW="${_bw_num}mbit"
      fi
    elif [[ "$_rest" == "!"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        local _ban_block="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        local _ban_block="$_rest"
        _rest=""
      fi
      if [[ "$_ban_block" == */* ]]; then
        DDOS_BAN_HITS="${_ban_block%/*}"
        DDOS_BAN_SEC="${_ban_block#*/}"
      fi
    elif [[ "$_rest" == "@"* ]]; then
      _rest="${_rest:1}"
      local _next_pos=$(echo "$_rest" | grep -bo '[:><^_~!@=]' | head -1 | cut -d: -f1)
      if [ -n "$_next_pos" ]; then
        DDOS_IFACE="${_rest:0:$_next_pos}"
        _rest="${_rest:$_next_pos}"
      else
        DDOS_IFACE="$_rest"
        _rest=""
      fi
    else
      # Неизвестный символ — ошибка
      return 1
    fi
  done

  # Если после всех маркеров что-то осталось — ошибка
  if [ -n "$_rest" ]; then
    return 1
  fi

  # Парсим блок : (rate)
  if [ -n "$_rate_block" ]; then
    # Формат: rate/period+burst
    local _rb="$_rate_block"
    # Извлекаем burst (после +)
    if [[ "$_rb" == *+* ]]; then
      DDOS_BURST="${_rb##*+}"
      _rb="${_rb%+*}"
    fi
    # Извлекаем period (после /)
    if [[ "$_rb" == */* ]]; then
      DDOS_RATE="${_rb%/*}"
      DDOS_RATE_UNIT="${_rb#*/}"
    else
      DDOS_RATE="$_rb"
    fi
  fi

  # Парсим блок > (est_rate)
  if [ -n "$_est_block" ]; then
    local _eb="$_est_block"
    if [[ "$_eb" == *+* ]]; then
      DDOS_EST_BURST="${_eb##*+}"
      _eb="${_eb%+*}"
    fi
    if [[ "$_eb" == */* ]]; then
      DDOS_EST_RATE="${_eb%/*}"
      DDOS_EST_RATE_UNIT="${_eb#*/}"
    else
      DDOS_EST_RATE="$_eb"
    fi
  elif [ "$_has_est" = true ]; then
    # Блок > был, но пустой — отключаем защиту для ESTABLISHED
    DDOS_EST_RATE="0"
    DDOS_EST_PACKETS="0"
  fi

  # Парсим блок < (connlimit + rate на новые)
  if [ -n "$_conn_block" ]; then
    # Формат: connlimit,new_rate/new_period
    local _cb="$_conn_block"
    if [[ "$_cb" == *,* ]]; then
      DDOS_CONNLIMIT="${_cb%,*}"
      local _new_part="${_cb#*,}"
      if [[ "$_new_part" == */* ]]; then
        DDOS_NEW_RATE="${_new_part%/*}"
        DDOS_NEW_RATE_UNIT="${_new_part#*/}"
      else
        DDOS_NEW_RATE="$_new_part"
      fi
    elif [[ "$_cb" == */* ]]; then
      DDOS_NEW_RATE="${_cb%/*}"
      DDOS_NEW_RATE_UNIT="${_cb#*/}"
    else
      DDOS_CONNLIMIT="$_cb"
    fi
  fi

  # Парсим блок ^ (est_packets)
  if [ -n "$_packets" ]; then
    DDOS_EST_PACKETS="$_packets"
  fi

  # Парсим блок _ (length)
  if [ -n "$_length" ]; then
    if [[ "$_length" == *-* ]]; then
      DDOS_LENGTH_MIN="${_length%-*}"
      DDOS_LENGTH_MAX="${_length#*-}"
    else
      DDOS_LENGTH_MIN="$_length"
    fi
  fi

  # Нормализация пустых значений → «0» (фикс: «80/tcp:» без rate давал
  # hashlimit-upto 0 → молча отрезал весь порт; теперь все-нули = no-op).
  [ -z "$DDOS_RATE" ] && DDOS_RATE="0"
  [ -z "$DDOS_EST_RATE" ] && DDOS_EST_RATE="0"
  [ -z "$DDOS_EST_BURST" ] && DDOS_EST_BURST="0"
  [ -z "$DDOS_CONNLIMIT" ] && DDOS_CONNLIMIT="0"
  [ -z "$DDOS_NEW_RATE" ] && DDOS_NEW_RATE="0"
  [ -z "$DDOS_EST_PACKETS" ] && DDOS_EST_PACKETS="0"
  [ -z "$DDOS_LENGTH_MIN" ] && DDOS_LENGTH_MIN="0"
  [ -z "$DDOS_LENGTH_MAX" ] && DDOS_LENGTH_MAX="0"
  [ -z "$DDOS_BW" ] && DDOS_BW="0"
  [ -z "$DDOS_BAN_HITS" ] && DDOS_BAN_HITS="0"
  [ -z "$DDOS_BAN_SEC" ] && DDOS_BAN_SEC="0"
  [ -z "$DDOS_REPLY_EST_RATE" ] && DDOS_REPLY_EST_RATE="0"
  [ -z "$DDOS_REPLY_EST_BURST" ] && DDOS_REPLY_EST_BURST="0"
  [ -z "$DDOS_REPLY_LENGTH_MIN" ] && DDOS_REPLY_LENGTH_MIN="0"
  [ -z "$DDOS_REPLY_LENGTH_MAX" ] && DDOS_REPLY_LENGTH_MAX="0"
  [ -z "$DDOS_REPLY_BW" ] && DDOS_REPLY_BW="0"

  # Валидация числовых полей (фикс аудита-T5): нечисловое значение (например
  # «300;touch /tmp/pwn» в ban-блоке) попадало в eval _ddos_exec → shell-инъекция.
  # Битое поле сбрасываем в «0» — соответствующий лимит просто не применяется.
  for _qn in DDOS_RATE DDOS_EST_RATE DDOS_EST_BURST DDOS_CONNLIMIT DDOS_NEW_RATE \
             DDOS_EST_PACKETS DDOS_LENGTH_MIN DDOS_LENGTH_MAX DDOS_BW \
             DDOS_BAN_HITS DDOS_BAN_SEC DDOS_REPLY_EST_RATE DDOS_REPLY_EST_BURST \
             DDOS_REPLY_LENGTH_MIN DDOS_REPLY_LENGTH_MAX DDOS_REPLY_BW; do
    eval "_qv=\${$_qn}"
    case "$_qv" in
      ''|*[!0-9]*) eval "$_qn=0" ;;
    esac
  done
  # DDOS_IFACE — только простые символы (попадает в eval в --iface-опции)
  case "$DDOS_IFACE" in
    ''|*[!A-Za-z0-9_.\-]*) DDOS_IFACE="" ;;
  esac

  return 0
}

# --- DDoS: парсинг DDOS-правила по порту ---
# Ищет в PORT_FORWARDING_DDOS строку с заданным портом.
# $1 = порт для поиска
# $2 = протокол (TCP/UDP, может быть пустым)
# $3 = семейство (v4/v6, может быть пустым)
# Устанавливает DDOS_* переменные после успешного парсинга.
# Возвращает 0 если правило найдено, 1 если нет.
# Если не найдено — все DDOS_* обнуляются (защита отключена).
parse_ddos_by_port() {
  local _target_port="$1" _target_proto="$2" _target_family="$3"
  DDOS_PORT=""; DDOS_PROTO=""; DDOS_FAMILY=""; DDOS_RATE=""; DDOS_RATE_UNIT=""; DDOS_BURST=""
  DDOS_EST_RATE=""; DDOS_EST_RATE_UNIT=""; DDOS_EST_BURST=""
  DDOS_CONNLIMIT=""; DDOS_NEW_RATE=""; DDOS_NEW_RATE_UNIT=""
  DDOS_EST_PACKETS=""; DDOS_LENGTH_MIN=""; DDOS_LENGTH_MAX=""
  DDOS_BW=""; DDOS_BAN_HITS=""; DDOS_BAN_SEC=""
  DDOS_REPLY_EST_RATE=""; DDOS_REPLY_EST_RATE_UNIT=""; DDOS_REPLY_EST_BURST=""
  DDOS_REPLY_LENGTH_MIN=""; DDOS_REPLY_LENGTH_MAX=""; DDOS_REPLY_BW=""
  DDOS_IFACE=""

  [ ${#PORT_FORWARDING_DDOS[@]} -eq 0 ] && return 1

  for _entry in "${PORT_FORWARDING_DDOS[@]}"; do
    [ -z "$_entry" ] && continue
    parse_ddos_entry "$_entry" || continue
    # Сверяем порт: точное совпадение, попадание в диапазон, или вхождение в список
    local _port_matched=false
    if [ -n "$DDOS_PORT_LIST" ]; then
      # Список портов: 8100,8105,8110 или 8300-8400 или смешанный
      # Разбиваем по запятым и проверяем каждый элемент
      local _saved_ifs="$IFS"
      IFS=',' read -ra _list_items <<< "$DDOS_PORT_LIST"
      IFS="$_saved_ifs"
      for _item in "${_list_items[@]}"; do
        if [[ "$_item" == *"-"* ]]; then
          # Диапазон: 8300-8400
          local _dstart="${_item%-*}" _dend="${_item#*-}"
          [[ "$_target_port" =~ ^[0-9]+$ ]] && [ "$_target_port" -ge "$_dstart" ] && [ "$_target_port" -le "$_dend" ] && { _port_matched=true; break; }
        else
          # Точное совпадение
          [ "$_item" = "$_target_port" ] && { _port_matched=true; break; }
        fi
      done
    elif [[ "$DDOS_PORT" == *"-"* ]]; then
      # DDOS-правило с диапазоном: target должен попадать в него
      local _dstart="${DDOS_PORT%-*}" _dend="${DDOS_PORT#*-}"
      [[ "$_target_port" =~ ^[0-9]+$ ]] || continue
      [ "$_target_port" -lt "$_dstart" ] && continue
      [ "$_target_port" -gt "$_dend" ] && continue
      _port_matched=true
    else
      [ "$DDOS_PORT" = "$_target_port" ] && _port_matched=true
    fi
    [ "$_port_matched" = false ] && continue
    # Сверяем протокол (регистронезависимо: udp/UDP/Udp и т.п.)
    if [ -n "$DDOS_PROTO" ] && [ -n "$_target_proto" ]; then
      # Если в правиле указан протокол — проверяем совпадение
      local _tp_upper
      _tp_upper=$(printf '%s' "$_target_proto" | tr '[:lower:]' '[:upper:]')
      local _match=0
      case ",${DDOS_PROTO}," in
        *",${_tp_upper},"*) _match=1 ;;
      esac
      [ "$_match" = "0" ] && continue
    fi
    # Сверяем семейство
    if [ -n "$DDOS_FAMILY" ] && [ -n "$_target_family" ]; then
      case ",${DDOS_FAMILY}," in
        *",${_target_family},"*) ;;
        *) continue ;;
      esac
    fi
    # Дефолты
    [ -z "$DDOS_RATE" ] && DDOS_RATE="0"
    [ -z "$DDOS_RATE_UNIT" ] && DDOS_RATE_UNIT="second"
    [ -z "$DDOS_BURST" ] && DDOS_BURST="5"
    [ -z "$DDOS_EST_RATE" ] && DDOS_EST_RATE="$DDOS_RATE"
    [ -z "$DDOS_EST_RATE_UNIT" ] && DDOS_EST_RATE_UNIT="$DDOS_RATE_UNIT"
    [ -z "$DDOS_EST_BURST" ] && DDOS_EST_BURST="$DDOS_BURST"
    [ -z "$DDOS_EST_PACKETS" ] && DDOS_EST_PACKETS="1"
    [ -z "$DDOS_LENGTH_MIN" ] && DDOS_LENGTH_MIN="0"
    [ -z "$DDOS_LENGTH_MAX" ] && DDOS_LENGTH_MAX="0"
    [ -z "$DDOS_CONNLIMIT" ] && DDOS_CONNLIMIT="1"
    [ -z "$DDOS_NEW_RATE" ] && DDOS_NEW_RATE="0"
    [ -z "$DDOS_NEW_RATE_UNIT" ] && DDOS_NEW_RATE_UNIT="second"
    [ -z "$DDOS_BW" ] && DDOS_BW="0"
    [ -z "$DDOS_BAN_HITS" ] && DDOS_BAN_HITS="0"
    [ -z "$DDOS_BAN_SEC" ] && DDOS_BAN_SEC="0"
    # REPLY: если не указаны — защита не применяется (отдельно от original)
    [ -z "$DDOS_REPLY_EST_RATE" ] && DDOS_REPLY_EST_RATE="0"
    [ -z "$DDOS_REPLY_EST_RATE_UNIT" ] && DDOS_REPLY_EST_RATE_UNIT="second"
    [ -z "$DDOS_REPLY_EST_BURST" ] && DDOS_REPLY_EST_BURST="5"
    [ -z "$DDOS_REPLY_LENGTH_MIN" ] && DDOS_REPLY_LENGTH_MIN="0"
    [ -z "$DDOS_REPLY_LENGTH_MAX" ] && DDOS_REPLY_LENGTH_MAX="0"
    [ -z "$DDOS_REPLY_BW" ] && DDOS_REPLY_BW="0"
    [ -z "$DDOS_IFACE" ] && DDOS_IFACE=""
    # Нормализация burst: iptables требует 1..1000000 (0 невалиден, молча
    # гасил правила; фикс аудита-DDoS)
    [ "$DDOS_BURST" = "0" ] && DDOS_BURST="5"
    [ "$DDOS_EST_BURST" = "0" ] && DDOS_EST_BURST="5"
    [ "$DDOS_REPLY_EST_BURST" = "0" ] && DDOS_REPLY_EST_BURST="5"
    return 0
  done

  # Не нашли — обнуляем
  DDOS_PORT=""; DDOS_PROTO=""; DDOS_FAMILY=""; DDOS_RATE="0"; DDOS_RATE_UNIT="second"; DDOS_BURST="0"
  DDOS_EST_RATE="0"; DDOS_EST_RATE_UNIT="second"; DDOS_EST_BURST="0"
  DDOS_CONNLIMIT="0"; DDOS_NEW_RATE="0"; DDOS_NEW_RATE_UNIT="second"
  DDOS_EST_PACKETS="0"; DDOS_LENGTH_MIN="0"; DDOS_LENGTH_MAX="0"; DDOS_BW="0"; DDOS_BAN_HITS="0"; DDOS_BAN_SEC="0"
  DDOS_REPLY_EST_RATE="0"; DDOS_REPLY_EST_RATE_UNIT="second"; DDOS_REPLY_EST_BURST="0"
  DDOS_REPLY_LENGTH_MIN="0"; DDOS_REPLY_LENGTH_MAX="0"; DDOS_REPLY_BW="0"
  DDOS_IFACE=""
  return 1
}

# --- DDoS: добавление правил ESTABLISHED в указанную цепочку ---
# $1 = IPT_CMD (iptables/ip6tables)
# $2 = CHAIN
# $3 = PROTO
# $4 = DIP (пусто = любой)
# $5 = DPORT
# $6 = SUBNET (пусто = всем)
# Использует глобальные DDOS_* переменные (должны быть установлены через parse_ddos_by_port)
ddos_add_established() {
  local _cmd="$1" _chain="$2" _proto="$3" _dip="$4" _dport="$5" _subnet="$6"
  # Для ЛЮБОГО списка портов (в т.ч. «8100&8105&8110») — общий счётчик:
  # имя hashlimit/recent строится от всего списка (shared-семантика);
  # per-port лимит задаётся только простым диапазоном «8100-8110».
  local _port_id="$_dport"
  if [ -n "$DDOS_PORT_LIST" ]; then
    _port_id="${DDOS_PORT_RAW//[^a-zA-Z0-9]/_}"
  fi
  # Короткие имена hashlimit (ядро молча отклоняет имена > 31 байта:
  # фикс аудита — длинные цепочки/порты гасили EST-правила без ошибок).
  local _chain_h=$(printf '%s' "$_chain" | md5sum | cut -c1-6)
  local _port_h=$(printf '%s' "$_port_id" | md5sum | cut -c1-6)
  local _hashname_est="EST_${_chain_h}_${_proto}_${_port_h}"
  local _hashname_pre="PRE_${_chain_h}_${_proto}_${_port_h}"
  local _next_packets=0
  # _ddos_exec, _addr_args, _iface_opt — определены в ddos_apply_rules (вызывающей функции), доступны здесь

  # Length_max: пакеты длиннее — DROP (если указан)
  if [ -n "$DDOS_LENGTH_MAX" ] && [ "$DDOS_LENGTH_MAX" != "0" ]; then
    _ddos_exec "-m length --length $((DDOS_LENGTH_MAX + 1)): -j DROP"
  fi

  if [ -n "$DDOS_EST_PACKETS" ] && [ "$DDOS_EST_PACKETS" != "0" ] && [ -n "$DDOS_RATE" ] && [ "$DDOS_RATE" != "0" ]; then
    # Первые N пакетов от сервера — строгий rate (как для NEW)
    _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1:${DDOS_EST_PACKETS} -m hashlimit --hashlimit-name $_hashname_pre --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_rate_str "$DDOS_RATE" "$DDOS_RATE_UNIT") --hashlimit-burst ${DDOS_BURST:-5} -j ACCEPT"
    _next_packets=$((DDOS_EST_PACKETS + 1))
  else
    _next_packets=0
  fi

  if [ -n "$DDOS_EST_RATE" ] && [ "$DDOS_EST_RATE" != "0" ]; then
    # После N пакетов (или сразу если est_packets=0) — по est_rate
    if [ "$_next_packets" != "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes ${_next_packets}: -m hashlimit --hashlimit-name $_hashname_est --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_rate_str "$DDOS_EST_RATE" "$DDOS_EST_RATE_UNIT") --hashlimit-burst ${DDOS_EST_BURST:-5} -j ACCEPT"
    else
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m hashlimit --hashlimit-name $_hashname_est --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_rate_str "$DDOS_EST_RATE" "$DDOS_EST_RATE_UNIT") --hashlimit-burst ${DDOS_EST_BURST:-5} -j ACCEPT"
    fi
  else
    # ESTABLISHED без лимита (только если est_rate=0 и нет est_packets, иначе rate выше уже всё ловит)
    if [ "${DDOS_EST_PACKETS:-0}" = "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    fi
  fi
}

# --- DDoS: ACCEPT с защитой (если есть DDOS-правило) или без ---
# $1 = IPT_CMD (iptables/ip6tables), $2 = CHAIN, $3 = PROTO
# $4 = DIP (пусто = любой), $5 = DPORT, $6 = SUBNET (пусто = всем)
# DDOS_* должны быть установлены через parse_ddos_by_port
# Если DDOS_RATE=0 — правила не добавляются
ddos_apply_rules() {
  local _cmd="$1" _chain="$2" _proto="$3" _dip="$4" _dport="$5" _subnet="$6"

  # Если ни один параметр защиты не активен — ничего не делаем
  if [ "$DDOS_LENGTH_MIN" = "0" ] && [ "$DDOS_LENGTH_MAX" = "0" ] && [ "$DDOS_EST_RATE" = "0" ] && [ "$DDOS_NEW_RATE" = "0" ] && [ "$DDOS_CONNLIMIT" = "0" ] && [ "$DDOS_RATE" = "0" ] && [ "$DDOS_BW" = "0" ] && [ "$DDOS_BAN_HITS" = "0" ] && [ "$DDOS_REPLY_EST_RATE" = "0" ] && [ "$DDOS_REPLY_BW" = "0" ] && [ "$DDOS_REPLY_LENGTH_MIN" = "0" ] && [ "$DDOS_REPLY_LENGTH_MAX" = "0" ]; then
    # ^N-only конфиг (EST_PACKETS без rate): PRE-правило требует DDOS_RATE,
    # est-ветка — EST_RATE — правил не построится, а terminal-ветка ДРОПНУЛА бы
    # established. Предупреждаем и пропускаем (фикс регресса: молча выставлялся
    # «голый ACCEPT» и порт оставался совсем без защиты).
    if [ -n "$DDOS_EST_PACKETS" ] && [ "$DDOS_EST_PACKETS" != "0" ]; then
      echo "⚠️  DDoS-правило с ^N (est_packets) но без rate — правила не построятся, пропущено (задайте rate/est_rate)" >&2
    else
      echo "ℹ️  DDoS-правило без параметров (например «порт:» без rate) — пропущено" >&2
    fi
    return 1
  fi

  # Для ЛЮБОГО списка портов (в т.ч. «8100&8105&8110») — общий счётчик:
  # имя hashlimit/recent строится от всего списка (shared-семантика);
  # per-port лимит задаётся только простым диапазоном «8100-8110».
  local _port_id="$_dport"
  if [ -n "$DDOS_PORT_LIST" ]; then
    _port_id="${DDOS_PORT_RAW//[^a-zA-Z0-9]/_}"
  fi

  local _safe_ip="${_dip//[!:.]/_}"
  # Короткие имена hashlimit (ядро: >31 байта отклоняет молча; фикс аудита:
  # длинные IPv6/IP/списки портов гасили правила без ошибок)
  local _ip_h=$(printf '%s' "$_safe_ip" | md5sum | cut -c1-6)
  local _port_h=$(printf '%s' "${DDOS_PORT_RAW:-$_dport}" | md5sum | cut -c1-6)
  local _hashname="D_${_proto}_${_ip_h}_${_port_h}"
  local _hashname_new="DN_${_proto}_${_ip_h}_${_port_h}"
  local _hashname_bw="BW_${_proto}_${_ip_h}_${_port_h}"
  local _hashname_ban="BAN_${_proto}_${_ip_h}_${_port_h}"
  local _iface_opt=""
  [ -n "$DDOS_IFACE" ] && _iface_opt="-i $DDOS_IFACE"
  # Сборка общих аргументов адреса (-d/-s) — формируется один раз, подставляется во все правила ниже
  local _addr_args=""
  [ -n "$_dip" ] && _addr_args="$_addr_args -d \"$_dip\""
  [ -n "$_subnet" ] && _addr_args="$_addr_args -s \"$_subnet\""
  # Хелпер: выполняет iptables с переменными _cmd/_chain/_proto/_dport/_iface_opt/_addr_args (eval раскрывает кавычки)
  _ddos_exec() { eval "$_cmd -t filter -A \"$_chain\" $_iface_opt -p \"$_proto\" --dport \"$_dport\" $_addr_args $1" 2>/dev/null || true; }
  # Маска для connlimit: /32 для IPv4, /128 для IPv6
  local _mask=32
  [ "$_cmd" = "ip6tables" ] && _mask=128

  # Нормализация burst: iptables требует 1..1000000 (фикс аудита-B2: путь
  # основного порта идёт через parse_ddos_entry без дефолтов; «0» гасил правила)
  [ "$DDOS_BURST" = "0" ] && DDOS_BURST="5"
  [ "$DDOS_EST_BURST" = "0" ] && DDOS_EST_BURST="5"
  [ "$DDOS_REPLY_EST_BURST" = "0" ] && DDOS_REPLY_EST_BURST="5"

  # Length_min
  if [ -n "$DDOS_LENGTH_MIN" ] && [ "$DDOS_LENGTH_MIN" != "0" ]; then
    _ddos_exec "-m length --length 0:$((DDOS_LENGTH_MIN - 1)) -j DROP"
  fi
  # ESTABLISHED — ДО reply-ветки (фикс аудита-DDoS: раньше reply-ACCEPT/репли-
  # DROP стояли первыми и делали правила >est_rate / ^est_packets / ~bw
  # недостижимыми; теперь established сначала проходит EST и BW-лимиты).
  ddos_add_established "$_cmd" "$_chain" "$_proto" "$_dip" "$_dport" "$_subnet"
  # Bandwidth (byte rate limit для ESTABLISHED)
  if [ -n "$DDOS_BW" ] && [ "$DDOS_BW" != "0" ]; then
    _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m hashlimit --hashlimit-name $_hashname_bw --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_bw_str "$DDOS_BW") -j ACCEPT"
  fi
  # REPLY трафик (сервер→клиент): если нет отдельной конфигурации — ACCEPT без лимита
  # ВНИМАНИЕ: `${VAR:-0}` — путь основного порта идёт через parse_ddos_entry,
  # где REPLY-переменные пустые (не "0"); пустая строка ≠ "0" ломала
  # диспетчер → безусловный REPLY-DROP гасил трафик (фикс аудита-B2).
  if [ "${DDOS_REPLY_EST_RATE:-0}" = "0" ] && [ "${DDOS_REPLY_BW:-0}" = "0" ] \
     && [ "${DDOS_REPLY_LENGTH_MIN:-0}" = "0" ] && [ "${DDOS_REPLY_LENGTH_MAX:-0}" = "0" ]; then
    # Default-ветка (reply-лимиты не заданы). БЕЗУСЛОВНЫЙ ACCEPT ставить нельзя,
    # если выше заданы EST/BW-лимиты: пакет, превысивший их, провалился бы
    # сквозь upto-ACCEPT'ы и здесь был бы принят — ветка защиты established
    # мертва (фикс аудита-DDoS-24: over-limit должен дропаться терминально,
    # как в reply-ветке; без лимитов established принимаем безусловно).
    if { [ -n "$DDOS_EST_RATE" ] && [ "$DDOS_EST_RATE" != "0" ]; } \
       || { [ -n "$DDOS_EST_PACKETS" ] && [ "$DDOS_EST_PACKETS" != "0" ]; } \
       || { [ -n "$DDOS_BW" ] && [ "$DDOS_BW" != "0" ]; }; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -j DROP"
    else
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -j ACCEPT"
    fi
  else
    # REPLY-лимиты (если заданы отдельные параметры для reply)
    local _hashname_rep="REP_${_proto}_${_ip_h}_${_port_h}"
    # REPLY length
    if [ -n "$DDOS_REPLY_LENGTH_MIN" ] && [ "$DDOS_REPLY_LENGTH_MIN" != "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -m length --length 0:$((DDOS_REPLY_LENGTH_MIN - 1)) -j DROP"
    fi
    # REPLY length_max
    if [ -n "$DDOS_REPLY_LENGTH_MAX" ] && [ "$DDOS_REPLY_LENGTH_MAX" != "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -m length --length $((DDOS_REPLY_LENGTH_MAX + 1)): -j DROP"
    fi
    # REPLY est_rate
    if [ -n "$DDOS_REPLY_EST_RATE" ] && [ "$DDOS_REPLY_EST_RATE" != "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -m hashlimit --hashlimit-name $_hashname_rep --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_rate_str "$DDOS_REPLY_EST_RATE" "$DDOS_REPLY_EST_RATE_UNIT") --hashlimit-burst ${DDOS_REPLY_EST_BURST:-5} -j ACCEPT"
    fi
    # REPLY bandwidth
    if [ -n "$DDOS_REPLY_BW" ] && [ "$DDOS_REPLY_BW" != "0" ]; then
      _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -m hashlimit --hashlimit-name REPBW_${_proto}_${_ip_h}_${_port_h} --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_bw_str "$DDOS_REPLY_BW") -j ACCEPT"
    fi
    # REPLY DROP для превысивших
    _ddos_exec "-m conntrack --ctstate ESTABLISHED,RELATED -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 1: -j DROP"
  fi
  # Бан (recent) — если IP превысил лимит нарушений, блокируем новые соединения
  if [ -n "$DDOS_BAN_HITS" ] && [ "$DDOS_BAN_HITS" != "0" ]; then
    _ddos_exec "-m conntrack --ctstate NEW -m recent --name $_hashname_ban --rcheck --seconds $DDOS_BAN_SEC --hitcount $DDOS_BAN_HITS -j DROP"
  fi
  # Connlimit (проверяется до NEW_RATE — нельзя создать соединение если лимит превышен)
  if [ -n "$DDOS_CONNLIMIT" ] && [ "$DDOS_CONNLIMIT" != "0" ]; then
    _ddos_exec "-m connlimit --connlimit-above $DDOS_CONNLIMIT --connlimit-mask $_mask -j DROP"
  fi
  # Rate на новые соединения (превысил → DROP, не превысил → падает на RATE)
  if [ -n "$DDOS_NEW_RATE" ] && [ "$DDOS_NEW_RATE" != "0" ]; then
    _ddos_exec "-m conntrack --ctstate NEW -m hashlimit --hashlimit-name $_hashname_new --hashlimit-mode srcip --hashlimit-above $(ddos_rate_str "$DDOS_NEW_RATE" "$DDOS_NEW_RATE_UNIT") -j DROP"
  fi
  # NEW — rate по пакетам
  if [ -n "$DDOS_RATE" ] && [ "$DDOS_RATE" != "0" ]; then
    _ddos_exec "-m conntrack --ctstate NEW -m hashlimit --hashlimit-name $_hashname --hashlimit-mode srcip,srcport --hashlimit-upto $(ddos_rate_str "$DDOS_RATE" "$DDOS_RATE_UNIT") --hashlimit-burst ${DDOS_BURST:-5} -j ACCEPT"
  fi
  # DROP (с отслеживанием для бана)
  if [ -n "$DDOS_BAN_HITS" ] && [ "$DDOS_BAN_HITS" != "0" ]; then
    # С бананом — добавляем IP в recent и DROP
    _ddos_exec "-m recent --name $_hashname_ban --set -j DROP"
  else
    # Без бана — просто DROP
    _ddos_exec "-j DROP"
  fi
}

# --- DDoS: ACCEPT для проброшенных портов (с DDOS или без) ---
pf_accept_or_ddos() {
  local _cmd="$1" _proto="$2" _dip="$3" _ext_port="$4" _int_port="$5" _subnet="$6"
  local _family="v4"
  [[ "$_cmd" == "ip6tables" ]] && _family="v6"
  if parse_ddos_by_port "$_ext_port" "$_proto" "$_family"; then
    ddos_apply_rules "$_cmd" "$PF_CHAIN_FILTER" "$_proto" "$_dip" "$_int_port" "$_subnet" && return
  fi
  # Без DDOS или без активных параметров — ACCEPT
  if [ -n "$_subnet" ]; then
    $_cmd -t filter -A "$PF_CHAIN_FILTER" -p $_proto -d $_dip --dport $_int_port -s $_subnet -j ACCEPT 2>/dev/null || true
  else
    $_cmd -t filter -A "$PF_CHAIN_FILTER" -p $_proto -d $_dip --dport $_int_port -j ACCEPT 2>/dev/null || true
  fi
}

# --- DDoS: загружаем модули ядра если ещё не загружены ---
modprobe xt_hashlimit 2>/dev/null || true
modprobe xt_connlimit 2>/dev/null || true
modprobe xt_connbytes 2>/dev/null || true
modprobe xt_length 2>/dev/null || true
modprobe xt_recent 2>/dev/null || true

# Включаем accounting для conntrack (нужен для connbytes)
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true

# --- Включаем IP forwarding если выключен ---
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "1" ]; then
    echo "✅ IPv4 forwarding включён"
else
    echo "❌ IPv4 forwarding ВЫКЛЮЧЕН! Включаю..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi

if [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" = "1" ]; then
    echo "✅ IPv6 forwarding включён"
else
    echo "❌ IPv6 forwarding ВЫКЛЮЧЕН! Включаю..."
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
fi

# rp_filter settings for proper WireGuard operation.
# Сохраняем ПРЕЖНИЕ значения (в .data/<tun>_sysctl.save) — down.sh восстановит их,
# чтобы up/down не оставлял глобальных мутаций хоста (rp_filter=0 навсегда).
if [ -n "$SCRIPT_DIR" ]; then
  mkdir -p "$SCRIPT_DIR/.data"
  # ОБЩИЙ оригинал rp_filter на каталог: первый up сохраняет, последний down
  # восстанавливает (важно для нескольких параллельных туннелей).
  SYSCTL_ORIG="$SCRIPT_DIR/.data/rp_filter.orig"
  if [ ! -f "$SYSCTL_ORIG" ]; then
    for _sf in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter \
               net.ipv6.conf.all.rp_filter net.ipv6.conf.default.rp_filter \
               net.netfilter.nf_conntrack_acct; do
      printf '%s=%s\n' "$_sf" "$(sysctl -n "$_sf" 2>/dev/null || echo 1)" >> "$SYSCTL_ORIG"
    done
  fi
fi
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
parse_local_subnets

echo "📡 Подсеть: $LOCAL_SUBNETS"

# --- Вычисление broadcast для IPv4 ---
LOCAL_SERVER_IP=""
BROADCAST_ADDR=""

if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS_IPV4" | cut -d'/' -f1)"
  calc_ipv4_info

  if [ "$SERVER_ON_NETWORK" -eq 1 ]; then
    echo "📍 IPv4: Сервер на network адресе ($LOCAL_SERVER_IP) — broadcast НЕ работает"
  else
    echo "📍 IPv4: Сервер НЕ на network адресе ($LOCAL_SERVER_IP) — broadcast работает"
  fi
fi

# --- Вычисление статуса IPv6 ---
LOCAL_SERVER_IP_IPV6=""
BROADCAST_ADDR_IPV6=""

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  LOCAL_SERVER_IP_IPV6="$(echo "$LOCAL_SUBNETS_IPV6" | cut -d'/' -f1)"
  calc_ipv6_status
  # Последний адрес v6-сети (= «broadcast» для пропуска лимитной группы)
  BROADCAST_ADDR_IPV6=$(LOCAL_SUBNETS_IPV6="$LOCAL_SUBNETS_IPV6" python3 -c \
    "import ipaddress,os; print(str(ipaddress.ip_network(os.environ['LOCAL_SUBNETS_IPV6'],strict=False)[-1]))" 2>/dev/null)

  if [ "$SERVER_ON_NETWORK_IPV6" -eq 1 ]; then
    echo "📍 IPv6: Сервер на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast НЕ работает"
  else
    echo "📍 IPv6: Сервер НЕ на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast работает"
  fi
fi

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
# Диапазон MARK: 1000-9990 (максимум 900 уникальных значений для tc)
# Аллокатор (фикс аудита-A3): сохраняет базу между up/down и сдвигает
# диапазон при коллизии с другими туннелями.
MARK_BASE=$(alloc_mark_base "$TUN_SAFE")

# --- Создаём rt_tables если его нет ---
mkdir -p /etc/iproute2 2>/dev/null || true
if [ ! -f /etc/iproute2/rt_tables ]; then
    echo "#
# reserved
#
#100 local
#200 adsl
#205 cidr
#210 intern
#211 adsl2
#212 adsl3
#253 wan
#254 local
#255 main
" > /etc/iproute2/rt_tables 2>/dev/null || true
fi

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

# --- Запуск WARP-интерфейсов (дополнительные WireGuard-интерфейсы для мульти-WARP) ---
# Пропускаем, если WARP_LIST пустой или содержит только "none"
# Используем счётчик ссылок для поддержки общих WARP между туннелями
# Парсим формат: "warp0,warp1=subnet1, subnet2" или "warp0,warp1"

# Создаём ОБЩУЮ папку для всех WARP файлов (ОБЩАЯ ДЛЯ ВСЕХ ИНТЕРФЕЙСОВ!)
# Файлы хранятся рядом с up.sh/down.sh скриптом в .data/warp/
STATE_BASE_DIR="$(dirname "$(readlink -f "$0")")/.data"
mkdir -p "$STATE_BASE_DIR" 2>/dev/null || true
mkdir -p "$STATE_BASE_DIR/warp" 2>/dev/null || true

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
# Reference counting + ПРЯМАЯ ПРОВЕРКА реального состояния интерфейса
WARP_ACTIVE=0
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  echo "🚀 Запуск WARP-туннеля: $warp"
  WARP_REF_FILE="$STATE_BASE_DIR/warp/${warp}.ref"
  WARP_ACTIVE_FILE="$STATE_BASE_DIR/warp/${warp}.active"

  # ПРЯМАЯ ПРОВЕРКА: запущен ли интерфейс реально
  WARP_RUNNING=0
  if ip link show "$warp" &>/dev/null; then
    WARP_RUNNING=1
  fi

  # Проверяем состояние WARP интерфейса и .ref файла
  # Логика:
  # 1. Нет интерфейса + Нет .ref → Запускаем интерфейс, создаём .ref=1
  # 2. Нет интерфейса + Есть .ref → Запускаем интерфейс, пересоздаём .ref=1
  # 3. Есть интерфейс + Есть .ref → Увеличиваем .ref += 1
  # 4. Есть интерфейс + Нет .ref → Создаём .ref=1

  if [ "$WARP_RUNNING" -eq 0 ] && [ ! -f "$WARP_REF_FILE" ]; then
    # Случай 1: Нет интерфейса + Нет .ref → Запускаем интерфейс, создаём .ref=1
    echo "🔧 Запуск WARP: $warp (интерфейс не активен, .ref не найден)"
    if awg-quick up "$SCRIPT_DIR/${warp}.conf" 2>/dev/null || awg-quick up "$warp" 2>/dev/null; then
      atomic_ref_update "$WARP_REF_FILE" "set" "1" >/dev/null
      echo "✅ WARP $warp запущен (ref=1)"
    else
      echo "❌ Ошибка запуска $warp (баг 1.16: по имени ищется только /etc/amnezia/amneziawg/)"
    fi
  elif [ "$WARP_RUNNING" -eq 0 ] && [ -f "$WARP_REF_FILE" ]; then
    # Случай 2: Нет интерфейса + Есть .ref → Запускаем интерфейс, пересоздаём .ref=1
    ref_count=$(atomic_ref_update "$WARP_REF_FILE" "get")
    echo "🔧 Перезапуск WARP: $warp (интерфейс не активен, ref=$ref_count)"
    if awg-quick up "$SCRIPT_DIR/${warp}.conf" 2>/dev/null || awg-quick up "$warp" 2>/dev/null; then
      atomic_ref_update "$WARP_REF_FILE" "set" "1" >/dev/null
      echo "✅ WARP $warp перезапущен (ref=1)"
    else
      echo "❌ Ошибка запуска $warp (баг 1.16: по имени ищется только /etc/amnezia/amneziawg/)"
    fi
  elif [ "$WARP_RUNNING" -eq 1 ] && [ -f "$WARP_REF_FILE" ]; then
    # Случай 3: Есть интерфейс + Есть .ref → Увеличиваем .ref += 1 (атомарно get+inc)
    ref_info=$(atomic_ref_update "$WARP_REF_FILE" "get_inc")
    ref_count="${ref_info%%:*}"
    new_count="${ref_info##*:}"
    echo "✅ WARP $warp уже запущен (ref=$ref_count → $new_count)"
  else
    # Случай 4: Есть интерфейс + Нет .ref → Создаём .ref=1
    echo "⚠️  WARP $warp уже запущен но .ref не найден — создаём .ref=1"
    atomic_ref_update "$WARP_REF_FILE" "set" "1" >/dev/null
  fi

  # ВАЖНО: Устанавливаем .active флаг
  if [ -f "$WARP_REF_FILE" ]; then
    touch "$WARP_ACTIVE_FILE"
  fi

  # Проверяем .active файл (надёжнее чем .ref из-за гонки)
  if [ -f "$WARP_ACTIVE_FILE" ]; then
    WARP_ACTIVE=1
  fi
done

# --- Очистка старых FORWARD правил этого туннеля (LAN_ALLOW, broadcast, MARK) ---
# Выполняется ДО добавления WARP/IFACE-правил: раньше grep-очистка удаляла
# только что созданные правила того же прохода up (баг 1.22). Имя туннеля
# заякорено пробелом, чтобы не задеть чужие туннели (awg1 vs awg10; баг 1.2).
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  while iptables -C FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null; do
    iptables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
  done
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  while ip6tables -C FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null; do
    ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
  done
fi
# Экранирование имени TUN для regex (фикс аудита-fresh: «wg.0» с точкой в
# grep-шаблоне матчил бы любой символ и сносил FORWARD-правила чужих туннелей)
_TUN_RE="$(printf '%s' "$TUN" | sed 's/[][\.*^$+?()|{}]/\\&/g')"
iptables-save -t filter 2>/dev/null | grep "^-A FORWARD .*-i ${_TUN_RE} " | while read -r _line; do
  _rule="${_line#-A }"
  iptables -D $_rule 2>/dev/null || true
done
ip6tables-save -t filter 2>/dev/null | grep "^-A FORWARD .*-i ${_TUN_RE} " | while read -r _line; do
  _rule="${_line#-A }"
  ip6tables -D $_rule 2>/dev/null || true
done
iptables-save -t mangle 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  iptables -t mangle -D $_rule 2>/dev/null || true
done
ip6tables-save -t mangle 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  ip6tables -t mangle -D $_rule 2>/dev/null || true
done

# --- WARP-маршрутизация и балансировка трафика через WARP интерфейсы ---
if [ "$WARP_ACTIVE" -eq 1 ]; then
  # --- Создаём таблицы маршрутизации для каждого WARP интерфейса ---
  declare -A WARP_TABLE_IDS
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    # Атомарная аллокация id в rt_tables (flock): параллельные up разных
    # туннелей не должны взять один и тот же TABLE_ID (аудит-20).
    TABLE_ID=$( (
      flock 9
      _tid=$(find_table_id "$warp")
      if [ "$_tid" = "0" ]; then
        echo "Ошибка: не удалось найти свободный TABLE_ID для $warp" >&2
      else
        grep -q "^$_tid[[:space:]]$warp$" /etc/iproute2/rt_tables || echo "$_tid $warp" >> /etc/iproute2/rt_tables
        echo "$_tid"
      fi
    ) 9>>/etc/iproute2/rt_tables )
    if [ "$TABLE_ID" != "0" ] && [ -n "$TABLE_ID" ]; then
      ip route replace default dev "$warp" table "$TABLE_ID"
      ip -6 route replace default dev "$warp" table "$TABLE_ID"
      WARP_TABLE_IDS["$warp"]="$TABLE_ID"
    fi
  done

  # --- iptables для маркировки трафика ---
  # Создаём цепочку в ОБЕИХ таблицах (iptables и ip6tables)
  iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -N "$RANDOM_WARP_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || ip6tables -t mangle -N "$RANDOM_WARP_CHAIN" 2>/dev/null || true

  # Добавляем правила PREROUTING ТОЛЬКО для трафика из VPN туннеля!
  # ВАЖНО: -i "$TUN" чтобы не маркировать весь остальной трафик на сервере
  iptables -t mangle -C PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -A PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -C PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || ip6tables -t mangle -A PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true

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

  # Локальные подсети СЕРВЕРА — в исключения (фикс WARP-аудита): клиент →
  # сервер (его туннельные адреса/LAN) должен ходить напрямую, а не в WARP:
  # иначе default-группа маркирует эти NEW-соединения и policy-роутинг уводит
  # их в WARP-таблицу (dоступ к серверу/локальным сервисам молча ломался).
  if [ -n "${LOCAL_SUBNETS_IPV4:-}" ]; then ALL_WARP_EXCLUSIONS+=("$LOCAL_SUBNETS_IPV4"); fi
  if [ -n "${LOCAL_SUBNETS_IPV6:-}" ]; then ALL_WARP_EXCLUSIONS+=("$LOCAL_SUBNETS_IPV6"); fi
  
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

  # --- Маркировка специфичных подсетей (АГРЕГАЦИЯ ПО ПОДСЕТЯМ; фикс:
  # повторяющиеся подсети в разных записях WARP_LIST сливаются в одну
  # группу интерфейсов — трафик подсети делится по ВСЕМ указанным WARP) ---
  MARK_OFFSET=0
  DEFAULT_WARP_COUNT=0
  DEFAULT_OFFSET=0
  DEFAULT_IFS=""
  while IFS='|' read -r _kind _off _cnt _sub _ifs; do
    if [ "$_kind" = "S" ]; then
      MARK_OFFSET="$_off"
      IFS=',' read -ra WARP_GROUP <<< "$_ifs"
      WARP_GROUP_COUNT="$_cnt"
      if [[ "$_sub" == *:* ]]; then
        # IPv6 подсеть — только ip6tables
        for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
          MARK=$((MARK_BASE + MARK_OFFSET + i))
          ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$_sub" -m conntrack --ctstate NEW \
            -m statistic --mode nth --every $WARP_GROUP_COUNT --packet $i \
            -j CONNMARK --set-mark $MARK
        done
      else
        # IPv4 подсеть — только iptables
        for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
          MARK=$((MARK_BASE + MARK_OFFSET + i))
          iptables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$_sub" -m conntrack --ctstate NEW \
            -m statistic --mode nth --every $WARP_GROUP_COUNT --packet $i \
            -j CONNMARK --set-mark $MARK
        done
      fi
    elif [ "$_kind" = "D" ]; then
      DEFAULT_OFFSET="$_off"
      DEFAULT_IFS="$_ifs"
      IFS=',' read -ra DEFAULT_WARP_GROUP <<< "$_ifs"
      DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
    fi
  done < <(warp_specific_layout)

  # --- Обработка интерфейсов БЕЗ подсетей (для всего остального трафика) ---
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    # restore-mark для СПЕЦИФИЧНЫХ потоков ДО их RETURN (фикс аудита-B3:
    # --set-mark пишет только ct-метку, skb-fwmark наполняет лишь
    # restore-mark; без него специфичный трафик уходил из цепочки без
    # fwmark, и ip rule по нему не срабатывал).
    iptables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
    ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
    # RETURN для специфичных подсетей — через -A (append), т.е. ПОСЛЕ их
    # CONNMARK-маркировок (фикс аудита: -I 1 ставил RETURN поверх цепочки,
    # и трафик на «warpX=subnet» уходил мимо WARP при наличии default-группы).
    for subnet in "${ALL_SPECIFIC_SUBNETS[@]}"; do
      # Определяем тип подсети (IPv4 или IPv6) и применяем правило только к нужной таблице
      if [[ "$subnet" == *:* ]]; then
        # IPv6 подсеть — применяем только к ip6tables
        ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -j RETURN 2>/dev/null || true
      else
        # IPv4 подсеть — применяем только к iptables
        iptables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -j RETURN 2>/dev/null || true
      fi
    done

    # Исключения (none=, LAN_ALLOW, LOCAL_SUBNETS) — ПОСЛЕ специфик-маркировок
    # и их RETURN, ПЕРЕД default-балансировкой (фикс регресса WARP: ранее
    # -I 1 поверх цепочки затенял явные записи 'warpX=подсеть', покрывающие
    # локальные сети сервера; специфик-маркировка терминальна и выигрывает,
    # остальной локальный трафик возвращается из WARP до default).
    if [ ${#ALL_WARP_EXCLUSIONS[@]} -gt 0 ]; then
      echo "🔒 Исключение ${#ALL_WARP_EXCLUSIONS[@]} IP/подсетей из WARP (локальная сеть + none=)"
      for subnet in "${ALL_WARP_EXCLUSIONS[@]}"; do
        if [[ "$subnet" == *:* ]]; then
          ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -j RETURN 2>/dev/null || true
        else
          iptables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -j RETURN 2>/dev/null || true
        fi
      done
    fi

    # Балансировка для всего остального трафика между ВСЕМИ интерфейсами без подсетей
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + DEFAULT_OFFSET + i))
      # IPv4 маркировка
      iptables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW \
        -m statistic --mode nth --every $DEFAULT_WARP_COUNT --packet $i \
        -j CONNMARK --set-mark $MARK
      # IPv6 маркировка
      ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW \
        -m statistic --mode nth --every $DEFAULT_WARP_COUNT --packet $i \
        -j CONNMARK --set-mark $MARK
    done
  fi

  # --- Восстанавливаем mark для всех пакетов ---
  iptables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark
  ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark

  # --- Добавляем ip rule для каждого MARK -> TABLE ---
  # Агрегированный layout: сначала специфичные подсети (в порядке layout),
  # затем default-группа. Оффсеты совпадают с маркировкой (warp_specific_layout).
  WARP_MARK_OFFSET=0
  while IFS='|' read -r _kind _off _cnt _sub _ifs; do
    if [ "$_kind" = "S" ]; then
      WARP_MARK_OFFSET="$_off"
      IFS=',' read -ra WARP_GROUP <<< "$_ifs"
      WARP_GROUP_COUNT="$_cnt"
      for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
        MARK=$((MARK_BASE + WARP_MARK_OFFSET + i))
        warp_iface="${WARP_GROUP[$i]}"
        TABLE_ID="${WARP_TABLE_IDS[$warp_iface]}"
        if [ -n "$TABLE_ID" ]; then
          # Сначала удаляем старые правила если есть (чтобы избежать дубликатов)
          ip rule del fwmark $MARK 2>/dev/null || true
          ip -6 rule del fwmark $MARK 2>/dev/null || true
          # Создаём IPv4 правило с приоритетом
          ip rule add priority $((32700 + WARP_MARK_OFFSET + i)) fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          # Создаём IPv6 правило с приоритетом
          ip -6 rule add priority $((32700 + WARP_MARK_OFFSET + i)) fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        fi
      done
    elif [ "$_kind" = "D" ]; then
      # Default-группа: те же марки, что в маркировке
      WARP_MARK_OFFSET="$_off"
      IFS=',' read -ra DEFAULT_WARP_GROUP <<< "$_ifs"
      DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
      for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
        MARK=$((MARK_BASE + WARP_MARK_OFFSET + i))
        warp_iface="${DEFAULT_WARP_GROUP[$i]}"
        TABLE_ID="${WARP_TABLE_IDS[$warp_iface]}"
        if [ -n "$TABLE_ID" ]; then
          ip rule del fwmark $MARK 2>/dev/null || true
          ip -6 rule del fwmark $MARK 2>/dev/null || true
          ip rule add priority $((32700 + WARP_MARK_OFFSET + i)) fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          ip -6 rule add priority $((32700 + WARP_MARK_OFFSET + i)) fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        fi
      done
    fi
  done < <(warp_specific_layout)

  # --- Настройка FORWARD и NAT для трафика через WARP ---
  # IPv4 правила (свои для каждого туннеля!)
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    iptables -C FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
    iptables -C FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -C POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
  done

  # IPv6 правила (свои для каждого туннеля!)
  for warp in "${!ALL_WARP_INTERFACES[@]}"; do
    ip6tables -C FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
    ip6tables -C FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    ip6tables -t nat -C POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
  done
fi

# --- Настройка FORWARD и NAT для трафика напрямую через внешний интерфейс ---
# Если WARP активен — это для подсетей из "none=..." в WARP_LIST, если нет — для всего трафика
# Используем суффиксированную цепочку для избежания конфликтов между туннелями

# IPv4 правила
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t filter -N "$INPUT_CHAIN" 2>/dev/null || true
  iptables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
  iptables -t filter -C INPUT -j "$INPUT_CHAIN" 2>/dev/null || iptables -t filter -A INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
fi
# --- DDoS защита основного порта ---
for _de in "${PORT_FORWARDING_DDOS[@]}"; do
  parse_ddos_entry "$_de" || continue
  [ "$DDOS_PORT" = "$PORT" ] || continue
  # Только UDP правило для основного порта (AWG всегда UDP)
  [ -z "$DDOS_PROTO" ] && continue
  [[ ",${DDOS_PROTO}," != *,UDP,* ]] && continue
  echo "🛡️ Настройка DDoS защиты для основного порта"
  if { [ -z "$DDOS_FAMILY" ] || [[ ",${DDOS_FAMILY}," == *,v4,* ]]; } && [ -n "$LOCAL_SUBNETS_IPV4" ]; then
    ddos_apply_rules "iptables" "$INPUT_CHAIN" "udp" "" "$PORT" ""
  fi
  if [ -z "$DDOS_FAMILY" ] || [[ ",${DDOS_FAMILY}," == *,v6,* ]]; then
    ddos_apply_rules "ip6tables" "$INPUT_CHAIN" "udp" "" "$PORT" ""
  fi
  break
done
# Разрешаем ICMP (пинг) из VPN подсети на сервер (IPv4)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t filter -C "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -p icmp -j ACCEPT 2>/dev/null || iptables -t filter -A "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV4" -p icmp -j ACCEPT 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -C FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
  iptables -C FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
fi

# IPv6 правила (С NAT!)
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t filter -N "$INPUT_CHAIN" 2>/dev/null || true
  ip6tables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
  ip6tables -t filter -C INPUT -j "$INPUT_CHAIN" 2>/dev/null || ip6tables -t filter -A INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
fi
# --- DDoS защита основного порта (IPv6) — применяется только к UDP-правилам с v6 в DDOS_FAMILY (или без указания семейства) ---
for _de in "${PORT_FORWARDING_DDOS[@]}"; do
  parse_ddos_entry "$_de" || continue
  [ "$DDOS_PORT" = "$PORT" ] || continue
  [ -z "$DDOS_PROTO" ] && continue
  [[ ",${DDOS_PROTO}," != *,UDP,* ]] && continue
  if { [ -z "$DDOS_FAMILY" ] || [[ ",${DDOS_FAMILY}," == *,v6,* ]]; } && [ -n "$LOCAL_SUBNETS_IPV6" ]; then
    ddos_apply_rules "ip6tables" "$INPUT_CHAIN" "udp" "" "$PORT" ""
  fi
  break
done
# Разрешаем ICMPv6 (пинг) из VPN подсети на сервер (IPv6)
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t filter -C "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -p icmpv6 -j ACCEPT 2>/dev/null || ip6tables -t filter -A "$INPUT_CHAIN" -s "$LOCAL_SUBNETS_IPV6" -p icmpv6 -j ACCEPT 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -C FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
  ip6tables -C FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  ip6tables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
fi

# --- Hairpin NAT ---
# Используем суффиксированную цепочку для избежания конфликтов между туннелями
# Создаём цепочку в ОБЕИХ таблицах (iptables и ip6tables)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t nat -N "$HAIRPIN_CHAIN" 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t nat -N "$HAIRPIN_CHAIN" 2>/dev/null || true
fi

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
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t nat -N "$PF_CHAIN_NAT" 2>/dev/null || true
  iptables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
  iptables -t filter -N "$PF_CHAIN_FILTER" 2>/dev/null || true
  iptables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
  iptables -t nat -N "$PF_CHAIN_SNAT" 2>/dev/null || true
  iptables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t nat -N "$PF_CHAIN_NAT" 2>/dev/null || true
  ip6tables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
  ip6tables -t filter -N "$PF_CHAIN_FILTER" 2>/dev/null || true
  ip6tables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
  ip6tables -t nat -N "$PF_CHAIN_SNAT" 2>/dev/null || true
  ip6tables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
fi

# Добавляем правила PREROUTING для ВСЕХ интерфейсов (универсально, без привязки к туннелям!)
# ВАЖНО: Проверяем что ссылка ещё не добавлена (защита от дубликатов!)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || iptables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || ip6tables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
fi

# FORWARD и POSTROUTING для текущего туннеля
# ВАЖНО: Проверяем что ссылка ещё не добавлена (защита от дубликатов!)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t filter -C FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || iptables -t filter -A FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
  iptables -t nat -C POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || iptables -t nat -A POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t filter -C FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || ip6tables -t filter -A FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
  ip6tables -t nat -C POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || ip6tables -t nat -A POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
fi

# --- Локальная сеть между клиентами ---
# Расширенная сегментация: каждый элемент массива — это группа IP/подсетей которые могут общаться ДРУГ С ДРУГОМ
# Формат: "IP1, IP2, IP3, ..." — все участники могут общаться со всеми остальными в этой группе
# Пример: "10.0.1.11, 10.0.1.0/30, 10.1.1.1" — все трое могут общаться между собой в обе стороны

# СНАЧАЛА запрещаем ВСЁ межклиентское общение (DROP в КОНЕЦ цепи)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -A FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -A FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
fi


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
      # Если частей несколько — определяем логику по типам адресов
      echo "  Группа: ${PARTS_CLEAN[*]} (все ↔ все)"

      # Разделяем участников по типам (IPv4 и IPv6 не могут общаться друг с другом)
      IPV4_PARTS=()
      IPV6_PARTS=()
      for part in "${PARTS_CLEAN[@]}"; do
        if [[ "$part" == *:* ]]; then
          IPV6_PARTS+=("$part")
        else
          IPV4_PARTS+=("$part")
        fi
      done

      # Считаем уникальных участников каждого типа (без declare -A для совместимости с bash < 4.0)
      IPV4_UNIQUE=()
      IPV6_UNIQUE=()
      for part in "${IPV4_PARTS[@]}"; do
        skip=
        for u in "${IPV4_UNIQUE[@]}"; do [ "$u" = "$part" ] && skip=1 && break; done
        [ -z "$skip" ] && IPV4_UNIQUE+=("$part")
      done
      for part in "${IPV6_PARTS[@]}"; do
        skip=
        for u in "${IPV6_UNIQUE[@]}"; do [ "$u" = "$part" ] && skip=1 && break; done
        [ -z "$skip" ] && IPV6_UNIQUE+=("$part")
      done

      # Универсальная функция обработки LAN_ALLOW группы для одного типа IP
      # Вызов: lan_allow_group 4 IPV4_PARTS IPV4_UNIQUE  или  lan_allow_group 6 IPV6_PARTS IPV6_UNIQUE
      # Использует eval для совместимости с bash < 4.3 (без nameref)
      lan_allow_group() {
          local ip_ver="$1"
          local _parts_name="$2"
          local _unique_name="$3"
          local IPT_CMD=""
          local LABEL=""
          if [ "$ip_ver" -eq 4 ]; then
              IPT_CMD="iptables"
              LABEL="IPv4"
          else
              IPT_CMD="ip6tables"
              LABEL="IPv6"
          fi

          local _parts_count
          eval "_parts_count=\${#$_parts_name[@]}"
          [ "$_parts_count" -eq 0 ] && return

          # 1. Unicast правила для ВСЕХ пар участников
          echo "   Создание unicast правил для $LABEL пар..."
          for ((i=0; i<_parts_count; i++)); do
              for ((j=i+1; j<_parts_count; j++)); do
                  local SRC DST
                  eval "SRC=\${$_parts_name[$i]}"
                  eval "DST=\${$_parts_name[$j]}"
                  echo "    $SRC ↔ $DST"
                  $IPT_CMD -I FORWARD -i "$TUN" -o "$TUN" -s "$SRC" -d "$DST" -j ACCEPT 2>/dev/null || true
                  $IPT_CMD -I FORWARD -i "$TUN" -o "$TUN" -s "$DST" -d "$SRC" -j ACCEPT 2>/dev/null || true
              done
          done

          # Вспомогательная: найти туннель для подсети (универсальная для intra и inter)
          _find_tun_for_subnet() {
              local target="$1"
              if [ "$target" = "$LOCAL_SUBNETS_IPV4" ] || [ "$target" = "$LOCAL_SUBNETS_IPV6" ]; then
                  echo "$TUN"
              elif local_subnet_overlaps "$target"; then
                  echo "$TUN"
              else
                  find_tunnel_for_subnet "$target"
              fi
          }

          # 2. Intra-subnet разрешён если один участник ИЛИ участник дубль
          if [ "$_parts_count" -eq 1 ]; then
              # Один участник — разрешаем intra-subnet
              local SUBNET
              eval "SUBNET=\${$_parts_name[0]}"
              local SUBNET_TUN=$(_find_tun_for_subnet "$SUBNET")
              [ -n "$SUBNET_TUN" ] && $IPT_CMD -I FORWARD -i "$SUBNET_TUN" -o "$SUBNET_TUN" -s "$SUBNET" -d "$SUBNET" -j ACCEPT 2>/dev/null || true
          else
              # Участников >1 — intra-subnet только для дублей
              local _unique_keys
              eval "_unique_keys=\"\${$_unique_name[@]}\""
              for SUBNET in $_unique_keys; do
                  local COUNT=0
                  for part_idx in $(seq 0 $((_parts_count - 1))); do
                      local _part_val
                      eval "_part_val=\${$_parts_name[$part_idx]}"
                      [ "$_part_val" = "$SUBNET" ] && ((COUNT++))
                  done
                  if [ "$COUNT" -gt 1 ]; then
                      local SUBNET_TUN=$(_find_tun_for_subnet "$SUBNET")
                      [ -n "$SUBNET_TUN" ] && $IPT_CMD -I FORWARD -i "$SUBNET_TUN" -o "$SUBNET_TUN" -s "$SUBNET" -d "$SUBNET" -j ACCEPT 2>/dev/null || true
                  fi
              done
          fi
      }

      # Обрабатываем IPv4 и IPv6 через одну функцию
      lan_allow_group 4 IPV4_PARTS IPV4_UNIQUE
      lan_allow_group 6 IPV6_PARTS IPV6_UNIQUE

      echo "   Межтуннельные правила:"

      # Проходим по каждой паре участников ОДНОГО ТИПА и создаём правила
      # IPv4 и IPv6 не могут общаться друг с другом — не создаём бесполезные правила
      for ((i=0; i<${#PARTS_CLEAN[@]}; i++)); do
        for ((j=0; j<${#PARTS_CLEAN[@]}; j++)); do
          # Пропускаем если это один и тот же участник
          [ $i -eq $j ] && continue

          SRC="${PARTS_CLEAN[$i]}"
          DST="${PARTS_CLEAN[$j]}"

          # Пропускаем если участники разных типов (IPv4 ↔ IPv6 бесполезно)
          if [[ "$SRC" == *:* ]] && [[ "$DST" != *:* ]]; then
            continue
          fi
          if [[ "$SRC" != *:* ]] && [[ "$DST" == *:* ]]; then
            continue
          fi

          # Пропускаем если это одинаковые подсети (для них есть intra-subnet)
          [ "$SRC" = "$DST" ] && continue

          # Определяем туннель для источника и получателя (универсальная функция)
          SRC_TUN=$(_find_tun_for_subnet "$SRC")
          DST_TUN=$(_find_tun_for_subnet "$DST")

          # Если не нашли туннель — пропускаем эту пару
          if [ -z "$SRC_TUN" ]; then
            echo "    ⚠️  Пропущено: $SRC (туннель не найден)"
            continue
          fi
          if [ -z "$DST_TUN" ]; then
            echo "    ⚠️  Пропущено: $DST (туннель не найден)"
            continue
          fi

          # Определяем iptables/ip6tables по типу
          if [[ "$SRC" == *:* ]]; then
              IPT_CMD="ip6tables"
          else
              IPT_CMD="iptables"
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

# --- Сохраняем ВСЕ параметры туннеля в один временный файл ---
# Это нужно для поиска туннелей по подсети и очистки в down.sh
# Храним: параметры, WARP_LIST, LAN_ALLOW, INTERFACE_MAP
TUNNELS_STATE_DIR="$STATE_BASE_DIR/temp"
mkdir -p "$TUNNELS_STATE_DIR" 2>/dev/null || true

# --- Собираем карту интерфейсов и подсетей для всех IP в LAN_ALLOW ---
# Это нужно чтобы down.sh мог очистить правила даже если интерфейс больше не существует
INTERFACE_MAP=()

# Для текущего туннеля (TUN) используем LOCAL_SUBNETS напрямую
# Не нужно искать туннель по IP — мы уже знаем что это TUN!
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  INTERFACE_MAP+=("$TUN=$LOCAL_SUBNETS_IPV4")
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  INTERFACE_MAP+=("$TUN=$LOCAL_SUBNETS_IPV6")
fi
# Для остальных правил LAN_ALLOW ищем туннели
for rule in "${LAN_ALLOW[@]}"; do
  IFS=',' read -ra PARTS <<< "$rule"
  for part in "${PARTS[@]}"; do
    part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$part" ] && continue

    # Пропускаем если это подсеть текущего туннеля (уже добавлена выше)
    if [ "$part" = "$LOCAL_SUBNETS_IPV4" ] || [ "$part" = "$LOCAL_SUBNETS_IPV6" ]; then
      continue
    fi

    # Ищем туннель универсальной функцией
    tun_name=$(find_tunnel_for_subnet "$part")

    if [ -n "$tun_name" ]; then
      # Получаем подсеть этого туннеля
      tun_subnet=$(ip -o addr show "$tun_name" 2>/dev/null | awk '{print $4}' | head -1)
      if [ -n "$tun_subnet" ]; then
        INTERFACE_MAP+=("$tun_name=$tun_subnet")
      else
        # Если интерфейс есть но IP нет — берём из .conf файла
        conf_file="$SCRIPT_DIR/${tun_name}.conf"
        if [ -f "$conf_file" ]; then
          conf_subnet=$(grep -E "^Address = " "$conf_file" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
          if [ -n "$conf_subnet" ]; then
            local tun_subnet_net=$(parse_conf_subnet "$conf_subnet")
            [ -n "$tun_subnet_net" ] && INTERFACE_MAP+=("$tun_name=$tun_subnet_net")
          fi
        fi
      fi
    fi
  done
done

# Удаляем дубликаты из INTERFACE_MAP
INTERFACE_MAP_UNIQUE=($(printf '%s\n' "${INTERFACE_MAP[@]}" | sort -u))

# Сохраняем параметры для down.sh: копируем awg0.sh + дописываем динамические
mkdir -p "$TUNNELS_STATE_DIR" 2>/dev/null || true
cp "$PARAMS_FILE" "$TUNNELS_STATE_DIR/${SCRIPT_NAME}.sh" 2>/dev/null || true
{
  echo ""
  echo "MARK_BASE=\"$MARK_BASE\""
  echo ""
  echo "INTERFACE_MAP=("
  for item in "${INTERFACE_MAP_UNIQUE[@]}"; do
    echo "  \"$item\""
  done
  echo ")"
} >> "$TUNNELS_STATE_DIR/${SCRIPT_NAME}.sh" 2>/dev/null || true

# --- Добавление правил для каждого проброса ---

# --- Broadcast/Multicast трафик (для игр и service discovery) ---
# РЕАЛИЗАЦИЯ заново (баг 1.21): старый механизм (марк + ACCEPT -d участника)
# не работал — broadcast-пакет имеет dst = BROADCAST_ADDR, и WireGuard всё равно
# не умеет доставлять один пакет многим пирам.
# Новый механизм — репликация на сервере:
#   * группа помечается маркой MARK_BASE+1000+GROUP_IDX (диапазон +1000..+1099,
#     вне WARP-диапазона +0..+999);
#   * маркировка в mangle PREROUTING (до DNAT/маршрутизации);
#   * оригинал DNAT-ится ПЕРВОМУ участнику группы (nat PREROUTING);
#   * остальным участникам уходят TEE-клоны (mangle POSTROUTING);
#   * помеченный broadcast пропускается в filter FORWARD (до общего DROP).
# Изоляция: правила срабатывают только на помеченные пакеты; немеченый
# broadcast (отправитель вне групп) падает в общий DROP.
# Участники группы = конкретные IP клиентов туннеля из [Peer] AllowedIPs
# серверного конфига, входящие в записи этой группы.
# Работает ТОЛЬКО если сервер НЕ занимает network адрес подсети.

# IP клиентов туннеля из серверного конфига (конкретные адреса для репликации)
parse_peer_ips() {
  local conf_file="$1"
  [ -f "$conf_file" ] || return 0
  awk '/^\[Peer\]/{in_peer=1}
       in_peer && /^AllowedIPs[[:space:]]*=/{sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); print}
       in_peer && /^\[/ && !/^\[Peer\]/{in_peer=0}' "$conf_file" 2>/dev/null
}

# Проверка: входит ли IP в одну из подсетей группы (определена в скрипте параметров)
BC_MARK_CHAIN="BC_MARK_${TUN_SAFE}"
BC_NAT_CHAIN="BC_NAT_${TUN_SAFE}"
BC_TEE_CHAIN="BC_TEE_${TUN_SAFE}"
BC_CMARK_CHAIN="BC_CMARK_${TUN_SAFE}"
BC_CNAT_CHAIN="BC_CNAT_${TUN_SAFE}"
SERVER_CONF_FILE="$SCRIPT_DIR/${SCRIPT_NAME}.conf"

# IPv4 Broadcast
BC_RELAY_GROUPS=""
# Собственные адреса сервера из конфига (Address) — цели редиректа для relay
IPV4_SERVER_ADDR=$(grep -m1 '^Address' "$SERVER_CONF_FILE" 2>/dev/null | sed -e 's/^Address *= *//' -e 's/,/ /g' | tr ' ' '\n' | grep -v ':' | head -1 | cut -d/ -f1)
IPV6_SERVER_ADDR=$(grep -m1 '^Address' "$SERVER_CONF_FILE" 2>/dev/null | sed -e 's/^Address *= *//' -e 's/,/ /g' | tr ' ' '\n' | grep ':' | head -1 | sed 's|/.*||')
if [ -n "$LOCAL_SUBNETS_IPV4" ] && [ -n "$BROADCAST_ADDR" ] && [ "$SERVER_ON_NETWORK" -eq 0 ]; then
  # Конкретные IPv4-адреса клиентов
  PEER_IPS_V4=()
  while IFS= read -r _peer_ips; do
    [ -z "$_peer_ips" ] && continue
    IFS=',' read -ra _parts <<< "$_peer_ips"
    for _p in "${_parts[@]}"; do
      _ip="${_p%%/*}"
      [[ "$_ip" == *:* ]] && continue
      [ -n "$_ip" ] && PEER_IPS_V4+=("$_ip")
    done
  done <<< "$(parse_peer_ips "$SERVER_CONF_FILE")"

  GROUP_IDX=0
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"

    # Собираем только IPv4 участников этой группы
    IPV4_PARTS=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$part" ] && continue
      [[ "$part" != *:* ]] && IPV4_PARTS+=("$part")
    done

    if [ ${#IPV4_PARTS[@]} -gt 0 ]; then
      if [ "$GROUP_IDX" -gt 99 ]; then
        echo "⚠️  Слишком много групп (>100) — broadcast для '$rule' пропущен"
      else
        VAL=$((MARK_BASE + 1000 + GROUP_IDX))
        # Участники группы = клиенты туннеля, чьи IP входят в её записи
        MEMBERS_V4=()
        for _peer in "${PEER_IPS_V4[@]}"; do
          [ -z "$_peer" ] && continue
          if ip_in_subnets "$_peer" "$rule"; then
            _dup=0
            for _m in "${MEMBERS_V4[@]}"; do [ "$_m" = "$_peer" ] && _dup=1 && break; done
            [ "$_dup" = "0" ] && MEMBERS_V4+=("$_peer")
          fi
        done

        if [ ${#MEMBERS_V4[@]} -gt 0 ]; then
          # Копии раздаёт relay-демон (AF_PACKET на интерфейсе туннеля)
          _GROUP_SRCS=""
          for src in "${IPV4_PARTS[@]}"; do
            [ -n "$_GROUP_SRCS" ] && _GROUP_SRCS="$_GROUP_SRCS,"
            _GROUP_SRCS="$_GROUP_SRCS$src"
          done
          _GROUP_MEMBERS=""
          for _m in "${MEMBERS_V4[@]}"; do
            [ -n "$_GROUP_MEMBERS" ] && _GROUP_MEMBERS="$_GROUP_MEMBERS,"
            _GROUP_MEMBERS="$_GROUP_MEMBERS$_m"
          done
          BC_RELAY_GROUPS="${BC_RELAY_GROUPS}${VAL}|${_GROUP_MEMBERS}|${_GROUP_SRCS};"
          echo "📢 Broadcast группа '$rule': участники ${MEMBERS_V4[*]} (mark $VAL)"
        fi
      fi
    fi

    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

# IPv6 Multicast (аналогично IPv4; отдельная таблица ip6tables, те же марки)
if [ -n "$LOCAL_SUBNETS_IPV6" ] && [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
  PEER_IPS_V6=()
  while IFS= read -r _peer_ips; do
    [ -z "$_peer_ips" ] && continue
    IFS=',' read -ra _parts <<< "$_peer_ips"
    for _p in "${_parts[@]}"; do
      _ip="${_p%%/*}"
      [[ "$_ip" != *:* ]] && continue
      [ -n "$_ip" ] && PEER_IPS_V6+=("$_ip")
    done
  done <<< "$(parse_peer_ips "$SERVER_CONF_FILE")"

  GROUP_IDX=0
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"

    IPV6_PARTS=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$part" ] && continue
      [[ "$part" == *:* ]] && IPV6_PARTS+=("$part")
    done

    if [ ${#IPV6_PARTS[@]} -gt 0 ]; then
      if [ "$GROUP_IDX" -gt 99 ]; then
        echo "⚠️  Слишком много групп (>100) — multicast для '$rule' пропущен"
      else
        VAL=$((MARK_BASE + 1000 + GROUP_IDX))
        # v6-multicast через клиентский wg не доставляется (свойство стека) — пропускаем

        MEMBERS_V6=()
        for _peer in "${PEER_IPS_V6[@]}"; do
          [ -z "$_peer" ] && continue
          if ip_in_subnets "$_peer" "$rule"; then
            _dup=0
            for _m in "${MEMBERS_V6[@]}"; do [ "$_m" = "$_peer" ] && _dup=1 && break; done
            [ "$_dup" = "0" ] && MEMBERS_V6+=("$_peer")
          fi
        done

        if [ ${#MEMBERS_V6[@]} -gt 0 ]; then
          _GROUP_SRCS=""
          for src in "${IPV6_PARTS[@]}"; do
            [ -n "$_GROUP_SRCS" ] && _GROUP_SRCS="$_GROUP_SRCS,"
            _GROUP_SRCS="$_GROUP_SRCS$src"
          done
          _GROUP_MEMBERS=""
          for _m in "${MEMBERS_V6[@]}"; do
            [ -n "$_GROUP_MEMBERS" ] && _GROUP_MEMBERS="$_GROUP_MEMBERS,"
            _GROUP_MEMBERS="$_GROUP_MEMBERS$_m"
          done
          BC_RELAY_GROUPS="${BC_RELAY_GROUPS}${VAL}|${_GROUP_MEMBERS}|${_GROUP_SRCS};"
          echo "📢 Multicast группа '$rule': участники ${MEMBERS_V6[*]} (mark $VAL)"
        fi
      fi
    fi

    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

# --- Relay-демон репликации broadcast/multicast ---
# Опыт: xt_TEE не переписывает dst клона (клон несёт пост-DNAT адрес), а при
# отправке на loopback пакет доставляется ЛОКАЛЬНО (INPUT), минуя PREROUTING.
# Поэтому репликацию выполняет локальный демон: помеченный broadcast
# редиректится на 127.0.0.1/::1 (BC_NAT выше, порт сохраняется), relay читает
# его raw-сокетом и рассылает копии участникам группы с СОХРАНЕНИЕМ src
# (IP_TRANSPARENT + марка relay для обхода hairpin-MASQUERADE).
# Убиваем прежние экземпляры БЕЗУСЛОВНО (фикс регресса: при опустевших
# группах старый демон продолжал слать копии по старым адресам, которые могли
# быть перевыданы новым клиентам).
pkill -f "bc_relay_${TUN_SAFE}.py" 2>/dev/null || true
if [ -n "$BC_RELAY_GROUPS" ]; then
  BC_RELAY_MARK=$((MARK_BASE + 9000))
  iptables -t nat -I "$HAIRPIN_CHAIN" 1 -m mark --mark $BC_RELAY_MARK -j RETURN 2>/dev/null || true
  ip6tables -t nat -I "$HAIRPIN_CHAIN" 1 -m mark --mark $BC_RELAY_MARK -j RETURN 2>/dev/null || true
  mkdir -p "$SCRIPT_DIR/.data"
  cat > "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.py" <<'PYEOF'
#!/usr/bin/env python3
# Relay v2 репликации broadcast/multicast: AF_PACKET на туннельном интерфейсе.
# Читает декапсулированные фреймы ДО маршрутизации (минимизирует зависимость
# от netfilter/loopback-ограничений), фильтрует UDP с dst=broadcast/multicast от
# источников групп LAN_ALLOW и рассылает копии участникам (IP_TRANSPARENT + SO_MARK).
import ipaddress, os, signal, socket, struct, sys

GROUPS = []  # (members4, srcs4, members6, srcs6)
for part in os.environ.get("BC_RELAY_GROUPS", "").rstrip(";").split(";"):
    if not part:
        continue
    _val, _members, _srcs = part.split("|", 2)
    m4 = [x for x in _members.split(",") if x and ":" not in x]
    m6 = [x for x in _members.split(",") if x and ":" in x]
    s4, s6 = [], []
    for s in _srcs.split(","):
        if not s:
            continue
        try:
            n = ipaddress.ip_network(s, strict=False)
            (s4 if n.version == 4 else s6).append(n)
        except ValueError:
            pass
    if m4 or m6:
        GROUPS.append((m4, s4, m6, s6))

RELAY_MARK = int(os.environ.get("BC_RELAY_MARK", "0"))
IFACE = os.environ.get("BC_RELAY_IFACE", "")
BROADCAST4 = os.environ.get("BC_RELAY_BC4", "255.255.255.255")
BROADCAST6 = os.environ.get("BC_RELAY_BC6", "ff02::1")
HAS4 = any(g[0] for g in GROUPS)
HAS6 = any(g[2] for g in GROUPS)
print("RELAY_V2_STARTED", IFACE, "v4" if HAS4 else "", "v6" if HAS6 else "", flush=True)

BLOCKED4 = {ipaddress.ip_address("255.255.255.255"), ipaddress.ip_address(BROADCAST4) if BROADCAST4 else None}
BLOCKED6 = {ipaddress.ip_address("ff02::1"), ipaddress.ip_address(BROADCAST6) if ":" in BROADCAST6 else None}
BLOCKED4.discard(None)
BLOCKED6.discard(None)


def send4(src_s, dport, payload, members):
    for m in members:
        if m == src_s:
            continue  # не эхом инициатору его же broadcast (фикс аудита)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, RELAY_MARK)
            s.bind((src_s, 0))
            s.sendto(payload, (m, dport))
            print("TX4", src_s, "->", m, dport, flush=True)
        except OSError as _e:
            print("TX4", src_s, "->", m, dport, "ERR", _e, flush=True)
        finally:
            s.close()


def send6(src_s, dport, payload, members):
    for m in members:
        if m == src_s:
            continue  # не эхом инициатору (фикс аудита)
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_IPV6, socket.IPV6_TRANSPARENT, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, RELAY_MARK)
            s.bind((src_s, 0))
            s.sendto(payload, (m, dport))
            print("TX6", src_s, "->", m, dport, flush=True)
        except OSError as _e:
            print("TX6", src_s, "->", m, dport, "ERR", _e, flush=True)
        finally:
            s.close()


def main():
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    pkt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    try:
        pkt.bind((IFACE, 0))
    except OSError as _e:
        print("BIND_ERR", _e, flush=True)
        sys.exit(1)  # фикс аудита-C3: раньше «молчаливый успех» с exit 0
    while True:
        try:
            pkt.settimeout(0.4)
            frame, _a = pkt.recvfrom(65535)
        except (socket.timeout, OSError):
            continue
        if len(frame) < 20:
            continue
        try:
            if frame[0] >> 4 == 4:
                ihl = (frame[0] & 0xF) * 4
                if frame[9] != 17 or ihl + 8 > len(frame):
                    continue
                src_s = socket.inet_ntoa(frame[12:16])
                dst_s = socket.inet_ntoa(frame[16:20])
                try:
                    dst_ip = ipaddress.ip_address(dst_s)
                except ValueError:
                    continue
                if dst_ip not in BLOCKED4:
                    continue
                ulen = struct.unpack("!H", frame[ihl + 4:ihl + 6])[0]
                if ulen < 8 or ihl + ulen > len(frame):
                    continue
                dport = struct.unpack("!H", frame[ihl + 2:ihl + 4])[0]
                payload = frame[ihl + 8:ihl + ulen]
                for m4, s4, _m6, _s6 in GROUPS:
                    if any(ipaddress.ip_address(src_s) in n for n in s4):
                        print("RX4", src_s, dst_s, dport, flush=True)
                        send4(src_s, dport, payload, m4)
                        break
            elif frame[0] >> 4 == 6:
                if frame[6] != 17:
                    continue
                src_s = socket.inet_ntop(socket.AF_INET6, frame[8:24])
                dst_s = socket.inet_ntop(socket.AF_INET6, frame[24:40])
                try:
                    dst_ip = ipaddress.ip_address(dst_s)
                except ValueError:
                    continue
                if dst_ip not in BLOCKED6:
                    continue
                ulen = struct.unpack("!H", frame[4:6])[0]
                if ulen < 8 or 40 + ulen > len(frame):
                    continue
                dport = struct.unpack("!H", frame[42:44])[0]
                payload = frame[48:40 + ulen]
                for _m4, _s4, m6, s6 in GROUPS:
                    if any(ipaddress.ip_address(src_s) in n for n in s6):
                        print("RX6", src_s, dst_s, dport, flush=True)
                        send6(src_s, dport, payload, m6)
                        break
        except Exception:
            continue


if __name__ == "__main__":
    main()
PYEOF
  chmod +x "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.py" 2>/dev/null || true
  BC_RELAY_MARK=$BC_RELAY_MARK BC_RELAY_GROUPS="$BC_RELAY_GROUPS" BC_RELAY_IFACE="$TUN" BC_RELAY_BC4="$BROADCAST_ADDR" nohup python3 "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.py" > "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.log" 2>&1 &
  echo $! > "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" 2>/dev/null || true
  # Liveness-проверка (фикс аудита-PF-24 + регресс): поллинг до 3с — холодный
  # python3-старт может превышать 0.4с; проверяем и маркер RELAY_V2_STARTED в
  # логе (процесс реально дошёл до main), и kill -0 (pidfile не от мёртвого).
  _rly_ok=0
  for _try in $(seq 1 30); do
    _rpid=$(cat "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" 2>/dev/null || true)
    if [ -n "$_rpid" ] && kill -0 "$_rpid" 2>/dev/null \
       && grep -q 'RELAY_V2_STARTED' "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.log" 2>/dev/null; then
      _rly_ok=1; break
    fi
    if [ -z "$_rpid" ] || ! kill -0 "$_rpid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [ "$_rly_ok" = "1" ]; then
    echo "✅ bc_relay ${TUN_SAFE} запущен (pid $_rpid)"
  else
    echo "⚠️  bc_relay для ${TUN_SAFE} не запустился (см. .data/bc_relay_${TUN_SAFE}.log) — broadcast/multicast доставляться не будут" >&2
    tail -3 "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.log" 2>/dev/null | sed 's/^/    /' >&2
    rm -f "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" 2>/dev/null || true
  fi
  echo "🚀 Relay broadcast запущен для ${TUN_SAFE} (марка $BC_RELAY_MARK, групп: $(echo "$BC_RELAY_GROUPS" | tr -cd ';' | wc -c))"
fi

# --- Добавление правил для каждого проброса ---

# Обработка правил проброски портов
declare -A GLOBAL_SNAT_RULES_ADDED
# Если есть DDOS-правила И правила пробросов — выводим сообщение
if [ ${#PORT_FORWARDING_DDOS[@]} -gt 0 ] && [ ${#PORT_FORWARDING_RULES[@]} -gt 0 ]; then
  echo "🛡️ Применение DDoS защиты для проброшенных портов"
fi
for rule in "${PORT_FORWARDING_RULES[@]}"; do

  # Разбор правила: новый формат CLIENT_IP:PORT[>PORT]:PROTO[:FLAGS][:SUBNETS]
  # FLAGS: SNAT,интерфейс или интерфейс,SNAT (порядок не важен)
  # Подсети через : (содержат /)

  # Ищем подсети (содержат /) — они всегда в конце
  ALLOWED_SUBNETS=""
  MAIN_PART="$rule"

  if [[ "$rule" == *"/"* ]]; then
    # Подсети — в КОНЦЕ правила, после последнего ':'. Хвост должен быть
    # МАКСИМАЛЬНЫМ: '…TCP:fd00:bb::/112' — это subnet 'fd00:bb::/112', а НЕ
    # flags 'fd00' + subnet 'bb::/112' (левомайстовый re-search до '$' даёт
    # самый длинный валидный хвост; баг 1.19). Функция — в скрипте параметров.
    SUBNET_SPLIT="$(split_rule_subnets "$rule")"
    MAIN_PART="${SUBNET_SPLIT%%|*}"
    ALLOWED_SUBNETS="${SUBNET_SPLIT#*|}"
    # Убираем trailing ':' из MAIN_PART (от '::' в клиентском IPv6 / разделителя)
    MAIN_PART="${MAIN_PART%:}"
  fi

  # Считаем количество ':' в основной части
  colon_count=$(echo "$MAIN_PART" | tr -cd ':' | wc -c)

  if [ "$colon_count" -lt 1 ]; then
    echo "Ошибка: неверный формат правила '$rule' (минимум CLIENT_IP:PORT)"
    continue
  fi

  # Разбираем MAIN_PART с конца — ищем порт, протокол, FLAGS
  # Формат: CLIENT_IP:PORT[:PROTO][:FLAGS]
  # CLIENT_IP может быть IPv4, IPv6 или список через запятую
  # PORT может быть диапазоном: 80-90 или 80>8080
  # PROTO: TCP, UDP или TCP,UDP
  # FLAGS: SNAT, интерфейс или SNAT,interface
  
  PF_PROTO=""
  PF_PORT_PROTO=""
  CLIENT_IP=""
  SNAT_REQUESTED=""
  INTERFACE=""
  
  # Разбиваем MAIN_PART по ':' и собираем поля с конца
  IFS=':' read -ra FIELDS <<< "$MAIN_PART"
  NUM_FIELDS=${#FIELDS[@]}
  
  # Минимум 2 поля: CLIENT_IP:PORT
  if [ $NUM_FIELDS -lt 2 ]; then
    echo "Ошибка: неверный формат правила '$rule' (минимум CLIENT_IP:PORT)"
    continue
  fi
  
  # Последнее поле — проверяем на FLAGS (SNAT или имя интерфейса)
  LAST_IDX=$((NUM_FIELDS - 1))
  LAST_FIELD="${FIELDS[$LAST_IDX]}"
  
  # Предпоследнее поле — проверяем на протокол или порт
  PREV_IDX=$((NUM_FIELDS - 2))
  PREV_FIELD="${FIELDS[$PREV_IDX]}"

  # Парсим с конца: сначала проверяем протокол, потом флаги
  if is_proto_field "$LAST_FIELD"; then
    # Последнее поле — протокол
    PF_PROTO="$LAST_FIELD"
    PF_PORT_PROTO="$PREV_FIELD"
    # CLIENT_IP — всё до порта
    CLIENT_IP=""
    for ((i=0; i<NUM_FIELDS-2; i++)); do
      [ $i -gt 0 ] && CLIENT_IP+=":"
      CLIENT_IP+="${FIELDS[$i]}"
    done
  elif is_flags_field "$LAST_FIELD"; then
    # Последнее поле — FLAGS
    parse_flags "$LAST_FIELD"
    SNAT_REQUESTED="$PARSED_SNAT"
    INTERFACE="$PARSED_IFACE"
    # 'ALL' в роли интерфейса = «все интерфейсы» (без -i; иначе правило
    # никогда не сматчится на реальных интерфейсах)
    if [ "$INTERFACE" = "ALL" ] || [ "$INTERFACE" = "all" ]; then
      INTERFACE=""
    fi

    if is_proto_field "$PREV_FIELD"; then
      # :PORT:PROTO:FLAGS
      PF_PROTO="$PREV_FIELD"
      # Порт — всё что между CLIENT_IP и PROTO
      PF_PORT_PROTO="${FIELDS[$((NUM_FIELDS - 3))]}"
      # CLIENT_IP — всё до порта
      CLIENT_IP=""
      for ((i=0; i<NUM_FIELDS-3; i++)); do
        [ $i -gt 0 ] && CLIENT_IP+=":"
        CLIENT_IP+="${FIELDS[$i]}"
      done
    else
      # :PORT:FLAGS (без протокола)
      PF_PROTO=""
      PF_PORT_PROTO="$PREV_FIELD"
      # CLIENT_IP — всё до порта
      CLIENT_IP=""
      for ((i=0; i<NUM_FIELDS-2; i++)); do
        [ $i -gt 0 ] && CLIENT_IP+=":"
        CLIENT_IP+="${FIELDS[$i]}"
      done
    fi
  else
    # Последнее поле — порт (без протокола и FLAGS)
    PF_PROTO=""
    PF_PORT_PROTO="$LAST_FIELD"
    # CLIENT_IP — всё до порта
    CLIENT_IP=""
    for ((i=0; i<NUM_FIELDS-1; i++)); do
      [ $i -gt 0 ] && CLIENT_IP+=":"
      CLIENT_IP+="${FIELDS[$i]}"
    done
  fi

  # Обработка протокола
  if [ -z "$CLIENT_IP" ]; then
    echo "Ошибка: в правиле '$rule' не указан клиент (IP)"
    continue
  fi
  if [ -z "$PF_PROTO" ]; then
    PF_PROTOCOLS=("TCP" "UDP")
  else
    PF_PROTOCOLS=()
    IFS=',' read -ra proto_parts <<< "$PF_PROTO"
    for p in "${proto_parts[@]}"; do
      p="${p// /}"
      p_upper=$(echo "$p" | tr '[:lower:]' '[:upper:]')
      if [ "$p_upper" = "TCP" ] || [ "$p_upper" = "UDP" ]; then
        # Проверяем дубликаты
        found=0
        for existing in "${PF_PROTOCOLS[@]}"; do
          [ "$existing" = "$p_upper" ] && found=1 && break
        done
        [ $found -eq 0 ] && PF_PROTOCOLS+=("$p_upper")
      fi
    done
    if [ ${#PF_PROTOCOLS[@]} -eq 0 ]; then
      PF_PROTOCOLS=("TCP" "UDP")
    fi
  fi

  # Проверка на пустой порт
  if [ -z "$PF_PORT_PROTO" ] || [ "$PF_PORT_PROTO" = ">" ]; then
    echo "Ошибка: пустой порт в правиле '$rule'"
    continue
  fi

  # Проверка что порт это число или диапазон
  port_check="${PF_PORT_PROTO//-/}"
  port_check="${port_check//>/}"
  if ! [[ "$port_check" =~ ^[0-9]+$ ]]; then
    echo "Ошибка: неверный порт '$PF_PORT_PROTO' в правиле '$rule'"
    continue
  fi

  # Поддержка списка CLIENT_IP через запятую (IPv4, IPv6 или оба)
  CLIENT_IP_ARRAY=()
  IFS=',' read -ra RAW_CLIENT_IPS <<< "$CLIENT_IP"
  for cip in "${RAW_CLIENT_IPS[@]}"; do
    cip="$(echo "$cip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -n "$cip" ] && CLIENT_IP_ARRAY+=("$cip")
  done

  if [ ${#CLIENT_IP_ARRAY[@]} -eq 0 ]; then
    echo "Ошибка: не указан клиентский IP в правиле '$rule'"
    continue
  fi

  # Валидация формата клиентских IP (фикс аудита-PF-24): невалидный IP
  # раньше молча ставил DNAT в никуда (iptables тихо пропускал). Строгая
  # проверка через python ipaddress — char-class принимала мусор вида 'fd00:::1'
  # и отклоняла валидные IPv4-mapped ('::ffff:10.0.0.1'; фикс регресса).
  for cip in "${CLIENT_IP_ARRAY[@]}"; do
    if SUBNET_ARG="$cip" python3 -c \
       "import ipaddress,os; ipaddress.ip_address(os.environ['SUBNET_ARG'])" 2>/dev/null; then
      :
    else
      echo "Ошибка: невалидный клиентский IP '$cip' в правиле '$rule'"
      continue 2
    fi
  done

  # Подготовка массива подсетей
  if [ -z "$ALLOWED_SUBNETS" ]; then
    USE_SUBNETS=0
    ALLOWED_SUBNETS_DISPLAY="ALL"
    SUBNETS_ARRAY=()
  else
    USE_SUBNETS=1
    SUBNETS_ARRAY=()
    ALLOWED_SUBNETS_DISPLAY="$ALLOWED_SUBNETS"
    IFS=',' read -ra RAW_SUBNETS <<< "$ALLOWED_SUBNETS"
    for s in "${RAW_SUBNETS[@]}"; do
      s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -n "$s" ] && SUBNETS_ARRAY+=("$s")
    done
  fi

  # Разбор внешнего/внутреннего портов
  IFS='>' read -r PF_PORT_EXT PF_PORT_INT <<< "$PF_PORT_PROTO"
  [ -z "$PF_PORT_INT" ] && PF_PORT_INT="$PF_PORT_EXT"

  # Валидация портов/диапазонов (фикс аудита-PF-24): 0/65536+/обратные
  # диапазоны и нечисла раньше молча ставили НИЧЕГО (DNAT не создавался).
  # Ошибка ЛЮБОЙ стороны → правило целиком пропускается (continue 2; фикс
  # регресса: continue внутри _pd-цикла пропускал только вторую сторону и
  # правило всё равно применялось + печатался ложный «открыт»).
  for _pd in "$PF_PORT_EXT" "$PF_PORT_INT"; do
    if [[ "$_pd" == *"-"* ]]; then
      if [[ "$_pd" == *-*-* ]]; then
        echo "Ошибка: более одного '-' в диапазоне портов '$_pd' в правиле '$rule'"
        continue 2
      fi
      _p1="${_pd%%-*}"; _p2="${_pd##*-}"
      if ! [[ "$_p1" =~ ^[1-9][0-9]*$ && "$_p2" =~ ^[1-9][0-9]*$ ]] \
         || [ "$_p1" -gt 65535 ] || [ "$_p2" -gt 65535 ] || [ "$_p1" -gt "$_p2" ]; then
        echo "Ошибка: неверный диапазон портов '$_pd' в правиле '$rule'"
        continue 2
      fi
    else
      if ! [[ "$_pd" =~ ^[1-9][0-9]*$ ]] || [ "$_pd" -gt 65535 ]; then
        echo "Ошибка: порт '$_pd' вне 1..65535 в правиле '$rule'"
        continue 2
      fi
    fi
  done

  # Определяем опцию интерфейса если указан
  IFACE_OPT=""
  if [ -n "$INTERFACE" ]; then
    IFACE_OPT="-i $INTERFACE"
  fi

  # Проходим по всем протоколам (TCP и/или UDP)
  for PF_PROTO in "${PF_PROTOCOLS[@]}"; do
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

      # ВАЖНО: Если IPv6 серверный IP пустой — SNAT для IPv6 НЕ РАБОТАЕТ!
      # Нельзя использовать IPv4 адрес для SNAT IPv6 трафика!
      # SNAT_FLAG — локальная переменная для этого CLIENT_IP
      if [ -z "$SERVER_IP" ]; then
        echo "⚠️  Предупреждение: IPv6 SNAT отключен для $CLIENT_IP (нет IPv6 адреса сервера)"
        SNAT_FLAG=""  # Отключаем SNAT для этого CLIENT_IP
      else
        # Используем SNAT_REQUESTED из правила
        SNAT_FLAG="$SNAT_REQUESTED"
      fi

      # Для DNAT IPv6 адреса нужно оборачивать в квадратные скобки: [IPv6]:port
      CLIENT_IP_DNAT="[$CLIENT_IP]"
      # ВАЖНО: Уникальный ключ SNAT для IPv6 (чтобы не конфликтовал с IPv4)
      SNAT_IP_PREFIX="ipv6:"
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
      # Уникальный ключ SNAT для IPv4
      SNAT_IP_PREFIX="ipv4:"
      # ВАЖНО: Если IPv4 серверный IP пустой — SNAT для IPv4 НЕ РАБОТАЕТ!
      if [ -z "$SERVER_IP" ]; then
        echo "⚠️  Предупреждение: IPv4 SNAT отключен для $CLIENT_IP (нет IPv4 адреса сервера)"
        SNAT_FLAG=""  # Отключаем SNAT для этого CLIENT_IP
      else
        # Используем SNAT_REQUESTED из правила
        SNAT_FLAG="$SNAT_REQUESTED"
      fi
    fi

    # Если подсети заданы, но для семейства этого клиента их нет — НЕ открываем
    # доступ всем (раньше уходили в ветку "доступ всем" — fail-open; баг 1.20)
    if [ "$USE_SUBNETS" = "1" ] && [ ${#FILTERED_SUBNETS[@]} -eq 0 ]; then
      echo "⚠️  Пропуск $CLIENT_IP: нет подсетей этого семейства (${ALLOWED_SUBNETS_DISPLAY})"
      continue
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
          continue 3
        fi
        for ((i=0; i<=RANGE_LEN; i++)); do
          EXT_PORT=$((PF_PORT_EXT_START + i))
          INT_PORT=$((PF_PORT_INT_START + i))
          if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
            for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$EXT_PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$INT_PORT"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO (глобально!)
              # ВАЖНО: Добавляем префикс ipv4:/ipv6 для уникальности между протоколами
              snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${INT_PORT}:${PF_PROTO}"
              if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
$IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$SERVER_IP"
              GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
            fi
            pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$EXT_PORT" "$INT_PORT" "$ALLOWED_SUBNET"
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            # доступ всем — без -s / -d
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$EXT_PORT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$INT_PORT"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO (глобально!)
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${INT_PORT}:${PF_PROTO}"
            if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$SERVER_IP"
              GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
            fi
            pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$EXT_PORT" "$INT_PORT" ""
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ]; then
            echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
          else
            echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
          fi
        done
        # После обработки обоих диапазонов — завершаем обработку этого CLIENT_IP
        continue
    fi
    # 2. Внешний диапазон, внутренний одиночный порт
    if [[ "$PF_PORT_EXT" == *"-"* ]] && [[ "$PF_PORT_INT" != *"-"* ]]; then
        PF_PORT_START="${PF_PORT_EXT%-*}"
        PF_PORT_END="${PF_PORT_EXT#*-}"
        for ((PORT_NUM=PF_PORT_START; PORT_NUM<=PF_PORT_END; PORT_NUM++)); do
          if [ ${#FILTERED_SUBNETS[@]} -gt 0 ]; then
            for ALLOWED_SUBNET in "${FILTERED_SUBNETS[@]}"; do
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PORT_NUM" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO (используем внутренний порт!)
              snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
              if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
                GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
              fi
              pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PORT_NUM" "$PF_PORT_INT" "$ALLOWED_SUBNET"
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PORT_NUM" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
              if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
                GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
              fi
              pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PORT_NUM" "$PF_PORT_INT" ""
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ]; then
            echo "$PF_PROTO порт $PORT_NUM->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
          else
            echo "$PF_PROTO порт $PORT_NUM->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
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
              $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
              # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
              snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
              if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
                GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
              fi
              pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PF_PORT_EXT" "$PORT_NUM" "$ALLOWED_SUBNET"
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
            if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
              GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
            fi
            pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PF_PORT_EXT" "$PORT_NUM" ""
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -m state --state RELATED,ESTABLISHED -j ACCEPT
          fi

          if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ]; then
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
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:PF_PORT_INT:PROTO
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
            if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
              GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
            fi
            pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PF_PORT_EXT" "$PF_PORT_INT" "$ALLOWED_SUBNET"
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
          done
        else
          $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
          snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
          if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
            $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
            GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
          fi
          pf_accept_or_ddos "$IPT_CMD" "$PF_PROTO" "$CLIENT_IP" "$PF_PORT_EXT" "$PF_PORT_INT" ""
          $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -m state --state RELATED,ESTABLISHED -j ACCEPT
        fi

        if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ]; then
          echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (SNAT)"
        else
          echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${ALLOWED_SUBNETS_DISPLAY} (no SNAT)"
        fi
    # Конец обработки всех вариантов портов
  done
  # Конец цикла по CLIENT_IP_ARRAY
done
done
# Конец цикла по PORT_FORWARDING_RULES

# Квоты трафика: массив TRAFFIC_QUOTAS из скрипта параметров (<tun>.sh).
  # Формат правила: "подсети:объём:период" (объём: b/k/m/g/t; период:
  # hour|day|week|month). Квота клиента = объём × вес (вес = число адресов
  # его блока/юнита выдачи) — математика как у лимитов скорости.
  # Работают и при включённых лимитах скорости: xt_quota (iptables) не пересекается с tc.
# Сериализация ВСЕЙ квотной секции с cron-проходом (фикс волны-2 аудита):
# lock берётся ДО слепока/teardown и держится до конца throttle-фазы —
# иначе up∥cron давали last-writer-wins по журналу и потерю дельты счётчиков
# при -F. Таймаут 600с: up ждёт завершения долгого cron-прохода; если всё же
# не дождались — предупреждение и продолжение (лучше примениться, чем оставить
# туннель без квот до следующего up).
exec 8>"${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.cron.lock"
flock -w 600 8 2>/dev/null || echo "⚠️ quota: не удалось дождаться cron-lock (600с) — применяюсь без сериализации" >&2
# Слепок расхода ДО безусловной очистки цепочек (фикс аудита-5x5): up поверх
# запущенного туннеля иначе терял расход с последнего снапшота (до часа при
# cron) — счётчики xt_quota живы до -F/-X, а восстановление остатков идёт из
# журнала. Исчерпавший до up клиент остаётся исчерпанным.
if [ -f "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.ledger" ]; then
  LEDGER_FILE="$SCRIPT_DIR/.data/quota/${TUN_SAFE}.ledger"
  declare -A LEDGER_PRE
  while IFS='|' read -r _lk _lp _ld _ll _ls _lr _lt _lb; do
    [ -z "$_lk" ] && continue
    LEDGER_PRE["$_lk|$_lp|$_ld"]="$_ll|$_ls|$_lr|$_lt|${_lb:-0}"
  done < "$LEDGER_FILE"
  declare -A LEDGER_PRE_NEW
  for _key in "${!LEDGER_PRE[@]}"; do
    _set="${_key%%|*}"; _pq="${_key#*|}"
    _pper="${_pq%%|*}"; _pdir="${_pq##*|}"
    _llim="${LEDGER_PRE[$_key]%%|*}"
    _lrest="${LEDGER_PRE[$_key]#*|}"
    _lspen="${_lrest%%|*}"; _lrest="${_lrest#*|}"; _lrt="${_lrest%%|*}"
    _lrest="${_lrest#*|}"; _lrest="${_lrest#*|}"
    _oldsnp="${_lrest%%|*}"
    _snp=$(snapshot_spent "$_set" "$_pper" "$_pdir")
    _delta=$(( _snp - _oldsnp )); [ "$_delta" -lt 0 ] && _delta=0
    _lspen=$(( _lspen + _delta ))
    LEDGER_PRE_NEW["$_key"]="$_llim|$_lspen|$_lrt|$(date +%s)|0"
  done
  : > "${LEDGER_FILE}.tmp.$$"
  for _lk in "${!LEDGER_PRE_NEW[@]}"; do
    echo "$_lk|${LEDGER_PRE_NEW[$_lk]}" >> "${LEDGER_FILE}.tmp.$$"
  done
  mv -f "${LEDGER_FILE}.tmp.$$" "$LEDGER_FILE"
fi
# Безусловная очистка старых квотных артефактов (выполняется и когда
# TRAFFIC_QUOTAS выключен): раньше teardown жил внутри guard и при пустом
# массиве повторный up оставлял висящие цепочки/прыжки с хвостовым DROP —
# клиенты оставались заблокированными (фикс аудита-T2/T9).
for _qc in $(iptables-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)" | sort -u); do
  iptables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
    _rule="${_line#-A }"
    iptables -D $_rule 2>/dev/null || true
  done
  iptables -F "$_qc" 2>/dev/null || true
  iptables -X "$_qc" 2>/dev/null || true
done
for _qc in $(ip6tables-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)" | sort -u); do
  ip6tables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
    _rule="${_line#-A }"
    ip6tables -D $_rule 2>/dev/null || true
  done
  ip6tables -F "$_qc" 2>/dev/null || true
  ip6tables -X "$_qc" 2>/dev/null || true
done
for _qc in $(iptables-save 2>/dev/null | grep -oE "Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u); do
  iptables -F "$_qc" 2>/dev/null || true
  iptables -X "$_qc" 2>/dev/null || true
done
for _qc in $(ip6tables-save 2>/dev/null | grep -oE "Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u); do
  ip6tables -F "$_qc" 2>/dev/null || true
  ip6tables -X "$_qc" 2>/dev/null || true
done
for _qs in $(ipset list -name 2>/dev/null | grep -E "^Q_${TUN_SAFE}_|^QT_${TUN_SAFE}_" || true); do
  ipset destroy "$_qs" 2>/dev/null || true
done
if [ "${#TRAFFIC_QUOTAS[@]}" -gt 0 ]; then

# Ограничение ОБЪЁМА трафика (xt_quota) по периодам из TRAFFIC_QUOTAS.
  # Ядро само считает байты и перестаёт матчить правило при исчерпании; в конце
  # подцепочки — DROP. Сброс периодов выполняет quota_update (cron, раз в час).
  # ВАЖНО: блок квот НЕ зависит от SUBNETS_LIMITS (лимитов скорости) —
  # квоты работают и без них.
  # Период-ключи: H, D3, W2, M4, D_T20, W_T5, M_T15, D3_T20...
  # Каждая кратность/точка — своей цепочки/сброса.
  # Формат правила: "подсети : [ап][:даун] : срок : [throttle..]"; режим квоты
  # ALL (общий пул ап+даун) при одном объёме, SEP (раздельно) при двух.
  # Throttle (послеквотный): 4-е поле — "скорость" (оба направления, режим 1)
  # или "ап:даун" (режим 2); применяется через HTB-классы на IFB (без марок).
  declare -A QUOTA_PAIR
  declare -A CL_BLOCK4 CL_BLOCK6   # набор → адреса клиента (план по набору)
  declare -A THR_MAP THR_UP THR_DOWN THR_PERIOD  # (набор|период)→tm|tu|td; набор→min-скорость; набор|период→вооружён
  _thr_idx=0
  THROTTLE_BASE=16384   # 0x4000 (зарезервировано; марки НЕ используются)
  THROTTLE_OVERFLOW_WARN=0
  THROTTLE_PAIRS=""
  # Гарантированная чистка старых mangle-правил throttle (прошлые сборки);
  # ПОСТРОЧНО (for $() разбил бы правила с пробелами на слова — не удалил бы).
  while IFS= read -r _qc; do
    [ -z "$_qc" ] && continue
    _qc="${_qc#-A }"
    iptables -t mangle -D $_qc 2>/dev/null || true
  done < <(iptables-save -t mangle 2>/dev/null | grep "QT_${TUN_SAFE}_")
  while IFS= read -r _qc; do
    [ -z "$_qc" ] && continue
    _qc="${_qc#-A }"
    ip6tables -t mangle -D $_qc 2>/dev/null || true
  done < <(ip6tables-save -t mangle 2>/dev/null | grep "QT_${TUN_SAFE}_")

  quota_build_period() {
    # Сборка цепочек периода из пар "set:MODE:up:down[:qu:qd]" (лимиты уже
    # взвешены; qu/qd — остатки после перезапуска, фолбэк — полные лимиты).
    #  SEP: SRC-цепочка — ап (src∈set), DST — даун (dst∈set), раздельные квоты.
    #  ALL: ОБЩИЙ пул — per-клиентская цепочка Q_<tun>_<клиент>_<период>_A с
    #        единственным правилом -m quota (счётчик делится на оба направления);
    #        SRC/DST-цепочки прыгают в неё (семейство решает таблицу).
    local _suf="$1" _pairs="$2" _pai _est _pm _up _dn _qu _qd _allc
    for _qc in "QUOTA_${TUN_SAFE}_${_suf}_SRC" "QUOTA_${TUN_SAFE}_${_suf}_DST"; do
      iptables -N "$_qc" 2>/dev/null || iptables -F "$_qc"
      ip6tables -N "$_qc" 2>/dev/null || ip6tables -F "$_qc"
    done
    # Сначала (пере)создаём ALL-цепочки периода — чтобы SRC/DST могли прыгать в них
    for _pai in $_pairs; do
      _est="${_pai%%:*}"; _prest="${_pai#*:}"; _pm="${_prest%%:*}"; _prest="${_prest#*:}"
      _up="${_prest%%:*}"; _prest="${_prest#*:}"
      _dn="${_prest%%:*}"; _prest="${_prest#*:}"
      if [ -n "$_prest" ]; then
        _qu="${_prest%%:*}"; _qd="${_prest##*:}"
      else
        # 4-полевая пара (свежий цикл): остатки = полные лимиты
        _qu="$_up"; _qd="$_dn"
      fi
      if [ "$_pm" != "SEP" ]; then
        _allc=$(quota_all_name "$_est" "$_suf")
        case "$_est" in
          *_V4) iptables -N "$_allc" 2>/dev/null || iptables -F "$_allc" ;;
          *_V6) ip6tables -N "$_allc" 2>/dev/null || ip6tables -F "$_allc" ;;
        esac
      fi
    done
    for _pai in $_pairs; do
      _est="${_pai%%:*}"; _prest="${_pai#*:}"; _pm="${_prest%%:*}"; _prest="${_prest#*:}"
      _up="${_prest%%:*}"; _prest="${_prest#*:}"
      _dn="${_prest%%:*}"; _prest="${_prest#*:}"
      if [ -n "$_prest" ]; then
        _qu="${_prest%%:*}"; _qd="${_prest##*:}"
      else
        _qu="$_up"; _qd="$_dn"
      fi
      if [ "$_pm" = "SEP" ]; then
        case "$_est" in
          *_V4)
            # RETURN (не ACCEPT): неисчерпавший клиент продолжает обход
            # FORWARD/INPUT/OUTPUT (доходит до изоляции/WARP/лимитов), а не
            # «принимается» квотой (иначе межклиентская изоляция обходится;
            # аудит). Исчерпавший: правило не матчит → хвостовой DROP ниже.
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -m quota --quota "$_qu" -j RETURN
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -m quota --quota "$_qd" -j RETURN
            # Послеквотный throttle: обход хвостового DROP — только вооружённый
            # период и вооружённая сторона (per-period; фикс волны-2 аудита)
            _pthr=$(quota_period_thr "$_est" "$_suf")
            _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
            [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -gt 0 ] && iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
            [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -gt 0 ] && iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
            ;;
          *_V6)
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -m quota --quota "$_qu" -j RETURN
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -m quota --quota "$_qd" -j RETURN
            _pthr=$(quota_period_thr "$_est" "$_suf")
            _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
            [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -gt 0 ] && ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
            [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -gt 0 ] && ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
            ;;
        esac
      else
        _allc=$(quota_all_name "$_est" "$_suf")
        case "$_est" in
          *_V4)
            # ALL-цепочка: RETURN при живой квоте (продолжить обход), DROP при
            # исчерпании. В SRC/DST после прыжка в ALL-цепочку ставим RETURN —
            # чтобы вернувшийся из неё (неисчерпавший) продолжил FORWARD и не
            # упал в хвостовой DROP периода (аудит).
            iptables -A "$_allc" -m quota --quota "$_qu" -j RETURN
            # Вооружён ПЕРИОД (per-period, фикс волны-2 аудита): хвостовой DROP
            # не ставим только для исчерпанного throttle-периода; 0-стороны
            # добиваются catch'ами ниже (односторонний throttle). Для
            # невооружённых периодов — DROP строг.
            _pthr=$(quota_period_thr "$_est" "$_suf")
            if [ "${_pthr%%|*}" != "1" ]; then
              iptables -A "$_allc" -j DROP
            fi
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j "$_allc"
            # Обход после исчерпания — по стороне периода (0-сторона: DROP)
            _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
            if [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -le 0 ]; then
              iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j DROP
            else
              iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
            fi
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j "$_allc"
            if [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -le 0 ]; then
              iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j DROP
            else
              iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
            fi
            ;;
          *_V6)
            ip6tables -A "$_allc" -m quota --quota "$_qu" -j RETURN
            _pthr=$(quota_period_thr "$_est" "$_suf")
            if [ "${_pthr%%|*}" != "1" ]; then
              ip6tables -A "$_allc" -j DROP
            fi
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j "$_allc"
            _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
            if [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -le 0 ]; then
              ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j DROP
            else
              ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
            fi
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j "$_allc"
            if [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -le 0 ]; then
              ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j DROP
            else
              ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
            fi
            ;;
        esac
      fi
    done
    iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -j DROP
    iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -j DROP
    ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -j DROP
    ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -j DROP
  }

  quota_jump_del() {
    # Чистый паттерн (как в очистке FORWARD в up): один проход iptables-save,
    # каждая строка → отдельный iptables -D; без sed|bash и временных файлов.
    local _qc="$1"
    iptables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
      _rule="${_line#-A }"
      iptables -D $_rule 2>/dev/null || true
    done
    ip6tables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
      _rule="${_line#-A }"
      ip6tables -D $_rule 2>/dev/null || true
    done
  }

  quota_jump_period() {
    local _suf="$1" _est _pai
    # Направления (по наборам клиентов):
    #  FORWARD: -i TUN src∈set -> SRC (uplink клиента); -o TUN dst∈set -> DST (downlink КЛИЕНТУ).
    #  (Ошибочный вариант «-i TUN -d» не ловил входящий интернет-трафик — download
    #   не ограничивался; аудит-квот.)
    #  INPUT: -i TUN src∈set = клиент -> сам сервер; OUTPUT: -o TUN dst∈set = сервер -> клиент.
    # Прыгаем ТОЛЬКО наборами, имеющими правило в этом периоде (пары из
    # QUOTA_BUILD[$_suf]). Раньше брался глобальный $_QSETS → клиент периода
    # «week» попадал в цепочку «day» другого клиента, где его нет, и был убит
    # хвостовым DROP (кросс-периодная блокировка; аудит).
    for _pai in ${QUOTA_BUILD[$_suf]:-}; do
      _est="${_pai%%:*}"
      case "$_est" in
        *_V4)
          iptables -I FORWARD 1 -i "$TUN" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_suf}_SRC"
          iptables -I FORWARD 1 -o "$TUN" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_suf}_DST"
          iptables -I INPUT 1 -i "$TUN" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_suf}_SRC"
          iptables -I OUTPUT 1 -o "$TUN" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_suf}_DST"
          ;;
        *_V6)
          ip6tables -I FORWARD 1 -i "$TUN" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_suf}_SRC"
          ip6tables -I FORWARD 1 -o "$TUN" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_suf}_DST"
          ip6tables -I INPUT 1 -i "$TUN" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_suf}_SRC"
          ip6tables -I OUTPUT 1 -o "$TUN" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_suf}_DST"
          ;;
      esac
    done
  }

  # --- Квоты: per-клиентские наборы ipset (ОДИН лимит на ВСЕ адреса клиента) ---
  # Клиенты берём из конфига по секциям [Peer] (имя из #_Name) — независимо
  # от broadcast-ветки; наборы Q_<tun>_<клиент>_V4/V6; на каждый период одно
  # правило квоты на клиента на семейство (v4-часть и v6-часть — раздельные
  # счётчики xt_quota: netfilter физически не имеет общего счётчика на
  # обе таблицы; внутри семейства лимит ОБЩИЙ на все адреса клиента).
  # Проверка окружения квот (фикс аудита-fresh: exit 1 здесь прерывал ВЕСЬ up —
  # туннель оставался без лимитов/throttle/cron; теперь квоты пропускаются,
  # остальное применяется).
  QUOTA_ENV_OK=1
  if ! command -v ipset >/dev/null 2>&1; then
    echo "⚠️  ipset не установлен (apt install ipset) — квоты недоступны" >&2
    QUOTA_ENV_OK=0
  fi
  # Модуль xt_set обязателен для -m set (аудит: без него ACCEPT-правила не
  # вставали бы и клиенты получали чистый DROP).
  modprobe xt_set 2>/dev/null || true
  if ! iptables -m set -h >/dev/null 2>&1; then
    echo "⚠️  модуль xt_set недоступен (iptables -m set) — квоты недоступны" >&2
    QUOTA_ENV_OK=0
  fi
  if [ "${QUOTA_ENV_OK:-1}" = "1" ]; then
  for _qs in $(ipset list -name 2>/dev/null | grep -E "^Q_${TUN_SAFE}_|^QT_${TUN_SAFE}_" || true); do
    ipset destroy "$_qs" 2>/dev/null || true
  done
  _QSETS=""
  while IFS='|' read -r _qname _qips; do
    [ -z "$_qips" ] && continue
    _Q4=""; _Q6=""
    IFS=',' read -ra _qaddr <<< "$_qips"
    for _qa in "${_qaddr[@]}"; do
      # Сохраняем МАСКУ (фикс: «fd00::4/127» — блок клиента из соотношения;
      # раньше %%/* срезал маску и в набор попадал лишь один адрес блока,
      # остальные адреса клиентской группы не имели общего лимита).
      _qa="$(echo "$_qa" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      case "$_qa" in
        *:*) [ -n "$_Q6" ] && _Q6="$_Q6,"; _Q6="$_Q6$_qa" ;;
        *)   [ -n "$_Q4" ] && _Q4="$_Q4,"; _Q4="$_Q4$_qa" ;;
      esac
    done
    _qsafe="$(printf '%s' "${_qname:-client}" | tr -c 'A-Za-z0-9_.-' '_')"
    _qnamelen=${#TUN_SAFE}
    _qmax=$(( 22 - _qnamelen ))  # Q_ + TUN + _ + X + _V4 <= 31 (лимит имени ipset)
    [ "$_qmax" -lt 6 ] && _qmax=6
    if [ ${#_qsafe} -gt "$_qmax" ]; then
      _qsafe="$(printf '%s' "$_qsafe" | cut -c1-$(( _qmax - 7 )))$(printf '%s' "$_qsafe" | md5sum | cut -c1-6)"
    fi
    # План квоты КЛИЕНТА: ВСЕ совпавшие правила (НАЛОЖЕНИЕ периодов);
    # строка: "KEY MODE v4u v4d v6u v6d thrMode thrUp thrDown"
    _q4blk="${_Q4%%[,]*}"
    _q6blk="${_Q6%%[,]*}"
    _qplan=$(quota_client_plan "$_q4blk" "$_q6blk")
    _qany=0; _qv4=0; _qv6=0
    # СБРОС массива плана клиента: «declare -A _PL» сам по себе НЕ очищает
    # существующий ассоциативный массив (лишь задаёт атрибут) — без (=) ключи
    # и значения ПРЕДЫДУЩЕГО клиента оставались, и набор с чужим объёмом
    # попадал в чужой период (кросс-периодная блокировка/перепутанные лимиты;
    # фикс аудита-T2).
    declare -A _PL=()
    while IFS= read -r _pl; do
      [ -z "$_pl" ] && continue
      _ple="${_pl%% *}"
      [ "$_ple" = "N" ] && continue
      _qany=1
      _prest="${_pl#* }"; _pm="${_prest%% *}"
      _prest="${_prest#* }"; _pu4="${_prest%% *}"
      _prest="${_prest#* }"; _pd4="${_prest%% *}"
      _prest="${_prest#* }"; _pu6="${_prest%% *}"
      _prest="${_prest#* }"; _pd6="${_prest%% *}"
      _prest="${_prest#* }"; _ptm="${_prest%% *}"
      _prest="${_prest#* }"; _ptu="${_prest%% *}"
      _ptd="${_prest##* }"
      { [ "$_pu4" -gt 0 ] || [ "$_pd4" -gt 0 ]; } && _qv4=1
      { [ "$_pu6" -gt 0 ] || [ "$_pd6" -gt 0 ]; } && _qv6=1
      _PL["$_ple"]="$_pm|$_pu4|$_pd4|$_pu6|$_pd6|$_ptm|$_ptu|$_ptd"
    done <<< "$_qplan"
    # Наборы создаём, если семейство квотируется хотя бы одним правилом
    _qset4=""; _qset6=""
    if [ "$_qany" = "1" ] && [ "$_qv4" = "1" ] && [ -n "$_Q4" ]; then
      _qset4="Q_${TUN_SAFE}_${_qsafe}_V4"
      ipset create "$_qset4" hash:net family inet 2>/dev/null || ipset flush "$_qset4" 2>/dev/null || true
      for _qa in $(echo "$_Q4" | tr ',' ' '); do ipset add "$_qset4" "$_qa" 2>/dev/null || true; done
      _QSETS="$_QSETS $_qset4"
      CL_BLOCK4["$_qset4"]="$_Q4"
    fi
    if [ "$_qany" = "1" ] && [ "$_qv6" = "1" ] && [ -n "$_Q6" ]; then
      _qset6="Q_${TUN_SAFE}_${_qsafe}_V6"
      ipset create "$_qset6" hash:net family inet6 2>/dev/null || ipset flush "$_qset6" 2>/dev/null || true
      for _qa in $(echo "$_Q6" | tr ',' ' '); do ipset add "$_qset6" "$_qa" 2>/dev/null || true; done
      _QSETS="$_QSETS $_qset6"
      CL_BLOCK6["$_qset6"]="$_Q6"
    fi
    for _ple in "${!_PL[@]}"; do
      _pb="${_PL[$_ple]}"
      _pm="${_pb%%|*}"; _pb="${_pb#*|}"
      _pu4="${_pb%%|*}"; _pb="${_pb#*|}"; _pd4="${_pb%%|*}"; _pb="${_pb#*|}"
      _pu6="${_pb%%|*}"; _pb="${_pb#*|}"; _pd6="${_pb%%|*}"; _pb="${_pb#*|}"
      _ptm="${_pb%%|*}"; _pb="${_pb#*|}"; _ptu="${_pb%%|*}"; _ptd="${_pb##*|}"
      if [ -n "$_qset4" ] && { [ "$_pu4" -gt 0 ] || [ "$_pd4" -gt 0 ]; }; then
        QUOTA_PAIR["$_ple"]="${QUOTA_PAIR[$_ple]:-} ${_qset4}:${_pm}:$_pu4:$_pd4"
        THR_MAP["$_qset4|$_ple"]="$_ptm|$_ptu|$_ptd"
      fi
      if [ -n "$_qset6" ] && { [ "$_pu6" -gt 0 ] || [ "$_pd6" -gt 0 ]; }; then
        QUOTA_PAIR["$_ple"]="${QUOTA_PAIR[$_ple]:-} ${_qset6}:${_pm}:$_pu6:$_pd6"
        THR_MAP["$_qset6|$_ple"]="$_ptm|$_ptu|$_ptd"
      fi
    done
  done <<< "$(parse_peer_sections "$SERVER_CONF_FILE")"
  # --- Конец: per-клиентские наборы ipset + план квот ---

  # --- Журнал квот (ledger): восстановление расхода и сроков, чистка призраков ---
  # Формат строки: <set>|<period>|<limit>|<spent>|<reset_ts>|<snap_ts>
  # При up: известные правила восстанавливают остаток (лимит − израсходовано);
  # если период истёк за время простоя — полный новый цикл; записи правил,
  # которых больше нет, удаляются (призраки не воскресают).
  mkdir -p "$SCRIPT_DIR/.data/quota" 2>/dev/null || true
  chmod 700 "$SCRIPT_DIR/.data" "$SCRIPT_DIR/.data/quota" 2>/dev/null || true
  LEDGER_FILE="$SCRIPT_DIR/.data/quota/${TUN_SAFE}.ledger"
  declare -A LEDGER
  if [ -f "$LEDGER_FILE" ]; then
    # Журнал в формате set|period|НАПРАВЛЕНИЕ|limit|spent|reset_ts|snap_ts|snap_bytes
    while IFS='|' read -r _lk _lp _ld _ll _ls _lr _lt _lb; do
      [ -z "$_lk" ] && continue
      LEDGER["$_lk|$_lp|$_ld"]="$_ll|$_ls|$_lr|$_lt|${_lb:-0}"
    done < "$LEDGER_FILE"
  fi
  declare -A LEDGER_NEW
  declare -A QUOTA_BUILD
  _now=$(date +%s)
  for _p in "${!QUOTA_PAIR[@]}"; do
    for _pai in ${QUOTA_PAIR[$_p]}; do
      _set="${_pai%%:*}"; _prest="${_pai#*:}"
      _pm="${_prest%%:*}"; _prest="${_prest#*:}"
      _up="${_prest%%:*}"; _dn="${_prest##*:}"
      # Throttle-карта этого (набор, период): tm|tu|td
      _qthr="${THR_MAP[$_set|$_p]:-0}"
      _qtm=0; _qtu=0; _qtd=0
      if [ -n "$_qthr" ] && [ "$_qthr" != "0" ]; then
        _qtm="${_qthr%%|*}"; _qrest="${_qthr#*|}"; _qtu="${_qrest%%|*}"; _qtd="${_qrest##*|}"
      fi
      # Режим квоты: ALL = ОДИН общий счётчик (ап+даун), SEP = раздельно
      # SRC(ап) / DST(даун). Журнал и сбросы — по ключу set|period|НАПРАВЛЕНИЕ.
      if [ "$_pm" = "SEP" ]; then _dirs="SRC DST"; else _dirs="ALL"; fi
      # Остатки по направлениям: по умолчанию полные лимиты (нет записи журнала
      # → свежий цикл); внутри цикла _dir перекрываются фактическим остатком.
      _qu="$_up"; _qd="$_dn"
      for _dir in $_dirs; do
        if [ "$_dir" = "SRC" ]; then _lim="$_up"
        elif [ "$_dir" = "DST" ]; then _lim="$_dn"
        else _lim="$_up"; fi
        _key="$_set|$_p|$_dir"
        _qr="$_lim"; _lspent=0
        # Новая запись: для периодов с точкой-фазой («*_T*») выравниваем фазу
        # (последняя граница), для чистых окон — момент создания.
        if [[ "$_p" == *_T* ]]; then _lrt=$(period_last "$_now" "$_p"); else _lrt="$_now"; fi
        if [ -n "${LEDGER[$_key]:-}" ]; then
          _lold="${LEDGER[$_key]%%|*}"; _lrest="${LEDGER[$_key]#*|}"
          _lspent="${_lrest%%|*}"; _lrest="${_lrest#*|}"; _lrt="${_lrest%%|*}"
          if [ "$_lold" = "$_lim" ]; then
            if period_is_point "$_p"; then
              _nx=$(period_next "$_lrt" "$_p")
              if [ "$_now" -ge "$_nx" ]; then
                # точка истекла: новый цикл с последней календарной границы
                _qr="$_lim"; _lspent=0; _lrt=$(period_last "$_now" "$_p")
              else
                # цикл продолжается: остаток с учётом израсходованного
                _qr=$(( _lim - _lspent )); [ "$_qr" -lt 0 ] && _qr=0
              fi
            else
              _pl=$(period_len "$_p")
              if [ $(( _now - _lrt )) -ge "$_pl" ]; then
                # окно истекло: граница = old + k×len (фаза окна сохраняется)
                _k=$(( ( _now - _lrt ) / _pl ))
                _qr="$_lim"; _lspent=0; _lrt=$(( _lrt + _k * _pl ))
              else
                # цикл продолжается: остаток
                _qr=$(( _lim - _lspent )); [ "$_qr" -lt 0 ] && _qr=0
              fi
            fi
          else
            # лимит правил изменён: новый цикл; фазу выравниваем КАК в cron
            # (иначе up и cron расходились по фазе точковых периодов до
            # следующего прохода; фикс аудита-5x5)
            _qr="$_lim"; _lspent=0
            if [[ "$_p" == *_T* ]]; then _lrt=$(period_last "$_now" "$_p")
            else _pl=$(period_len "$_p"); _lrt=$(( _lrt + ( ( _now - _lrt ) / _pl ) * _pl )); fi
          fi
        fi
        # Остаток направления: SRC→_qu, DST→_qd, ALL→оба (общий пул)
        case "$_dir" in
          SRC) _qu="$_qr" ;;
          DST) _qd="$_qr" ;;
          ALL) _qu="$_qr"; _qd="$_qr" ;;
        esac
        LEDGER_NEW["$_key"]="$_lim|$_lspent|$_lrt|$_now|0"
        # Throttle (НАЛОЖЕНИЕ): сбор min-скорости исчерпанных направлений;
        # применяется после цикла (одна фаза на клиента)
        if [ "$_qtm" -ge 1 ] && [ "$_lspent" -ge "$_lim" ]; then
          # Вооружённость ПЕРИОДА (фикс волны-2 аудита): DROP-хвост/обход
          # решаются per-период — исчерпание throttle-периода не должно снимать
          # строгий DROP no-throttle периода того же клиента.
          if { [ "$_qtm" = "1" ] && [ "$_qtu" -gt 0 ]; } || { [ "$_qtm" = "2" ] && { [ "$_qtu" -gt 0 ] || [ "$_qtd" -gt 0 ]; }; }; then
            THR_PERIOD["$_set|$_p"]=1
          fi
          if [ "$_qtm" = "2" ]; then
            case "$_dir" in
              SRC|ALL)
                # min ТОЛЬКО положительных ставок (фикс регресса: односторонний
                # «1m:0» писал 0 в min и убивал объявленный throttle другого
                # периода «64k:64k»)
                if [ "$_qtu" -gt 0 ] && { [ -z "${THR_UP[$_set]:-}" ] || [ "$_qtu" -lt "${THR_UP[$_set]:-}" ]; }; then
                  THR_UP["$_set"]="$_qtu"
                fi ;;
            esac
            case "$_dir" in
              DST|ALL)
                if [ "$_qtd" -gt 0 ] && { [ -z "${THR_DOWN[$_set]:-}" ] || [ "$_qtd" -lt "${THR_DOWN[$_set]:-}" ]; }; then
                  THR_DOWN["$_set"]="$_qtd"
                fi ;;
            esac
          else
            # режим 1: один общий лимит скорости на оба направления
            if [ "$_qtu" -gt 0 ] && { [ -z "${THR_UP[$_set]:-}" ] || [ "$_qtu" -lt "${THR_UP[$_set]:-}" ]; }; then
              THR_UP["$_set"]="$_qtu"
            fi
            if [ "$_qtu" -gt 0 ] && { [ -z "${THR_DOWN[$_set]:-}" ] || [ "$_qtu" -lt "${THR_DOWN[$_set]:-}" ]; }; then
              THR_DOWN["$_set"]="$_qtu"
            fi
          fi
        fi
      done
      QUOTA_BUILD["$_p"]="${QUOTA_BUILD[$_p]:-} ${_set}:${_pm}:$_up:$_dn:$_qu:$_qd"
    done
  done
  # Throttle-фаза ПРИМЕНЕНИЯ вынесена в конец up (после блока лимитов):
  # лимиты пересоздают qdisc/ifb и снесли бы pref-5 фильтры/классы throttle
  # (аудит). См. блок перед "——————" в конце скрипта.
  # Запись журнала: новые и актуальные записи (призраки исчезают сами).
  # Атомарно: temp + rename; tmp уникален по PID (гонка up∥cron∥down — общий
  # .tmp перемешивал бы записи; фикс аудита-T3).
  : > "${LEDGER_FILE}.tmp.$$"
  for _lk in "${!LEDGER_NEW[@]}"; do
    echo "$_lk|${LEDGER_NEW[$_lk]}" >> "${LEDGER_FILE}.tmp.$$"
  done
  mv -f "${LEDGER_FILE}.tmp.$$" "$LEDGER_FILE"

  # Старые цепочки/прыжки/наборы уже снесены БЕЗУСЛОВНО перед блоком (см.
  # выше — работает и при TRAFFIC_QUOTAS=()); здесь только строим новые.
  for _p in "${!QUOTA_BUILD[@]}"; do
    quota_build_period "$_p" "${QUOTA_BUILD[$_p]}"
  done

  for _p in "${!QUOTA_BUILD[@]}"; do
    quota_jump_period "$_p"
  done

  # Сидируем STATE (фикс аудита-C4: без записи cron никогда не создавал
  # .last, prev==now на каждом вызове → сбросы периодов не работали вовсе).
  # Throttle-динамика (классы поверх) выполняется cron'ом/up через
  # quota_throttle_on/off — см. выше; здесь ничего не создаём.
  echo "$(date +%s)" > "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.last" 2>/dev/null || true

  # Скрипт сброса периодов (вызывается cron'ом раз в час; аргумент — TUN_SAFE)
  cat > "$SCRIPT_DIR/.data/quota/quota_update_${TUN_SAFE}.sh" <<'QUOTASCRIPT'
#!/bin/bash
# Сброс истёкших периодов квот трафика. Аргумент: TUN_SAFE.
TUN_SAFE="$1"
[ -z "$TUN_SAFE" ] && exit 0
# Имя НАСТОЯЩЕГО интерфейса (второй аргумент от cron; фикс аудита: TUN_SAFE
# заменяет '-' на '_', и пути к temp/<имя>.sh и ../<имя>.conf разъезжались
# для имён с '-'/'.').
PARAMS_NAME="$2"
[ -z "$PARAMS_NAME" ] && exit 0
SD="$(dirname "$(readlink -f "$0")")"
PARAMS_NAME_BASE="$(basename "$0")"
# Скрипт лежит в .data/quota/: QUOTA_DIR — его каталог, SD — .data
QUOTA_DIR="$SD"
SD="$(dirname "$SD")"
STATE="$QUOTA_DIR/${TUN_SAFE}.last"
PARAMS="$SD/temp/${PARAMS_NAME}.sh"
[ -f "$PARAMS" ] || exit 0
# shellcheck disable=SC1090
source "$PARAMS"
# Квотные значения берём из скрипта параметров (source выше)
now=$(date +%s)
# Квоты выключены в параметрах: задача-сирота (up с пустым TRAFFIC_QUOTAS
# снимает cron, но до этого прохода скрипт не должен обнулять журнал —
# фикс аудита-5x5). Полная пересборка конфига без квот — через up/down.
if [ "${#TRAFFIC_QUOTAS[@]}" -eq 0 ]; then exit 0; fi
# Сериализация проходов (фикс аудита-5x5): на больших конфигах снапшоты по
# ключам могут идти минуты — два пересекающихся cron (или cron∥up-фаза
# throttle, держащая тот же lock) дали бы last-writer-wins по журналу.
# Занятый lock → пропустить проход (безопасно: следующий час догонит).
LOCK="${QUOTA_DIR}/${TUN_SAFE}.cron.lock"
exec 9>"$LOCK"
flock -n 9 || exit 0
# STATE — только диагностическая метка; сбросы решаются по ledger (reset_ts).

# Клиенты берём из конфига по секциям [Peer] (в параметр-файле их списка нет)
parse_peer_sections() {
  local conf_file="$1"
  [ -f "$conf_file" ] || return 0
  awk '
    /^\[Peer\]/ { in_peer=1; name=""; ips=""; next }
    in_peer && /^#_Name[[:space:]]*=/ { sub(/^#_Name[[:space:]]*=[[:space:]]*/, ""); name=$0; next }
    in_peer && /^AllowedIPs[[:space:]]*=/ { sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); ips=$0; next }
    in_peer && /^\[/ && !/^\[Peer\]/ { print name "|" ips; in_peer=0 }
    in_peer && /^$/ { print name "|" ips; in_peer=0 }
    END { if (in_peer) print name "|" ips }
  ' "$conf_file" 2>/dev/null
}
SERVER_CONF_FILE="$SD/../${PARAMS_NAME}.conf"
if [ ! -f "$SERVER_CONF_FILE" ]; then
  echo "❌ quota_update: серверный конфиг не найден ($SERVER_CONF_FILE) — квоты не пересозданы (безопасная остановка)" >&2
  exit 1
fi
# per-клиентские наборы ipset (как в up.sh): пересоздаём — адреса клиентов могли измениться
for _qs in $(ipset list -name 2>/dev/null | grep -E "^Q_${TUN_SAFE}_" || true); do
  ipset destroy "$_qs" 2>/dev/null || true
done
declare -A QUOTA_PAIR
declare -A CL_BLOCK4 CL_BLOCK6   # набор → адреса клиента (план по набору)
declare -A THR_MAP THR_UP THR_DOWN THR_PERIOD # (набор|период)→tm|tu|td; набор→min; набор|период→вооружён
_QSETS=""
while IFS='|' read -r _qname _qips; do
  [ -z "$_qips" ] && continue
  _Q4=""; _Q6=""
  IFS=',' read -ra _qaddr <<< "$_qips"
  for _qa in "${_qaddr[@]}"; do
    # Маска сохраняется (блоки клиентов /127,/126... из соотношения)
    _qa="$(echo "$_qa" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    case "$_qa" in
      *:*) [ -n "$_Q6" ] && _Q6="$_Q6,"; _Q6="$_Q6$_qa" ;;
      *)   [ -n "$_Q4" ] && _Q4="$_Q4,"; _Q4="$_Q4$_qa" ;;
    esac
  done
  _qsafe="$(printf '%s' "${_qname:-client}" | tr -c 'A-Za-z0-9_.-' '_')"
  _qnamelen=${#TUN_SAFE}
  _qmax=$(( 22 - _qnamelen ))  # Q_ + TUN + _ + X + _V4 <= 31 (лимит имени ipset)
  [ "$_qmax" -lt 6 ] && _qmax=6
  if [ ${#_qsafe} -gt "$_qmax" ]; then
    _qsafe="$(printf '%s' "$_qsafe" | cut -c1-$(( _qmax - 7 )))$(printf '%s' "$_qsafe" | md5sum | cut -c1-6)"
  fi
  # План квоты клиента: ВСЕ совпавшие правила (НАЛОЖЕНИЕ периодов).
  # Каждая строка: KEY MODE v4u v4d v6u v6d thrMode thrUp thrDown; N — нет квоты.
  _q4blk="${_Q4%%[,]*}"
  _q6blk="${_Q6%%[,]*}"
  _qplan=$(quota_client_plan "$_q4blk" "$_q6blk")
  _qany=0; _qv4=0; _qv6=0
  # Сброс плана клиента (как в up): declare -A без (=) не чистит массив.
  declare -A _PL=()
  while IFS= read -r _pl; do
    [ -z "$_pl" ] && continue
    _ple="${_pl%% *}"
    [ "$_ple" = "N" ] && continue
    _qany=1
    _prest="${_pl#* }"; _pm="${_prest%% *}"
    _prest="${_prest#* }"; _pu4="${_prest%% *}"
    _prest="${_prest#* }"; _pd4="${_prest%% *}"
    _prest="${_prest#* }"; _pu6="${_prest%% *}"
    _prest="${_prest#* }"; _pd6="${_prest%% *}"
    _prest="${_prest#* }"; _ptm="${_prest%% *}"
    _prest="${_prest#* }"; _ptu="${_prest%% *}"
    _ptd="${_prest##* }"
    { [ "$_pu4" -gt 0 ] || [ "$_pd4" -gt 0 ]; } && _qv4=1
    { [ "$_pu6" -gt 0 ] || [ "$_pd6" -gt 0 ]; } && _qv6=1
    _PL["$_ple"]="$_pm|$_pu4|$_pd4|$_pu6|$_pd6|$_ptm|$_ptu|$_ptd"
  done <<< "$_qplan"
  if [ "$_qany" = "1" ]; then
    _qset4=""; _qset6=""
    if [ "$_qv4" = "1" ] && [ -n "$_Q4" ]; then
      _qset4="Q_${TUN_SAFE}_${_qsafe}_V4"
      ipset create "$_qset4" hash:net family inet 2>/dev/null || ipset flush "$_qset4" 2>/dev/null || true
      for _qa in $(echo "$_Q4" | tr ',' ' '); do ipset add "$_qset4" "$_qa" 2>/dev/null || true; done
      _QSETS="$_QSETS $_qset4"
      CL_BLOCK4["$_qset4"]="$_Q4"
    fi
    if [ "$_qv6" = "1" ] && [ -n "$_Q6" ]; then
      _qset6="Q_${TUN_SAFE}_${_qsafe}_V6"
      ipset create "$_qset6" hash:net family inet6 2>/dev/null || ipset flush "$_qset6" 2>/dev/null || true
      for _qa in $(echo "$_Q6" | tr ',' ' '); do ipset add "$_qset6" "$_qa" 2>/dev/null || true; done
      _QSETS="$_QSETS $_qset6"
      CL_BLOCK6["$_qset6"]="$_Q6"
    fi
    for _ple in "${!_PL[@]}"; do
      _pb="${_PL[$_ple]}"
      _pm="${_pb%%|*}"; _pb="${_pb#*|}"
      _pu4="${_pb%%|*}"; _pb="${_pb#*|}"; _pd4="${_pb%%|*}"; _pb="${_pb#*|}"
      _pu6="${_pb%%|*}"; _pb="${_pb#*|}"; _pd6="${_pb%%|*}"; _pb="${_pb#*|}"
      _ptm="${_pb%%|*}"; _pb="${_pb#*|}"; _ptu="${_pb%%|*}"; _ptd="${_pb##*|}"
      if [ -n "$_qset4" ] && { [ "$_pu4" -gt 0 ] || [ "$_pd4" -gt 0 ]; }; then
        QUOTA_PAIR["$_ple"]="${QUOTA_PAIR[$_ple]:-} ${_qset4}:${_pm}:$_pu4:$_pd4"
        THR_MAP["$_qset4|$_ple"]="$_ptm|$_ptu|$_ptd"
      fi
      if [ -n "$_qset6" ] && { [ "$_pu6" -gt 0 ] || [ "$_pd6" -gt 0 ]; }; then
        QUOTA_PAIR["$_ple"]="${QUOTA_PAIR[$_ple]:-} ${_qset6}:${_pm}:$_pu6:$_pd6"
        THR_MAP["$_qset6|$_ple"]="$_ptm|$_ptu|$_ptd"
      fi
    done
  fi
done <<< "$(parse_peer_sections "$SERVER_CONF_FILE")"

# epoch_of и quota-хелперы приходят из параметров (source выше)
rebuild() {
  # Пересоздание цепочек периода из пар "set:MODE:up:down" (после истечения).
  # SEP — раздельные SRC(ап)/DST(даун) квоты; ALL — общая цепочка клиента.
  # RETURN (не ACCEPT): неисчерпавший продолжает обход FORWARD — синхронно с
  # up-сборкой (аудит). Остатки берём из LEDGER_NEW (лимит−spent per-набор):
  # истёкшие ключи имеют spent=0 → полный лимит (новый цикл); неистёкшие
  # клиенты того же периода сохраняют свой остаток (фикс аудита: раньше
  # rebuild ставил полные лимиты всем клиентам периода — «бесплатный цикл»).
  local _suf="$1" _pairs="$2" _pai _est _pm _up _dn _allc _qu _qd
  _quota_remaining() {
    # $1=set $2=период $3=направление(SRC|DST|ALL) $4=лимит
    local _r="$4" _rest _sp
    if [ -n "${LEDGER_NEW[$1|$2|$3]:-}" ]; then
      _rest="${LEDGER_NEW[$1|$2|$3]#*|}"
      _sp="${_rest%%|*}"
      _r=$(( $4 - _sp )); [ "$_r" -lt 0 ] && _r=0
    fi
    echo "$_r"
  }
  for _qc in "QUOTA_${TUN_SAFE}_${_suf}_SRC" "QUOTA_${TUN_SAFE}_${_suf}_DST"; do
    iptables -N "$_qc" 2>/dev/null || iptables -F "$_qc"
    ip6tables -N "$_qc" 2>/dev/null || ip6tables -F "$_qc"
  done
  for _pai in $_pairs; do
    _est="${_pai%%:*}"; _prest="${_pai#*:}"; _pm="${_prest%%:*}"; _prest="${_prest#*:}"
    _up="${_prest%%:*}"; _dn="${_prest##*:}"
    if [ "$_pm" != "SEP" ]; then
      _allc=$(quota_all_name "$_est" "$_suf")
      case "$_est" in
        *_V4) iptables -N "$_allc" 2>/dev/null || iptables -F "$_allc" ;;
        *_V6) ip6tables -N "$_allc" 2>/dev/null || ip6tables -F "$_allc" ;;
      esac
    fi
  done
  for _pai in $_pairs; do
    _est="${_pai%%:*}"; _prest="${_pai#*:}"; _pm="${_prest%%:*}"; _prest="${_prest#*:}"
    _up="${_prest%%:*}"; _dn="${_prest##*:}"
    if [ "$_pm" = "SEP" ]; then
      _qu=$(_quota_remaining "$_est" "$_suf" SRC "$_up")
      _qd=$(_quota_remaining "$_est" "$_suf" DST "$_dn")
      case "$_est" in
        *_V4)
          iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -m quota --quota "$_qu" -j RETURN
          iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -m quota --quota "$_qd" -j RETURN
          # Throttle-обход — только вооружённый период и сторона (per-period)
          _pthr=$(quota_period_thr "$_est" "$_suf")
          _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
          [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -gt 0 ] && iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
          [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -gt 0 ] && iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
          ;;
        *_V6)
          ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -m quota --quota "$_qu" -j RETURN
          ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -m quota --quota "$_qd" -j RETURN
          _pthr=$(quota_period_thr "$_est" "$_suf")
          _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
          [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -gt 0 ] && ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
          [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -gt 0 ] && ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
          ;;
      esac
    else
      _qu=$(_quota_remaining "$_est" "$_suf" ALL "$_up")
      _allc=$(quota_all_name "$_est" "$_suf")
      case "$_est" in
        *_V4)
          iptables -A "$_allc" -m quota --quota "$_qu" -j RETURN
          # Вооружён ПЕРИОД (per-period, фикс волны-2 аудита) — хвост не ставим
          # только для исчерпанного throttle-периода; 0-стороны — catch'ами
          _pthr=$(quota_period_thr "$_est" "$_suf")
          if [ "${_pthr%%|*}" != "1" ]; then
            iptables -A "$_allc" -j DROP
          fi
          iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j "$_allc"
          _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
          if [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -le 0 ]; then
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j DROP
          else
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
          fi
          iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j "$_allc"
          if [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -le 0 ]; then
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j DROP
          else
            iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
          fi
          ;;
        *_V6)
          ip6tables -A "$_allc" -m quota --quota "$_qu" -j RETURN
          _pthr=$(quota_period_thr "$_est" "$_suf")
          if [ "${_pthr%%|*}" != "1" ]; then
            ip6tables -A "$_allc" -j DROP
          fi
          ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j "$_allc"
          _ptu="${_pthr#*|}"; _ptu="${_ptu%%|*}"; _ptd="${_pthr##*|}"
          if [ "${_pthr%%|*}" = "1" ] && [ "$_ptu" -le 0 ]; then
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j DROP
          else
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -m set --match-set "$_est" src -j RETURN
          fi
          ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j "$_allc"
          if [ "${_pthr%%|*}" = "1" ] && [ "$_ptd" -le 0 ]; then
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j DROP
          else
            ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -m set --match-set "$_est" dst -j RETURN
          fi
          ;;
      esac
    fi
  done
  iptables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -j DROP
  iptables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -j DROP
  ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_SRC" -j DROP
  ip6tables -A "QUOTA_${TUN_SAFE}_${_suf}_DST" -j DROP
}
# Слепок израсходованности клиента приходит из параметров (source выше):
# snapshot_spent set период НАПРАВЛЕНИЕ (SRC|DST|ALL)
# --- Журнал квот в cron: слепки + сбросы (ledger, как в up) ---
LEDGER_FILE="$QUOTA_DIR/${TUN_SAFE}.ledger"
declare -A LEDGER
if [ -f "$LEDGER_FILE" ]; then
  while IFS='|' read -r _lk _lp _ld _ll _ls _lr _lt _lb; do
    [ -z "$_lk" ] && continue
    LEDGER["$_lk|$_lp|$_ld"]="$_ll|$_ls|$_lr|$_lt|${_lb:-0}"
  done < "$LEDGER_FILE"
fi
declare -A LEDGER_NEW
for _p in "${!QUOTA_PAIR[@]}"; do
  for _pai in ${QUOTA_PAIR[$_p]}; do
    _set="${_pai%%:*}"; _prest="${_pai#*:}"
    _pm="${_prest%%:*}"; _prest="${_prest#*:}"
    _up="${_prest%%:*}"; _dn="${_prest##*:}"
    # Throttle-карта этого (набор, период): tm|tu|td
    _qthr="${THR_MAP[$_set|$_p]:-0}"
    _qtm=0; _qtu=0; _qtd=0
    if [ -n "$_qthr" ] && [ "$_qthr" != "0" ]; then
      _qtm="${_qthr%%|*}"; _qrest="${_qthr#*|}"; _qtu="${_qrest%%|*}"; _qtd="${_qrest##*|}"
    fi
    # Режим квоты: ALL = общий счётчик, SEP = раздельно SRC/DST
    if [ "$_pm" = "SEP" ]; then _dirs="SRC DST"; else _dirs="ALL"; fi
    for _dir in $_dirs; do
      if [ "$_dir" = "SRC" ]; then _lim="$_up"
      elif [ "$_dir" = "DST" ]; then _lim="$_dn"
      else _lim="$_up"; fi
      _key="$_set|$_p|$_dir"
      _lspent=0; _lsnap="$now"; _snp=0
      _expired=0
      # reset_ts для ключа: из журнала (если есть), иначе now
      if [ -n "${LEDGER[$_key]:-}" ]; then
        _lold="${LEDGER[$_key]%%|*}"
        _lrest="${LEDGER[$_key]#*|}"
        _lrest="${_lrest#*|}"; _lrt="${_lrest%%|*}"
      else
        _lold="$_lim"
        if [[ "$_p" == *_T* ]]; then _lrt=$(period_last "$now" "$_p"); else _lrt="$now"; fi
      fi
      if [ "$_lold" != "$_lim" ]; then
        _expired=1
      elif period_is_point "$_p"; then
        [ "$now" -ge "$(period_next "$_lrt" "$_p")" ] && _expired=1
      else
        [ $(( now - _lrt )) -ge "$(period_len "$_p")" ] && _expired=1
      fi
      if [ "$_expired" = "1" ]; then
        # Период истёк: журнал получает новый цикл; цепочка пересоздаётся ниже
        if period_is_point "$_p"; then
          _lrt=$(period_last "$now" "$_p")
        else
          _pl=$(period_len "$_p")
          _lrt=$(( _lrt + ( ( now - _lrt ) / _pl ) * _pl ))
        fi
        _lspent=0
      else
        # Слепок: израсходовано к текущему моменту. Счётчики iptables после
        # рестарта начинаются с нуля — прибавляем ТОЛЬКО приращение поверх
        # сохранённого расхода (поле snap_bytes = последний слепок счётчика).
        _snp=$(snapshot_spent "$_set" "$_p" "$_dir")
        _oldsp=0; _oldsnp=0
        if [ -n "${LEDGER[$_key]:-}" ]; then
          _lrest="${LEDGER[$_key]#*|}"
          _oldsp="${_lrest%%|*}"
          _lrest="${_lrest#*|}"   # rt
          _lrest="${_lrest#*|}"   # snap_ts
          _lrest="${_lrest#*|}"   # → snap_bytes
          _oldsnp="${_lrest%%|*}"
        fi
        _delta=$(( _snp - _oldsnp )); [ "$_delta" -lt 0 ] && _delta=0
        _lspent=$(( _oldsp + _delta ))
        _lsnap="$now"
        # Throttle (НАЛОЖЕНИЕ): сбор min-скорости исчерпанных направлений;
        # применяется после цикла
        if [ "$_qtm" -ge 1 ] && [ "$_lspent" -ge "$_lim" ]; then
          # Вооружённость периода — per-период (фикс волны-2 аудита)
          if { [ "$_qtm" = "1" ] && [ "$_qtu" -gt 0 ]; } || { [ "$_qtm" = "2" ] && { [ "$_qtu" -gt 0 ] || [ "$_qtd" -gt 0 ]; }; }; then
            THR_PERIOD["$_set|$_p"]=1
          fi
          if [ "$_qtm" = "2" ]; then
            case "$_dir" in
              SRC|ALL)
                if [ -z "${THR_UP[$_set]:-}" ] || [ "$_qtu" -lt "${THR_UP[$_set]:-}" ]; then
                  THR_UP["$_set"]="$_qtu"
                fi ;;
            esac
            case "$_dir" in
              DST|ALL)
                if [ -z "${THR_DOWN[$_set]:-}" ] || [ "$_qtd" -lt "${THR_DOWN[$_set]:-}" ]; then
                  THR_DOWN["$_set"]="$_qtd"
                fi ;;
            esac
          else
            if [ -z "${THR_UP[$_set]:-}" ] || [ "$_qtu" -lt "${THR_UP[$_set]:-}" ]; then
              THR_UP["$_set"]="$_qtu"
            fi
            if [ -z "${THR_DOWN[$_set]:-}" ] || [ "$_qtu" -lt "${THR_DOWN[$_set]:-}" ]; then
              THR_DOWN["$_set"]="$_qtu"
            fi
          fi
        fi
      fi
      LEDGER_NEW["$_key"]="$_lim|$_lspent|$_lrt|$_lsnap|0"
    done
  done
done
# ПРИМЕЧАНИЕ (фикс аудита-5x5): поле snap_bytes пишется 0, а не _snp — каждый
# проход пересоздаёт ВСЕ цепочки (см. rebuild ниже), счётчик нового правила
# xt_quota стартует с нуля, и база должна совпадать с ним. С базой = старый
# счётчик дельта следующего прохода уходила в минус (клампилась в 0), расход
# замирал, и rebuild каждый час «перевыдавал» остаток квоты заново.
# Миграция дофиксового формата .thr (3 поля; фикс аудита-5x5 + регресс):
# префы назначаем УНИКАЛЬНЫЕ (5+idx) — общий «|5» для ≥2 legacy-наборов давал
# им один pref, и off() одного набора сносил фильтры другого (вооружённые
# хвосты без tc = послеквотный безлимит).
awk -F'|' 'NF==3 {print $0 "|" (5+NR)} NF>3 {print}' "${QUOTA_DIR}/${TUN_SAFE}.thr" > "${QUOTA_DIR}/${TUN_SAFE}.thr.mig" 2>/dev/null && mv -f "${QUOTA_DIR}/${TUN_SAFE}.thr.mig" "${QUOTA_DIR}/${TUN_SAFE}.thr"
true
# Зачистка устаревших throttle-записей (наборы вне текущих квот — конфиг
# изменён между проходами; cron не должен держать чужие классы/фильтры).
for _old in $(grep -oE '^Q_[^|]+' "${QUOTA_DIR}/${TUN_SAFE}.thr" 2>/dev/null | sort -u); do
  case " ${_QSETS:-} " in
    *" $_old "*) ;;
    *) quota_throttle_off "$_old" "$PARAMS_NAME" ;;
  esac
done
# Throttle-фаза применения (min-скорость исчерпанных направлений на клиента)
for _qsn in ${_QSETS:-}; do
  _tu="${THR_UP[$_qsn]:-0}"; _td="${THR_DOWN[$_qsn]:-0}"
  if [ "$_tu" -gt 0 ] || [ "$_td" -gt 0 ]; then
    if ! quota_throttle_on "$_qsn" "$_tu" "$_td" "${CL_BLOCK4[$_qsn]:-}" "${CL_BLOCK6[$_qsn]:-}" "$PARAMS_NAME"; then
      # Вооружение не удалось: rebuild ниже (по обновлённым intent/THR_PERIOD)
      # вернёт строгий DROP — «без хвоста и без tc» исключено (фикс волны-2)
      THR_UP["$_qsn"]=0; THR_DOWN["$_qsn"]=0
      for _pp in "${!THR_PERIOD[@]}"; do
        case "$_pp" in
          "$_qsn|"*) unset THR_PERIOD["$_pp"] ;;
        esac
      done
      echo "⚠️ throttle не вооружён для $_qsn — rebuild вернёт строгий DROP" >&2
    fi
  else
    quota_throttle_off "$_qsn" "$PARAMS_NAME" "${CL_BLOCK4[$_qsn]:-}" "${CL_BLOCK6[$_qsn]:-}"
  fi
done
# Полное снятие throttle без лимитов скорости — сносим HTB/ingress-артефакты
if [ ! -s "${QUOTA_DIR}/${TUN_SAFE}.thr" ] 2>/dev/null && [ "${#SUBNETS_LIMITS[@]}" -eq 0 ]; then
  tc qdisc del dev "$PARAMS_NAME" root 2>/dev/null || true
  tc qdisc del dev "$PARAMS_NAME" handle ffff: ingress 2>/dev/null || true
fi
# Пересоздание цепочек ВСЕХ периодов каждый проход (а не только истёкших):
# rebuild берёт остатки per-клиента из LEDGER_NEW (истёкшие ключи — spent=0 →
# полный лимит), а цепочки только что вооружённых throttle-клиентов получают
# снятый DROP-хвост СРАЗУ — иначе «послеквотный лимит» молчал бы до конца
# периода за хвостовым DROP (фикс аудита-e2e). Заодно самовосстановление
# цепочек при ручной правке. RESET_PERIODS не нужен: журнал решает всё.
for _p in "${!QUOTA_PAIR[@]}"; do
  rebuild "$_p" "${QUOTA_PAIR[$_p]}"
done
# --- Жизненный цикл прыжков и сирот (фикс аудита-5x5) ---
# Прыжки ставит только up — после nft-flush/ручной правки или добавления
# клиента без up квота молча не применялась бы до следующего up, а удалённый
# клиент оставался бы в старом прыжке и падал на хвостовой DROP периода.
# Сносим ВСЕ QUOTA-прыжки и ставим заново по текущим наборам; сироты-цепочки
# (периодов/клиентов вне QUOTA_PAIR) и их наборы уничтожаем.
for _T in iptables ip6tables; do
  $_T-save 2>/dev/null | grep -E -- "-j QUOTA_${TUN_SAFE}_" | sed 's/^-A //' | while read -r _j; do
    $_T -D $_j 2>/dev/null || true
  done
done
_VALID=""
for _p in "${!QUOTA_PAIR[@]}"; do
  _VALID="$_VALID QUOTA_${TUN_SAFE}_${_p}_SRC QUOTA_${TUN_SAFE}_${_p}_DST"
  for _pai in ${QUOTA_PAIR[$_p]}; do
    _est="${_pai%%:*}"
    _pm2="${_pai#*:}"; _pm2="${_pm2%%:*}"
    if [ "$_pm2" = "ALL" ]; then _VALID="$_VALID $(quota_all_name "$_est" "$_p")"; fi
  done
done
for _T in iptables ip6tables; do
  for _ch in $( $_T-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)|Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u ); do
    case " $_VALID " in
      *" $_ch "*) ;;
      *) $_T -F "$_ch" 2>/dev/null || true ;;
    esac
  done
done
# ВТОРОЙ проход -X: цепочки-сироты могут ссылаться друг на друга (W_SRC →
# Q_..._W_A); -F всех сирот на первом проходе снимает эти ссылки, только
# теперь -X не падает (фикс аудита-5x5: однопроходный вариант оставлял
# пустые обёртки при неудачном порядке сортировки).
for _T in iptables ip6tables; do
  for _ch in $( $_T-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)|Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u ); do
    case " $_VALID " in
      *" $_ch "*) ;;
      *) $_T -X "$_ch" 2>/dev/null || true ;;
    esac
  done
done
# Наборы клиентов вне плана (прыжки/цепочки уже снесены — destroy теперь пройдёт)
for _s in $(ipset list -name 2>/dev/null | grep -E "^Q_${TUN_SAFE}_" || true); do
  case " ${_QSETS:-} " in
    *" $_s "*) ;;
    *) ipset destroy "$_s" 2>/dev/null || true ;;
  esac
done
# Прыжки по текущим наборам (только пары своего периода)
for _p in "${!QUOTA_PAIR[@]}"; do
  for _pai in ${QUOTA_PAIR[$_p]}; do
    _est="${_pai%%:*}"
    case "$_est" in
      *_V4)
        iptables -I FORWARD 1 -i "$PARAMS_NAME" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_p}_SRC"
        iptables -I FORWARD 1 -o "$PARAMS_NAME" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_p}_DST"
        iptables -I INPUT 1 -i "$PARAMS_NAME" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_p}_SRC"
        iptables -I OUTPUT 1 -o "$PARAMS_NAME" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_p}_DST"
        ;;
      *_V6)
        ip6tables -I FORWARD 1 -i "$PARAMS_NAME" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_p}_SRC"
        ip6tables -I FORWARD 1 -o "$PARAMS_NAME" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_p}_DST"
        ip6tables -I INPUT 1 -i "$PARAMS_NAME" -m set --match-set "$_est" src -j "QUOTA_${TUN_SAFE}_${_p}_SRC"
        ip6tables -I OUTPUT 1 -o "$PARAMS_NAME" -m set --match-set "$_est" dst -j "QUOTA_${TUN_SAFE}_${_p}_DST"
        ;;
    esac
  done
done
# Перезапись журнала: только актуальные правила (призраки исчезают); атомарно.
: > "${LEDGER_FILE}.tmp.$$"
for _lk in "${!LEDGER_NEW[@]}"; do
  echo "$_lk|${LEDGER_NEW[$_lk]}" >> "${LEDGER_FILE}.tmp.$$"
done
mv -f "${LEDGER_FILE}.tmp.$$" "$LEDGER_FILE"
# STATE — диагностическая метка последнего запуска (не участвует в сбросах)
echo "$now" > "$STATE" 2>/dev/null || true
QUOTASCRIPT
  chmod +x "$SCRIPT_DIR/.data/quota/quota_update_${TUN_SAFE}.sh"
  # cron: раз в час; убираем старую строку с тем же тэгом при перегенерации
  ( crontab -l 2>/dev/null | grep -v "# awg-quota-${TUN_SAFE}$"; \
    echo "0 * * * * bash \"$SCRIPT_DIR/.data/quota/quota_update_${TUN_SAFE}.sh\" ${TUN_SAFE} ${SCRIPT_NAME} >/dev/null 2>&1 # awg-quota-${TUN_SAFE}" ) | crontab -
  echo "📊 Квоты трафика включены (правил: ${#TRAFFIC_QUOTAS[@]}; клиентов: $(echo "$_QSETS" | wc -w))"
  else
    echo "⚠️  КВОТЫ ПРОПУЩЕНЫ (ipset/xt_set недоступны) — остальной up продолжается" >&2
  fi
else
  # Квоты выключены: полная разборка — cron-задача, скрипт обновления и .thr
  # (иначе почасовая задача-сирота обнуляла бы журнал; фикс аудита-5x5).
  crontab -l 2>/dev/null | grep -v "# awg-quota-${TUN_SAFE}$" | crontab -
  rm -f "$SCRIPT_DIR/.data/quota/quota_update_${TUN_SAFE}.sh" "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.thr" 2>/dev/null || true
fi

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
# Применяется только если SUBNETS_LIMITS не пустой
# Примечание: для больших подсетей (/16 и больше) этот цикл может работать долго
# Если лимит = 0 для подсети — эта подсеть пропускается (лимит отключен)
# Формат: "subnet:rate" или "subnet:rate_in:rate_out" или "subnet" (без лимита)
# ВАЖНО: валидация через validate_subnet_mask() которая уже есть в скрипте!
if [ ${#SUBNETS_LIMITS[@]} -gt 0 ]; then

  # Валидация подсетей через validate_subnet_mask()
  VALID_SUBNETS_LIMITS=()
  for entry in "${SUBNETS_LIMITS[@]}"; do
    _valid=1
    # Подсети - парсим с конца до mask (/prefix)
    _subnets=$(parse_entry "$entry" | cut -d'|' -f1)
    [ "$_subnets" = "$entry" ] && _subnets="$entry"
    IFS=',' read -ra _sublist <<< "$_subnets"
    for _s in "${_sublist[@]}"; do
      _s="$(echo "$_s" | tr -d ' ')"
      [ -z "$_s" ] && continue
      if ! validate_subnet_mask "$_s"; then
        _valid=0; break
      fi
    done
    [ "$_valid" = "1" ] && VALID_SUBNETS_LIMITS+=("$entry")
  done
  
  # Если все правила отфильтрованы — выходим
  if [ ${#VALID_SUBNETS_LIMITS[@]} -eq 0 ]; then
    echo "ℹ️  Лимиты скорости отключены (нет валидных правил)"
fi
   
  # SUBNETS_LIMITS уже валидирован при генерации - просто используем как есть
  # Формат уже правильный: subnet:rate или subnet:rate_in:rate_out или subnet
  SUBNETS_LIMITS=("${VALID_SUBNETS_LIMITS[@]}")
  
  # Проверяем есть ли лимит - парсим с конца до mask
  HAS_ACTIVE_LIMIT=0
  for entry in "${SUBNETS_LIMITS[@]}"; do
    _rate=$(parse_entry "$entry" | cut -d'|' -f2)
    if [ -n "$_rate" ] && [ "$_rate" != "0" ]; then
      # Нормализация единиц: «100mbit/10gbit/512kbit» → «100m» → «100»
      # (фикс стенда-парсеров: суффиксы *bit не активировали лимит молча)
      _rate="${_rate//bit/}"
      _rate="${_rate//[kmgtpKMGTP:]/}"
      # Нормализация 0-токена с суффиксом ('0mbit'→'0' — выкл; фикс регресса:
      # иначе all-disabled конфиг строил IFB+BRIDGE и резал весь туннель) и
      # допуск дробных ставок ('0.5m' — раньше молча «лимиты отключены»)
      case "$_rate" in
        ''|*[!0-9.]*) ;;
        *) [ "$_rate" != "0" ] && { HAS_ACTIVE_LIMIT=1; break; } ;;
      esac
    fi
  done

# Если все лимиты = 0 — не создаём ifb
  if [ "${HAS_ACTIVE_LIMIT:-0}" = "0" ]; then
    echo "ℹ️  Все лимиты = 0, шейпинг отключен"
  fi

  if [ "${HAS_ACTIVE_LIMIT:-0}" != "0" ]; then
  IFB_IN="ifb_${TUN_SAFE}_in"
  IFB_OUT="ifb_${TUN_SAFE}_out"
  IFB_MIX="ifb_${TUN_SAFE}_mix"

  if [ ! -d /sys/module/ifb ]; then
    if ! modprobe ifb; then
      echo "Ошибка: не удалось загрузить модуль ifb"
      exit 1
    fi
  fi

  # Устанавливаем TUN_SUBNET4/6 из уже распарсенных LOCAL_SUBNETS
  TUN_SUBNET4="$LOCAL_SUBNETS_IPV4"
  TUN_SUBNET6="$LOCAL_SUBNETS_IPV6"

  ip link set "$IFB_IN" down 2>/dev/null || true
  ip link delete "$IFB_IN" 2>/dev/null || true
  ip link set "$IFB_OUT" down 2>/dev/null || true
  ip link delete "$IFB_OUT" 2>/dev/null || true
  ip link set "$IFB_MIX" down 2>/dev/null || true
  ip link delete "$IFB_MIX" 2>/dev/null || true

  tc qdisc del dev "$TUN" root 2>/dev/null || true
  tc qdisc del dev "$TUN" handle ffff: ingress 2>/dev/null || true
  tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
  tc qdisc del dev "$IFB_IN" root 2>/dev/null || true
  tc qdisc del dev "$IFB_MIX" root 2>/dev/null || true

  tc qdisc add dev "$TUN" root handle 1: htb default 1
  tc class add dev "$TUN" parent 1: classid 1:1 htb rate 10gbit ceil 10gbit quantum 65535 2>/dev/null || true
  tc qdisc add dev "$TUN" handle ffff: ingress

  # Анализируем какие IFB интерфейсы нужны
  # _needs_mix - нужен IFB_MIX (для правил "subnet:rate")
  # _needs_out - нужен IFB_OUT (для download в правилах "subnet:rate:rate")
  # _needs_in - нужен IFB_IN (для upload в правилах "subnet:rate:rate")
  _needs_mix=0
  _needs_out=0
  _needs_in=0

  if [ ${#SUBNETS_LIMITS[@]} -gt 0 ]; then
      for _entry in "${SUBNETS_LIMITS[@]}"; do
          _info=$(parse_entry "$_entry")
          _type=$(echo "$_info" | cut -d'|' -f3)
          _rate=$(echo "$_info" | cut -d'|' -f2)

          if [ "$_type" = "mix" ]; then
              _needs_mix=1
          elif [ "$_type" = "separate" ]; then
              # Сторона «0» = без собственного лимита: перехват (mirred/catch-all)
              # для неё НЕ создаём, иначе её трафик давился бы BRIDGE_RATE моста
              # (фикс аудита-T4: _needs_out ставился безусловно → «0:10m» резал
              # download мостом вместо «без лимита»).
              _dn="${_rate%%:*}"
              _up="${_rate##*:}"
              # Нормализация 0-токена с суффиксом ('0mbit' == '0'; фикс регресса
              # аудита-limits-24: raw-сравнение снова открывало T4-баг для
              # «0mbit:10m» — disabled-сторона получала catch-all и BRIDGE-cap)
              case "$_dn" in 0|0m|0M|0mb|0Mb|0mbit|0Mbit|0k|0K|0kb|0Kb|0kbit|0Kbit) _dn="0" ;; esac
              case "$_up" in 0|0m|0M|0mb|0Mb|0mbit|0Mbit|0k|0K|0kb|0Kb|0kbit|0Kbit) _up="0" ;; esac
              [ "$_dn" != "0" ] && _needs_out=1
              [ "$_up" != "0" ] && _needs_in=1
          fi
      done
  fi

  # Создаём IFB интерфейсы ТОЛЬКО если они нужны
  if [ "$_needs_mix" = "1" ]; then
      # MIX mode: создаём ifb_mix для общих лимитов
      ip link add "$IFB_MIX" type ifb 2>/dev/null || true
      ip link set "$IFB_MIX" up
      tc qdisc add dev "$IFB_MIX" root handle 1: htb default 1
      # Per-subnet mirred добавляется отдельно для каждого правила SUBNETS_LIMITS
  fi

  if [ "$_needs_out" = "1" ]; then
      # Separate mode: создаём ifb_out для upload (egress → parent 1:)
      ip link add "$IFB_OUT" type ifb 2>/dev/null || true
      ip link set "$IFB_OUT" up
      tc qdisc add dev "$IFB_OUT" root handle 1: htb default 1
      # Per-subnet mirred добавляется отдельно для каждого правила SUBNETS_LIMITS
  fi

  if [ "$_needs_in" = "1" ]; then
      # Separate mode: создаём ifb_in для download (ingress → parent ffff:)
      ip link add "$IFB_IN" type ifb 2>/dev/null || true
      ip link set "$IFB_IN" up
      tc qdisc add dev "$IFB_IN" root handle 1: htb default 1
      # Per-subnet mirred добавляется отдельно для каждого правила SUBNETS_LIMITS
  fi

  # Парсим BRIDGE (формат: MAX_CLIENTS:BRIDGE_RATE:QUANT)
  # MAX может быть записан в hex («FFFF» = 65535, потолок 16-битного minor tc)
  _rest="${BRIDGE#*:}"
  MAX_CLIENTS_RAW="${BRIDGE%%:*}"
  case "$MAX_CLIENTS_RAW" in
    0x*|0X*) MAX_CLIENTS_PER_HIERARCHY=$((MAX_CLIENTS_RAW)) ;;
    *[A-Fa-f]*) MAX_CLIENTS_PER_HIERARCHY=$((16#$MAX_CLIENTS_RAW)) ;;
    ''|*[!0-9]*) MAX_CLIENTS_PER_HIERARCHY=65535 ;;  # битый BRIDGE → безопасный потолок
    *) MAX_CLIENTS_PER_HIERARCHY="$MAX_CLIENTS_RAW" ;;
  esac
  # Жёсткий клампинг (аудит-агенты): 0/битые → 65535; >65535 → 65535
  # (иначе minor>16 бит → tc-ошибки, а «0» даёт division by 0 в major/minor).
  [ -z "$MAX_CLIENTS_PER_HIERARCHY" ] && MAX_CLIENTS_PER_HIERARCHY=65535
  [ "$MAX_CLIENTS_PER_HIERARCHY" -gt 65535 ] && MAX_CLIENTS_PER_HIERARCHY=65535
  # 0/1 невалидны: 0 — division by 0, 1 → CLIENT_SLOTS=0 (то же) → 65535.
  [ "$MAX_CLIENTS_PER_HIERARCHY" -lt 2 ] && MAX_CLIENTS_PER_HIERARCHY=65535
  # Клиентских классов на иерархию: minor 1 занят «мусорным» default-классом
  # (безлимит), клиентские — с minor 2.
  CLIENT_SLOTS=$((MAX_CLIENTS_PER_HIERARCHY - 1))
  BRIDGE_RATE="${_rest%%:*}"
  QUANT="${_rest##*:}"

  # Отдельные счётчики для каждого IFB
  _mix_client_num=0
  _out_client_num=0
  _in_client_num=0
  # Глобальный аккумулятор классов по ВСЕМ правилам (аудит-агенты: per-rule
  # cap есть, суммарного лимита не было — 2 правила × 65536 вешали up).
  TOTAL_LIMIT_CLASSES=0
  # Базы major'ов правил (формулы major = база + (n-1)/CLIENT_SLOTS;
  # фикс аудита: аккумулирование major давало дрейф на втором переносе)
  _rule_base_major=2
  _rule_base_out_major=2
  _rule_base_in_major=2

  # Функция для добавления фильтров на root 1: для указанных подсетей
  add_root_filters_for() {
    local _ifb="$1"
    local _major="$2"
    local _subnets="$3"

    if [ -z "$_subnets" ]; then
      return
    fi

    IFS=',' read -ra _subnet_list <<< "$_subnets"
    for _sub in "${_subnet_list[@]}"; do
      _sub="$(echo "$_sub" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$_sub" ] && continue

      # Определяем протокол
      if [[ "$_sub" == *:* ]]; then
        _proto="ipv6"
        _match="ip6"
      else
        _proto="ip"
        _match="ip"
      fi

      # Определяем prio: IPv5 на step 1 вверх (разные протоколы не могут делить prio в u32)
      if [[ "$_sub" == *:* ]]; then
          _root_prio=$((_current_root_prio + 10))
      else
          _root_prio=$_current_root_prio
      fi

      # Добавляем фильтры на root 1: для маршрутизации в указанный мост
      # DST матч — для download трафика (пакет на IFB имеет dst=клиент VPN)
      tc filter add dev "$_ifb" parent 1: protocol $_proto prio $_root_prio u32 match $_match dst "$_sub" flowid $_major || echo "⚠️ Ошибка root filter ($_proto dst $_sub)" >&2
      # SRC матч — для upload трафика (пакет на IFB имеет src=клиент VPN)
      tc filter add dev "$_ifb" parent 1: protocol $_proto prio $_root_prio u32 match $_match src "$_sub" flowid $_major || echo "⚠️ Ошибка root filter ($_proto src $_sub)" >&2
    done
  }

  # Функция для создания новой иерархии tc классов на УКАЗАННОМ IFB
  # После создания моста добавляет фильтры на root 1: для всех подсетей правила
  create_tc_hierarchy_for() {
    local _ifb="$1"
    local _major="$2"
    local _subnets="$3"
    local _next_major=$_major

    # Создаём мост (класс с лимитом BRIDGE_RATE) - child класса 1:1
    tc class add dev "$_ifb" parent 1:1 classid 1:${_next_major} htb rate "$BRIDGE_RATE" ceil "$BRIDGE_RATE" quantum "$QUANT" 2>/dev/null || true
    tc qdisc add dev "$_ifb" parent 1:${_next_major} handle ${_next_major}: htb default 1 2>/dev/null || true
    # «Мусорный» default-класс (minor 1): непокрытый трафик иерархии идёт сюда
    # (rate BRIDGE — фактически без лимита), а не в класс первого клиента.
    tc class add dev "$_ifb" parent ${_next_major}: classid ${_next_major}:1 htb rate "$BRIDGE_RATE" ceil "$BRIDGE_RATE" quantum "$QUANT" 2>/dev/null || true

    # Добавляем фильтры на root 1: для всех подсетей этого правила
    add_root_filters_for "$_ifb" "1:${_next_major}" "$_subnets"
  }

  # Создаём начальные bridge классы ТОЛЬКО на нужных IFB
  if [ "$_needs_mix" = "1" ]; then
      # Root класс (1:1) - считает весь трафик на IFB_MIX
      tc class add dev "$IFB_MIX" parent 1: classid 1:1 htb rate "$BRIDGE_RATE" ceil "$BRIDGE_RATE" quantum "$QUANT" 2>/dev/null || true
  fi

  if [ "$_needs_out" = "1" ]; then
      # Root класс (1:1) - считает весь трафик на IFB_OUT
      tc class add dev "$IFB_OUT" parent 1: classid 1:1 htb rate "$BRIDGE_RATE" ceil "$BRIDGE_RATE" quantum "$QUANT" 2>/dev/null || true
  fi

  if [ "$_needs_in" = "1" ]; then
      # Root класс (1:1) - считает весь трафик на IFB_IN
      tc class add dev "$IFB_IN" parent 1: classid 1:1 htb rate "$BRIDGE_RATE" ceil "$BRIDGE_RATE" quantum "$QUANT" 2>/dev/null || true
  fi

  _mix_major=1
  _out_major=1
  _in_major=1
  _mix_minor=1
  _out_minor=1
  _in_minor=1
  _current_root_prio=99

  # Catch-all mirred: трафик вне SUBNETS_LIMITS попадает на IFB_MIX (BRIDGE лимит)
  # Per-subnet mirred внутри loop имеют приоритет (first-match-wins)
  if [ "$_needs_mix" = "1" ]; then
    tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
    tc filter add dev "$TUN" parent 1: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
    tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
    tc filter add dev "$TUN" parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
  fi
  if [ "$_needs_out" = "1" ]; then
    tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT" || echo "⚠️ tc filter" >&2
    tc filter add dev "$TUN" parent 1: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT" || echo "⚠️ tc filter" >&2
  fi
  if [ "$_needs_in" = "1" ]; then
    tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN" || echo "⚠️ tc filter" >&2
    tc filter add dev "$TUN" parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN" || echo "⚠️ tc filter" >&2
  fi

  echo "📊 Настройка лимитов скорости..."

  for entry in "${SUBNETS_LIMITS[@]}"; do
      # Парсим лимиты (формат: "subnet1, subnet2:LIM" или "subnet1:LIM_D:LIM_U")
      # Лимит - всё что ПОСЛЕДНЕГО '/' (mask) - prefix digits
      _parsed=$(parse_entry "$entry")
      SUBNETS_PART=$(echo "$_parsed" | cut -d'|' -f1)
      _lim_part=$(echo "$_parsed" | cut -d'|' -f2)
      [ -z "$_lim_part" ] && _lim_part="0"

      # Инкремент приоритета для root фильтров (каждое правило свой prio)
      _current_root_prio=$((_current_root_prio + 1))

      # Парсим Download и Upload лимиты
      if echo "$_lim_part" | grep -q ':'; then
          LIM_DOWN="${_lim_part%%:*}"
          LIM_UP="${_lim_part##*:}"
      else
          LIM_DOWN="$_lim_part"
          LIM_UP="$_lim_part"
      fi

      # Определяем тип правила: MIX (одно значение) или SEPARATE (два значения через :)
      _rule_type="mix"
      if echo "$_lim_part" | grep -q ':'; then
          _rule_type="separate"
      fi

      # Сохраняем оригинальные значения до замены
      _orig_down="$LIM_DOWN"
      _orig_up="$LIM_UP"
      # '0mbit'/'0kbit' и т.п. — выключено, как '0' (фикс аудита-limits-24:
      # иначе 0-токен с суффиксом считался активным лимитом и давал rate 0/мусор
      # — подсеть молча уходила в BRIDGE-класс вместо «без лимита»)
      case "$_orig_down" in 0|0m|0M|0mb|0Mb|0mbit|0Mbit|0k|0K|0kb|0Kb|0kbit|0Kbit) _orig_down="0" ;; esac
      case "$_orig_up" in 0|0m|0M|0mb|0Mb|0mbit|0Mbit|0k|0K|0kb|0Kb|0kbit|0Kbit) _orig_up="0" ;; esac

      # Нормализация единиц для tc (фикс стенда-парсеров: «5m/100mbit/10gbit»
      # склеивались с приклеиваемым «mbit» → «5mmbit» → tc «Illegal rate», лимит
      # молча не работал). Голое число = мегабиты. Оставляем только цифры.
      LIM_DOWN="$(echo "$LIM_DOWN" | sed -E 's/[a-zA-Z]+$//')"
      LIM_UP="$(echo "$LIM_UP" | sed -E 's/[a-zA-Z]+$//')"

      # Если оба лимита = 0, пропускаем всю группу
      if [ "$_orig_down" = "0" ] && [ "$_orig_up" = "0" ]; then
          echo "⚡ $SUBNETS_PART -> лимит отключен (0)"
          continue
      fi

      # Флаги: создавать ли классы для каждой стороны
      _create_down=1
      _create_up=1
      [ "$_orig_down" = "0" ] && _create_down=0
      [ "$_orig_up" = "0" ] && _create_up=0

      # Для совместимости - если одно значение, используем его как общий
      LIM="$LIM_DOWN"
      
      # Разбиваем подсети по запятой и обрезаем пробелы
      SUBNET_ARRAY=()
      IFS=',' read -ra RAW_SUBNETS <<< "$SUBNETS_PART"
      for s in "${RAW_SUBNETS[@]}"; do
        s="$(echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "$s" ] && SUBNET_ARRAY+=("$s")
      done

      # Фикс аудита-limits-24: per-address режим с >65536 адресов (v4 /9../15,
      # v6 /96../111) молча НЕ лимитировал подсеть (list_subnet_ips падает).
      # Проверка ДО mirred-редиректов: иначе «пропущенное» правило всё равно
      # тащило бы трафик в IFB-BRIDGE-класс (вводящее в заблуждение; регресс).
      if [ "${#SUBNET_ARRAY[@]}" -eq 1 ]; then
        _one_info=$(get_subnet_info "${SUBNET_ARRAY[0]}")
        _one_addr="${_one_info%%:*}"
        if [ -n "$_one_addr" ] && [ "$_one_addr" -gt 65536 ] 2>/dev/null; then
          echo "⚠️ ${SUBNET_ARRAY[0]}: $_one_addr адресов — per-address режим не поддерживается (>65536; минимум /16 для IPv4, /112 для IPv6) — правило пропущено" >&2
          continue
        fi
      fi

      # Per-subnet mirred на TUN: перенаправляем трафик ТОЛЬКО этих подсетей на нужные IFB
      # Вместо старого catch-all (match u32 0 0), который забирал весь трафик
      for _mirred_sub in "${SUBNET_ARRAY[@]}"; do
        if [[ "$_mirred_sub" == *:* ]]; then
            _mirred_proto="ipv6"
            _mirred_match="ip6"
        else
            _mirred_proto="ip"
            _mirred_match="ip"
        fi
        if [ "$_rule_type" = "mix" ]; then
            # MIX: оба направления на IFB_MIX (prio 100 — раньше catch-all 49152,
            # фикс аудита: иначе catch-all затенял per-subnet в MIX+SEPARATE)
            tc filter add dev "$TUN" parent 1: protocol $_mirred_proto prio 100 u32 match $_mirred_match dst "$_mirred_sub" action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
            tc filter add dev "$TUN" parent ffff: protocol $_mirred_proto prio 100 u32 match $_mirred_match src "$_mirred_sub" action mirred egress redirect dev "$IFB_MIX" || echo "⚠️ tc filter" >&2
        else
            # Separate: OUT на parent 1: (egress=download=dst), IN на parent ffff: (ingress=upload=src)
            if [ "$_create_down" = "1" ]; then
                tc filter add dev "$TUN" parent 1: protocol $_mirred_proto prio 100 u32 match $_mirred_match dst "$_mirred_sub" action mirred egress redirect dev "$IFB_OUT" || echo "⚠️ tc filter" >&2
            fi
            if [ "$_create_up" = "1" ]; then
                tc filter add dev "$TUN" parent ffff: protocol $_mirred_proto prio 100 u32 match $_mirred_match src "$_mirred_sub" action mirred egress redirect dev "$IFB_IN" || echo "⚠️ tc filter" >&2
            fi
        fi
  done

  # Если только одна подсеть — создаём 1 класс на КАЖДЫЙ IP (без маскирования!)
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

      # Получаем информацию о подсети через helper функцию
      SUBNET_INFO=$(get_subnet_info "$SUBNET")
      NUM_ADDRS=$(echo "$SUBNET_INFO" | cut -d':' -f1)
      PREFIXLEN=$(echo "$SUBNET_INFO" | cut -d':' -f2)

      # Адрес сети (network): не выдаётся клиентам → не лимитируется
      NET_ADDR=$(SUBNET_ARG="$SUBNET" python3 -c \
        "import ipaddress,os; print(str(ipaddress.ip_network(os.environ['SUBNET_ARG'],strict=False).network_address))" 2>/dev/null)

      # Пропуски резервных групп — только если подсеть правила совпадает с
      # главной (LOCAL_SUBNETS): для чужих подсетей лимитируем всё «как есть».
      _rule_has_main=0
      if [ "$SUBNET" = "$LOCAL_SUBNETS_IPV4" ] || [ "$SUBNET" = "$LOCAL_SUBNETS_IPV6" ] \
         || subnets_equal "$SUBNET" "$LOCAL_SUBNETS_IPV4" \
         || subnets_equal "$SUBNET" "$LOCAL_SUBNETS_IPV6"; then
        _rule_has_main=1
      fi

      # Принудительный перенос на новую иерархию для каждого правила
      # Это разносит разные правила SUBNETS_LIMITS по разным иерархиям
      _mix_client_num=0
      _mix_major=$((_mix_major + 1))
      _mix_minor=1
      _rule_base_major=$_mix_major
      create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"

      # Одна подсеть = 1 класс на КАЖДЫЙ IP (без маскирования!)
      IPS=$(list_subnet_ips "$SUBNET")

      # Принудительный перенос на новую иерархию для separate режима (ОДИН раз на правило)
      if [ "$_rule_type" != "mix" ]; then
          _out_client_num=0
          _out_major=$((_out_major + 1))
          _out_minor=1
          _rule_base_out_major=$_out_major
          create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
          _in_client_num=0
          _in_major=$((_in_major + 1))
          _in_minor=1
          _rule_base_in_major=$_in_major
          create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
      fi

      for ip in $IPS; do
          # Дополнительная прослойка: адрес из ЗАПИСИ подсети правила (часть
          # до '/'), если запись НЕ выровнена на адрес сети — адрес считается
          # «зарезервированным» и его класс не создаётся (в т.ч. чужие сети).
          _a_addr="${SUBNET%%/*}"
          if [ -n "$_a_addr" ] && [ "$_a_addr" != "$NET_ADDR" ] && [ "$ip" = "$_a_addr" ]; then
            continue
          fi
          # Пропуски (network/сервер/broadcast) имеют смысл ТОЛЬКО для главной
          # подсети сервера (LOCAL_SUBNETS): в правило с посторонней подсетью
          # адреса резервов не пропускаются — лимитируется всё «как есть».
          if [ "$_rule_has_main" = "1" ]; then
          [ -n "$NET_ADDR" ] && [ "$ip" = "$NET_ADDR" ] && continue
          if [ "$IP_VERSION" = "ipv6" ]; then
              [ -n "$LOCAL_SERVER_IP_IPV6" ] && [ "$ip" = "$LOCAL_SERVER_IP_IPV6" ] && continue
              if [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ] && [ -n "$BROADCAST_ADDR_IPV6" ] \
                 && [ "$ip" = "$BROADCAST_ADDR_IPV6" ]; then continue; fi
          else
              [ -n "$LOCAL_SERVER_IP" ] && [ "$ip" = "$LOCAL_SERVER_IP" ] && continue
              if [ "$SERVER_ON_NETWORK" -eq 0 ] && [ -n "$BROADCAST_ADDR" ] \
                 && [ "$ip" = "$BROADCAST_ADDR" ]; then continue; fi
          fi
          fi
          if [ "$_rule_type" = "mix" ]; then
              _mix_client_num=$((_mix_client_num + 1))
              _mix_major=$((_rule_base_major + (_mix_client_num - 1) / CLIENT_SLOTS))
              _mix_minor=$(((_mix_client_num - 1) % CLIENT_SLOTS + 2))
              if [ "$_mix_major" -gt "$_rule_base_major" ] && [ "$_mix_minor" -eq 2 ]; then
                  create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
              fi
              _classid="${_mix_major}:${_mix_minor}"
              _major="${_mix_major}:"

              if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                  tc class add dev "$IFB_MIX" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 dst $ip flowid $_classid || echo "⚠️ tc filter" >&2
                      tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 src $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  else
                      tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip dst $ip flowid $_classid || echo "⚠️ tc filter" >&2
                      tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip src $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  fi
                  tc qdisc add dev "$IFB_MIX" parent $_classid fq_codel 2>/dev/null || true
              fi
          else
              _out_client_num=$((_out_client_num + 1))
              _out_major=$((_rule_base_out_major + (_out_client_num - 1) / CLIENT_SLOTS))
              _out_minor=$(((_out_client_num - 1) % CLIENT_SLOTS + 2))
              if [ "$_out_major" -gt "$_rule_base_out_major" ] && [ "$_out_minor" -eq 2 ]; then
                  create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
              fi
              _classid="${_out_major}:${_out_minor}"
              _major="${_out_major}:"

              if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                  tc class add dev "$IFB_OUT" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      # OUT на parent 1: (egress) = download = dst клиента
                      tc filter add dev "$IFB_OUT" protocol ipv6 parent ${_out_major}: prio 2 u32 match ip6 dst $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  else
                      tc filter add dev "$IFB_OUT" protocol ip parent ${_out_major}: prio 1 u32 match ip dst $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  fi
                  tc qdisc add dev "$IFB_OUT" parent $_classid fq_codel 2>/dev/null || true
              fi

              _in_client_num=$((_in_client_num + 1))
              _in_major=$((_rule_base_in_major + (_in_client_num - 1) / CLIENT_SLOTS))
              _in_minor=$(((_in_client_num - 1) % CLIENT_SLOTS + 2))
              if [ "$_in_major" -gt "$_rule_base_in_major" ] && [ "$_in_minor" -eq 2 ]; then
                  create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
              fi
              _classid="${_in_major}:${_in_minor}"
              _major="${_in_major}:"

              if [ "$_create_up" = "1" ] && [ "$_orig_up" != "0" ]; then
                  tc class add dev "$IFB_IN" parent $_major classid $_classid htb rate "${LIM_UP}"mbit ceil "${LIM_UP}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      # IN на parent ffff: (ingress) = upload = src клиента
                      tc filter add dev "$IFB_IN" protocol ipv6 parent ${_in_major}: prio 2 u32 match ip6 src $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  else
                      tc filter add dev "$IFB_IN" protocol ip parent ${_in_major}: prio 1 u32 match ip src $ip flowid $_classid || echo "⚠️ tc filter" >&2
                  fi
                  tc qdisc add dev "$IFB_IN" parent $_classid fq_codel 2>/dev/null || true
              fi
          fi
      done
      # Глобальный аккумулятор (single-ветка; фикс аудита: раньше учитывалась
      # только ratio-ветка — warning не срабатывал на per-address правилах)
      if [ "$_rule_type" = "mix" ]; then
          TOTAL_LIMIT_CLASSES=$((TOTAL_LIMIT_CLASSES + _mix_client_num))
      else
          TOTAL_LIMIT_CLASSES=$((TOTAL_LIMIT_CLASSES + _out_client_num + _in_client_num))
      fi
      if [ "$TOTAL_LIMIT_CLASSES" -gt 250000 ]; then
          echo "⚠️  Суммарное число классов лимитов ($TOTAL_LIMIT_CLASSES) чрезмерно — up может зависнуть/исчерпать память" >&2
      fi
      if [ "$_rule_type" = "mix" ]; then
          echo "⚡ $SUBNET -> ${_orig_down} mbit (MIX)"
      else
          echo "⚡ $SUBNET -> ↓${_orig_down} mbit ↑${_orig_up} mbit"
      fi
  else
      # Принудительный перенос на новую иерархию для каждого правила
      # Это разносит разные правила SUBNETS_LIMITS по разным иерархиям
      _mix_client_num=0
      _mix_major=$((_mix_major + 1))
      _mix_minor=1
      _rule_base_major=$_mix_major
      create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
      if [ "$_rule_type" != "mix" ]; then
          _out_client_num=0
          _out_major=$((_out_major + 1))
          _out_minor=1
          _rule_base_out_major=$_out_major
          create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
          _in_client_num=0
          _in_major=$((_in_major + 1))
          _in_minor=1
          _rule_base_in_major=$_in_major
          create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
      fi
      # Сеть каждой подсети правила (для прослойки невыровненных записей)
      # пересчитывается ЗАНОВО для каждого правила (фикс аудита: stale _ANET
      # ложно считал выровненные записи последующих правил невыровненными).
      unset _ANET_SET 2>/dev/null || true

      # Несколько подсетей — поддерживаем кратные соотношения
      # MULTIPLIER из Bash передаётся как параметр
      RATIO_INFO=$(calc_subnet_ratios "$SUBNETS_PART")
          NUM_CLASSES=$(echo "$RATIO_INFO" | cut -d'|' -f1)

          # Страховка (фикс аудита): /96 → 2^32 классов вешал up навечно
          if [ "$NUM_CLASSES" -gt 65536 ]; then
              echo "⚠️  $SUBNETS_PART: слишком много классов ($NUM_CLASSES) — лимит пропущен"
              continue
          fi

          # Подсчёт общего количества классов
          if [ "$_rule_type" = "mix" ]; then
              _total_classes="$NUM_CLASSES"
          else
              _total_classes=0
              [ "$_create_down" = "1" ] && _total_classes=$((_total_classes + NUM_CLASSES))
              [ "$_create_up" = "1" ] && _total_classes=$((_total_classes + NUM_CLASSES))
          fi
          TOTAL_LIMIT_CLASSES=$((TOTAL_LIMIT_CLASSES + _total_classes))
          if [ "$TOTAL_LIMIT_CLASSES" -gt 250000 ]; then
              echo "⚠️  Суммарное число классов лимитов ($TOTAL_LIMIT_CLASSES) чрезмерно — up может зависнуть/исчерпать память" >&2
          fi

for idx in $(seq 0 $((NUM_CLASSES - 1))); do
                  # Сеть каждой подсети правила (для проверки «выровнена ли запись»)
                  # — считаем один раз на правило, не на юнит.
                  if [ -z "${_ANET_SET:-}" ]; then
                    _ANET=()
                    i2=0
                    for _rs2 in "${SUBNET_ARRAY[@]}"; do
                      _ANET[i2]=$(SUBNET_ARG="$_rs2" python3 -c \
                        "import ipaddress,os; print(str(ipaddress.ip_network(os.environ['SUBNET_ARG'],strict=False).network_address))" 2>/dev/null)
                      i2=$((i2+1))
                    done
                    _ANET_SET=1
                  fi
                  # Пропуски резервов — только когда правило содержит главную
                  # подсеть (LOCAL_SUBNETS); для чужих подсетей — всё лимитируется.
                  _rule_has_main=0
                  for _rhm in "${SUBNET_ARRAY[@]}"; do
                    if [ "$_rhm" = "$LOCAL_SUBNETS_IPV4" ] || [ "$_rhm" = "$LOCAL_SUBNETS_IPV6" ] \
                       || subnets_equal "$_rhm" "$LOCAL_SUBNETS_IPV4" \
                       || subnets_equal "$_rhm" "$LOCAL_SUBNETS_IPV6"; then
                      _rule_has_main=1
                    fi
                  done
                  if [ "$_rule_has_main" = "1" ]; then
                  # Юнит 0 = группа network-адреса (не выдаётся клиентам) →
                  # пропускается (как серверная и broadcast-группы)
                  [ "$idx" = "0" ] && continue
                  # Пропуск юнита: блок любой подсети содержит адрес СЕРВЕРА
                  # (нестандартный адрес — ловим именно группу) ИЛИ блок главной
                  # подсети заканчивается на broadcast, когда broadcast активен
                  # (сервер не на network). Класс и фильтры для него не создаются,
                  # нумерация остальных юнитов не сдвигается.
                  _skip=0
                  i=0
                  for sub_info in $(echo "$RATIO_INFO" | cut -d'|' -f2- | tr '|' ' '); do
                    [ -z "$sub_info" ] && { i=$((i+1)); continue; }
                    _rsn=${SUBNET_ARRAY[$i]}
                    _scount=$(echo "$sub_info" | cut -d':' -f1)
                    _sratio=$(echo "$sub_info" | cut -d':' -f4)
                    _snum=$(echo "$sub_info" | cut -d':' -f5)
                    [ "$_sratio" = "0" ] && { i=$((i+1)); continue; }
                    [ "$_snum" = "0" ] && { i=$((i+1)); continue; }
                    [ "$idx" -gt $((_snum - 1)) ] && { i=$((i+1)); continue; }
                    _sbase=$(get_block_ip "$_rsn" "$_sratio" "$idx")
                    if [ -n "$_sbase" ]; then
                      # Пропуски — ТОЛЬКО для подсети правила, совпадающей с
                      # главной (LOCAL_SUBNETS): чужая подсеть лимитируется
                      # целиком, её адреса network/broadcast не пропускаются.
                      _sub_main=0
                      [ "$_rsn" = "$LOCAL_SUBNETS_IPV4" ] && _sub_main=1
                      [ "$_rsn" = "$LOCAL_SUBNETS_IPV6" ] && _sub_main=1
                      if [ "$_sub_main" = "0" ]; then
                        subnets_equal "$_rsn" "$LOCAL_SUBNETS_IPV4" && _sub_main=1
                        subnets_equal "$_rsn" "$LOCAL_SUBNETS_IPV6" && _sub_main=1
                      fi
                      if [ "$_sub_main" = "1" ]; then
                      _srv=""
                      if [[ "$_rsn" == *:* ]]; then
                        _srv="$LOCAL_SERVER_IP_IPV6"
                      else
                        _srv="$LOCAL_SERVER_IP"
                      fi
                      if [ -n "$_srv" ] && net_contains_ip "$_sbase" "$_srv"; then
                        _skip=1
                      fi
                      # broadcast-группа: только если broadcast активен
                      if [[ "$_rsn" == *:* ]]; then
                        if [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ] && net_is_last_block "$_rsn" "$_sbase"; then
                          _skip=1
                        fi
                      else
                        if [ "$SERVER_ON_NETWORK" -eq 0 ] && net_is_last_block "$_rsn" "$_sbase"; then
                          _skip=1
                        fi
                      fi
                      fi
                      # Доп. прослойка (для ЛЮБОЙ подсети, вне гейта _rule_has_main —
                      # фикс аудита: для foreign-only правил тоже): запись НЕ
                      # выровнена (адрес до '/' != адрес сети) → юнит с адресом
                      # записи пропускается (адрес «зарезервирован» записью).
                      _a_addr="${_rsn%%/*}"
                      _an="${_ANET[$i]}"
                      if [ -n "$_a_addr" ] && [ "$_a_addr" != "$_an" ] && net_contains_ip "$_sbase" "$_a_addr"; then
                        _skip=1
                      fi
                    fi
                    i=$((i+1))
                  done
                  [ "$_skip" = "1" ] && continue
                  fi
                  if [ "$_rule_type" = "mix" ]; then
                    _mix_client_num=$((_mix_client_num + 1))
                    _mix_major=$((_rule_base_major + (_mix_client_num - 1) / CLIENT_SLOTS))
                    _mix_minor=$(((_mix_client_num - 1) % CLIENT_SLOTS + 2))
                    if [ "$_mix_major" -gt "$_rule_base_major" ] && [ "$_mix_minor" -eq 2 ]; then
                        create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
                    fi
                    _classid="${_mix_major}:${_mix_minor}"
                    _major="${_mix_major}:"

                    if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                        tc class add dev "$IFB_MIX" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi
                else
                    _out_client_num=$((_out_client_num + 1))
                    _out_major=$((_rule_base_out_major + (_out_client_num - 1) / CLIENT_SLOTS))
                    _out_minor=$(((_out_client_num - 1) % CLIENT_SLOTS + 2))
                    if [ "$_out_major" -gt "$_rule_base_out_major" ] && [ "$_out_minor" -eq 2 ]; then
                        create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
                    fi
                    _classid="${_out_major}:${_out_minor}"
                    _major="${_out_major}:"

                    if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                        tc class add dev "$IFB_OUT" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi

                    _in_client_num=$((_in_client_num + 1))
                    _in_major=$((_rule_base_in_major + (_in_client_num - 1) / CLIENT_SLOTS))
                    _in_minor=$(((_in_client_num - 1) % CLIENT_SLOTS + 2))
                    if [ "$_in_major" -gt "$_rule_base_in_major" ] && [ "$_in_minor" -eq 2 ]; then
                        create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
                    fi
                    _classid="${_in_major}:${_in_minor}"
                    _major="${_in_major}:"

                    if [ "$_create_up" = "1" ] && [ "$_orig_up" != "0" ]; then
                        tc class add dev "$IFB_IN" parent $_major classid $_classid htb rate "${LIM_UP}"mbit ceil "${LIM_UP}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi
                fi

                i=0
                for sub_info in $(echo "$RATIO_INFO" | cut -d'|' -f2- | tr '|' ' '); do
                  [ -z "$sub_info" ] && continue

                  count=$(echo "$sub_info" | cut -d':' -f1)
                  prefix=$(echo "$sub_info" | cut -d':' -f2)
                  ip_type=$(echo "$sub_info" | cut -d':' -f3)
                  ratio=$(echo "$sub_info" | cut -d':' -f4)
                  num_classes=$(echo "$sub_info" | cut -d':' -f5)

                  [ "$ratio" = "0" ] && continue
                  [ "$num_classes" = "0" ] && continue
                  max_idx=$((num_classes - 1))
                  [ "$idx" -gt "$max_idx" ] && continue

                  subnet="${SUBNET_ARRAY[$i]}"

                  BLOCK_BASE=$(get_block_ip "$subnet" "$ratio" "$idx")

                  if [ -n "$BLOCK_BASE" ]; then
                      if [ "$_rule_type" = "mix" ]; then
                          if [ "$_create_down" = "1" ]; then
                              if [ "$ip_type" = "ipv6" ]; then
                                  tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 dst $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                                  tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 src $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              else
                                  tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip dst $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                                  tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip src $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              fi
                          fi
                      else
                          if [ "$_create_down" = "1" ]; then
                              # OUT на parent 1: (egress) = download = dst клиента
                              if [ "$ip_type" = "ipv6" ]; then
                                  tc filter add dev "$IFB_OUT" protocol ipv6 parent ${_out_major}: prio 2 u32 match ip6 dst $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              else
                                  tc filter add dev "$IFB_OUT" protocol ip parent ${_out_major}: prio 1 u32 match ip dst $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              fi
                          fi
                          if [ "$_create_up" = "1" ]; then
                              # IN на parent ffff: (ingress) = upload = src клиента
                              if [ "$ip_type" = "ipv6" ]; then
                                  tc filter add dev "$IFB_IN" protocol ipv6 parent ${_in_major}: prio 2 u32 match ip6 src $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              else
                                  tc filter add dev "$IFB_IN" protocol ip parent ${_in_major}: prio 1 u32 match ip src $BLOCK_BASE flowid $_classid || echo "⚠️ tc filter" >&2
                              fi
                          fi
                      fi
                  fi

                  i=$((i + 1))
              done

              if [ "$_rule_type" = "mix" ]; then
                  if [ "$_create_down" = "1" ]; then
                      tc qdisc add dev "$IFB_MIX" parent $_classid fq_codel 2>/dev/null || true
                  fi
              else
                  if [ "$_create_down" = "1" ]; then
                      tc qdisc add dev "$IFB_OUT" parent $_classid fq_codel 2>/dev/null || true
                  fi
                  if [ "$_create_up" = "1" ]; then
                      tc qdisc add dev "$IFB_IN" parent $_classid fq_codel 2>/dev/null || true
                  fi
              fi
          done
          if [ "$_rule_type" = "mix" ]; then
              echo "⚡ $SUBNETS_PART -> ${_orig_down} mbit (MIX) (${_total_classes} классов)"
          else
              echo "⚡ $SUBNETS_PART -> ↓${_orig_down} mbit ↑${_orig_up} mbit (${_total_classes} классов)"
          fi
        fi
    done
    echo "✅ Лимиты скорости настроены"
  fi
fi

# --- Послеквотный throttle: применяем ПОСЛЕ блока лимитов ---
# (лимиты пересоздавали root/ingress qdisc на TUN и ifb_<tun>_mix — сносили
# pref-5 фильтры и HTB-классы throttle; аудит: перенос фазы в конец up).
# Lock уже удерживается с начала квотной секции (см. выше) — фаза идёт под ним.
# Миграция дофиксового формата .thr (3 поля, без pref; фикс аудита-5x5 +
# регресс): уникальные prefs (5+idx) — общий «|5» коллайдил между наборами
awk -F'|' 'NF==3 {print $0 "|" (5+NR)} NF>3 {print}' "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr" > "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr.mig" 2>/dev/null && mv -f "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr.mig" "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr"
true
# Зачистка устаревших throttle-записей (наборы вне текущих квот: правило
# удалено/конфиг изменён; up без down иначе держал бы их классы и фильтры).
for _old in $(grep -oE '^Q_[^|]+' "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr" 2>/dev/null | sort -u); do
  case " ${_QSETS:-} " in
    *" $_old "*) ;;
    *) quota_throttle_off "$_old" "$TUN" ;;
  esac
done
if [ "${#TRAFFIC_QUOTAS[@]}" -gt 0 ]; then
  for _qsn in ${_QSETS:-}; do
    _tu="${THR_UP[$_qsn]:-0}"; _td="${THR_DOWN[$_qsn]:-0}"
    if [ "$_tu" -gt 0 ] || [ "$_td" -gt 0 ]; then
      if ! quota_throttle_on "$_qsn" "$_tu" "$_td" "${CL_BLOCK4[$_qsn]:-}" "${CL_BLOCK6[$_qsn]:-}" "$TUN"; then
        # Вооружение не удалось (пул pref исчерпан / tc не встал): возвращаем
        # строгий DROP — снимаем намерение и пересобираем периоды набора
        # (без хвоста и без throttle дыры быть не должно; фикс волны-2 аудита)
        THR_UP["$_qsn"]=0; THR_DOWN["$_qsn"]=0
        for _pp in "${!THR_PERIOD[@]}"; do
          case "$_pp" in
            "$_qsn|"*) unset THR_PERIOD["$_pp"] ;;
          esac
        done
        for _pp in "${!QUOTA_BUILD[@]}"; do
          case " ${QUOTA_BUILD[$_pp]} " in
            *" $_qsn:"*) quota_build_period "$_pp" "${QUOTA_BUILD[$_pp]}" ;;
          esac
        done
        echo "⚠️ throttle не вооружён для $_qsn — периоды пересобраны со строгим DROP" >&2
      fi
    else
      quota_throttle_off "$_qsn" "$TUN" "${CL_BLOCK4[$_qsn]:-}" "${CL_BLOCK6[$_qsn]:-}"
    fi
  done
fi
# Полное снятие throttle без лимитов скорости: убираем HTB/ingress-артефакты
# (функционально безвредны — 10gbit default, но это мусор на интерфейсе;
# фикс аудита-5x5).
if [ ! -s "${SCRIPT_DIR%/}/.data/quota/${TUN_SAFE}.thr" ] 2>/dev/null && [ "${#SUBNETS_LIMITS[@]}" -eq 0 ]; then
  tc qdisc del dev "$TUN" root 2>/dev/null || true
  tc qdisc del dev "$TUN" handle ffff: ingress 2>/dev/null || true
fi
exec 8>&- 2>/dev/null || true

echo "————————————————————————————————"
if [ "$UPLOG" = "1" ]; then
  echo "📄 Лог сохранён: $LOG_FILE"
fi

exit 0
'''

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################


down_script_template_warp = r'''#!/bin/bash

# --- Определение пути и имени ---
DOWN_SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$DOWN_SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$DOWN_SCRIPT_PATH" down.sh)"

# --- Чтение параметров из файла сохранённого up.sh ---
STATE_BASE_DIR="$SCRIPT_DIR/.data"
TUNNELS_STATE_DIR="$STATE_BASE_DIR/temp"
TUNNEL_PARAMS_FILE="$TUNNELS_STATE_DIR/${SCRIPT_NAME}.sh"

# Восстановление глобальных sysctl, изменённых up.sh (rp_filter и др.)
# (сохранены в .data/<tun>_sysctl.save при up).
# ВАЖНО (параллельные туннели): восстанавливаем ТОЛЬКО если это последний
# активный туннель этого генератора — иначе down одного интерфейса сломал бы
# работу другого (которому всё ещё нужен rp_filter=0). Активность определяем
# по файлам параметров в .data/temp/*.sh (каждый up создаёт свой, down удаляет).
# Общий оригинал rp_filter (каталог .data): восстанавливаем только когда
# это последний активный туннель этого каталога.
OTHER_TUNNELS=$(ls "$TUNNELS_STATE_DIR"/*.sh 2>/dev/null | grep -v "/${SCRIPT_NAME}\.sh$" | wc -l)
SYSCTL_ORIG="$SCRIPT_DIR/.data/rp_filter.orig"
if [ "$OTHER_TUNNELS" -eq 0 ] && [ -f "$SYSCTL_ORIG" ]; then
  while IFS='=' read -r _sk _sv; do
    [ -n "$_sk" ] && [ -n "$_sv" ] && sysctl -w "$_sk=$_sv" >/dev/null 2>&1 || true
  done < "$SYSCTL_ORIG"
  rm -f "$SYSCTL_ORIG" 2>/dev/null || true
fi

# Инициализируем переменные
TUN=""
IFACE=""
PORT=""
LOCAL_SUBNETS=""
MARK_BASE=""
WARP_LIST=()
LAN_ALLOW=()
INTERFACE_MAP=()

# Читаем параметры — файл содержит копию awg0.sh + MARK_BASE + INTERFACE_MAP
if [ -f "$TUNNEL_PARAMS_FILE" ]; then
  source "$TUNNEL_PARAMS_FILE"
else
  echo "⚠️  Файл параметров не найден: $TUNNEL_PARAMS_FILE"
  echo "   Восстановление параметров из имени скрипта..."
  TUN="$SCRIPT_NAME"
  IFACE=""  # Не известен — очистка FORWARD будет пропущена
  # MARK_BASE вычислим позже из имени туннеля
  # LOCAL_SUBNETS не известен — очистка будет частичной
fi

# --- Настройка логирования ---
LOG_DIR="$SCRIPT_DIR/.data/log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Включаем логирование только если DOWNLOG=1
if [ "$DOWNLOG" = "1" ]; then
  LOG_FILE="$LOG_DIR/${TUN}down.log"
  exec 3>"$LOG_FILE"
  BASH_XTRACEFD=3
  set -x
fi

# Helper функции загружены из params через source:
# atomic_ref_update, find_tun_from_map

# --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
LOCAL_SUBNETS_IPV4=""
LOCAL_SUBNETS_IPV6=""
if command -v parse_local_subnets &>/dev/null 2>/dev/null; then
  parse_local_subnets
fi

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

# --- Проверка: занимает ли сервер NETWORK адрес (для broadcast/multicast) ---
# Нужно для правильной очистки правил в down скрипте
SERVER_ON_NETWORK=0
SERVER_ON_NETWORK_IPV6=0

if [ -n "$LOCAL_SUBNETS_IPV4" ] && [ -n "$LOCAL_SERVER_IP" ]; then
  SERVER_ON_NETWORK=$(check_server_network "$LOCAL_SERVER_IP" "$LOCAL_SUBNETS_IPV4")
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ] && [ -n "$LOCAL_SERVER_IP_IPV6" ]; then
  SERVER_ON_NETWORK_IPV6=$(check_server_network "$LOCAL_SERVER_IP_IPV6" "$LOCAL_SUBNETS_IPV6")
fi

# "Безопасное" имя туннеля для суффиксов (только буквы/цифры/_)
TUN_SAFE="$(echo "$TUN" | sed 's/[^a-zA-Z0-9]/_/g')"
if command -v safe_tun_name &>/dev/null 2>/dev/null; then
  TUN_SAFE=$(safe_tun_name "$TUN")
fi
# Суффиксированные/уникальные имена цепочек/ресурсов
PF_CHAIN_NAT="PORT_FORWARD_NAT_${TUN_SAFE}"
PF_CHAIN_FILTER="PORT_FORWARD_FILTER_${TUN_SAFE}"
PF_CHAIN_SNAT="PORT_FORWARD_SNAT_${TUN_SAFE}"
RANDOM_WARP_CHAIN="RANDOM_WARP_${TUN_SAFE}"
IFB_IN="ifb_${TUN_SAFE}_in"
IFB_OUT="ifb_${TUN_SAFE}_out"
IFB_MIX="ifb_${TUN_SAFE}_mix"
INPUT_CHAIN="INPUT_${TUN_SAFE}"
HAIRPIN_CHAIN="HAIRPIN_${TUN_SAFE}"

echo "————————————————————————————————"

# MARK специфичен для туннеля — берём СОХРАНЁННУЮ аллокацию, если есть
# (фикс аудита-A3: down обязан использовать ту же базу, что и up, иначе
# сдвинутый диапазон не будет найден и правила останутся).
if [ -f "$SCRIPT_DIR/.data/mark_base_${TUN_SAFE}" ]; then
  MARK_BASE=$(cat "$SCRIPT_DIR/.data/mark_base_${TUN_SAFE}" 2>/dev/null)
elif command -v calc_mark_base &>/dev/null 2>/dev/null; then
  MARK_BASE=$(calc_mark_base "$TUN")
else
  TUN_HASH=$(echo -n "$TUN" | cksum 2>/dev/null | cut -d' ' -f1)
  if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
    TUN_HASH=$(echo -n "$TUN" | md5sum 2>/dev/null | cut -c1-8)
    TUN_HASH=$((16#$TUN_HASH))
  fi
  if [ -z "$TUN_HASH" ] || [ "$TUN_HASH" = "0" ]; then
    TUN_HASH=${#TUN}
  fi
  MARK_BASE=$((1000 + ((TUN_HASH % 900) * 11 % 900) * 10))
fi

# --- Остановка WARP-туннелей ---
# WARP_LIST уже доступен из source выше
WARP_ACTIVE=0

# Собираем все уникальные WARP интерфейсы из всех записей WARP_LIST
# ВАЖНО: Извлекаем ТОЛЬКО имена интерфейсов (до '='), игнорируя подсети!
declare -A ALL_WARP_INTERFACES
for entry in "${WARP_LIST[@]}"; do
  # Пропускаем "none" и пустые записи
  if [ "$entry" = "none" ] || [ -z "$entry" ]; then
    continue
  fi

  # Извлекаем ТОЛЬКО имена интерфейсов (часть ДО '=')
  # Пример: "awg10warp0=8.8.8.8, 8.8.4.4" → "awg10warp0"
  #         "awg10warp3, awg10warp4" → "awg10warp3, awg10warp4"
  if [[ "$entry" == *"="* ]]; then
    interfaces_part="${entry%%=*}"
  else
    interfaces_part="$entry"
  fi

  # Разбиваем интерфейсы по запятой и обрезаем пробелы
  IFS=',' read -ra RAW_INTERFACES <<< "$interfaces_part"
  for iface in "${RAW_INTERFACES[@]}"; do
    iface="$(echo "$iface" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    # Проверяем что это имя интерфейса (не подсеть и не IP)
    if [ -n "$iface" ] && [ "$iface" != "none" ] && [[ "$iface" != *"."* ]] && [[ "$iface" != *":"* ]] && [[ "$iface" != *"/"* ]]; then
      ALL_WARP_INTERFACES["$iface"]=1
    fi
  done
done

# Останавливаем каждый уникальный WARP интерфейс
# Reference counting + ПРЯМАЯ ПРОВЕРКА реального состояния интерфейса
WARP_ACTIVE=0

# СОХРАНЯЕМ список WARP интерфейсов ДО остановки (для последующей очистки!)
declare -A STOPPED_WARP_INTERFACES
declare -A STOPPED_WARP_ZERO_REFS
# Сохраняем TABLE_ID для каждого WARP ДО удаления записей из rt_tables
# (иначе при удалении ip rule rt_tables уже не содержит запись → ip rule не удаляется)
declare -A WARP_TABLE_IDS
for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  STOPPED_WARP_INTERFACES["$warp"]=1
done

for warp in "${!ALL_WARP_INTERFACES[@]}"; do
  echo "🛑 Остановка WARP-туннеля: $warp"
  WARP_REF_FILE="$STATE_BASE_DIR/warp/${warp}.ref"

  # ПРЯМАЯ ПРОВЕРКА: запущен ли интерфейс реально
  WARP_RUNNING=0
  if ip link show "$warp" &>/dev/null; then
    WARP_RUNNING=1
  fi

  # Проверяем .ref файл: атомарный get+dec (баг 1.7 — раньше get и dec были раздельными, гонка)
  WARP_STOPPED_OK=1
  if [ -f "$WARP_REF_FILE" ]; then
    ref_info=$(atomic_ref_update "$WARP_REF_FILE" "get_dec")
    ref_count="${ref_info%%:*}"
    new_count="${ref_info##*:}"

    if [ "$new_count" -le 0 ]; then
      # Последний пользователь — закрываем WARP (если он запущен)
      STOPPED_WARP_ZERO_REFS["$warp"]=1
      if [ "$WARP_RUNNING" -eq 1 ]; then
        # Предпочитаем конфиг рядом со скриптами (баг 1.16), иначе имя из стандартного каталога
        if awg-quick down "$SCRIPT_DIR/${warp}.conf" 2>/dev/null || awg-quick down "$warp" 2>/dev/null; then
          : # WARP остановлен
        else
          WARP_STOPPED_OK=0
          echo "❌ Ошибка остановки $warp — таблицы и .ref НЕ очищаем (баг 1.10)"
        fi
      else
        echo "⚠️  WARP $warp не запущен (ref=$ref_count) — очистка..."
      fi

      if [ "$WARP_STOPPED_OK" = "1" ]; then
        # Очищаем таблицу маршрутизации (только если последний пользователь)
        TABLE_ID=$(awk -v name="$warp" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
        if [ -n "$TABLE_ID" ]; then
          WARP_TABLE_IDS["$warp"]="$TABLE_ID"
          ip route flush table "$TABLE_ID" 2>/dev/null || true
          sed -i "/^${TABLE_ID}[[:space:]]\+${warp}$/d" /etc/iproute2/rt_tables 2>/dev/null || true
          echo "🗑️  Таблица маршрутизации $warp (ID $TABLE_ID) очищена"
        fi

        rm -f "$WARP_REF_FILE"
      fi
    else
      # Счётчик уменьшен, таблица остаётся для других
      echo "📋 WARP $warp используется другими туннелями (ref=$ref_count → $new_count)"
    fi
  else
    # .ref нет — проверяем запущен ли WARP и закрываем если да
    STOPPED_WARP_ZERO_REFS["$warp"]=1
    if [ "$WARP_RUNNING" -eq 1 ]; then
      echo "⚠️  WARP $warp запущен но .ref не найден — очистка..."
      if awg-quick down "$SCRIPT_DIR/${warp}.conf" 2>/dev/null || awg-quick down "$warp" 2>/dev/null; then
        : # WARP остановлен
      else
        WARP_STOPPED_OK=0
        echo "❌ Ошибка остановки $warp — таблицы НЕ очищаем (баг 1.10)"
      fi

      if [ "$WARP_STOPPED_OK" = "1" ]; then
        # Очищаем таблицу маршрутизации
        TABLE_ID=$(awk -v name="$warp" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
        if [ -n "$TABLE_ID" ]; then
          WARP_TABLE_IDS["$warp"]="$TABLE_ID"
          ip route flush table "$TABLE_ID" 2>/dev/null || true
          sed -i "/^${TABLE_ID}[[:space:]]\+${warp}$/d" /etc/iproute2/rt_tables 2>/dev/null || true
          echo "🗑️  Таблица маршрутизации $warp (ID $TABLE_ID) очищена"
        fi
      fi
    else
      echo "⚠️  WARP $warp не запущен и .ref не найден — пропускаем"
    fi
  fi

  # Удаляем .active файл только если WARP реально остановлен (ref=0 или .ref не найден)
  if [ "${STOPPED_WARP_ZERO_REFS["$warp"]+x}" = "x" ]; then
    rm -f "$STATE_BASE_DIR/warp/${warp}.active" 2>/dev/null || true
  fi
done

# Все переменные (TUN, IFACE, PORT, LOCAL_SUBNETS, WARP_LIST, LAN_ALLOW, INTERFACE_MAP, MARK_BASE)
# уже загружены через source в начале скрипта.

# Разбираем LOCAL_SUBNETS на IPv4 и IPv6
if command -v parse_local_subnets &>/dev/null 2>/dev/null; then
  parse_local_subnets
fi

# --- Очистка маршрутизации и таблиц для WARP ---
# Очищаем ВСЕГДА для всех WARP интерфейсов которые были остановлены
# Используем STOPPED_WARP_INTERFACES (сохранён ДО чтения файла параметров!)
if [ ${#STOPPED_WARP_INTERFACES[@]} -gt 0 ]; then
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

  # --- Удаляем ip rule для специфичных подсетей и default-группы ---
  # Агрегированный layout (warp_specific_layout) — те же оффсеты, что в up
  while IFS='|' read -r _kind _off _cnt _sub _ifs; do
    if [ "$_kind" = "S" ]; then
      MARK_OFFSET="$_off"
      IFS=',' read -ra WARP_GROUP <<< "$_ifs"
      WARP_GROUP_COUNT="$_cnt"
      for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
        MARK=$((MARK_BASE + MARK_OFFSET + i))
        warp_iface="${WARP_GROUP[$i]}"
        # Получаем TABLE_ID из сохранённого значения (rt_tables уже очищен при остановке WARP)
        TABLE_ID="${WARP_TABLE_IDS[$warp_iface]:-}"
        [ -z "$TABLE_ID" ] && TABLE_ID=$(awk -v name="$warp_iface" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
        if [ -n "$TABLE_ID" ]; then
          # Удаляем IPv4 правило
          ip rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          # Удаляем IPv6 правило
          ip -6 rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          # Роуты удаляем ТОЛЬКО при ref=0: иначе другой туннель остаётся
          # с маркировкой, но без маршрута — чёрная дыра (баг 1.5)
          if [ "${STOPPED_WARP_ZERO_REFS["$warp_iface"]+x}" = "x" ]; then
            ip route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
            ip -6 route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
          fi
        else
          # Fallback: пробуем удалить по имени интерфейса
          ip rule del fwmark $MARK table "$warp_iface" 2>/dev/null || true
          ip -6 rule del fwmark $MARK table "$warp_iface" 2>/dev/null || true
          if [ "${STOPPED_WARP_ZERO_REFS["$warp_iface"]+x}" = "x" ]; then
            ip route del default dev "$warp_iface" table "$warp_iface" 2>/dev/null || true
            ip -6 route del default dev "$warp_iface" table "$warp_iface" 2>/dev/null || true
          fi
        fi
      done
    elif [ "$_kind" = "D" ]; then
      MARK_OFFSET="$_off"
      IFS=',' read -ra DEFAULT_WARP_GROUP <<< "$_ifs"
      DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
      for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
        MARK=$((MARK_BASE + MARK_OFFSET + i))
        warp_iface="${DEFAULT_WARP_GROUP[$i]}"
        # Получаем TABLE_ID из сохранённого значения (rt_tables уже очищен при остановке WARP)
        TABLE_ID="${WARP_TABLE_IDS[$warp_iface]:-}"
        [ -z "$TABLE_ID" ] && TABLE_ID=$(awk -v name="$warp_iface" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
        if [ -n "$TABLE_ID" ]; then
          # Удаляем IPv4 правило
          ip rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          # Удаляем IPv6 правило
          ip -6 rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
          # Роуты удаляем ТОЛЬКО при ref=0 (баг 1.5)
          if [ "${STOPPED_WARP_ZERO_REFS["$warp_iface"]+x}" = "x" ]; then
            ip route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
            ip -6 route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
          fi
        fi
      done
    fi
  done < <(warp_specific_layout)
fi

# --- Очистка FORWARD и NAT для WARP (только для остановленных интерфейсов) ---
# FORWARD правила туннель-специфичны (-i "$TUN") — чистим для всех WARP этого туннеля
for warp in "${!STOPPED_WARP_INTERFACES[@]}"; do
  iptables -D FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

  ip6tables -D FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  ip6tables -D FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
done

# MASQUERADE правила ОБЩИЕ для всех туннелей (без -i) — чистим только когда ref=0
for warp in "${!STOPPED_WARP_ZERO_REFS[@]}"; do
  while iptables -t nat -D POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null; do :; done
  while ip6tables -t nat -D POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null; do :; done
done

# --- Очистка iptables/ip6tables для балансировки WARP (цепочка специфична для туннеля) ---
# Очищаем всегда, даже если WARP не активен (на случай если правила остались)
# Используем обе команды для поддержки IPv4 и IPv6
iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -D PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$RANDOM_WARP_CHAIN" 2>/dev/null || true

ip6tables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
ip6tables -t mangle -X "$RANDOM_WARP_CHAIN" 2>/dev/null || true

# --- Очистка FORWARD для трафика через WARP (IPv4) ---
# Уже выполнена в блоке «Очистка FORWARD» выше (по правилам -i $TUN) — не дублируем!

# --- Очистка broadcast/multicast репликации (цепочки BC_* и relay-демон) ---
# Марки повторяют up.sh: MARK_BASE+1000+GROUP_IDX по порядку групп LAN_ALLOW.
BC_MARK_CHAIN="BC_MARK_${TUN_SAFE}"
BC_NAT_CHAIN="BC_NAT_${TUN_SAFE}"
BC_TEE_CHAIN="BC_TEE_${TUN_SAFE}"

# Останавливаем relay-демон репликации (если запущен)
if [ -f "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" ]; then
    _RPID=$(cat "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" 2>/dev/null || true)
    if [ -n "$_RPID" ]; then
      kill "$_RPID" 2>/dev/null || true
      # Даём демону пару секунд на выход (мягкий stop)
      for _wi in 1 2 3 4 5; do
        kill -0 "$_RPID" 2>/dev/null || break
        sleep 0.2
      done
    fi
    rm -f "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.pid" 2>/dev/null || true
else
    # Фоллбэк pkill: pidfile потерян/не создан — демон мог остаться висеть
    pkill -f "bc_relay_${TUN_SAFE}.py" 2>/dev/null || true
fi
rm -f "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.py" 2>/dev/null || true
rm -f "$SCRIPT_DIR/.data/bc_relay_${TUN_SAFE}.log" 2>/dev/null || true
BC_CMARK_CHAIN="BC_CMARK_${TUN_SAFE}"
BC_CNAT_CHAIN="BC_CNAT_${TUN_SAFE}"

# IPv4
iptables -t mangle -D PREROUTING -i "$TUN" -j "$BC_MARK_CHAIN" 2>/dev/null || true
iptables -t mangle -F "$BC_MARK_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$BC_MARK_CHAIN" 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$TUN" -j "$BC_NAT_CHAIN" 2>/dev/null || true
iptables -t nat -F "$BC_NAT_CHAIN" 2>/dev/null || true
iptables -t nat -X "$BC_NAT_CHAIN" 2>/dev/null || true
iptables -t mangle -D POSTROUTING -o "$TUN" -j "$BC_TEE_CHAIN" 2>/dev/null || true
iptables -t mangle -F "$BC_TEE_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$BC_TEE_CHAIN" 2>/dev/null || true
# Клоны (loopback-реинжекция)
iptables -t mangle -D PREROUTING -i lo -j "$BC_CMARK_CHAIN" 2>/dev/null || true
iptables -t mangle -F "$BC_CMARK_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$BC_CMARK_CHAIN" 2>/dev/null || true
iptables -t nat -D PREROUTING -i lo -j "$BC_CNAT_CHAIN" 2>/dev/null || true
iptables -t nat -F "$BC_CNAT_CHAIN" 2>/dev/null || true
iptables -t nat -X "$BC_CNAT_CHAIN" 2>/dev/null || true

# IPv6 (если туннель с IPv6)
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t mangle -D PREROUTING -i "$TUN" -j "$BC_MARK_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -F "$BC_MARK_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -X "$BC_MARK_CHAIN" 2>/dev/null || true
  ip6tables -t nat -D PREROUTING -i "$TUN" -j "$BC_NAT_CHAIN" 2>/dev/null || true
  ip6tables -t nat -F "$BC_NAT_CHAIN" 2>/dev/null || true
  ip6tables -t nat -X "$BC_NAT_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -D POSTROUTING -o "$TUN" -j "$BC_TEE_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -F "$BC_TEE_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -X "$BC_TEE_CHAIN" 2>/dev/null || true
  # Клоны (loopback-реинжекция)
  ip6tables -t mangle -D PREROUTING -i lo -j "$BC_CMARK_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -F "$BC_CMARK_CHAIN" 2>/dev/null || true
  ip6tables -t mangle -X "$BC_CMARK_CHAIN" 2>/dev/null || true
  ip6tables -t nat -D PREROUTING -i lo -j "$BC_CNAT_CHAIN" 2>/dev/null || true
  ip6tables -t nat -F "$BC_CNAT_CHAIN" 2>/dev/null || true
  ip6tables -t nat -X "$BC_CNAT_CHAIN" 2>/dev/null || true
fi

# ACCEPT-правила помеченного broadcast/multicast (filter FORWARD)
BROADCAST_ADDR=""
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  BROADCAST_ADDR=$(get_broadcast_addr "$LOCAL_SUBNETS_IPV4")
fi

if [ -n "$BROADCAST_ADDR" ] && [ "$SERVER_ON_NETWORK" -eq 0 ]; then
  GROUP_IDX=0
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"
    IPV4_PARTS=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$part" ] && continue
      [[ "$part" != *:* ]] && IPV4_PARTS+=("$part")
    done
    if [ ${#IPV4_PARTS[@]} -gt 0 ] && [ "$GROUP_IDX" -le 99 ]; then
      VAL=$((MARK_BASE + 1000 + GROUP_IDX))
      iptables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $VAL -j ACCEPT 2>/dev/null || true
      _C_BIT=$((VAL | 0x100))
      iptables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $_C_BIT -j ACCEPT 2>/dev/null || true
    fi
    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ] && [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
  GROUP_IDX=0
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"
    IPV6_PARTS=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$part" ] && continue
      [[ "$part" == *:* ]] && IPV6_PARTS+=("$part")
    done
    if [ ${#IPV6_PARTS[@]} -gt 0 ] && [ "$GROUP_IDX" -le 99 ]; then
      VAL=$((MARK_BASE + 1000 + GROUP_IDX))
      ip6tables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $VAL -j ACCEPT 2>/dev/null || true
      _C_BIT=$((VAL | 0x100))
      ip6tables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $_C_BIT -j ACCEPT 2>/dev/null || true
    fi
    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

# --- Удаляем Hairpin NAT (IPv4 + IPv6) ---
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
  iptables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
  iptables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
  ip6tables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
  ip6tables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true
fi

# --- Полное удаление цепочек проброса портов (специфично для туннеля) ---
# IPv4 + IPv6 очистка
echo "🧹 Очистка проброса портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_SNAT, $PF_CHAIN_FILTER)"

# СНАЧАЛА удаляем ссылки из глобальных цепочек (IPv4 + IPv6)
echo "   Удаление ссылок из PREROUTING, FORWARD, POSTROUTING..."

if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  # PREROUTING → PF_CHAIN_NAT
  iptables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
  # FORWARD → PF_CHAIN_FILTER
  iptables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
  # POSTROUTING → PF_CHAIN_SNAT
  iptables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  # PREROUTING → PF_CHAIN_NAT
  ip6tables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
  # FORWARD → PF_CHAIN_FILTER
  ip6tables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
  # POSTROUTING → PF_CHAIN_SNAT
  ip6tables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
fi

# ПОТОМ очищаем цепочки (IPv4 + IPv6)
echo "🧹 Очистка цепочек..."

if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  # PF_CHAIN_NAT
  iptables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
  # PF_CHAIN_SNAT
  iptables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
  # PF_CHAIN_FILTER
  iptables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  # PF_CHAIN_NAT
  ip6tables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
  # PF_CHAIN_SNAT
  ip6tables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
  # PF_CHAIN_FILTER
  ip6tables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
fi

# В КОНЦЕ удаляем цепочки (IPv4 + IPv6)
echo "   Удаление цепочек..."

if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  # PF_CHAIN_NAT
  iptables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true
  # PF_CHAIN_SNAT
  iptables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true
  # PF_CHAIN_FILTER
  iptables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true
fi

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  # PF_CHAIN_NAT
  ip6tables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true
  # PF_CHAIN_SNAT
  ip6tables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true
  # PF_CHAIN_FILTER
  ip6tables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true
fi

# --- Очистка FORWARD и NAT для трафика напрямую через внешний интерфейс ---
# Очищаем суффиксированную цепочку INPUT (IPv4 + IPv6)

# IPv4 INPUT
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -t filter -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
  iptables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
  iptables -t filter -X "$INPUT_CHAIN" 2>/dev/null || true
fi

# IPv6 INPUT
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -t filter -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true
  ip6tables -t filter -F "$INPUT_CHAIN" 2>/dev/null || true
  ip6tables -t filter -X "$INPUT_CHAIN" 2>/dev/null || true
fi

# Очищаем правило локальной сети (из up скрипта) (IPv4 + IPv6)
# LAN_ALLOW уже прочитан выше из файла параметров!

# Получаем имя туннеля для очистки LAN_ALLOW правил
# Используем $TUN напрямую — это текущий туннель
MAIN_TUN="$TUN"

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

    # Разделяем по типам (IPv4/IPv6)
    IPV4_PARTS=()
    IPV6_PARTS=()
    for part in "${PARTS_CLEAN[@]}"; do
      if [[ "$part" == *:* ]]; then
        IPV6_PARTS+=("$part")
      else
        IPV4_PARTS+=("$part")
      fi
    done

    # ОЧИСТКА INTRA-SUBNET (для дублей и одиночных участников)
    # ВАЖНО (баг 1.6): up создаёт intra-правила через _find_tun_for_subnet, и SUBNET_TUN
    # может быть ЧУЖИМ туннелем — чистим по карте INTERFACE_MAP (+ фоллбэк на MAIN_TUN).
    # IPv4 - очищаем ВСЕ комбинации src/dst
    if [ ${#IPV4_PARTS[@]} -ge 1 ] && [ -n "$MAIN_TUN" ]; then
      for src in "${IPV4_PARTS[@]}"; do
        # Очищаем intra-subnet правило (src=dst) на найденном туннеле и на своём
        SRC_TUN_INTRA=$(find_tun_from_map "$src")
        [ -z "$SRC_TUN_INTRA" ] && SRC_TUN_INTRA="$MAIN_TUN"
        iptables -D FORWARD -i "$SRC_TUN_INTRA" -o "$SRC_TUN_INTRA" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
        [ "$SRC_TUN_INTRA" != "$MAIN_TUN" ] && iptables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
        # Очищаем cross-subnet правила (src→dst для всех dst)
        for dst in "${IPV4_PARTS[@]}"; do
          if [ "$src" != "$dst" ]; then
            iptables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$dst" -j ACCEPT 2>/dev/null || true
          fi
        done
      done
    fi

    # IPv6 - очищаем ВСЕ комбинации src/dst
    if [ ${#IPV6_PARTS[@]} -ge 1 ] && [ -n "$MAIN_TUN" ]; then
      for src in "${IPV6_PARTS[@]}"; do
        # Очищаем intra-subnet правило (src=dst) на найденном туннеле и на своём
        SRC_TUN_INTRA=$(find_tun_from_map "$src")
        [ -z "$SRC_TUN_INTRA" ] && SRC_TUN_INTRA="$MAIN_TUN"
        ip6tables -D FORWARD -i "$SRC_TUN_INTRA" -o "$SRC_TUN_INTRA" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
        [ "$SRC_TUN_INTRA" != "$MAIN_TUN" ] && ip6tables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
        # Очищаем cross-subnet правила (src→dst для всех dst)
        for dst in "${IPV6_PARTS[@]}"; do
          if [ "$src" != "$dst" ]; then
            ip6tables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$dst" -j ACCEPT 2>/dev/null || true
          fi
        done
      done
    fi

    # ОЧИСТКА INTER-SUBNET (все пары одного типа)
    for ((i=0; i<${#PARTS_CLEAN[@]}; i++)); do
      for ((j=0; j<${#PARTS_CLEAN[@]}; j++)); do
        [ $i -eq $j ] && continue

        SRC="${PARTS_CLEAN[$i]}"
        DST="${PARTS_CLEAN[$j]}"

        # Пропускаем разные типы (IPv4 ↔ IPv6)
        if [[ "$SRC" == *:* ]] && [[ "$DST" != *:* ]]; then
          continue
        fi
        if [[ "$SRC" != *:* ]] && [[ "$DST" == *:* ]]; then
          continue
        fi

        # Пропускаем одинаковые подсети (для них intra-subnet)
        [ "$SRC" = "$DST" ] && continue

        # Находим туннели из сохранённой карты
        SRC_TUN=$(find_tun_from_map "$SRC")
        DST_TUN=$(find_tun_from_map "$DST")

        # Пропускаем если туннель не найден
        [ -z "$SRC_TUN" ] && continue
        [ -z "$DST_TUN" ] && continue

        if [[ "$SRC" == *:* ]]; then
          IPT_CMD="ip6tables"
        else
          IPT_CMD="iptables"
        fi

        # Удаляем правило
        $IPT_CMD -D FORWARD -i "$SRC_TUN" -o "$DST_TUN" -s "$SRC" -d "$DST" -j ACCEPT 2>/dev/null || true
      done
    done
  done

  # LAN_ALLOW_FILE больше не используется — всё в файле параметров
fi

# Удаляем DROP правило межклиентского трафика (оно было добавлено в up.sh)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
fi

# Очищаем все FORWARD правила для этого туннеля (LAN_ALLOW, broadcast, MARK)
iptables-save -t filter 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  iptables -D $_rule 2>/dev/null || true
done
ip6tables-save -t filter 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  ip6tables -D $_rule 2>/dev/null || true
done
# Очищаем mangle FORWARD правила для этого туннеля (broadcast MARK)
iptables-save -t mangle 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  iptables -t mangle -D $_rule 2>/dev/null || true
done
ip6tables-save -t mangle 2>/dev/null | grep "^-A FORWARD .*-i $TUN " | while read -r _line; do
  _rule="${_line#-A }"
  ip6tables -t mangle -D $_rule 2>/dev/null || true
done

# Очищаем старые универсальные правила (если вдруг они есть)
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  iptables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true
fi
if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true
fi

# Очищаем правила FORWARD для трафика напрямую через внешний интерфейс
# IFACE может быть пустым если файл параметров не найден
if [ -n "$IFACE" ]; then
  if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
    iptables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
  if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
    ip6tables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
    ip6tables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
else
  echo "⚠️  Пропущено: очистка FORWARD для IFACE (не известен)"
fi

# POSTROUTING MASQUERADE не удаляем — он общий для всех туннелей (IPv4 и IPv6)

# --- Откат лимитов скорости (tc и ifb) ---
# Очищаем всё, что могло быть создано для этого туннеля
# tc работает на уровне устройств, поэтому очистка универсальна для IPv4 + IPv6
echo "🧹 Очистка лимитов скорости"
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" handle ffff: ingress 2>/dev/null || true

# Устанавливаем TUN_SUBNET4/6 из уже распарсенных LOCAL_SUBNETS
TUN_SUBNET4="$LOCAL_SUBNETS_IPV4"
TUN_SUBNET6="$LOCAL_SUBNETS_IPV6"

tc qdisc del dev "$IFB_IN" root 2>/dev/null || true
ip link set "$IFB_IN" down 2>/dev/null || true
ip link delete "$IFB_IN" 2>/dev/null || true
tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
ip link set "$IFB_OUT" down 2>/dev/null || true
ip link delete "$IFB_OUT" 2>/dev/null || true
tc qdisc del dev "$IFB_MIX" root 2>/dev/null || true
ip link set "$IFB_MIX" down 2>/dev/null || true
ip link delete "$IFB_MIX" 2>/dev/null || true

# --- Квоты трафика: снятие cron-задачи, удаление цепочек и state ---
( crontab -l 2>/dev/null | grep -v "# awg-quota-${TUN_SAFE}$" ) | crontab - 2>/dev/null || true
# Удаление прыжков по имени цепочки (snapshot-подход: один проход
# iptables-save, каждый -A → отдельный -D; клиентские IP в down неизвестны,
# поэтому удаляем по имени цепочки, как в up).
quota_jump_del() {
  local _qc="$1"
  iptables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
    _rule="${_line#-A }"
    iptables -D $_rule 2>/dev/null || true
  done
  ip6tables-save 2>/dev/null | grep -- "-j $_qc" | while read -r _line; do
    _rule="${_line#-A }"
    ip6tables -D $_rule 2>/dev/null || true
  done
}
# --- Квоты: ФИНАЛЬНЫЙ слепок расхода перед удалением цепочек ---
# Сериализация с cron/up (фикс аудита-fresh: down раньше не брал lock —
# последний-писатель-побеждал по журналу и cron мог возрождать цепочки
# мёртвого интерфейса).
exec 8>"$SCRIPT_DIR/.data/quota/${TUN_SAFE}.cron.lock"
flock -w 300 8 2>/dev/null || echo "⚠️ quota-down: не удалось дождаться cron-lock (300с)" >&2
# (иначе до 59 минут между cron-слепком и down терялись бы при восстановлении)
# Гейт — по наличию журнала, а не TRAFFIC_QUOTAS: параметры могли быть
# отредактированы в TRAFFIC_QUOTAS=() до down, а расход всё равно нужно
# зафиксировать (фикс аудита-5x5).
if [ -f "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.ledger" ]; then
  LEDGER_FILE="$SCRIPT_DIR/.data/quota/${TUN_SAFE}.ledger"
  declare -A LEDGER_D
  while IFS='|' read -r _lk _lp _ld _ll _ls _lr _lt _lb; do
    [ -z "$_lk" ] && continue
    LEDGER_D["$_lk|$_lp|$_ld"]="$_ll|$_ls|$_lr|$_lt|${_lb:-0}"
  done < "$LEDGER_FILE"
  declare -A LEDGER_NEW_D
  for _key in "${!LEDGER_D[@]}"; do
    _set="${_key%%|*}"; _pq="${_key#*|}"
    _pper="${_pq%%|*}"; _pdir="${_pq##*|}"
    _llim="${LEDGER_D[$_key]%%|*}"
    _lrest="${LEDGER_D[$_key]#*|}"
    _lspen="${_lrest%%|*}"; _lrest="${_lrest#*|}"; _lrt="${_lrest%%|*}"
    _lrest="${_lrest#*|}"; _lrest="${_lrest#*|}"
    _oldsnp="${_lrest%%|*}"
    _snp=$(snapshot_spent "$_set" "$_pper" "$_pdir")
    _delta=$(( _snp - _oldsnp )); [ "$_delta" -lt 0 ] && _delta=0
    _lspen=$(( _lspen + _delta ))
    LEDGER_NEW_D["$_key"]="$_llim|$_lspen|$_lrt|$(date +%s)|0"
  done
  : > "${LEDGER_FILE}.tmp.$$"
  for _lk in "${!LEDGER_NEW_D[@]}"; do
    echo "$_lk|${LEDGER_NEW_D[$_lk]}" >> "${LEDGER_FILE}.tmp.$$"
  done
  mv -f "${LEDGER_FILE}.tmp.$$" "$LEDGER_FILE"
fi

# Динамические периоды-ключи (H, D3, D_T20, W_T5, M_T15, ...): чистим ВСЕ
# цепочки по префиксу QUOTA_${TUN_SAFE}_ (не по фиксированному списку).
for _qc in $(iptables-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)" | sort -u); do
  quota_jump_del "$_qc"
  iptables -F "$_qc" 2>/dev/null || true
  iptables -X "$_qc" 2>/dev/null || true
done
for _qc in $(ip6tables-save 2>/dev/null | grep -oE "QUOTA_${TUN_SAFE}_[A-Za-z0-9_]+_(SRC|DST)" | sort -u); do
  quota_jump_del "$_qc"
  ip6tables -F "$_qc" 2>/dev/null || true
  ip6tables -X "$_qc" 2>/dev/null || true
done
# Общие (ALL) цепочки клиентов — после периодных (те уже пусты)
for _qc in $(iptables-save 2>/dev/null | grep -oE "Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u); do
  iptables -F "$_qc" 2>/dev/null || true
  iptables -X "$_qc" 2>/dev/null || true
done
for _qc in $(ip6tables-save 2>/dev/null | grep -oE "Q_${TUN_SAFE}_[A-Za-z0-9_.-]+_A" | sort -u); do
  ip6tables -F "$_qc" 2>/dev/null || true
  ip6tables -X "$_qc" 2>/dev/null || true
done
rm -f "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.last" "$SCRIPT_DIR/.data/quota/quota_update_${TUN_SAFE}.sh" "$SCRIPT_DIR/.data/quota/${TUN_SAFE}.thr" 2>/dev/null || true
exec 8>&- 2>/dev/null || true
ip link del "ifb_${TUN_SAFE}_mix" 2>/dev/null || true
# Throttle-чистка: mangle-правила маркировки исчерпавших + QT-наборы (ПОСТРОЧНО,
  # иначе for $() разбивает правила с пробелами и не удаляет их)
  while IFS= read -r _qc; do
    [ -z "$_qc" ] && continue
    _qc="${_qc#-A }"
    iptables -t mangle -D $_qc 2>/dev/null || true
  done < <(iptables-save -t mangle 2>/dev/null | grep "QT_${TUN_SAFE}_")
  while IFS= read -r _qc; do
    [ -z "$_qc" ] && continue
    _qc="${_qc#-A }"
    ip6tables -t mangle -D $_qc 2>/dev/null || true
  done < <(ip6tables-save -t mangle 2>/dev/null | grep "QT_${TUN_SAFE}_")
for _qs in $(ipset list -name 2>/dev/null | grep -E "^QT_${TUN_SAFE}_" || true); do
  ipset destroy "$_qs" 2>/dev/null || true
done
# per-клиентские наборы ipset (квоты) — уничтожаем
for _qs in $(ipset list -name 2>/dev/null | grep -E "^Q_${TUN_SAFE}_" || true); do
  ipset destroy "$_qs" 2>/dev/null || true
done

# --- Удаляем файл параметров ---
rm -f "$TUNNEL_PARAMS_FILE" 2>/dev/null || true
rm -f "$SCRIPT_DIR/.data/mark_base_${TUN_SAFE}" 2>/dev/null || true

echo "————————————————————————————————"
if [ "$DOWNLOG" = "1" ]; then
  echo "📄 Лог сохранён: $LOG_FILE"
fi'''

# Исходник единого сайдкара имитации awg-imitat (режимы utls|dtls; прежде —
# отдельные awg-utls и awg-dtls). Один go.mod, одна сборка. Форматы вывода
# JSON и флаги сохранены прежними (Python-парсеры не меняются).
_IMITAT_SIDECAR_GO_MOD = r'''module awg-imitat

go 1.24

require (
	github.com/pion/dtls/v2 v2.2.12
	github.com/refraction-networking/utls v1.8.2
)
'''

_IMITAT_SIDECAR_MAIN_GO = r'''// awg-imitat — единый сайдкар имитации (режимы через -mode).
//
// Режим utls (по умолчанию): генерирует Chrome QUIC ClientHello (TLS 1.3)
// через uTLS и согласованный с ним TLS 1.3 ServerHello.
// Вывод в stdout: JSON {"clienthello_hex": "...", "serverhello_hex": "...", "scid_hex": "..."}
//   - clienthello_hex — полное handshake-сообщение ClientHello (тип 0x01 + длина + тело),
//     готовое к обёртке в CRYPTO frame и QUIC Initial пакет.
//   - serverhello_hex — полное handshake-сообщение ServerHello (тип 0x02 + длина + тело),
//     отвечающее на ClientHello: echo session_id, cipher TLS_AES_128_GCM_SHA256,
//     key_share X25519 (отдельный серверный ключ).
//   - scid_hex — initial_source_connection_id из transport parameters (совпадает
//     с SCID в QUIC header).
// В QUIC legacy_session_id пустой (compat-режим запрещён, RFC 9001 §8.1; BoringSSL
// QUIC: UNEXPECTED_COMPATIBILITY_MODE при непустом — измерено на Google 16.09.2026).
// Согласованность между сторонами даёт seed (публичный ключ сервера): выбор cipher.
//
// Режим dtls: генерирует настоящие WebRTC DTLS 1.2 сообщения через Pion DTLS
// (продакшн-стек WebRTC): ClientHello (клиент) и ServerHello + flight
// (сервер, реальный X.509 сертификат + настоящая ECDSA-подпись в SKX).
// Вывод в stdout: JSON {"clienthello_hex", "serverhello_hex",
//                       "certificate_hex", "skx_hex", "shd_hex"}
//   - clienthello_hex — полный DTLS record (record header + handshake ClientHello).
//   - serverhello_hex — полный DTLS record с ServerHello.
//   - certificate_hex — полный DTLS record с Certificate.
//   - skx_hex         — полный DTLS record с ServerKeyExchange.
//   - shd_hex         — полный DTLS record с ServerHelloDone.
// Каждое handshake-сообщение сервера — отдельный record (как реальный Pion:
// ServerHello seq=0, Certificate seq=1, SKX seq=2, SHD seq=3).
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	utls "github.com/refraction-networking/utls"
)

// ---------- режим utls: QUIC (Chrome TLS 1.3 через uTLS) ----------

// fakeConn удовлетворяет net.Conn для UClient без реального сокета.
// BuildHandshakeState() только строит ClientHello и не пишет в conn.
type fakeConn struct {
	net.Conn
}

type output struct {
	ClientHello string `json:"clienthello_hex"`
	ServerHello string `json:"serverhello_hex"`
	SCID        string `json:"scid_hex"`
}

// quicVarint кодирует v как QUIC variable-length integer (RFC 9000 §16).
// ФИКС 16.09.2026: префиксные биты (01/10/11) ставятся в СТАРШИЕ биты ПЕРВОГО
// байта (0x40/0x80/0xc0), а не в 16/32/64-битную позицию — иначе byte()
// отрезал их, и все значения >= 64 кодировались неверно (aioquic отвечал
// TRANSPORT_PARAMETER_ERROR: "Could not parse QUIC transport parameter").
func quicVarint(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{byte(0x40 | v>>8), byte(v)}
	case v < 1<<30:
		return []byte{byte(0x80 | v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		return []byte{
			byte(0xc0 | v>>56),
			byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
	}
}

// octets декодирует hex в байты (тела GREASE-расширений из захвата Chrome 152).
func octets(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return out
}

// transportParameter добавляет id + len + value (RFC 9000 §18).
func transportParameter(b []byte, id uint64, value []byte) []byte {
	b = append(b, quicVarint(id)...)
	b = append(b, quicVarint(uint64(len(value)))...)
	return append(b, value...)
}

// buildTransportParams собирает блок QUIC transport parameters клиента.
func buildTransportParams(scid []byte) []byte {
	var b []byte
	b = transportParameter(b, 0x0f, scid)          // initial_source_connection_id
	b = transportParameter(b, 0x01, quicVarint(30000))  // max_idle_timeout
	b = transportParameter(b, 0x03, quicVarint(1200))   // max_udp_payload_size
	b = transportParameter(b, 0x04, quicVarint(65536))  // initial_max_data
	b = transportParameter(b, 0x05, quicVarint(262144)) // initial_max_stream_data_bidi_local
	b = transportParameter(b, 0x06, quicVarint(262144)) // initial_max_stream_data_bidi_remote
	b = transportParameter(b, 0x07, quicVarint(262144)) // initial_max_stream_data_uni
	b = transportParameter(b, 0x08, quicVarint(256))    // initial_max_streams_bidi
	b = transportParameter(b, 0x09, quicVarint(256))    // initial_max_streams_uni
	b = transportParameter(b, 0x0c, nil)                // disable_active_migration
	b = transportParameter(b, 0x0e, quicVarint(8))      // active_connection_id_limit
	b = transportParameter(b, 0x20, quicVarint(1200))   // max_datagram_frame_size
	return b
}

// buildServerHello собирает TLS 1.3 ServerHello, отвечающий на ClientHello spec.
// Возвращает полное handshake-сообщение (тип 0x02 + длина + тело).
// sessionID — echo legacy_session_id из ClientHello; для QUIC передаётся nil
// (пустой echo — compat-режим запрещён, RFC 9001 §8.1; BoringSSL QUIC требует
// пустой session_id в обе стороны — SSL_R_UNEXPECTED_COMPATIBILITY_MODE).
// keyShareData — публичный ключ X25519 сервера (отдельный от клиентского).
func buildServerHello(sessionID []byte, keyShareData []byte) []byte {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil
	}
	body := []byte{0x03, 0x03} // legacy_version: в ServerHello всегда 0x0303
	body = append(body, random...)
	body = append(body, byte(len(sessionID))) // legacy_session_id_echo
	body = append(body, sessionID...)
	body = append(body, 0x13, 0x01) // cipher_suite TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)       // legacy_compression_method null

	// extensions
	var ext []byte
	sv := []byte{0x03, 0x04} // supported_versions: TLS 1.3
	ext = append(ext, 0x00, 0x2b)
	ext = append(ext, byte(len(sv)>>8), byte(len(sv)))
	ext = append(ext, sv...)
	ks := []byte{0x00, 0x1d} // key_share: X25519
	ks = append(ks, byte(len(keyShareData)>>8), byte(len(keyShareData)))
	ks = append(ks, keyShareData...)
	ext = append(ext, 0x00, 0x33)
	ext = append(ext, byte(len(ks)>>8), byte(len(ks)))
	ext = append(ext, ks...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	msg := []byte{0x02} // handshake type ServerHello
	msg = append(msg, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	msg = append(msg, body...)
	return msg
}

func runUTLS(sni, seed string) {
	// Реальный X25519 публичный ключ для key_share
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	keyShareData := priv.PublicKey().Bytes()

	// SCID (8 байт) — идёт и в transport parameters, и в QUIC header
	scid := make([]byte, 8)
	if _, err := rand.Read(scid); err != nil {
		fmt.Fprintln(os.Stderr, "rand:", err)
		os.Exit(1)
	}
	tpData := buildTransportParams(scid)

	// QUIC: legacy_session_id в ClientHello ПУСТОЙ (compat-режим запрещён, RFC 9001 §8.1)
	// — детерминированный от seed session_id здесь не используется (BoringSSL QUIC
	// отклоняет непустой); согласованность сервера и клиентов обеспечивают cipher
	// (выбор от seed) и пустой session_id в обоих направлениях.

	// Chrome QUIC ClientHello (TLS 1.3 only, ALPN h3, quic_transport_parameters)
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS13,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: func() []utls.TLSExtension {
			// GREASE-расширения: Chrome 152 (quiche) шлёт их 4 шт и РАНДОМИЗИРУЕТ
			// на каждое соединение. Мы: 0xfe0d (ECH-grease; тело = валидный
			// ECHConfigList из живого захвата — BoringSSL парсит его) всегда +
			// 3 случайных из пула (тела из захвата; значения формата ?a?a uTLS
			// дополнительно рандомизирует сам). ec_point_formats (0x0b) Chrome
			// в QUIC не шлёт. (16.09.2026; валидировано живыми прогонами.)
			greasePool := []struct {
				id   uint16
				body []byte
			}{
				{0x001b, octets("020002")},
				{0x44cd, octets("0003026833")},
				{0xca34, octets("00cc04d679090404d679090504d679090808839a648c9b2d010808839a648c9b2d010d08839a648c9b2d01090582df13020d04d679090a08839a648c9b2d010c0582df13020e04d679090b0582df13021208839a648c9b2d010b04d67909060582df13020f04d679090904d679090d0582df1302130582df13020604d679090108839a648c9b2d010a08839a648c9b2d011304d67909070582df13020104d679090e04d679090208839a648c9b2d011204d679090f04d679090304d679090c08839a648c9b2d01070582df130214")},
				{0x6a6a, []byte{0x6a, 0x6a}},
				{0x1a1a, []byte{0x1a, 0x1a}},
			}
			extList := []utls.TLSExtension{&utls.SNIExtension{ServerName: sni}}
			used := map[int]bool{}
			for len(used) < 3 {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(len(greasePool))))
				if err != nil {
					break
				}
				i := int(n.Int64())
				if used[i] {
					continue
				}
				used[i] = true
				extList = append(extList, &utls.GenericExtension{Id: greasePool[i].id, Data: greasePool[i].body})
			}
			extList = append(extList, &utls.GenericExtension{Id: 0xfe0d, Data: octets("00000100011c0020a07ecc411c1c6ec6266ffe3ddff8f230e13790916fbb3f4811e6afa799cf601000f0827a0581671b4d6d0b9dce7e1451ea7d8bcb346b6904e3ae273809519d73dcafdcb8b23f060f6a65f5780166ac83f8f97d7dde5e7454feefddadc20470d50afc05dce4a7c04e4d011b97b891b9151a28da6ee32fd5553babd1ca74dd189e60afe54e491b291e262b003a5bc4c138904ba762be62bfcff699d528225059ab26d840259c8c1ff4e9c6b16221f2ef485b5481a473bacc05a6a99e71ee9c95e3179118ed4c2ef6ebb3f334f2c7e26e8c841c20ce1978e1ad7e972b55124dac9b2cee9006b6b2ba0046a40d6500768cdd2fe98ae4933dff55dedb15835ae771cd3a6cf583993972834addf30fe654fac442da")})
			extList = append(extList, &utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384,
			}})
			extList = append(extList, &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}})
			extList = append(extList, &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}})
			extList = append(extList, &utls.ALPNExtension{AlpnProtocols: []string{"h3"}})
			extList = append(extList, &utls.GenericExtension{Id: 0x0039, Data: tpData})
			extList = append(extList, &utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519, Data: keyShareData},
			}})
			extList = append(extList, &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}})
			return extList
		}(),
	}

	config := &utls.Config{ServerName: sni}
	uconn := utls.UClient(&fakeConn{}, config, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		fmt.Fprintln(os.Stderr, "preset:", err)
		os.Exit(1)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	raw := uconn.HandshakeState.Hello.Raw

	// QUIC: legacy_session_id в ClientHello обязан быть ПУСТЫМ (RFC 9001 §8.1:
	// compatibility mode в QUIC запрещён; BoringSSL QUIC-сервер отклоняет любой
	// непустой session_id — SSL_R_UNEXPECTED_COMPATIBILITY_MODE / illegal_parameter,
	// tls13_server.cc «if (SSL_is_quic(ssl) && client_hello.session_id_len > 0)».
	// Измерено на стенде 16.09.2026: Google (www.google.com:443) закрывал рукопожатие
	// с этим алертом именно из-за 32-байтового session_id; после обнуления — принял.
	// uTLS строит 32-байтовый session_id (TCP-совместимость), поэтому вырезаем его
	// из raw-байтов целиком: raw[38]=длина (0x20) + raw[39:71]=значение удаляются,
	// остальное тело сдвигается влево, длина handshake в raw[1:4] уменьшается на 32.
	if len(raw) >= 71 && raw[38] == 0x20 {
		raw = append(raw[:39], raw[71:]...)
		raw[38] = 0x00
		body := len(raw) - 4
		raw[1] = byte(body >> 16)
		raw[2] = byte(body >> 8)
		raw[3] = byte(body)
	}

	// Серверный key share (X25519) — отдельный ключ от клиентского
	serverCurve := ecdh.X25519()
	serverPriv, err := serverCurve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server keygen:", err)
		os.Exit(1)
	}
	serverKeyShare := serverPriv.PublicKey().Bytes()
	serverHello := buildServerHello(nil, serverKeyShare)

	out := output{
		ClientHello: hex.EncodeToString(raw),
		ServerHello: hex.EncodeToString(serverHello),
		SCID:        hex.EncodeToString(scid),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
		os.Exit(1)
	}
}

// ---------- режим dtls: WebRTC DTLS 1.2 (Pion) ----------

// captureConn перехватывает записи; при наличии readData отдаёт их один раз
// (для сервера — скормить ClientHello), затем блокирует чтение.
type captureConn struct {
	readData []byte
	readOnce bool
	captured []byte
	done     chan struct{}
	mu       sync.Mutex // защита captured (пишет goroutine dtls.*, читает runDTLS)
}

func (c *captureConn) Read(p []byte) (int, error) {
	if !c.readOnce && len(c.readData) > 0 {
		c.readOnce = true
		n := copy(p, c.readData)
		return n, nil
	}
	<-c.done
	return 0, fmt.Errorf("abort")
}
func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.captured = append(c.captured, p...)
	c.mu.Unlock()
	return len(p), nil
}
// snapshot возвращает копию захваченных записей (без гонок).
func (c *captureConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.captured...)
}
// hasCapture проверяет наличие записей (без гонок).
func (c *captureConn) hasCapture() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.captured) > 0
}
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }

func genCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Случайный serial (у реальных WebRTC-сертификатов — случайный, не 1).
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	// Случайный CN (реальные WebRTC-сертификаты не имеют фиксированного имени).
	cnBytes := make([]byte, 8)
	if _, err := rand.Read(cnBytes); err != nil {
		return tls.Certificate{}, err
	}
	cn := fmt.Sprintf("webrtc-%x", cnBytes)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func waitCaptured(c *captureConn) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !c.hasCapture() {
		time.Sleep(10 * time.Millisecond)
	}
	if !c.hasCapture() {
		fmt.Fprintln(os.Stderr, "dtls: no capture (endpoint не ответил)")
		return false
	}
	return true
}

// hsHeader собирает DTLS handshake header (12 байт) + body.
func hsHeader(typ byte, body []byte, msgSeq int) []byte {
	h := make([]byte, 12)
	h[0] = typ
	h[1] = byte(len(body) >> 16)
	h[2] = byte(len(body) >> 8)
	h[3] = byte(len(body))
	h[4] = byte(msgSeq >> 8)
	h[5] = byte(msgSeq)
	h[9] = byte(len(body) >> 16)
	h[10] = byte(len(body) >> 8)
	h[11] = byte(len(body))
	return append(h, body...)
}

// record собирает DTLS record (epoch 0, заданный seq) из payload.
// header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
func record(seq int, payload []byte) []byte {
	r := make([]byte, 13)
	r[0] = 0x16
	r[1] = 0xfe
	r[2] = 0xfd
	// epoch r[3:5] = 0
	// seq r[5:11] — 6 байт big-endian (полная запись; фикс аудита: раньше
	// писался только младший байт — корректно лишь для msgSeq < 256)
	r[5] = byte(seq >> 40)
	r[6] = byte(seq >> 32)
	r[7] = byte(seq >> 24)
	r[8] = byte(seq >> 16)
	r[9] = byte(seq >> 8)
	r[10] = byte(seq)
	r[11] = byte(len(payload) >> 8)
	r[12] = byte(len(payload))
	return append(r, payload...)
}

func runDTLS(sni string) {
	// 1. ClientHello через Pion клиент
	clientConn := &captureConn{done: make(chan struct{})}
	go func() {
		dtls.Client(clientConn, &dtls.Config{
			ServerName:             sni,
			ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
			SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			CipherSuites: []dtls.CipherSuiteID{
				dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		})
		close(clientConn.done)
	}()
	if !waitCaptured(clientConn) {
		os.Exit(1)
	}
	ch := clientConn.snapshot()

	// 2. ServerHello + flight через Pion сервер (без cookie-обмена, как в WebRTC)
	cert, err := genCert()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cert:", err)
		os.Exit(1)
	}
	srvConn := &captureConn{readData: ch, done: make(chan struct{})}
	go func() {
		dtls.Server(srvConn, &dtls.Config{
			Certificates:            []tls.Certificate{cert},
			ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
			SRTPProtectionProfiles:  []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			InsecureSkipVerifyHello: true, // WebRTC: без HelloVerifyRequest, ServerHello сразу
		})
		close(srvConn.done)
	}()
	if !waitCaptured(srvConn) {
		os.Exit(1)
	}
	srv := srvConn.snapshot()

	// Разбираем серверные записи на handshake-сообщения
	type hsMsg struct {
		typ    byte
		msgSeq int
		body   []byte
	}
	var msgs []hsMsg
	i := 0
	for i+13 <= len(srv) {
		if srv[i] != 0x16 {
			break // не handshake (напр., DTLS Alert) — не раскодируем как flight
		}
		length := int(srv[i+11])<<8 | int(srv[i+12])
		if i+13+length > len(srv) {
			break // обрезанный record: bounds-check (фикс аудита: паника на Alert)
		}
		payload := srv[i+13 : i+13+length]
		off := 0
		for off+12 <= len(payload) {
			typ := payload[off]
			mlen := int(payload[off+1])<<16 | int(payload[off+2])<<8 | int(payload[off+3])
			msgSeq := int(payload[4])<<8 | int(payload[5])
			if off+12+mlen > len(payload) {
				break // обрезанный handshake-body: bounds-check
			}
			body := payload[off+12 : off+12+mlen]
			msgs = append(msgs, hsMsg{typ, msgSeq, body})
			off += 12 + mlen
		}
		i += 13 + length
	}

	// Каждое handshake-сообщение сервера — отдельный record (как реальный Pion:
	// ServerHello seq=0, Certificate seq=1, SKX seq=2, SHD seq=3).
	// record seq == msg_seq для серверного flight (оба стартуют с 0 и растут вместе).
	var serverHello, certificate, skx, shd []byte
	for _, m := range msgs {
		rec := record(m.msgSeq, hsHeader(m.typ, m.body, m.msgSeq))
		switch m.typ {
		case 0x02:
			serverHello = rec
		case 0x0b:
			certificate = rec
		case 0x0c:
			skx = rec
		case 0x0e:
			shd = rec
		}
	}

	out, err := json.Marshal(map[string]string{
		"clienthello_hex": fmt.Sprintf("%x", ch),
		"serverhello_hex": fmt.Sprintf("%x", serverHello),
		"certificate_hex": fmt.Sprintf("%x", certificate),
		"skx_hex":         fmt.Sprintf("%x", skx),
		"shd_hex":         fmt.Sprintf("%x", shd),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
	os.Exit(0)
}

// main — единая точка входа: -mode utls|dtls.
func main() {
	mode := flag.String("mode", "utls", "режим: utls (QUIC ClientHello) | dtls (WebRTC DTLS 1.2)")
	sni := flag.String("sni", "www.example.com", "SNI / server name")
	seed := flag.String("seed", "", "seed для детерминированного session_id (режим utls)")
	flag.Parse()
	switch *mode {
	case "dtls":
		runDTLS(*sni)
	default:
		runUTLS(*sni, *seed)
	}
}
'''

# Исходник WARP-probe сайдкара: проверка WARP-эндпоинта НАСТОЯЩИМ WireGuard
# рукопожатием (Noise_IKpsk2...; алгоритм по wireguard-go: noise-protocol.go,
# noise-helpers.go, cookie.go, tai64n.go). Собирается на лету, как awg-imitat.
_WARP_PROBE_GO_MOD = r'''module awg-probe

go 1.24

require golang.org/x/crypto v0.31.0
'''

_WARP_PROBE_GO = r'''// awg-probe — проверка WireGuard/AmneziaWG endpoint'а «настоящим рукопожатием».
//
// Строит корректный WG handshake initiation (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s,
// алгоритм взят из wireguard-go: device/noise-protocol.go, noise-helpers.go,
// device/cookie.go и tai64n.go) и ждёт ответ сервера:
//   - type 2 (handshake response)  -> endpoint работает, рукопожатие состоялось;
//   - type 3 (cookie reply)        -> endpoint работает (отвечает, под нагрузкой);
//   - любой другой корректный UDP-ответ -> endpoint отвечает;
//   - таймаут / ECONNREFUSED       -> endpoint не работает.
//
// Вывод в stdout: JSON {"ok": bool, "type": "handshake|cookie|other|none"}.
//
// Для валидного рукопожатия нужен клиентский приватный ключ, ЗАРЕГИСТРИРОВАННЫЙ
// на сервере (для WARP это ключ из gen_pair_keys, отправленный в /reg) и
// публичный ключ сервера (peer public key из API).
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	wgLabelMAC1       = "mac1----"

	msgInitiationSize  = 148
	msgResponseSize    = 92
	msgCookieReplySize = 64
	typeInitiation     = 1
	typeResponse       = 2
	typeCookieReply    = 3
)

var initialChainKey [blake2s.Size]byte
var initialHash [blake2s.Size]byte
var zeroNonce [chacha20poly1305.NonceSize]byte

func b2s256(data ...[]byte) [blake2s.Size]byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	var out [blake2s.Size]byte
	h.Sum(out[:0])
	return out
}

func b2s128(key []byte, data []byte) [16]byte {
	mac, _ := blake2s.New128(key)
	mac.Write(data)
	var out [16]byte
	mac.Sum(out[:0])
	return out
}

func hmacBlake(key, in0 []byte) [blake2s.Size]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	var out [blake2s.Size]byte
	mac.Sum(out[:0])
	return out
}

func kdf1(key, input []byte) [blake2s.Size]byte {
	t := hmacBlake(key, input)
	return hmacBlake(t[:], []byte{0x1})
}

func kdf2(key, input []byte) ([blake2s.Size]byte, [blake2s.Size]byte) {
	prk := hmacBlake(key, input)
	t0 := hmacBlake(prk[:], []byte{0x1})
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, prk[:])
	mac.Write(t0[:])
	mac.Write([]byte{0x2})
	var t1 [blake2s.Size]byte
	mac.Sum(t1[:0])
	return t0, t1
}

func mixHash(h *[blake2s.Size]byte, data []byte) {
	*h = b2s256(h[:], data)
}

func mixKey(ck *[blake2s.Size]byte, data []byte) {
	*ck = kdf1(ck[:], data)
}

func clamp(priv []byte) {
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
}

func tai64nNow() [12]byte {
	var ts [12]byte
	const base = uint64(0x400000000000000a)
	now := time.Now()
	binary.BigEndian.PutUint64(ts[:8], base+uint64(now.Unix()))
	binary.BigEndian.PutUint32(ts[8:], uint32(now.Nanosecond())&^0xffffff)
	return ts
}

// buildInitiation строит полный 148-байтовый handshake initiation.
// Возвращает (пакет, ""), либо ("", тип_ошибки) — без паник на вырожденных ключах.
func buildInitiation(serverPub, clientPriv []byte) ([]byte, string) {
	if initialChainKey == [blake2s.Size]byte{} {
		initialChainKey = b2s256([]byte(noiseConstruction))
		initialHash = b2s256(initialChainKey[:], []byte(wgIdentifier))
	}

	hash := initialHash
	chainKey := initialChainKey

	// клиентский статический ключ (наш, зарегистрированный)
	clientPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil {
		return nil, "dh-error"
	}
	sp := serverPub

	// эфемерный ключ
	ephRaw := make([]byte, 32)
	if _, err := rand.Read(ephRaw); err != nil {
		return nil, "rng-error"
	}
	clamp(ephRaw)
	ephPub, err := curve25519.X25519(ephRaw, curve25519.Basepoint)
	if err != nil {
		return nil, "dh-error"
	}

	mixHash(&hash, sp)        // серверный static в транскрипт
	mixKey(&chainKey, ephPub) // chainKey = KDF1(chainKey, ephPub)
	mixHash(&hash, ephPub)    // эфемерный ключ в транскрипт

	// шифруем клиентский статический ключ
	ss1, err := curve25519.X25519(ephRaw, sp)
	if err != nil {
		return nil, "dh-error"
	}
	ck, key := kdf2(chainKey[:], ss1)
	chainKey = ck
	aead, _ := chacha20poly1305.New(key[:])
	msgStatic := aead.Seal(nil, zeroNonce[:], clientPub, hash[:])
	mixHash(&hash, msgStatic)

	// шифруем timestamp
	ss2, err := curve25519.X25519(clientPriv, sp)
	if err != nil {
		return nil, "dh-error"
	}
	ck, key = kdf2(chainKey[:], ss2)
	chainKey = ck
	aead, _ = chacha20poly1305.New(key[:])
	ts := tai64nNow()
	msgTimestamp := aead.Seal(nil, zeroNonce[:], ts[:], hash[:])
	mixHash(&hash, msgTimestamp)

	// sender index
	var sender [4]byte
	if _, err := rand.Read(sender[:]); err != nil {
		return nil, "rng-error"
	}

	msg := make([]byte, 0, msgInitiationSize)
	msg = append(msg, 1, 0, 0, 0) // type
	msg = append(msg, sender[:]...)
	msg = append(msg, ephPub...)
	msg = append(msg, msgStatic...)
	msg = append(msg, msgTimestamp...)
	// MAC1: key = HASH("mac1----" || server_pub); over msg без последних 32 байт
	mac1Key := b2s256([]byte(wgLabelMAC1), sp)
	mac1 := b2s128(mac1Key[:], msg)
	msg = append(msg, mac1[:]...)
	msg = append(msg, make([]byte, 16)...) // MAC2 = 0 (нет cookie)
	return msg, ""
}

func probe(endpoint, serverPub, clientPriv string, timeoutMs int, retries int) (bool, string) {
	sp, err := base64.StdEncoding.DecodeString(serverPub)
	if err != nil || len(sp) != 32 {
		return false, "bad-server-pub"
	}
	cp, err := base64.StdEncoding.DecodeString(clientPriv)
	if err != nil || len(cp) != 32 {
		return false, "bad-client-priv"
	}
	msg, buildErr := buildInitiation(sp, cp)
	if buildErr != "" {
		return false, buildErr
	}

	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return false, "resolve"
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if retries <= 0 {
		retries = 2
	}
	buf := make([]byte, 512)
	for i := 0; i < retries; i++ {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return false, "dial"
		}
		conn.SetDeadline(time.Now().Add(timeout))
		_, werr := conn.Write(msg)
		if werr != nil {
			conn.Close()
			continue
		}
		n, rerr := conn.Read(buf)
		conn.Close()
		if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
			if i+1 < retries {
				time.Sleep(300 * time.Millisecond)
			}
			continue
		}
		if rerr != nil {
			return false, "read-error"
		}
		if n < 4 {
			return true, "other"
		}
		typ := binary.LittleEndian.Uint32(buf[:4])
		switch typ {
		case typeResponse:
			if n >= msgResponseSize {
				return true, "handshake"
			}
			return true, "other"
		case typeCookieReply:
			if n >= msgCookieReplySize {
				return true, "cookie"
			}
			return true, "other"
		default:
			return true, "other"
		}
	}
	return false, "none"
}

func main() {
	endpoint := flag.String("endpoint", "", "host:port")
	serverPub := flag.String("server-pub", "", "base64 серверный публичный ключ (peer public_key из API)")
	clientPriv := flag.String("client-priv", "", "base64 клиентский приватный ключ (зарегистрированный)")
	timeoutMs := flag.Int("timeout-ms", 1500, "таймаут ожидания ответа, мс")
	retries := flag.Int("retries", 2, "число попыток")
	flag.Parse()
	// Поддержка stdin-JSON {"endpoint":..,"server_pub":..,"client_priv":..}:
	// позволяет не светить приватный ключ в argv (ps); CLI-режим не ломается
	// (Decode только при неполных флагах; пустой stdin → EOF → пропуск).
	if *endpoint == "" || *serverPub == "" || *clientPriv == "" {
		var in struct {
			Endpoint   string `json:"endpoint"`
			ServerPub  string `json:"server_pub"`
			ClientPriv string `json:"client_priv"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&in); err == nil {
			if *endpoint == "" {
				*endpoint = in.Endpoint
			}
			if *serverPub == "" {
				*serverPub = in.ServerPub
			}
			if *clientPriv == "" {
				*clientPriv = in.ClientPriv
			}
		}
	}

	if *endpoint == "" || *serverPub == "" || *clientPriv == "" {
		fmt.Fprintln(os.Stderr, "usage: awg-probe -endpoint host:port -server-pub <b64> -client-priv <b64> [-timeout-ms N] [-retries N]")
		os.Exit(2)
	}
	ok, typ := probe(*endpoint, *serverPub, *clientPriv, *timeoutMs, *retries)
	out, _ := json.Marshal(map[string]any{"ok": ok, "type": typ})
	fmt.Println(string(out))
}
'''

# ----------------- Генерация параметров обфускации -----------------

def generate_cps_packet(
    static_bytes: str | None = None,
    static_bytes_range: int = 0,  # Если > 0, то длина static_bytes будет случайной
    use_timestamp: bool = False,
    random_bytes: int = 0,
    random_bytes_range: int = 0,  # Если > 0, то random_bytes будет случайным в диапазоне
    random_ascii: int = 0,
    random_ascii_range: int = 0,  # Если > 0, то random_ascii будет случайным в диапазоне
    random_digits: int = 0,
    random_digits_range: int = 0,  # Если > 0, то random_digits будет случайным в диапазоне
) -> str:
    """
    Генерация CPS-пакета (I1-I5) для маскировки под легитимные UDP протоколы.

    Протоколы для России (никогда не заблокируют):
    - DNS (порт 53) — без DNS интернет не работает
    - QUIC (порт 443) — Google, YouTube, Chrome
    - DTLS (порт 443) — WebRTC, Zoom, Teams
    - NTP (порт 123) — синхронизация времени

    Формат: <b 0xHEX><t><r N><rc N><rd N> (по документации AmneziaWG)

    ВАЖНО: Размеры должны быть разумными чтобы не крашить ядро!
    """
    parts = []

    # Генерируем static_bytes с рандомной длиной если указан диапазон
    if static_bytes:
        if static_bytes_range > 0:
            # Сохраняем базовую сигнатуру и добавляем случайные байты (расширения)
            base_hex = static_bytes[2:]  # Убираем "0x", оставляем hex (например "01" из "0x01")
            # Генерируем случайное количество дополнительных байт (0 до static_bytes_range)
            extra_bytes = random.randint(0, static_bytes_range)
            if extra_bytes > 0:
                extra_hex = secrets.token_hex(extra_bytes)
                static_bytes = f"0x{base_hex}{extra_hex}"
            # Иначе оставляем базовую сигнатуру без изменений
        parts.append(f"<b {static_bytes}>")

    if use_timestamp:
        parts.append("<t>")

    # Если указан диапазон, генерируем случайное значение
    def _append_random_part(tag, base, rng):
        if rng > 0:
            actual = random.randint(base, base + rng)
        else:
            actual = base
        if actual > 0:
            parts.append(f"<{tag} {actual}>")

    _append_random_part("r", random_bytes, random_bytes_range)
    _append_random_part("rc", random_ascii, random_ascii_range)
    _append_random_part("rd", random_digits, random_digits_range)

    return "".join(parts)


def _generate_j_params() -> tuple[int, int, int]:
    """Генерация Jc, Jmin, Jmax (junk-пакеты)."""
    Jc = random.randint(80, 120)
    Jmin = random.randint(48, 64)
    Jmax = random.randint(Jmin + 8, 80)
    return Jc, Jmin, Jmax


def _s_params_have_length_collision(S1: int, S2: int, S3: int, S4: int) -> bool:
    """True, если при таких S ВОЗМОЖНО совпадение длины data-пакета с handshake-пакетом.

    Зачем проверка. Ядро распознаёт тип принятого пакета по ДЛИНЕ, а при
    совпадении длины дочитывает 4 байта по смещению S1/S2/S3 и сверяет их с
    H1/H2/H3 (receive.c, awg_determine_type_and_padding). Если 4 байта попали
    в диапазон H — пакет уничтожается как «Invalid MAC of handshake».

    Длины (транспорт):
        data     = S4 + 32 + ALIGN(plaintext, 16)
                   (16 — message_data, 16 — тег, ALIGN — выравнивание до 16)
        init     = S1 + 148
        response = S2 + 92
        cookie   = S3 + 64
    Равенство возможно ⟺ ALIGN(plaintext,16) = S_i − S4 + K, K ∈ {116, 60, 32}.
    ALIGN по определению кратен 16, поэтому условие «коллизия возможна» — это
    ровно сравнение по модулю 16 (необходимое И достаточное: любое кратное 16
    значение ALIGN реализуется реальными пакетами, максимум здесь 366 < MTU).

    Измерено на стенде (ядро 3.1.20260812, 11.09.2026) для 2.0-стиля
    S=(100,108,88,8), широкие H, RandomTrailers=off — потери 5-25% РОВНО в
    предсказанных окнах размеров и 0% на соседних байтах:
        init   окно ping -s 165..180 (ALIGN=208), s=160/185 → 0%
        resp   окно ping -s 117..132 (ALIGN=160), s=116/133 → 0%
        cookie окно ping -s 69..84   (ALIGN=112), s=68/85   → 0%
    (dmesg: 23× «Invalid MAC of handshake, dropping packet»).
    У AWG/1.0/1.5 H статичные (ширина диапазона 1) → вероятность 1/2^32 ≈ 0,
    отсев им не нужен; у 3.1 S1=S2=S3=S4 и чтение всегда попадает в поле type
    (диапазон H4, непересекающийся с H1-H3) → ложное срабатывание структурно
    невозможно. Отсев нужен только 2.0/3.0 — версиям с H-диапазонами.

    Эта функция также годится для проверки УЖЕ выпущенных конфигов
    (прочитать S1-S4 и вызвать её).
    """
    return ((S1 - S4 + 116) % 16 == 0
            or (S2 - S4 + 60) % 16 == 0
            or (S3 - S4 + 32) % 16 == 0)


def _generate_s_params(avoid_length_collision: bool = False) -> tuple[int, int, int, int]:
    """Генерация S1, S2, S3, S4 (случайные префиксы).

    Все S-параметры отличаются минимум на 3 единицы.
    S1+56 ≠ S2 (требование AmneziaWG).

    avoid_length_collision=True (для AWG2.0/AWG3.0 — версий с H-диапазонами)
    дополнительно отбрасывает наборы, при которых длина data-пакета может
    совпасть с длиной handshake-пакета — см. _s_params_have_length_collision
    («тихий» отброс пакетов конкретных размеров). Это rejection sampling:
    распределение остаётся равномерным по безопасным наборам, диапазоны и
    энтропия не меняются, отбраковывается ~17% попыток.
    """
    while True:
        S1 = random.randint(61, 255)
        S2 = random.randint(29, 127)
        S3 = random.randint(13, 63)
        S4 = random.randint(5, 9)

        s_values = [S1, S2, S3, S4]
        min_diff_ok = all(abs(s_values[i] - s_values[j]) >= 3
                          for i in range(len(s_values)) for j in range(i+1, len(s_values)))

        if S1 + 56 != S2 and min_diff_ok:
            if avoid_length_collision and _s_params_have_length_collision(S1, S2, S3, S4):
                continue
            break
    
    return S1, S2, S3, S4


def _generate_h_params_static() -> tuple[int, int, int, int]:
    """Генерация H1-H4 как статичных чисел (для AWG1.0, AWG1.5).

    Все H-параметры отличаются минимум на 30,000.
    Возвращаемые значения перемешиваются для непредсказуемости.
    """
    H_MIN_DIFF = 30000

    while True:
        H1 = random.randint(0x10000011, 0xFFFFFFF0)
        H2 = random.randint(0x10000011, 0xFFFFFFF0)
        H3 = random.randint(0x10000011, 0xFFFFFFF0)
        H4 = random.randint(0x10000011, 0xFFFFFFF0)

        h_values = [H1, H2, H3, H4]
        h_diff_ok = all(abs(h_values[i] - h_values[j]) >= H_MIN_DIFF
                        for i in range(len(h_values)) for j in range(i+1, len(h_values)))

        if h_diff_ok:
            break

    # Перемешиваем значения перед возвратом
    h_values = [H1, H2, H3, H4]
    random.shuffle(h_values)

    return h_values[0], h_values[1], h_values[2], h_values[3]


def _generate_h_params_ranges() -> tuple[str, str, str, str]:
    """Генерация H1-H4 как диапазонов (для AWG2.0).

    Возвращает строки формата "start-end".
    Каждый диапазон 300M-600M (случайный размер), с зазором ≥30,000 между диапазонами.
    """
    H_MIN_SIZE = 300000000  # 300M минимальный размер
    H_MAX_SIZE = 600000000  # 600M максимальный размер
    H_MIN_GAP = 30000       # 30K минимальный зазор

    while True:
        # Генерируем 4 случайных размера диапазонов
        h_sizes = [random.randint(H_MIN_SIZE, H_MAX_SIZE) for _ in range(4)]

        # Генерируем 4 стартовые точки
        h_starts = []
        max_possible_start = 2147483647 - H_MAX_SIZE - H_MIN_GAP * 3
        for _ in range(4):
            h_start = random.randint(5, max_possible_start)
            h_starts.append(h_start)

        # Проверяем на пересечения (с учётом разных размеров)
        overlaps = False
        for i in range(4):
            for j in range(i + 1, 4):
                start_i, end_i = h_starts[i], h_starts[i] + h_sizes[i]
                start_j, end_j = h_starts[j], h_starts[j] + h_sizes[j]

                # Проверяем есть ли зазор ≥30K между диапазонами
                if end_i + H_MIN_GAP > start_j and end_j + H_MIN_GAP > start_i:
                    overlaps = True
                    break
            if overlaps:
                break

        if not overlaps:
            break

    # Создаём диапазоны
    ranges = [(s, s + sz) for s, sz in zip(h_starts, h_sizes, strict=True)]
    random.shuffle(ranges)

    return (f"{ranges[0][0]}-{ranges[0][1]}",
            f"{ranges[1][0]}-{ranges[1][1]}",
            f"{ranges[2][0]}-{ranges[2][1]}",
            f"{ranges[3][0]}-{ranges[3][1]}")


def _generate_s_params_awg31() -> tuple[int, int, int, int]:
    """Генерация S1-S4 для AWG3.1: ОДНО случайное значение (≥12) на все четыре.

    Два независимых требования AWG3.1, оба измерены на ядре 3.1.20260812
    (стенд 185.103.34, 11.09.2026) по исходникам модуля
    /usr/src/amneziawg-1.0.0 + e2e в netns:

    1) S ≥ 12 — жёсткое требование HeaderProtectionKey. Ядро ОТВЕРГАЕТ S < 12
       (`Unable to modify interface: Invalid argument`): nonce ChaCha20 для HP —
       первые 12 байт S-префикса (peer.h/receive.c: awg_header_protection_init
       получает буфер паддинга). Свип: S=0/4/6/8/10/11 → rejected,
       S=12/13/15/16 → rc=0. Граница ровно 12.

    2) S1=S2=S3=S4 — доки РЕКОМЕНДУЮТ при RandomTrailers (docs.amnezia.org: «рекомендуется
       задавать одинаковые значения... снижается риск неправильного определения типа пакета»);
       мы измерили, что при широких кастомных H это де-факто ОБЯЗАТЕЛЬНО (см. изоляцию ниже).
       В receive.c при random_trailers проверка типа заменяется на
       `skb->len >= expected_len` вместо `==`, поэтому КАЖДЫЙ удлинённый
       трейлерами data-пакет прогоняется через распознавание handshake:
       читаются 4 байта по смещению S1/S2/S3 и сверяются с диапазонами H1/H2/H3.
       При разных S это смещение попадает в случайные байты (S-префикс,
       ciphertext, key_idx), и при широких H-диапазонах (300M-600M у генератора
       2.0) пакет ложно опознаётся как handshake и уничтожается
       («Invalid MAC of handshake, dropping packet»).

       Изоляция (менялась только ширина H, S=17/28/12/22, trailers ON):
         H 400M → c->s 25% / s->c 45% потерь, dmesg InvalidMAC=8
         H1-4 = 1,2,3,4 (одиночные) → 0% / 0%, InvalidMAC=0
         trailers OFF + H 400M → 0%
       При S1=S2=S3=S4 читаемые 4 байта — это ровно поле type самого пакета,
       которое лежит в H4-диапазоне (непересекающемся с H1/H2/H3), поэтому
       ложное срабатывание структурно невозможно при любой ширине H:
         S=20/20/20/20 + H 400M + HP + trailers → 0% потерь, InvalidMAC=0
       (контроль с теми же H и разными S → 65% / 35%).

    Поэтому здесь одно значение на все четыре S: это и требование HP (≥12),
    и единственный способ не терять пакеты с RandomTrailers, не сужая
    H-диапазоны (сужение H ослабило бы маскировку, доставшуюся от 2.0).

    Диапазон 12..19 (16.09.2026, сужен с 12..32 по требованию пользователя):
    пол 12 — требование HP; потолок 19 — накладные одного слоя при внешнем
    IPv6 (80 + S4) не превышают 99 байт (< 100), поэтому MTU 1300 в цепочке
    туннель-в-туннеле остаётся безопасным при любых наших параметрах.
    """
    s = random.randint(12, 19)  # пол 12 — HP; потолок 19 — накладные ≤ 99 байт/слой при IPv6
    return s, s, s, s


def _generate_content_padding(rng: random.Random | None = None) -> str:
    """Генерация ContentPaddingAddition (AWG3.0+): случайный диапазон добавки.

    Добавляет случайные байты к транспортному payload (ломает кратность 16).
    Нижняя граница 1 (каждый пакет что-то да получает), верхняя — случайная
    31..63 на каждый конфиг; фактическую добавку сверху всё равно режет окно
    (min(add, udpWindow-size), peer.h) — MTU не раздувается. Нижняя полоса
    выбрана по замеру стоимости (16.09.2026): с hi 63..127 паддинг в среднем
    ~78 Б/пакет на 100-Б пакетах; с 31..63 ожидается ~32 Б/пакет — компромисс
    «джиттер размеров vs трафик для мобильных».
    rng: при задании — случайный источник (для комментариев-подсказок 3.x
    в конфигах младших версий: global random НЕ трогается — стрим-инвариант).
    """
    rng = rng if rng is not None else random
    hi = rng.randint(31, 63)
    return f"1-{hi}"


def _generate_timing_params(rng: random.Random | None = None) -> dict[str, str]:
    """Генерация 5 таймингов-диапазонов (AWG3.0+).

    16.09.2026: RekeyAfterTime/RejectAfterTime рандомизируются на КАЖДЫЙ
    конфиг (сервер — один набор, каждый клиент — свой): тайминги — локальные
    таймеры, по проводу не передаются, совпадение сервер↔клиент НЕ требуется
    (проверено e2e, в т.ч. при диких расхождениях значений) → разнос ритмов
    рекеев убирает общий «сигнал генератора» при наблюдении нескольких
    туннелей. Формула (инвариант в каждом конфиге: Reject_min = Rekey_max+60):
      RekeyAfterTime  = "a-b": a=240..360, b=a+240..360  → итого 240..720
      RejectAfterTime = "c-d": c=b+60,     d=c+60        → итого 540..840
    Дополнительно (16.09.2026): RekeyTimeout, KeepaliveTimeout и
    MaxHandshakeAttempts тоже per-config: каждое "a-b" со СВОИМ случайным a=6..9,
    b=a+a (итог 6..18) — декорреляция локальных таймеров между конфигами.
    rng: при задании — случайный источник (для комментариев-подсказок 3.x
    в конфигах младших версий: global random НЕ трогается — стрим-инвариант).
    """
    rng = rng if rng is not None else random
    a = rng.randint(240, 360)
    b = a + rng.randint(240, 360)
    c = b + 60
    d = c + 60
    t_rt = rng.randint(6, 9)
    t_ka = rng.randint(6, 9)
    t_ma = rng.randint(6, 9)
    return {
        "RekeyAfterTime": f"{a}-{b}",
        "RekeyTimeout": f"{t_rt}-{t_rt * 2}",
        "RejectAfterTime": f"{c}-{d}",
        "KeepaliveTimeout": f"{t_ka}-{t_ka * 2}",
        "MaxHandshakeAttempts": f"{t_ma}-{t_ma * 2}",
    }


def _generate_header_protection_key() -> str:
    """Генерация HeaderProtectionKey (AWG3.1): 32 случайных байта, base64.

    Один ключ на сервер и всех клиентов (server-side параметр): у клиентов
    берётся из серверного конфига, а не генерируется заново.
    Формат как у wg-ключей (base64 от 32 байт).
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _generate_i_params(for_client: bool = False, for_server: bool = True, domain: str = "", seed: str = "", proto: str = "") -> dict[str, str]:
    """Генерация I1-I5 (CPS-пакеты для маскировки под легитимные UDP протоколы).

    Если указан domain — генерируются QUIC ClientHello с его SNI (для клиента)
    или QUIC ServerHello (для сервера). Если domain не указан — старый пул из 6 протоколов.

    Если доступна библиотека cryptography — QUIC пакеты шифруются (AES-128-GCM + Header Protection),
    что делает их неотличимыми от настоящих QUIC Initial/Handshake.

    Контролируемые диапазоны (можно менять под свои нужды):
      I_TEXT_MIN/I_TEXT_MAX — длина текста I-строк в конфиге (символы)
      I_TRAFFIC_MIN/I_TRAFFIC_MAX — сумма <r>+<rc>+<rd> (байт трафика)
      Если результат выходит за диапазон — генерация повторяется.
    """
    # ─── Настраиваемые диапазоны ─────────────────────────────────
    I_TEXT_MIN = 60     # Мин. длина текста всех I-строк в конфиге
    I_TEXT_MAX = 180    # Макс. длина текста всех I-строк в конфиге
    I_TRAFFIC_MIN = 600 # Мин. объём генерируемого трафика (r+rc+rd)
    I_TRAFFIC_MAX = 900 # Макс. объём генерируемого трафика (r+rc+rd)
    I_COUNT_MIN = 3     # Мин. количество I-строк (старый пул)
    I_COUNT_MAX = 5     # Макс. количество I-строк (старый пул)
    MAX_ATTEMPTS = 10   # Лимит попыток чтобы не зависнуть
    # Для пулов с 1 протоколом (domain / server) — мягкие рамки
    I_SNI_TEXT_MIN = 600
    I_SNI_TEXT_MAX = 4000  # 16.09.2026: QUIC Initial с PADDING до 1200 байт = 2400 hex-символов
                           # (+ теги и 2-4 строки серии) — старый кап 2400 резал I1 даже у
                           # aioquic-пути (латентный баг, срабатывал best-effort фоллбэк)
    I_SNI_TRAFFIC_MIN = 600
    I_SNI_TRAFFIC_MAX = 2400
    I_SNI_COUNT_MIN = 3     # Количество I-строк для single-pool / имитации
    I_SNI_COUNT_MAX = 5
    # ──────────────────────────────────────────────────────────────

    # Пул протоколов в виде функций — генерируется только при вызове
    def _gen_dns():
        return generate_cps_packet(
            static_bytes="0x01", static_bytes_range=10, use_timestamp=False,
            random_bytes=30, random_bytes_range=30,
            random_ascii=60, random_ascii_range=60,
            random_digits=10, random_digits_range=6,
        )

    def _gen_quic():
        return generate_cps_packet(
            static_bytes="0xc7", static_bytes_range=20, use_timestamp=True,
            random_bytes=120, random_bytes_range=80,
            random_ascii=180, random_ascii_range=140,
            random_digits=12, random_digits_range=6,
        )

    def _gen_dtls():
        return generate_cps_packet(
            static_bytes="0x16FEFD", static_bytes_range=15, use_timestamp=True,
            random_bytes=80, random_bytes_range=70,
            random_ascii=200, random_ascii_range=200,
            random_digits=8, random_digits_range=6,
        )

    def _gen_ntp():
        return generate_cps_packet(
            static_bytes="0x1B", static_bytes_range=3, use_timestamp=True,
            random_bytes=0, random_bytes_range=0,
            random_ascii=0, random_ascii_range=0,
            random_digits=42, random_digits_range=6,
        )

    def _gen_random():
        return generate_cps_packet(
            static_bytes=f"0x{secrets.token_hex(2)}", static_bytes_range=2, use_timestamp=False,
            random_bytes=40, random_bytes_range=40,
            random_ascii=50, random_ascii_range=50,
            random_digits=0, random_digits_range=0,
        )

    def _gen_srtp():
        return generate_cps_packet(
            static_bytes="0x8060", static_bytes_range=4, use_timestamp=True,
            random_bytes=20, random_bytes_range=60,
            random_ascii=0, random_ascii_range=0,
            random_digits=8, random_digits_range=4,
        )

    # ────────────────────────────────────────────────────────────────

    # Протоколы для маскировки под конкретный домен (через ;domain=)
    # ─── Шифрование QUIC Initial (AES-128-GCM + Header Protection) ───
    _QUIC_INITIAL_SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
    try_AESGCM = None
    if cryptography is not None:

        def _hkdf_extract(salt, ikm):
            return hmac.new(salt, ikm, hashlib.sha256).digest()

        def _hkdf_expand(prk, info, length):
            hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info, backend=default_backend())
            return hkdf.derive(prk)

        def _hkdf_expand_label(secret, label, context, length):
            """HKDF-Expand-Label (RFC 8446 §7.1): info = struct {uint16 len; opaque label; opaque context}."""
            full_label = b"tls13 " + label
            hkdf_label = (struct.pack(">H", length) + bytes([len(full_label)]) +
                          full_label + bytes([len(context)]) + context)
            return _hkdf_expand(secret, hkdf_label, length)

        def _quic_encrypt_initial(dcid_hex: str, scid_hex: str, plaintext_hex: str,
                                  is_server: bool = False) -> str:
            dcid = bytes.fromhex(dcid_hex)
            scid = bytes.fromhex(scid_hex)
            # RFC 9001 §5.2: initial_secret -> client/server_initial_secret -> key/iv/hp
            prk = _hkdf_extract(_QUIC_INITIAL_SALT, dcid)
            secret = _hkdf_expand_label(prk, b'server in' if is_server else b'client in', b'', 32)
            key = _hkdf_expand_label(secret, b'quic key', b'', 16)
            iv  = _hkdf_expand_label(secret, b'quic iv', b'', 12)
            hp  = _hkdf_expand_label(secret, b'quic hp', b'', 16)

            plaintext = bytes.fromhex(plaintext_hex)
            pn = 0
            pn_len = 1
            pn_bytes = pn.to_bytes(pn_len, 'big')
            # Заголовок (без PN): type + version + DCID_len + DCID + SCID_len + SCID + Token_len + Length
            header = (b'\xc0\x00\x00\x00\x01'
                      b'\x08' + dcid +
                      b'\x08' + scid +
                      b'\x00')
            payload_len = len(plaintext) + pn_len + 16  # +PN byte, +16 GCM tag
            header += bytes.fromhex(_quic_varint(payload_len))
            # RFC 9001 §5.4.2: AAD = заголовок + unmasked PN
            aad = header + pn_bytes
            # RFC 9001 §5.3: nonce = IV XOR PN, PN пишется в ПОСЛЕДНИЕ байты IV
            nonce = bytearray(iv)
            nonce[12 - pn_len] ^= pn
            nonce = bytes(nonce)
            # AES-128-GCM encrypt
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext, aad)
            encrypted = ct[:-16]
            tag = ct[-16:]
            # RFC 9001 §5.4.2: sample берётся с pn_offset + 4 (PN считается 4-байтовым).
            # encrypted начинается с pn_offset+pn_len, поэтому sample = encrypted[4-pn_len : 20-pn_len]
            if len(encrypted) < 16:  # фикс аудита: guard для короткого plaintext
                raise ValueError("QUIC: ciphertext короче 16 байт для Header Protection")
            sample = encrypted[4 - pn_len : 20 - pn_len]
            ecb_cipher = Cipher(algorithms.AES(hp), modes.ECB(), backend=default_backend())
            ecb_enc = ecb_cipher.encryptor()
            mask = ecb_enc.update(sample) + ecb_enc.finalize()

            first_byte = 0xc0 ^ (mask[0] & 0x0f)
            pn_protected = bytes([pn_bytes[0] ^ (mask[1] if len(mask) > 1 else 0)])

            result_hex = (
                first_byte.to_bytes(1, 'big').hex() +
                header[1:].hex() +
                pn_protected.hex() +
                encrypted.hex() +
                tag.hex()
            )
            return result_hex

        try_AESGCM = _quic_encrypt_initial

    def _build_quic_packet(crypto_hex: str, default_range: int = 60,
                           scid_hex_preset: str = "", is_server: bool = False,
                           pad_target: int = 0) -> tuple[str, int]:
        """Оборачивает hex CRYPTO frame в QUIC Long Header (с шифрованием если доступно).

        pad_target > 0 — добрать PADDING-фреймы (0x00 в ЗАЩИЩЁННОМ payload, RFC 9000 §19.1)
        до точного размера пакета (RFC 9000 §14.1: Initial от клиента и от сервера обязан
        быть >= 1200 байт). Фикс 16.09.2026: без паддинга реальные QUIC-серверы
        (Cloudflare, Google — проверено на стенде) молча отбрасывают Initial,
        с паддингом — отвечают.
        """
        dcid_hex = secrets.token_hex(8)
        scid_hex = scid_hex_preset or secrets.token_hex(8)
        if try_AESGCM is not None:
            if pad_target > 0:
                for _pad in range(pad_target):
                    pkt = try_AESGCM(dcid_hex, scid_hex, crypto_hex + "00" * _pad,
                                     is_server=is_server)
                    pkt_len = len(pkt) // 2
                    if pkt_len == pad_target:
                        return pkt, 0
                    if pkt_len > pad_target:
                        break
                raise ValueError(f"QUIC: не удалось набрать PADDING до {pad_target} байт")
            return try_AESGCM(dcid_hex, scid_hex, crypto_hex, is_server=is_server), 0
        # Фоллбэк без cryptography (пакет не зашифрован — только для вида); паддинг нулями
        if pad_target > 0:
            for _pad in range(pad_target):
                payload_len = len(crypto_hex) // 2 + 1 + _pad
                quic_hex = (f"c000000001"
                            f"08{dcid_hex}"
                            f"08{scid_hex}"
                            f"00"
                            f"{_quic_varint(payload_len)}"
                            f"00"
                            f"{crypto_hex}{'00' * _pad}")
                if len(quic_hex) // 2 == pad_target:
                    return quic_hex, 0
                if len(quic_hex) // 2 > pad_target:
                    break
            raise ValueError(f"QUIC: не удалось набрать PADDING до {pad_target} байт (фоллбэк)")
        payload_len = len(crypto_hex) // 2 + 1
        quic_hex = (f"c000000001"
                    f"08{dcid_hex}"
                    f"08{scid_hex}"
                    f"00"
                    f"{_quic_varint(payload_len)}"
                    f"00"
                    f"{crypto_hex}")
        return quic_hex, default_range

    def _quic_varint(value: int) -> str:
        """Кодирует целое в QUIC variable-length integer (hex)."""
        if value < 64:
            return f"{value:02x}"
        elif value < 16384:
            return f"{(0x4000 | value):04x}"
        elif value < 1073741824:
            return f"{(0x80000000 | value):08x}"
        else:
            return f"{(0xc000000000000000 | value):016x}"

    # ─── Реальный QUIC через aioquic (TLS 1.3, настоящий стек) ───
    def _quic_initial_via_aioquic(is_server: bool) -> str | None:
        """Генерирует реальный QUIC Initial/ServerHello пакет через aioquic (TLS 1.3).

        Возвращает hex пакета или None если aioquic недоступен / произошла ошибка.
        ClientHello содержит SNI (domain) и настоящий TLS 1.3 от BoringSSL-профиля.
        """
        if aioquic is None:
            return None
        try:
            now = time.time()
            alpn = ["h3"]
            sni = domain or "www.example.com"

            # Клиентский Initial (реальный TLS 1.3 ClientHello с SNI)
            client_cfg = QuicConfiguration(is_client=True, alpn_protocols=alpn)
            client_cfg.server_name = sni
            client_conn = QuicConnection(configuration=client_cfg)
            client_conn.connect(("192.0.2.1", 443), now=now)
            client_dg = client_conn.datagrams_to_send(now=now)
            if not client_dg:
                return None
            # datagrams_to_send возвращает список (datagram_bytes, addr)
            client_initial = client_dg[0][0]

            if not is_server:
                return client_initial.hex()

            # Серверный ответ (ServerHello) — нужен самоподписанный сертификат
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sni)])
            cert = (x509.CertificateBuilder()
                    .subject_name(name).issuer_name(name)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                    .sign(key, hashes.SHA256()))
            # Серверу нужен original_destination_connection_id (DCID клиента) для вывода Initial-ключа
            client_dcid = pull_quic_header(Buffer(data=client_initial), host_cid_length=8).destination_cid
            server_cfg = QuicConfiguration(is_client=False, alpn_protocols=alpn)
            server_cfg.certificate = cert
            server_cfg.private_key = key
            server_conn = QuicConnection(configuration=server_cfg,
                                         original_destination_connection_id=client_dcid)
            server_conn.receive_datagram(client_initial, addr=("192.0.2.1", 12345), now=now)
            server_dg = server_conn.datagrams_to_send(now=now)
            if not server_dg:
                return None
            return server_dg[0][0].hex()
        except Exception:
            return None

    # ────────────────────────────────────────────────────────────────

    def _quic_clienthello_via_utls() -> tuple[str, str, str] | None:
        """Генерирует Chrome QUIC ClientHello и согласованный ServerHello через uTLS-сайдкар.

        Возвращает (clienthello_hex, serverhello_hex, scid_hex) или None если сайдкар недоступен / ошибка.
        clienthello_hex — полное handshake-сообщение ClientHello (тип 0x01 + длина + тело).
        serverhello_hex — полное handshake-сообщение ServerHello (тип 0x02 + длина + тело),
            согласованное с ClientHello (echo session_id). Может быть "" если сайдкар старый.
        scid_hex — initial_source_connection_id из transport parameters (совпадает с SCID в header).
        """
        sidecar = _ensure_imitat_sidecar()
        if not sidecar:
            return None
        try:
            rc, out = exec_cmd([sidecar, "-mode", "utls", "-sni", domain or "www.example.com",
                                "-seed", seed or ""], timeout=15)
            if rc != 0:
                logger.warning("⚠  uTLS-сайдкар вернул код %s: %s", rc, out.strip()[:200])
                return None
            data = json.loads(out.strip().splitlines()[-1])
            ch_hex = data.get("clienthello_hex", "")
            sh_hex = data.get("serverhello_hex", "")
            scid_hex = data.get("scid_hex", "")
            if not ch_hex or not scid_hex:
                return None
            return ch_hex, sh_hex, scid_hex
        except Exception as e:
            logger.warning("⚠  uTLS-сайдкар не сработал: %s", e)
            return None

    def _gen_quic_client():
        """QUIC Initial: uTLS (Chrome TLS 1.3) → aioquic (TLS 1.3) → рукописный TLS 1.2."""
        utls = _quic_clienthello_via_utls()
        if utls:
            ch_hex, _, scid_hex = utls
            # CRYPTO frame: type 06 + varint(offset=0) + varint(len) + данные.
            # ФИКС 16.09.2026: раньше было "06"+"00000000"+f"{len:08x}" — 4 байта
            # с неверным varint-префиксом (00…) → парсер читал длину 0, и реальные
            # серверы (Cloudflare/Google) молча отбрасывали Initial. Проверено
            # на стенде: с корректным varint серверы отвечают.
            crypto_hex = "06" + _quic_varint(0) + _quic_varint(len(ch_hex) // 2) + ch_hex
            # PADDING-фреймы до 1200 байт (RFC 9000 §14.1) — иначе дроп
            quic_hex, qr_static_range = _build_quic_packet(crypto_hex, scid_hex_preset=scid_hex,
                                                           pad_target=1200)
            return generate_cps_packet(
                static_bytes=f"0x{quic_hex}", static_bytes_range=qr_static_range,
                use_timestamp=True,
                random_bytes=200, random_bytes_range=100,
                random_ascii=100, random_ascii_range=100,
                random_digits=10, random_digits_range=5,
            )
        aio_hex = _quic_initial_via_aioquic(is_server=False)
        if aio_hex:
            return generate_cps_packet(
                static_bytes=f"0x{aio_hex}", static_bytes_range=0,
                use_timestamp=True,
                random_bytes=200, random_bytes_range=100,
                random_ascii=100, random_ascii_range=100,
                random_digits=10, random_digits_range=5,
            )
        sni_bytes = domain.encode('utf-8')
        sni_hex = sni_bytes.hex()
        random_hex = secrets.token_hex(32)
        session_id_hex = secrets.token_hex(32)

        # TLS 1.2 cipher suites (первый — детерминированный от seed, совпадает с сервером)
        suites_pool = ["c02b", "c02f", "c02c", "c030", "cca8", "cca9",
                       "c013", "c014", "0033", "0039", "002f", "009c"]
        if seed:
            # Тот же seed и тот же пул что на сервере → одинаковый выбранный cipher
            rnd = random.Random(seed)
            preferred = rnd.choice(["c02b", "c02f", "c02c", "c030", "cca8", "cca9"])
            suites_pool.remove(preferred)
            suites_pool.insert(0, preferred)
        cipher_hex = "".join(suites_pool)
        cipher_len = len(cipher_hex) // 2
        # SNI extension data (RFC 6066): list_len + name_type(00) + name_len + name.
        # ext_hex ниже добавляет ext_type(0000) + ext_data_len.
        sni_ext_hex = f"{len(sni_bytes)+3:04x}00{len(sni_bytes):04x}{sni_hex}"
        # supported_groups (x25519, secp256r1, secp384r1)
        groups_hex = ("000a00140012001d0017001800190100"
                      "1c000b000a0009")
        # signature_algorithms (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ...)
        sigalgs_hex = ("000d001a001806010602060305010502"
                       "0503040104020403080408040508")
        # ALPN (h2, http/1.1)
        alpn_hex = "0010000e000c02683208687474702f312e31"
        # supported_versions: только TLS 1.2 (0x0303)
        sv_hex = "002b0003020303"
        # ec_point_formats: uncompressed
        ecpt_hex = "000b00020100"
        # QUIC Transport Parameters
        scid_hex = secrets.token_hex(8)
        tp_body = (
            "00" + f"{len(scid_hex)//2:04x}" + scid_hex +        # initial_source_connection_id
            "01" + "0002" + "7530" +                              # max_idle_timeout (30000ms)
            "03" + "0002" + "04b0" +                              # max_udp_payload_size (1200)
            "04" + "0004" + "00010000" +                          # initial_max_data (65536)
            "06" + "0002" + "0100" +                              # initial_max_streams_bidi (256)
            "07" + "0002" + "0100"                                # initial_max_streams_uni (256)
        )
        qtp_hex = "0039" + f"{len(tp_body)//2:04x}" + tp_body
        # key_share (X25519 dummy public key)
        ks_hex = "0033" + "0026" + "0024" + "001d" + "0020" + secrets.token_hex(32)
        # All extensions
        ext_hex = (f"0000{len(sni_ext_hex)//2:04x}{sni_ext_hex}"  # SNI
                   f"{groups_hex}"                                 # supported_groups
                   f"{sigalgs_hex}"                                # signature_algorithms
                   f"{sv_hex}"                                     # supported_versions
                   f"{alpn_hex}"                                   # ALPN
                   f"{ecpt_hex}"                                   # ec_point_formats
                   f"{qtp_hex}"                                    # QUIC transport params
                   f"ff01000100"                                   # renegotiation_info
                   f"00120000"                                     # signed_certificate_timestamp (empty)
                   f"{ks_hex}")                                    # key_share
        ext_len = len(ext_hex) // 2
        # ClientHello body
        ch_body = (f"0303{random_hex}20{session_id_hex}"  # version + random + session
                   f"{cipher_len:04x}{cipher_hex}"         # cipher suites
                   f"0100"                                 # compression: null
                   f"{ext_len:04x}{ext_hex}")              # extensions
        ch_len = len(ch_body) // 2
        ch_hex = f"01{ch_len:06x}{ch_body}"
        # QUIC CRYPTO Frame (plaintext для шифрования) — varint длины корректный
        crypto_hex = "06" + _quic_varint(0) + _quic_varint(len(ch_hex) // 2) + ch_hex
        quic_hex, qr_static_range = _build_quic_packet(
            crypto_hex, scid_hex_preset=scid_hex,
            pad_target=1200 if try_AESGCM is not None else 0)
        if try_AESGCM is not None:
            # Хвостовые <r>/<rc>/<rd> расширяются в датаграмме ПОСЛЕ валидного
            # Initial-пакета. Проверено на стенде: Cloudflare отвечает и на
            # датаграмму с таким хвостом (16.09.2026).
            rb, rbr, ra, rar, rd, rdr = 200, 100, 100, 100, 10, 5
        else:
            rb, rbr, ra, rar, rd, rdr = 400, 200, 200, 200, 20, 10
        return generate_cps_packet(
            static_bytes=f"0x{quic_hex}", static_bytes_range=qr_static_range,
            use_timestamp=True,
            random_bytes=rb, random_bytes_range=rbr,
            random_ascii=ra, random_ascii_range=rar,
            random_digits=rd, random_digits_range=rdr,
        )

    def _gen_quic_client_handshake():
        """QUIC Handshake (завершение рукопожатия клиента)."""
        payload = secrets.token_hex(64)
        dcid_hex = secrets.token_hex(8)
        scid_hex = secrets.token_hex(8)
        body_len = 1 + len(payload)//2  # PN(1) + payload
        handshake_hex = (f"e000000001"
                         f"08{dcid_hex}"
                         f"08{scid_hex}"
                         f"{_quic_varint(body_len)}"
                         f"00"                                           # PN=0
                         f"{payload}")
        return generate_cps_packet(
            static_bytes=f"0x{handshake_hex}", static_bytes_range=30,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=100, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    def _gen_quic_server():
        """QUIC ServerHello: uTLS (согласованный с ClientHello) → aioquic TLS 1.3 → TLS 1.2."""
        utls = _quic_clienthello_via_utls()
        if utls:
            _, sh_hex, _ = utls
            if sh_hex:
                # varint длины CRYPTO + PADDING до 1200 (см. _gen_quic_client, 16.09.2026)
                crypto_hex = "06" + _quic_varint(0) + _quic_varint(len(sh_hex) // 2) + sh_hex
                quic_hex, qr_static_range = _build_quic_packet(crypto_hex, default_range=40,
                                                               is_server=True, pad_target=1200)
                if try_AESGCM is not None:
                    rb, rbr, ra, rar, rd, rdr = 200, 100, 100, 100, 10, 5
                else:
                    rb, rbr, ra, rar, rd, rdr = 300, 200, 300, 200, 20, 10
                return generate_cps_packet(
                    static_bytes=f"0x{quic_hex}", static_bytes_range=qr_static_range,
                    use_timestamp=True,
                    random_bytes=rb, random_bytes_range=rbr,
                    random_ascii=ra, random_ascii_range=rar,
                    random_digits=rd, random_digits_range=rdr,
                )
        aio_hex = _quic_initial_via_aioquic(is_server=True)
        if aio_hex:
            return generate_cps_packet(
                static_bytes=f"0x{aio_hex}", static_bytes_range=0,
                use_timestamp=True,
                random_bytes=200, random_bytes_range=100,
                random_ascii=100, random_ascii_range=100,
                random_digits=10, random_digits_range=5,
            )
        random_hex = secrets.token_hex(32)
        session_id_hex = secrets.token_hex(32)
        chosen_cipher = (random.Random(seed).choice([
            "c02b", "c02f", "c02c", "c030", "cca8", "cca9"
        ]) if seed else secrets.choice([
            "c02b", "c02f", "c02c", "c030", "cca8", "cca9"
        ]))
        sh_body = (f"0303{random_hex}20{session_id_hex}"
                   f"{chosen_cipher}"
                   f"00")
        sh_len = len(sh_body) // 2
        sh_hex = f"02{sh_len:06x}{sh_body}"
        crypto_hex = "06" + "00000000" + f"{len(sh_hex)//2:08x}{sh_hex}"
        quic_hex, qr_static_range = _build_quic_packet(crypto_hex, default_range=40, is_server=True)

        if try_AESGCM is not None:
            rb, rbr, ra, rar, rd, rdr = 200, 100, 100, 100, 10, 5
        else:
            rb, rbr, ra, rar, rd, rdr = 300, 200, 300, 200, 20, 10
        return generate_cps_packet(
            static_bytes=f"0x{quic_hex}", static_bytes_range=qr_static_range,
            use_timestamp=True,
            random_bytes=rb, random_bytes_range=rbr,
            random_ascii=ra, random_ascii_range=rar,
            random_digits=rd, random_digits_range=rdr,
        )

    def _gen_quic_server_handshake():
        """QUIC серверный flight (EncryptedExtensions+Cert+CertVerify+Finished).

        Handshake-пакеты шифруются ключами рукопожатия, которые DPI не может вывести
        (нужны приватные ключи) — payload для него непрозрачен. Поэтому достаточно
        реалистичной ДЛИНЫ: серверный flight с сертификатом ~1000+ байт.
        """
        payload = secrets.token_hex(1000)  # фрагмент flight с сертификатом
        dcid_hex = secrets.token_hex(8)
        scid_hex = secrets.token_hex(8)
        body_len = 1 + len(payload)//2  # PN(1) + payload
        handshake_hex = (f"e000000001"
                         f"08{dcid_hex}"
                         f"08{scid_hex}"
                         f"{_quic_varint(body_len)}"
                         f"00"
                         f"{payload}")
        return generate_cps_packet(
            static_bytes=f"0x{handshake_hex}", static_bytes_range=30,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=150, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    def _gen_quic_appdata():
        """QUIC 1-RTT (application data) — короткий заголовок.

        Реальный хендшейк завершается данными приложения (1-RTT, short header).
        Payload шифруется сессионными ключами — DPI видит только заголовок и длину.
        """
        payload = secrets.token_hex(48)
        dcid_hex = secrets.token_hex(8)
        # short header: 0x40 (fixed bit, pn_len=1) + DCID(8) + PN(1) + payload
        appdata_hex = f"40{dcid_hex}00{payload}"
        return generate_cps_packet(
            static_bytes=f"0x{appdata_hex}", static_bytes_range=0,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=100, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    # ─── STUN имитация (WebRTC ICE / NAT traversal) ─────────────
    def _stun_mi_key() -> str:
        """Ключ MESSAGE-INTEGRITY: детерминированный от seed (как session_id в QUIC),
        иначе случайный. Реальный HMAC-SHA1, просто не привязан к живой ICE-сессии."""
        if seed:
            return hashlib.sha256(seed.encode()).hexdigest()
        return secrets.token_hex(32)

    def _stun_build(msg_type_hex: str, attrs_hex: str, mi_key: str = "") -> str:
        """Собирает STUN-сообщение (RFC 5389): header + attributes + [MESSAGE-INTEGRITY] + FINGERPRINT.

        Header: type(2) + length(2) + magic cookie 0x2112A442 + transaction ID(12).
        MESSAGE-INTEGRITY (0x0008, если задан mi_key): HMAC-SHA1 по сообщению с
        обнулённым значением MI (RFC 5389 §15.4) — криптографически валидный.
        FINGERPRINT (0x8028): CRC-32 сообщения (с обнулённым значением атрибута)
        XOR 0x5354554E. DPI может проверить FINGERPRINT — считаем корректно.
        """
        txid = secrets.token_hex(12)
        # length = attrs + MI(24, если есть: 4 header + 20 value) + FINGERPRINT(8); header = 20 байт
        extra = 8 + (24 if mi_key else 0)
        total_len = (len(attrs_hex) // 2) + extra
        msg = msg_type_hex + f"{total_len:04x}" + "2112a442" + txid + attrs_hex
        if mi_key:
            # MI: HMAC-SHA1 по сообщению + header MI (type+len), значение 0
            mi_input = msg + "0008" + "0014" + "00" * 20
            mi = hmac.new(mi_key.encode(), bytes.fromhex(mi_input), hashlib.sha1).hexdigest()
            msg += "0008" + "0014" + mi
        # FINGERPRINT: RFC 8489 §14.6 — CRC-32 по сообщению БЕЗ самого атрибута
        # (фикс аудита: конкатенация «8028 0004 00000000» давала CRC, не
        # совпадающий с проверкой специ-совместимого DPI).
        fp = (zlib.crc32(bytes.fromhex(msg)) & 0xffffffff) ^ 0x5354554E
        msg += "8028" + "0004" + f"{fp:08x}"
        return msg

    def _gen_stun_client():
        """STUN Binding Request (WebRTC ICE connectivity check)."""
        priority = "0024" + "0004" + "6e7a1b7f"          # PRIORITY (1853634559)
        ice_ctrl = "802a" + "0008" + secrets.token_hex(8)  # ICE-CONTROLLING tie-breaker
        ufrag = "abc123:xyz789"                            # ICE username fragment
        pad = (4 - (len(ufrag) % 4)) % 4                   # STUN: атрибуты кратны 4 байтам
        username = "0006" + f"{len(ufrag):04x}" + ufrag.encode().hex() + "00" * pad
        msg = _stun_build("0001", priority + ice_ctrl + username, mi_key=_stun_mi_key())
        return generate_cps_packet(
            static_bytes=f"0x{msg}", static_bytes_range=0,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=100, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    def _gen_stun_server():
        """STUN Binding Success Response (XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY)."""
        # XOR-MAPPED-ADDRESS (0x0020): reserved+family(1) + XOR-port(2) + XOR-addr(4)
        port = 52884
        ip = 0xC0A80101  # 192.168.1.1
        xport = port ^ 0x2112
        xaddr = ip ^ 0x2112A442
        xma = "0020" + "0008" + "0001" + f"{xport:04x}" + f"{xaddr:08x}"
        # MESSAGE-INTEGRITY (0x0008): настоящий HMAC-SHA1(20) от ключа из seed.
        msg = _stun_build("0101", xma, mi_key=_stun_mi_key())
        return generate_cps_packet(
            static_bytes=f"0x{msg}", static_bytes_range=0,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=100, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    # ─── DTLS 1.2 имитация (WebRTC) ─────────────────────────────
    def _dtls_suites():
        """Cipher suites DTLS 1.2 (WebRTC): первый — детерминированный от seed."""
        # Только те cipher suites, что предлагает Pion DTLS ClientHello (c02b/c02f/c02c/c030),
        # чтобы ServerHello всегда выбирал cipher из списка клиента.
        suites_pool = ["c02b", "c02f", "c02c", "c030"]
        if seed:
            rnd = random.Random(seed)
            preferred = rnd.choice(suites_pool)
            suites_pool.remove(preferred)
            suites_pool.insert(0, preferred)
        return suites_pool

    def _dtls_sni_ext():
        """SNI extension (если задан domain)."""
        if not domain:
            return ""
        sni_bytes = domain.encode('utf-8')
        sni_hex = sni_bytes.hex()
        return f"0000{len(sni_bytes)+5:04x}00{len(sni_bytes):04x}{sni_hex}"

    def _dtls_extensions():
        """Набор extensions DTLS 1.2 как у Chrome WebRTC.

        Порядок и состав повторяют реальный ClientHello: server_name,
        extended_master_secret, renegotiation_info, supported_groups,
        ec_point_formats, signature_algorithms, use_srtp. НЕ включаем
        supported_versions (0x002b) — это фича TLS 1.3, в DTLS 1.2 её нет.
        """
        groups_hex = ("000a00140012001d0017001800190100"
                      "1c000b000a0009")
        sigalgs_hex = ("000d001a001806010602060305010502"
                       "0503040104020403080408040508")
        ecpt_hex = "000b00020100"
        srtp_hex = "000e0005000200010000"
        ems_hex = "00170000"          # extended_master_secret (пустое значение)
        reneg_hex = "ff01000100"
        return (_dtls_sni_ext() + ems_hex + reneg_hex + groups_hex
                + ecpt_hex + sigalgs_hex + srtp_hex)

    def _dtls_record(content_type: int, epoch: int, seq: int, payload_hex: str) -> str:
        """DTLS 1.2 record: content_type(1) + version fefd + epoch(2) + seq(6) + length(2) + payload."""
        return f"{content_type:02x}fefd{epoch:04x}{seq:012x}{len(payload_hex)//2:04x}{payload_hex}"

    def _dtls_handshake(msg_type: int, msg_seq: int, body_hex: str) -> str:
        """DTLS handshake msg: type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_len(3) + body."""
        body_len = len(body_hex) // 2
        return f"{msg_type:02x}{body_len:06x}{msg_seq:04x}000000{body_len:06x}{body_hex}"

    def _dtls_packet(record_hex: str) -> str:
        """Обёртка CPS-пакета для DTLS record."""
        return generate_cps_packet(
            static_bytes=f"0x{record_hex}", static_bytes_range=0,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=100, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    _dtls_pion_cache = None

    def _dtls_clienthello_via_pion():
        """Генерирует настоящие WebRTC DTLS 1.2 сообщения через Pion DTLS-сайдкар.

        Возвращает кортеж (clienthello_hex, serverhello_hex, certificate_hex,
        skx_hex, shd_hex) — полные DTLS records, или None если сайдкар
        недоступен / ошибка. Результат кэшируется: один запуск сайдкара на все
        I-параметры, чтобы ServerHello и flight были согласованы с ClientHello
        (один и тот же handshake).
        """
        nonlocal _dtls_pion_cache
        if _dtls_pion_cache is not None:
            return _dtls_pion_cache
        sidecar = _ensure_imitat_sidecar()
        if not sidecar:
            return None
        try:
            rc, out = exec_cmd([sidecar, "-mode", "dtls", "-sni", domain or "www.example.com"], timeout=15)
            if rc != 0:
                logger.warning("⚠  DTLS-сайдкар вернул код %s: %s", rc, out.strip()[:200])
                return None
            data = json.loads(out.strip().splitlines()[-1])
            ch_hex = data.get("clienthello_hex", "")
            sh_hex = data.get("serverhello_hex", "")
            cert_hex = data.get("certificate_hex", "")
            skx_hex = data.get("skx_hex", "")
            shd_hex = data.get("shd_hex", "")
            if not ch_hex:
                return None
            _dtls_pion_cache = (ch_hex, sh_hex, cert_hex, skx_hex, shd_hex)
            return _dtls_pion_cache
        except Exception as e:
            logger.warning("⚠  DTLS-сайдкар не сработал: %s", e)
            return None

    def _gen_dtls_client():
        """DTLS 1.2 ClientHello (WebRTC) — msg_seq=0, epoch=0 seq=0.

        Если доступен Pion DTLS-сайдкар — используем настоящий WebRTC ClientHello
        (неотличим от реального). Иначе рукописный (та же структура, но без
        точного порядка extensions реального стека).
        """
        pion = _dtls_clienthello_via_pion()
        if pion:
            return _dtls_packet(pion[0])
        random_hex = secrets.token_hex(32)
        cipher_hex = "".join(_dtls_suites())
        cipher_len = len(cipher_hex) // 2
        ext_hex = _dtls_extensions()
        ext_len = len(ext_hex) // 2
        # ClientHello body: version + random + session_id(0) + cookie(0) + ciphers + compression + extensions
        ch_body = (f"fefd{random_hex}"
                   f"00"                       # session_id len 0
                   f"00"                       # cookie len 0
                   f"{cipher_len:04x}{cipher_hex}"
                   f"0100"                     # compression: len 1, null
                   f"{ext_len:04x}{ext_hex}")
        return _dtls_packet(_dtls_record(0x16, 0, 0, _dtls_handshake(0x01, 0, ch_body)))

    def _gen_dtls_client_kex():
        """DTLS 1.2 ClientKeyExchange (ECDHE) — msg_seq=1, epoch=0 seq=1."""
        pubkey = secrets.token_hex(33)         # compressed P-256 point
        body = f"{33:02x}{pubkey}"
        return _dtls_packet(_dtls_record(0x16, 0, 1, _dtls_handshake(0x10, 1, body)))

    def _gen_dtls_ccs():
        """DTLS ChangeCipherSpec. Record-seq: после server flight
        (SH=0,Cert=1,SKX=2,SHD=3) — 4; у клиента (CH=0,CKE=1) — 2.
        Фикс аудита: жёсткий seq=2 коллизировал с SKX в серверном пуле."""
        return _dtls_packet(_dtls_record(0x14, 0, 4 if for_server else 2, "01"))

    def _gen_dtls_finished():
        """DTLS Finished (зашифрован) — epoch=1 seq=0.
        msg_seq зависит от направления: сервер после ServerHelloDone(3) → 4,
        клиент после ClientKeyExchange(1) → 2."""
        body = secrets.token_hex(12)           # verify_data (SHA-256 PRF)
        msg_seq = 4 if for_server else 2
        return _dtls_packet(_dtls_record(0x16, 1, 0, _dtls_handshake(0x14, msg_seq, body)))

    def _gen_dtls_appdata():
        """DTLS ApplicationData (зашифрован) — epoch=1 seq=1."""
        payload = secrets.token_hex(random.randint(40, 120))
        return _dtls_packet(_dtls_record(0x17, 1, 1, payload))

    def _gen_dtls_server():
        """DTLS 1.2 ServerHello (WebRTC) — msg_seq=0, epoch=0 seq=0.

        Если доступен Pion DTLS-сайдкар — настоящий ServerHello (реальный стек,
        cipher из набора клиента). Иначе рукописный (та же структура).
        """
        pion = _dtls_clienthello_via_pion()
        if pion and pion[1]:
            return _dtls_packet(pion[1])
        random_hex = secrets.token_hex(32)
        # Выбираем только из cipher suites, предлагаемых клиентом (Pion: c02b/c02f/c02c/c030).
        chosen_cipher = (random.Random(seed).choice([
            "c02b", "c02f", "c02c", "c030"
        ]) if seed else secrets.choice([
            "c02b", "c02f", "c02c", "c030"
        ]))
        # ServerHello body: version + random + session_id(0) + cipher + compression + extensions(0)
        sh_body = (f"fefd{random_hex}"
                   f"00"                       # session_id len 0
                   f"{chosen_cipher}"
                   f"00"                       # compression: null
                   f"0000")                    # extensions len 0
        return _dtls_packet(_dtls_record(0x16, 0, 0, _dtls_handshake(0x02, 0, sh_body)))

    def _gen_dtls_server_cert():
        """DTLS 1.2 Certificate — msg_seq=1, epoch=0 seq=1.

        Если доступен Pion DTLS-сайдкар — настоящий X.509 сертификат (реальный
        DER, случайный serial/CN). Иначе рукописный (та же структура).
        """
        pion = _dtls_clienthello_via_pion()
        if pion and pion[2]:
            return _dtls_packet(pion[2])
        cert = secrets.token_hex(random.randint(600, 900))
        cert_entry = f"{len(cert)//2:06x}{cert}"
        cert_body = f"{len(cert_entry)//2:06x}{cert_entry}"
        return _dtls_packet(_dtls_record(0x16, 0, 1, _dtls_handshake(0x0b, 1, cert_body)))

    def _gen_dtls_server_skx():
        """DTLS 1.2 ServerKeyExchange — msg_seq=2, epoch=0 seq=2.

        Если доступен Pion DTLS-сайдкар — настоящий SKX (реальная ECDSA-подпись
        в ServerKeyExchange). Иначе рукописный.
        """
        pion = _dtls_clienthello_via_pion()
        if pion and pion[3]:
            return _dtls_packet(pion[3])
        skx_pub = secrets.token_hex(33)
        skx_sig = secrets.token_hex(70)        # ECDSA P-256 подпись ~70 байт
        skx_body = f"030017{33:02x}{skx_pub}0603{70:04x}{skx_sig}"
        return _dtls_packet(_dtls_record(0x16, 0, 2, _dtls_handshake(0x0c, 2, skx_body)))

    def _gen_dtls_server_shd():
        """DTLS 1.2 ServerHelloDone — msg_seq=3, epoch=0 seq=3."""
        pion = _dtls_clienthello_via_pion()
        if pion and pion[4]:
            return _dtls_packet(pion[4])
        return _dtls_packet(_dtls_record(0x16, 0, 3, _dtls_handshake(0x0e, 3, "")))

    # Определяем пул в зависимости от направления, протокола и domain
    if proto == "dtls":
        if for_server:
            pool_fns = [_gen_dtls_server, _gen_dtls_server_cert, _gen_dtls_server_skx, _gen_dtls_server_shd, _gen_dtls_ccs, _gen_dtls_finished, _gen_dtls_appdata]
        else:
            pool_fns = [_gen_dtls_client, _gen_dtls_client_kex, _gen_dtls_ccs, _gen_dtls_finished, _gen_dtls_appdata]
    elif proto == "stun":
        if for_server:
            pool_fns = [_gen_stun_server]
        else:
            pool_fns = [_gen_stun_client]
    elif for_server and domain:
        pool_fns = [_gen_quic_server, _gen_quic_server_handshake, _gen_quic_appdata]
    elif domain:
        pool_fns = [_gen_quic_client, _gen_quic_client_handshake, _gen_quic_appdata]
    else:
        # Стандартный случайный пул
        pool_fns = [_gen_dns, _gen_quic, _gen_dtls, _gen_ntp, _gen_random, _gen_srtp]

    # Генерация с валидацией диапазонов
    # Флаг для domain-пулов — строгий порядок Initial→Handshake
    is_imitation_pool = bool(domain)

    selected = []
    best_selected = None
    best_distance = float('inf')
    for _attempt in range(MAX_ATTEMPTS):
        if proto == "stun":
            # STUN: серия Binding Request / Binding Response (ICE connectivity checks)
            count = random.randint(I_SNI_COUNT_MIN, I_SNI_COUNT_MAX)
            current = [pool_fns[0]() for _ in range(count)]
        elif proto == "dtls":
            # DTLS: реалистичная последовательность рукопожатия WebRTC DTLS 1.2
            # (без cookie-обмена — в WebRTC клиент уже аутентифицирован через ICE):
            #   клиент: ClientHello → ClientKeyExchange → ChangeCipherSpec → Finished → AppData
            #   сервер: ServerHello → Certificate → ServerKeyExchange → ServerHelloDone
            #           → ChangeCipherSpec → Finished → AppData
            #   (каждое сообщение сервера — отдельный record, как реальный Pion)
            # Ключевой инсайт (как в QUIC): после ChangeCipherSpec (epoch 0→1) сообщения
            # Finished/AppData зашифрованы — DPI видит только тип+длину, payload непрозрачен.
            if for_server:
                # Сервер всегда шлёт полный flight (ServerHello+Cert+SKX+SHD) → минимум 4.
                count = random.randint(4, I_SNI_COUNT_MAX)
                order = [_gen_dtls_server, _gen_dtls_server_cert, _gen_dtls_server_skx, _gen_dtls_server_shd, _gen_dtls_ccs, _gen_dtls_finished, _gen_dtls_appdata]
            else:
                count = random.randint(I_SNI_COUNT_MIN, I_SNI_COUNT_MAX)
                order = [_gen_dtls_client, _gen_dtls_client_kex, _gen_dtls_ccs, _gen_dtls_finished, _gen_dtls_appdata]
            current = [order[min(i, len(order) - 1)]() for i in range(count)]
        elif is_imitation_pool:
            count = random.randint(I_SNI_COUNT_MIN, I_SNI_COUNT_MAX)
            # QUIC: реалистичный порядок реального хендшейка, а не чередование:
            #   клиент: ClientHello → Finished → AppData
            #   сервер: ServerHello → Flight → AppData
            # (после первого пакета остальные заполняются AppData)
            if for_server:
                order = [_gen_quic_server, _gen_quic_server_handshake, _gen_quic_appdata]
            else:
                order = [_gen_quic_client, _gen_quic_client_handshake, _gen_quic_appdata]
            current = [order[min(i, len(order) - 1)]() for i in range(count)]
        else:
            is_single_pool = len(pool_fns) == 1
            if is_single_pool:
                min_count = I_SNI_COUNT_MIN
                max_possible = I_SNI_COUNT_MAX
            else:
                max_count = len(pool_fns)
                min_count = min(I_COUNT_MIN, max_count)
                max_possible = min(I_COUNT_MAX, max_count)
            if min_count >= max_possible:
                count = min_count
            else:
                count = random.randint(min_count, max_possible)
            current = [fn() for fn in random.sample(pool_fns, min(count, len(pool_fns)))]
            random.shuffle(current)

        # Проверка веса строк и объёма трафика
        use_sni_ranges = is_imitation_pool or (len(pool_fns) == 1) or proto in ("stun", "dtls")
        t_min = I_SNI_TEXT_MIN if use_sni_ranges else I_TEXT_MIN
        t_max = I_SNI_TEXT_MAX if use_sni_ranges else I_TEXT_MAX
        tr_min = I_SNI_TRAFFIC_MIN if use_sni_ranges else I_TRAFFIC_MIN
        tr_max = I_SNI_TRAFFIC_MAX if use_sni_ranges else I_TRAFFIC_MAX

        text_total = sum(len(s) for s in current)
        traffic_total = sum(
            sum(int(x) for x in re.findall(r'<r (\d+)>', s)) +
            sum(int(x) for x in re.findall(r'<rc (\d+)>', s)) +
            sum(int(x) for x in re.findall(r'<rd (\d+)>', s))
            for s in current
        )

        if t_min <= text_total <= t_max and tr_min <= traffic_total <= tr_max:
            selected = current
            break

        # Отклонения от диапазонов
        text_err = max(0, t_min - text_total) + max(0, text_total - t_max)
        traffic_err = max(0, tr_min - traffic_total) + max(0, traffic_total - tr_max)
        distance = text_err + traffic_err
        if distance < best_distance:
            best_distance = distance
            best_selected = current

    else:
        # Не нашли идеального — используем лучший
        selected = best_selected if best_selected else selected

    # Перемешиваем порядок — только для случайных пулов
    if not is_imitation_pool:
        random.shuffle(selected)

    # Распределяем по I1-IN
    result = {}
    for i, packet in enumerate(selected, start=1):
        result[f"I{i}"] = packet

    return result



def generate_all_params(version: str, for_client: bool = False, for_server: bool = True, for_warp: bool = False, domain: str = "", tun_name: str = "", seed_override: str = "", proto: str = "", server_pubkey: str = "") -> dict:
    """
    УНИВЕРСАЛЬНАЯ ФУНКЦИЯ — генерирует ВСЕ параметры обфускации сразу.

    Возвращает полный набор параметров, но неподдерживаемые версии = None.

    Таблица реализации:
Эта таблица описывает сервер/клиент
┌────────┬──────────────┬───────────────┬──────────────┬────────────┬──────────────┐
│ Версия │ Jc,Jmin,Jmax │ S1,S2         │ H1-H4        │ I1-I5      │ S3,S4        │
├────────┼──────────────┼───────────────┼──────────────┼────────────┼──────────────┤
│ WG     │ - коммент    │ - коммент     │ - коммент    │ - коммент  │ - коммент    │
│ AWG    │ + разные     │ + одинаковые  │ - коммент    │ - коммент  │ - коммент    │
│ AWG1.0 │ + разные     │ + одинаковые  │ + статичные  │ - коммент  │ - коммент    │
│ AWG1.5 │ + разные     │ + одинаковые  │ + статичные  │ + клиент   │ - коммент    │
│ AWG2.0 │ + разные     │ + одинаковые  │ + диапазоны  │ + клиент   │ + одинаковые │
└────────┴──────────────┴───────────────┴──────────────┴────────────┴──────────────┘
Эта таблица описывает сервер/клиент, warp сервер/клиент
┌────────┬───────────────────┬────────────────────────────┬────────────────────────────┬────────────────────┬────────────────────────────┐
│ Версия │ Jc,Jmin,Jmax      │ S1,S2                      │ H1-H4                      │ I1-I5              │ S3,S4                      │
├────────┼───────────────────┼────────────────────────────┼────────────────────────────┼────────────────────┼────────────────────────────┤
│ WG     │ - с:#,к/Wс/Wк:нет │ - с:#,к/Wс/Wк:нет          │ - с:#,к/Wс/Wк:нет          │ - с:#,к/Wс/Wк:нет  │ - с:#,к/Wс/Wк:нет          │
│ AWG    │ + с/к/Wс/Wк:свои  │ + с/к:одинаковые,Wс/Wк:нет │ - с:#,к/Wс/Wк:нет          │ - с:#,к/Wс/Wк:нет  │ - с:#,к/Wс/Wк:нет          │
│ AWG1.0 │ + с/к/Wс/Wк:свои  │ + с/к:одинаковые,Wс/Wк:нет │ + с/к:одинаковые,Wс/Wк:нет │ - с:#,к/Wс/Wк:нет  │ - с:#,к/Wс/Wк:нет          │
│ AWG1.5 │ + с/к/Wс/Wк:свои  │ + с/к:одинаковые,Wс/Wк:нет │ + с/к:одинаковые,Wс/Wк:нет │ + с/к/Wс/Wк:свои   │ - с:#,к/Wс/Wк:нет          │
│ AWG2.0 │ + с/к/Wс/Wк:свои  │ + с/к:одинаковые,Wс/Wк:нет │ + с/к:одинаковые,Wс/Wк:нет │ + с/к/Wс/Wк:свои   │ + с/к:одинаковые,Wс/Wк:нет │
└────────┴───────────────────┴────────────────────────────┴────────────────────────────┴────────────────────┴────────────────────────────┘

    Args:
        version: "WG", "AWG", "AWG1.0", "AWG1.5", "AWG2.0"
        for_client: Если True, генерировать I1-I5 для клиента
        for_server: Если True, генерировать ВСЕ параметры (даже неподдерживаемые) для сервера

    Returns:
        Словарь со всеми параметрами. None = параметр не поддерживается (закомментировать).
    """
    # Генерируем полный набор параметров для максимальной версии (AWG2.0)
    Jc, Jmin, Jmax = _generate_j_params()

    # S1-S4: для AWG3.1 — ОДНО значение на все четыре, 12..19 (см. docstring
    # _generate_s_params_awg31: S<12 → Invalid argument при HeaderProtectionKey;
    # при RandomTrailers разные S дают ложное распознавание data-пакетов как
    # handshake при широких H-диапазонах — измеренные потери 25-65%, InvalidMAC).
    # Для остальных версий — как раньше (у 2.0 S различаются минимум на 3), но
    # у 2.0/3.0 (H — ДИАПАЗОНЫ) включается отсев коллизий длины data/handshake:
    # см. _s_params_have_length_collision (измеренные потери 5-25% на конкретных
    # размерах пакетов). У AWG/1.0/1.5 H статичные → отсев не нужен и не
    # применяется, чтобы не сдвигать их исторические значения.
    # ВАЖНО: S1/S2 генерируются ровно один раз — порядок вызовов сохраняется
    # для воспроизводимости потока (тест «поток random не сдвинут»).
    # (16.09.2026: _i_seed от S больше не зависит — см. ниже.)
    if version == "AWG3.1":
        S1, S2, S3, S4 = _generate_s_params_awg31()
    else:
        S1, S2, S3, S4 = _generate_s_params(
            avoid_length_collision=version in ("AWG2.0", "AWG3.0"))

    # seed для session_id (QUIC) и выбора cipher (TLS 1.2) — ПУБЛИЧНЫЙ КЛЮЧ СЕРВЕРА
    # (16.09.2026: раньше было S1+S2+pubkey. session_id = sha256(seed) лежит на проводе
    # открытым, и при известном pubkey (он публичный — в каждом клиентском конфиге)
    # S1/S2 выводились перебором: 3.1 — 8 вариантов, 2.0 — ~19k. S — не ключевой
    # материал, но это лишний оракул. Заменено на один pubkey: публичен по дизайну,
    # энтропия 256 бит, перебор невозможен; сервер и клиенты одного интерфейса знают
    # один и тот же ключ → состыковка ClientHello/ServerHello сохраняется.
    # Публичный ключ высокоэнтропиен и уникален на интерфейс (лежит в обоих конфигах),
    # исключает коллизии между интерфейсами.
    _i_seed = seed_override if seed_override else server_pubkey

    # H1-H4: статичные для AWG1.0/1.5, диапазоны для AWG2.0
    # AWG3.0/3.1: диапазоны как в 2.0 (HP с кастомными H работает e2e —
    # проверено на стенде; жертва H1-H4 не требуется).
    if version in ("AWG2.0", "AWG3.0", "AWG3.1"):
        H1, H2, H3, H4 = _generate_h_params_ranges()
    else:
        H1, H2, H3, H4 = _generate_h_params_static()

    # S1-S4 уже сгенерированы выше (единая точка генерации).

    # Определяем какие параметры поддерживаются в данной версии
    supports_jc = version in ["AWG", "AWG1.0", "AWG1.5", "AWG2.0", "AWG3.0", "AWG3.1"]
    supports_s1_s2 = version in ["AWG", "AWG1.0", "AWG1.5", "AWG2.0", "AWG3.0", "AWG3.1"]
    supports_h = version in ["AWG1.0", "AWG1.5", "AWG2.0", "AWG3.0", "AWG3.1"]
    supports_i = version in ["AWG1.5", "AWG2.0", "AWG3.0", "AWG3.1"]  # I1-I5 для сервера и клиента
    supports_s3_s4 = version in ["AWG2.0", "AWG3.0", "AWG3.1"]
    # AWG3.x: аддитивные механизмы (ContentPadding, тайминги, DisableCookies)
    supports_3x_add = version in ["AWG3.0", "AWG3.1"]
    # AWG3.1: HeaderProtectionKey + RandomTrailers (жертвы: S ≥ 12 и S1=S2=S3=S4 —
    # см. _generate_s_params_awg31, измерено на ядре 3.1.20260812)
    supports_3x_full = version == "AWG3.1"

    # Новые параметры 3.x: значения генерируются ЛЕНИВО — только для версий,
    # которые их поддерживают. Безусловный вызов сдвигал бы поток global random
    # (ContentPadding) и менял I1-I5 у старых версий при том же seed — прямое
    # нарушение «3.0 = 2.0 + новое, без вреда старому».
    _padding = _generate_content_padding() if (supports_3x_add and not for_warp) else None
    # 16.09.2026: тайминги генерируются И для WARP (в отличие от паддинга и HP) —
    # это чисто локальные клиентские таймеры, по проводу не передаются и работают
    # против любого эндпоинта, включая ванильный WireGuard (проверено e2e:
    # клиент с рекеем 300-400с против ванильного сервера — 0% потерь).
    _timings = _generate_timing_params() if supports_3x_add else {}
    _hp_key = _generate_header_protection_key() if (supports_3x_full and not for_warp) else None

    # Формируем результат
    result = {}

    # Общий паттерн для групп параметров: поддерживается → активные значения;
    # не поддерживается → для сервера закомментированные, иначе None (нет в конфиге).
    # suppress_for_warp: True — параметр не генерируется для WARP (S/H), False — генерируется (J).
    def _add_param_group(keys, values, supported, comment_key, comment_val, suppress_for_warp=True):
        if supported and not (for_warp and suppress_for_warp):
            result.update(dict(zip(keys, values, strict=True)))
        elif for_server and not for_warp:
            result.update(dict(zip(keys, values, strict=True)))
            result[comment_key] = comment_val
        else:
            result.update({k: None for k in keys})

    # Jc, Jmin, Jmax — генерируются и для WARP
    _add_param_group(("Jc", "Jmin", "Jmax"), (Jc, Jmin, Jmax), supports_jc, "_J_comment", "AWG+",
                     suppress_for_warp=False)

    # S1, S2 — не генерируются для WARP
    _add_param_group(("S1", "S2"), (S1, S2), supports_s1_s2, "_S12_comment", "AWG+")

    # S3, S4 — не генерируются для WARP
    _add_param_group(("S3", "S4"), (S3, S4), supports_s3_s4, "_S34_comment", "AWG2.0")

    # H1-H4 — не генерируются для WARP
    _add_param_group(("H1", "H2", "H3", "H4"), (H1, H2, H3, H4), supports_h, "_H_comment", "AWG1.0+")

    # I1-I5 — пакеты-приманки
    # AWG1.5, AWG2.0: активные значения для всех конфигов
    # WG, AWG, AWG1.0: коммент для сервера, нет для клиента/WARP
    if supports_i:
        result.update(_generate_i_params(for_client=for_client, for_server=for_server, domain=domain, seed=_i_seed, proto=proto))
    else:
        if for_server and not for_warp:
            i_params = _generate_i_params(for_client=for_client, for_server=for_server, domain=domain, seed=_i_seed, proto=proto)
            result.update({
                "I1": i_params.get("I1"),
                "I2": i_params.get("I2"),
                "I3": i_params.get("I3"),
                "I4": i_params.get("I4"),
                "I5": i_params.get("I5"),
                "_I_comment": "AWG1.5+"
            })
        else:
            result.update({"I1": None, "I2": None, "I3": None, "I4": None, "I5": None})

    # --- AWG3.0+ : аддитивные механизмы (без жертв со стороны старых параметров) ---
    # ВАЖНО: БЕЗОБИДНЫЕ 3.x (5 таймингов, ContentPaddingAddition, DisableCookies)
    # в серверных конфигах версий ниже 3.0 выводятся закомментированными
    # («# KEY = val  # AWG3.0»), как у J/S/H/I — значения информационные,
    # раскомментировать можно (ядро принимает их в любой конфигурации).
    # НЕ комментируются никогда: HeaderProtectionKey (ядро отвергнет: в 2.0/3.0
    # S4 = 5..9 < 12, не равны) и RandomTrailers (с неравными S — потери
    # 25-65%). Для клиентов и WARP — строго None (комментарии только в
    # серверных конфигах, как у J/S/H/I).
    _3x_on = supports_3x_add and not for_warp
    # 16.09.2026: 5 таймингов разрешены и в WARP (3.0/3.1) — локальные таймеры,
    # не влияют на провода; проволочные 3.x (паддинг, cookies, trailers, HP)
    # остаются WARP-запрещёнными (их не распарсит сторонний эндпоинт).
    _timings_on = supports_3x_add
    # 16.09.2026: сервер ниже 3.0 — БЕЗОБИДНЫЕ 3.x выводятся комментариями-
    # подсказками («# KEY = val  # AWG3.0»), как у S/H/J/I: значения
    # информационные, раскомментировать можно (ядро принимает их в любой
    # конфигурации — тайминги проверены даже при S=0 против ванильного WG).
    # НЕ комментируются: HeaderProtectionKey (в 2.0/3.0 S4 = 5..9 < 12 — ядро
    # отвергнет конфиг) и RandomTrailers (с неравными S — потери 25-65%).
    # Значения комментариев берутся из ОТДЕЛЬНОГО локального RNG — global
    # random не трогается (стрим-инвариант «старые версии = прежние значения»).
    _3x_comment_mode = for_server and not for_warp and not supports_3x_add

    if _3x_comment_mode:
        _hint_rng = random.Random()
        _pad_hint = _generate_content_padding(rng=_hint_rng)
        _tim_hint = _generate_timing_params(rng=_hint_rng)
        result["ContentPaddingAddition"] = _pad_hint
        result["_PADDING_comment"] = "AWG3.0"
        result["DisableCookies"] = "on"
        result["_COOKIES_comment"] = "AWG3.0"
        for _tk in ("RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                    "KeepaliveTimeout", "MaxHandshakeAttempts"):
            result[_tk] = _tim_hint.get(_tk)
        result["_TIMINGS_comment"] = "AWG3.0"
    else:
        result["ContentPaddingAddition"] = _padding if _3x_on else None
        result["DisableCookies"] = "on" if _3x_on else None
        for _tk in ("RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                    "KeepaliveTimeout", "MaxHandshakeAttempts"):
            result[_tk] = _timings.get(_tk) if _timings_on else None
    result["RandomTrailers"] = "on" if (supports_3x_full and not for_warp) else None

    # HeaderProtectionKey — строго server-side и только 3.1: один ключ на сервер
    # и всех его клиентов. Клиентам он вшивается из серверного конфига
    # (_fill_client_obfuscation_params → _fill_awg3_lines(server_params=...)),
    # а не генерируется заново (иначе handshake развалится).
    if _3x_on and supports_3x_full and not for_client:
        result["HeaderProtectionKey"] = _hp_key
    else:
        result["HeaderProtectionKey"] = None

    return result

# ----------------- Генерация ключей -----------------

def gen_pair_keys() -> tuple[str, str]:
    """Генерация пары ключей (PrivateKey + PublicKey) через awg > wg > Python."""
    # Всегда сначала пробуем awg, потом wg, потом Python fallback
    for wgtool in ["awg", "wg"]:
        rc, out = exec_cmd([wgtool, "genkey"])
        if rc == 0 and out:
            priv = out.strip()
            rc, out = exec_cmd([wgtool, "pubkey"], input=priv + "\n")
            if rc == 0 and out:
                pub = out.strip()
                # Проверка формата (аудит-20): мусорный вывод сломал бы конфиг.
                # Явные проверки вместо assert — assert удаляется при python -O
                # (bandit B101), что отключило бы валидацию в оптимизированном запуске.
                import base64 as _b64
                try:
                    _priv_b = _b64.b64decode(priv + "=" * ((4 - len(priv) % 4) % 4), validate=True)
                    _pub_b = _b64.b64decode(pub + "=" * ((4 - len(pub) % 4) % 4), validate=True)
                    # Фикс аудита: проверки длин СТРОКИ (43/44) недостаточно —
                    # base64 из 44 символов может декодироваться в 33 байта.
                    if len(_priv_b) != 32 or len(_pub_b) != 32:
                        raise ValueError
                except Exception:
                    continue  # пробуем следующий инструмент/fallback
                return priv, pub

    # Python fallback через cryptography
    if cryptography is None:
        raise RuntimeError("Не удалось сгенерировать ключи: нет awg/wg и нет cryptography")

    priv_key = X25519PrivateKey.generate()
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    # НЕ убираем padding ('='): wg pubkey и WARP API требуют ключ с padding
    priv = base64.b64encode(priv_bytes).decode()
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub = base64.b64encode(pub_bytes).decode()
    return priv, pub


def gen_preshared_key() -> str:
    """Генерация preshared key через openssl rand или os.urandom."""
    rc, out = exec_cmd(["openssl", "rand", "-base64", "32"])
    if rc == 0 and out:
        return out.strip()
    try:
        return base64.b64encode(os.urandom(32)).decode("ascii")
    except Exception:
        raise RuntimeError("Не удалось сгенерировать preshared key") from None


# ----------------- Утилиты -----------------


def atomic_write_text(path: pathlib.Path, text: str, encoding: str = "utf-8") -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(dir=str(path.parent))
    prev_mode = None
    prev_uid = None
    prev_gid = None
    try:
        try:
            st = path.stat()
            prev_mode = st.st_mode & 0o7777
            prev_uid, prev_gid = st.st_uid, st.st_gid
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())  # durable before atomic replace
        os.replace(tmpname, str(path))
        # Сохраняем права/владельца существующего файла (аудит-20: mkstemp
        # создавал файл 0600, сбивая ручные chmod/chown на конфигах).
        if prev_mode is not None:
            try:
                os.chmod(str(path), prev_mode)
            except OSError:
                pass
        if prev_uid is not None and hasattr(os, 'chown'):
            try:
                os.chown(str(path), prev_uid, prev_gid)
            except OSError:
                pass
        # fsync родительской директории (фикс аудита): rename сам по себе
        # не гарантирует переживания краха хоста без durable-каталога.
        try:
            _dfd = os.open(str(path.parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(_dfd)
            finally:
                os.close(_dfd)
        except OSError:
            pass
    finally:
        try:
            if os.path.exists(tmpname):
                os.remove(tmpname)
        except Exception:
            pass


def _atomic_rmw(path: pathlib.Path, make, attempts: int = 3) -> str:
    """Атомарный read-modify-write с повторной попыткой по mtime (фикс аудита-A1:
    параллельные -a/-u/-d теряли клиента/правку; без fcntl, переносимо).

    make() вызывается заново на каждой попытке: fresh load + вся мутация,
    возвращает ПОЛНЫЙ новый текст. Запись — только если файл не менялся
    между stat до load и stat перед save.
    """
    _path = pathlib.Path(path)
    _last: Exception | None = None
    for _attempt in range(1, attempts + 1):
        try:
            _st1 = _path.stat()
        except OSError:
            _st1 = None
        text = make()
        try:
            _st2 = _path.stat()
        except OSError:
            _st2 = None
        if _st1 is not None and _st2 is not None:
            def _fkey(st):
                return (getattr(st, "st_mtime_ns", st.st_mtime), st.st_size, getattr(st, "st_ino", 0))
            if _fkey(_st1) != _fkey(_st2):
                _last = RuntimeError(
                    f'Конфиг {_path.name} изменён параллельно (попытка {_attempt}/{attempts}), перечитываю...')
                logger.warning("%s", _last)
                continue
        atomic_write_text(_path, text)
        return text
    raise RuntimeError(f'Конфиг {_path} меняется параллельно: не удалось сохранить за {attempts} попытки') from _last


def exec_cmd(cmd, input: str | None = None, shell: bool = False, timeout: int | None = None,
             cwd: str | None = None) -> tuple[int, str]:
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
            errors="replace",  # фикс аудита: не-UTF8 вывод не теряет диагностику
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
        )
        rc = proc.returncode
        out = proc.stdout or ""
        return rc, out
    except subprocess.TimeoutExpired as e:
        return 124, getattr(e, "output", "") or ""
    except Exception as e:
        return 1, f"exec_cmd failed: {e}"


def _ensure_sidecar(binary_name: str, main_go: str, go_mod: str,
                    hash_file: str, display: str, missing_flag: str) -> str | None:
    """Возвращает путь к бинарнику Go-сайдкара, собрав его при необходимости.

    Приоритет: уже установленный бинарник (PATH / /usr/local/bin) → сборка из
    встроенного исходника во временный каталог, бинарник кладётся рядом с
    awgcreate.py (нужен Go). Временные исходники удаляются после сборки.

    Семантика ошибок (фикс аудита): отсутствие Go — фатально (флаг missing_flag);
    сетевые/дисковые сбои (go mod tidy, build, исключения) — ТРАНЗИТНЫ:
    не блокируют навсегда, а ставят 5-минутный бэкофф (иначе при мёртвой сети
    цикл probe гонял бы tidy по 180с на каждый эндпоинт).
    """
    if globals()[missing_flag]:
        return None
    if time.monotonic() < _SIDECAR_RETRY_AT.get(binary_name, 0.0):
        return None
    # Уже установленный бинарник
    for _cand in (shutil.which(binary_name), f"/usr/local/bin/{binary_name}"):
        if _cand and os.path.isfile(_cand):
            return _cand
    # Бинарник рядом с awgcreate.py
    binary = SCRIPT_DIR / binary_name
    # Фикс аудита: go.mod входит в кэш-ключ (изменение зависимостей
    # пересобирает бинарник, а не подсовывает устаревший).
    src_hash = hashlib.sha256((main_go + "\0" + go_mod).encode()).hexdigest()
    if binary.is_file():
        try:
            if (SCRIPT_DIR / hash_file).read_text(encoding="utf-8").strip() == src_hash:
                return str(binary)
        except OSError:
            pass
    go = shutil.which("go")
    if not go:
        globals()[missing_flag] = True
        logger.warning("⚠  %s не собран: Go не найден (установите через awgcreate.sh)", display)
        return None
    build_dir = None
    try:
        build_dir = tempfile.mkdtemp(prefix=f"{binary_name}-")
        build_path = pathlib.Path(build_dir)
        (build_path / "main.go").write_text(main_go, encoding="utf-8")
        (build_path / "go.mod").write_text(go_mod, encoding="utf-8")
        rc, out = exec_cmd(["go", "mod", "tidy"], cwd=build_dir, timeout=180)
        if rc != 0:
            _SIDECAR_RETRY_AT[binary_name] = time.monotonic() + 300
            logger.warning("⚠  go mod tidy (транзитно, повтор через ~5 мин): %s", out.strip()[:200])
            return None
        rc, out = exec_cmd(["go", "build", "-o", str(binary), "."], cwd=build_dir, timeout=180)
        if rc != 0:
            _SIDECAR_RETRY_AT[binary_name] = time.monotonic() + 300
            logger.warning("⚠  go build (транзитно, повтор через ~5 мин): %s", out.strip()[:200])
            return None
        (SCRIPT_DIR / hash_file).write_text(src_hash, encoding="utf-8")
        _SIDECAR_RETRY_AT.pop(binary_name, None)
        globals()[missing_flag] = False
        logger.info("✅ %s собран: %s", display, binary)
        return str(binary)
    except Exception as e:
        _SIDECAR_RETRY_AT[binary_name] = time.monotonic() + 300
        logger.warning("⚠  сборка %s не удалась (транзитно, повтор через ~5 мин): %s", display, e)
        return None
    finally:
        if build_dir:
            shutil.rmtree(build_dir, ignore_errors=True)


def _ensure_imitat_sidecar() -> str | None:
    """Возвращает путь к бинарнику единого сайдкара имитации (awg-imitat),
    собрав его при необходимости. Режимы: utls (QUIC ClientHello), dtls (WebRTC)."""
    return _ensure_sidecar(
        "awg-imitat", _IMITAT_SIDECAR_MAIN_GO, _IMITAT_SIDECAR_GO_MOD,
        ".awg-imitat.hash", "имитация uTLS/DTLS", "_IMITAT_SIDECAR_MISSING")


def _ensure_warp_probe_sidecar() -> str | None:
    """Возвращает путь к бинарнику WARP-probe (настоящее WG-рукопожатие), собрав при необходимости."""
    return _ensure_sidecar(
        "awg-probe", _WARP_PROBE_GO, _WARP_PROBE_GO_MOD,
        ".awg-probe.hash", "WARP-probe", "_WARP_PROBE_MISSING")


def check_warp_endpoint(host_port: str, server_pubkey: str = "", client_private_key: str = "",
                        timeout: float = 1.5) -> tuple[bool, str]:
    """Проверка WARP-эндпоинта «настоящим WireGuard-рукопожатием».

    Аргументы: endpoint host:port; server_pubkey (peer public_key из API Cloudflare);
    client_private_key (наш зарегистрированный ключ). Ответ сервера (handshake
    response или cookie reply) — надёжное подтверждение «живости». Без probe
    или ключей — фоллбэк на старую UDP-эвристику check_endpoint.
    Возвращает (ok, способ/тип подтверждения).
    """
    if not server_pubkey or not client_private_key:
        return check_endpoint(host_port, timeout), "heuristic"
    probe = _ensure_warp_probe_sidecar()
    if probe is None:
        return check_endpoint(host_port, timeout), "heuristic-fallback"
    # Фикс аудита: приватный ключ клиента НЕ передаётся через argv (светился
    # в ps//proc любому локальному пользователю) — probe читает его из stdin.
    probe_input = json.dumps({
        "endpoint": host_port,
        "server_pub": server_pubkey,
        "client_priv": client_private_key,
    }) + "\n"
    rc, out_raw = exec_cmd([
        probe, "-endpoint", host_port,
        "-server-pub", server_pubkey,
        "-timeout-ms", str(int(timeout * 1000)),
        "-retries", "2",
    ], input=probe_input)
    if rc == 0 and out_raw:
        try:
            data = json.loads(out_raw.strip().splitlines()[-1])
            ok = bool(data.get("ok"))
            how = str(data.get("type", "unknown"))
            # «не сетевые» результаты probe (битые ключи/резолв/чтение) —
            # фоллбэк на эвристику; честное «нет ответа» (none) — авторитетно.
            if ok:
                return True, how
            if how in ("none", "timeout"):
                return False, how
            return check_endpoint(host_port, timeout), "heuristic-fallback"
        except Exception:
            pass
    # probe упал/вернул мусор — аккуратный фоллбэк на эвристику
    return check_endpoint(host_port, timeout), "heuristic-fallback"




def get_main_iface() -> str | None:
    rc, out = exec_cmd(["ip", "link", "show"])
    if rc != 0:
        logger.warning("⚠  Не удалось выполнить 'ip link show': %s", out.strip())
        return None
    for line in out.splitlines():
        if "<BROADCAST" in line and "state UP" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                iface = parts[1].strip()
                # Отрезаем @ifN (veth peer index внутри контейнера)
                return iface.split("@")[0]
    return None


def get_ext_ipaddr() -> str:
    """
    Получение внешнего IP адреса сервера.

    Приоритет: IPv4 → IPv6.
    Сначала пробуем получить IPv4, только если не получилось — IPv6.

    Returns:
        str: Внешний IPv4 или IPv6 адрес сервера

    Raises:
        RuntimeError: Если ни один сервис не ответил
    """
    # Все сервисы (проверяем в два прогона: сначала IPv4, потом IPv6)
    services = [
        "https://icanhazip.com",
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
        "https://wtfismyip.com/text",
        "https://api64.ipify.org",
    ]

    def _fetch_ip_version(version: int) -> tuple[str | None, str | None]:
        """Один прогон по сервисам: возвращает (IP нужной версии, последняя ошибка)."""
        last_error = None
        for service_url in services:
            try:
                # Короткие таймауты: блокировка до ~полутора минут при недоступной
                # сети неприемлема (аудит-20); 3 сек на сервис, до 3 попыток.
                r = requests.get(service_url, timeout=3)
                r.raise_for_status()
                ip = r.text.strip()
                addr = ipaddress.ip_address(ip)
                if addr.version == version:
                    return ip, last_error
            except requests.exceptions.RequestException as e:
                last_error = f"{service_url}: {e}"
            except ValueError:
                last_error = f"{service_url}: неверный формат IP"
        return None, last_error

    # Первый прогон: ищем IPv4
    ip, last_error = _fetch_ip_version(4)
    if ip:
        return ip

    # Второй прогон: ищем IPv6 (если первый неудался)
    ip, last_error = _fetch_ip_version(6)
    if ip:
        return ip

    # Ни один сервис не сработал
    raise RuntimeError(f"Не удалось получить внешний IP. Последняя ошибка: {last_error}")


# ----------------- WGConfig (Original Logic) -----------------

class WGConfig:
    def __init__(self, filename: str | None = None):
        self.lines: list[str] = []
        self.iface: dict[str, str] = {}
        self.peer: dict[str, dict[str, str]] = {}
        self.idsline: dict[str, int] = {}
        self.cfg_fn: pathlib.Path | None = None
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
                    max_line = max(max_line, lineinfo[v])
            item['_lines_range'] = (min_line, max_line)
        return len(self.peer)

    def save(self, filename: str | None = None) -> None:
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
        # Сдвигаем _lines_range остальных пиров (иначе повторные операции в том же
        # объекте удаляют/вставляют по устаревшим номерам строк — баг 1.13)
        for other in self.peer.values():
            rmin, rmax = other['_lines_range']
            if rmin >= min_line:
                other['_lines_range'] = (rmin - secsize, rmax - secsize)
            elif rmax >= min_line:
                other['_lines_range'] = (rmin, rmax - secsize)
        return ipaddr

    def set_param(self, c_name: str, param_name: str, param_value: str, force: bool = False, offset: int = 0) -> None:
        if c_name not in self.peer:
            raise RuntimeError(f'Клиент не найден: {c_name}')
        line_prefix = "" if not param_name.startswith('_') else "#_"
        param_key = param_name.removeprefix('_')
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
        # Сдвигаем _lines_range остальных пиров (баг 1.13)
        for other_name, other in self.peer.items():
            if other_name == c_name:
                continue
            rmin, rmax = other['_lines_range']
            if rmin >= pos:
                other['_lines_range'] = (rmin + 1, rmax + 1)
            elif rmax >= pos:
                other['_lines_range'] = (rmin, rmax + 1)


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


def _normalize_endpoint(ep: str) -> str:
    """Приводит endpoint к формату wg-quick: 'host:port' / '[v6]:port'.

    Для IPv6-литералов брекеты обязательны (wg/awg-quick не парсят голый [v6]:port),
    а getaddrinfo, наоборот, их не принимает — нормализуем в одном месте (баг 1.17).
    """
    ep = ep.strip()
    if not ep:
        return ep
    if ep.startswith("[") and ep.endswith("]"):
        return ep
    # Многодвоеточие: vs «v6[:порт]» и «голый v6» неразличимы по count(':')
    # (фикс аудита-C1). Порядок интерпретаций:
    #  1) хвост-число = порт -> «[v6]:port» (host валиден);
    #  2) иначе голый IPv6-адрес -> «[v6]» (rsplit(':',1) съел бы «::»).
    if ep.count(":") >= 2:
        _tail = ep.rsplit(":", 1)[-1]
        if _tail.isdigit():
            try:
                _h, _p = ep.rsplit(":", 1)
                ipaddress.ip_address(_h)
                return f"[{_h}]:{_p}"
            except ValueError:
                pass
        try:
            ipaddress.ip_address(ep)
            return f"[{ep}]"
        except ValueError:
            pass
    try:
        host, port = ep.rsplit(":", 1)
    except ValueError:
        return ep
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        # Порт вне диапазона/не число — не выдаём мусор в конфиг (аудит-C1)
        logger.warning("⚠  Endpoint %r: невалидный порт %r — как есть", ep, port)
        return ep
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return f"[{host.strip('[]')}]:{port}"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    if isinstance(ip, ipaddress.IPv6Address):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


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
    # Снимаем брекеты IPv6-литерала '[2606:...]' — getaddrinfo их не понимает (баг 1.17)
    host = host.strip("[]").strip()
    if not host:
        return False
    # Попытка TCP
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, _, sa = res
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
            af, socktype, proto, _, sa = res
            s = socket.socket(af, socktype, proto)
            s.settimeout(timeout)
            try:
                s.connect(sa)
                s.send(b"\x00")
                # UDP-«успех» сам по себе ничего не доказывает (аудит-20):
                # ждём короткий промежуток — ICMP port-unreachable (ECONNREFUSED)
                # означает «мёртвый» endpoint. Таймаут = «живой» (нет опровержения).
                try:
                    s.recv(1)
                except TimeoutError:
                    pass
                except ConnectionRefusedError:
                    s.close()
                    continue
                except OSError:
                    pass
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


def _select_endpoint_from_api_result(result: dict) -> object | None:
    """
    Попытаться извлечь endpoint из различных возможных структур ответа API.
    Возвращает список endpoint'ов для проверки (строка или список строк).
    """
    try:
        cfg = result.get("config") or {}
        peers = cfg.get("peers") or []
        if peers and isinstance(peers, list):
            ep = peers[0].get("endpoint")
            if ep:
                # Если endpoint словарь (новый формат API)
                if isinstance(ep, dict):
                    endpoints = []
                    # host уже содержит порт
                    host = ep.get("host", "")
                    if host:
                        endpoints.append(host)
                    # v4 может иметь порт 0 — проверяем ports
                    v4 = ep.get("v4", "")
                    ports = ep.get("ports", [])
                    if v4 and ports and isinstance(ports, list):
                        # Создаём endpoint'ы для каждого порта (v4 может быть
                        # IPv6-литералом — не режем по первому ':'; баг 1.15)
                        v4_host = v4.strip().strip('[]') if v4.count(':') > 1 else v4.split(':', 1)[0].strip()
                        for port in ports:
                            endpoints.append(_normalize_endpoint(f"{v4_host}:{port}"))
                    return endpoints if endpoints else None
                return str(ep)
    except Exception:
        pass
    try:
        ep = result.get("endpoint")
        if ep:
            return str(ep)
    except Exception:
        pass
    try:
        endpoints = result.get("endpoints") or result.get("servers")
        if isinstance(endpoints, list) and endpoints:
            first = endpoints[0]
            if isinstance(first, str):
                return first
            if isinstance(first, dict):
                ep = first.get("endpoint")
                if ep:
                    return str(ep)
    except Exception:
        pass
    return None


def generate_warp_config(tun_name: str, index: int, mtu: int, proxy: str = "", version: str = "AWG2.0", for_server: bool = True) -> tuple[str, str]:
    """
    Генерация одного WARP-конфига (универсальная функция).

    for_server=True  → Серверный WARP (с Table = off, для up/down скриптов)
    for_server=False → Клиентский WARP (без Table = off, для личного использования)
    """
    api = "https://api.cloudflareclient.com/v0i1909051800"
    headers = {"user-agent": "amneziawg-script/1.0", "content-type": "application/json"}

    # Настройка proxy если указан
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        priv_key, pub_key = gen_pair_keys()
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
    except requests.exceptions.HTTPError:
        # Пробрасываем наверх: generate_warp_configs обрабатывает 429 (rate-limit)
        raise
    except Exception as e:
        raise RuntimeError(f"Ошибка WARP API: {e}") from None

    # Валидация ответа API: не создаём заведомо нерабочий конфиг
    if not peer_pub:
        raise RuntimeError("В конфиге Cloudflare отсутствует public_key пира")
    if not client_ipv4 and not client_ipv6:
        raise RuntimeError("В конфиге Cloudflare отсутствуют адреса интерфейса (v4/v6)")

    candidates = []
    api_endpoints = _select_endpoint_from_api_result(result_obj)
    if api_endpoints:
        # Если вернулся список — добавляем все endpoint'ы
        if isinstance(api_endpoints, list):
            candidates.extend(api_endpoints)
        else:
            candidates.append(api_endpoints)
    candidates.extend(CANDIDATE_WARP_ENDPOINTS)

    chosen = None
    total_endpoints = len(candidates)
    for idx, ep in enumerate(candidates, 1):
        try:
            logger.info("🔍 Проверка endpoint %d/%d: %s ...", idx, total_endpoints, ep)
            ok, how = check_warp_endpoint(ep, server_pubkey=peer_pub,
                                          client_private_key=priv_key, timeout=0.9)
            if ok:
                chosen = ep
                if how in ("handshake", "cookie"):
                    logger.info("✅ Endpoint найден: %s (реальное WG-рукопожатие: %s)", chosen, how)
                else:
                    logger.info("✅ Endpoint найден: %s", chosen)
                break
            else:
                logger.info("❌ Endpoint не доступен: %s", ep)
        except Exception as e:
            logger.info("❌ Endpoint ошибка: %s (%s)", ep, e)
            continue

    if not chosen:
        raise RuntimeError("Не найден доступный endpoint для WARP (проверено %d endpoint'ов)" % total_endpoints)

    # Генерируем все параметры обфускации через общую функцию
    # WARP это клиентский конфиг, поэтому for_client=True
    # for_warp=True — чтобы соответствовать таблице (S1,S2, H1-H4, S3,S4 = нет для WARP)
    warp_obf_params = generate_all_params(version, for_client=True, for_server=False, for_warp=True)

    persistent_keepalive = _generate_persistent_keepalive(version)
    out = g_warp_config
    out = out.replace("<WARP_PRIVATE_KEY>", priv_key)
    
    # Jc, Jmin, Jmax (для WG — отсутствуют, плейсхолдеры очищаются)
    out = _fill_j_lines(out, warp_obf_params)

    out = out.replace("<MTU>", str(mtu))
    out = out.replace("<WARP_ADDRESS>", ", ".join([x for x in (client_ipv4, client_ipv6) if x]))
    out = out.replace("<WARP_PEER_PUBLIC_KEY>", peer_pub)
    out = out.replace("<PERSISTENT_KEEPALIVE>", str(persistent_keepalive))
    out = out.replace("<WARP_ENDPOINT>", _normalize_endpoint(chosen))

    # I1-I5
    out = _fill_i_lines(out, warp_obf_params)

    # 5 таймингов (3.0/3.1): локальные таймеры WARP-клиента — безопасны для
    # стороннего эндпоинта (проверено против ванильного WireGuard, 16.09.2026)
    out = _fill_awg3_lines(out, warp_obf_params)

    # Table = off только для серверного WARP (любой версии)
    out = out.replace("<TABLE_LINE>", "Table = off\n" if for_server else "")

    filename = f"{tun_name}warp{index}.conf"
    return out, filename


def _generate_warps(num_warps: int, make_one, parent_dir: pathlib.Path) -> list[str]:
    """Единый цикл генерации N WARP-конфигов (объединяет дубли серверного и
    автономного путей): на конфиг до 3 попыток; HTTP 429 → backoff 2/4/6 c
    (уважение rate-limit Cloudflare); прочие ошибки → пауза 1/2/3 c; при
    провале N-го конфига частичные результаты удаляются, ошибка типизируется.
    make_one(i) → имя файла (сам записывает конфиг в parent_dir).
    """
    created: list[str] = []
    last_error = None
    for i in range(num_warps):
        success = False
        for attempt in range(3):  # 3 попытки достаточно
            try:
                created.append(make_one(i))
                success = True
                break
            except requests.exceptions.HTTPError as he:
                status = getattr(he.response, "status_code", None)
                if status == 429:
                    backoff = 2 + attempt * 2  # 2, 4, 6 сек
                    logger.warning("⚠  Cloudflare API rate-limited; ожидаю %d сек", backoff)
                    time.sleep(backoff)
                    if attempt == 2:  # фикс аудита: причина 429 не должна теряться
                        last_error = f"Cloudflare API rate-limited (429) после {attempt + 1} попыток"
                    continue
                logger.warning("⚠  HTTP ошибка при генерации WARP: %s", he)
                last_error = str(he)
                break
            except Exception as e:
                logger.warning("⚠  Попытка генерации WARP %d не удалась: %s", attempt + 1, e)
                last_error = str(e)
                time.sleep(1 + attempt)
                continue
        if not success:
            for created_name in created:
                try:
                    p = parent_dir.joinpath(created_name)
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
            if last_error:
                raise RuntimeError(f"Ошибка WARP API: {last_error}")
            raise RuntimeError("WARP конфиги не сгенерированы")
    return created


def generate_warp_configs(tun_name: str, num_warps: int, mtu: int, proxy: str = "", version: str = "AWG2.0", for_server: bool = True) -> list[str]:
    """
    Генерация N WARP-конфигов с попытками и откатом при неудаче.
    
    for_server=True  → Серверный WARP (с Table = off)
    for_server=False → Клиентский WARP (без Table = off)
    """
    parent = pathlib.Path(g_main_config_fn).parent

    def _make_one(i: int) -> str:
        conf_text, fname = generate_warp_config(tun_name, i, mtu, proxy, version, for_server)
        atomic_write_text(parent.joinpath(fname), conf_text)
        return fname

    warp_configs = _generate_warps(num_warps, _make_one, parent)
    logger.info("✅ Сгенерировано WARP конфигов: %d", len(warp_configs))
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
                        logger.warning("⚠  Некорректный CIDR от %s (%s): %s", site, proto, item)
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


def parse_endpoints_config(text: str, default_port: str) -> list[dict[str, str]]:
    out = []
    if not text:
        return out
    tokens: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '#' in line:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
        # Разбиваем по пробелам (несколько эндпоинтов на строке)
        for sub in line.split():
            sub = sub.strip()
            if not sub:
                continue
            # Разбиваем по запятым, потом склеиваем параметры (domain=, mtu=) обратно
            parts = [p.strip() for p in sub.split(",") if p.strip()]
            merged = []
            for part in parts:
                # Параметр = key=value без порта (domain=yandex.ru, mtu=1340, ;mtu=1340)
                if "=" in part and ":" not in part:
                    key_part = part.split("=", 1)[0].strip().lstrip(";")
                    if key_part.isalpha():
                        if merged:
                            merged[-1] += "," + part
                            continue
                merged.append(part)
            tokens.extend(merged)

    for p in tokens:
        raw = p
        label = ""
        mtu_val = ""
        domain_val = ""
        proto_val = ""

        # Парсинг ;key=value,key=value (разделители параметров: ',' или ';')
        if ";" in p:
            p, param_str = p.split(";", 1)
            params = {}
            for pair in re.split(r"[;,]", param_str):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.strip()] = v.strip()
            m = params.get("mtu", "")
            if m and m.isdigit():
                mi = int(m)
                if 1280 <= mi <= 1440:
                    mtu_val = m
            d = params.get("domain", "")
            if d:
                domain_val = d
            pr = params.get("proto", "")
            if pr in ("dtls", "quic", "stun"):
                proto_val = pr

        # Значения параметров фиксируются на момент вызова (без позднего
        # замыкания на переменные цикла — B023): default-аргументы захватывают
        # значения СЕЙЧАС, поведение идентично старому.
        def _append(host, port, label, _mtu=mtu_val, _domain=domain_val, _proto=proto_val):
            out.append({"host": host, "port": str(port), "label": label,
                        "mtu": _mtu, "domain": _domain, "proto": _proto})

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
                _append(host, port, label)
                continue
            except ValueError:
                hostport = p

        hostpart = hostport
        lbl = ""
        # Точный разбор метки от портовой части: "PORT-LABEL". Метка может
        # содержать дефисы (напр. "13789-DE-FRA3") — порт всегда строгое
        # число, поэтому отделяем его первым, а остаток (если есть)
        # трактуем как метку целиком.
        if ':' in hostpart:
            _hh, _rr = hostpart.rsplit(':', 1)
            _ml = re.match(r'^([0-9]+)(?:-(.*))?$', _rr)
            if _ml and _ml.group(2) is not None:
                lbl = _sanitize_label(_ml.group(2).strip())
                hostpart = f"{_hh}:{_ml.group(1)}"
        if not lbl and '-' in hostpart:
            # Legacy/без-порта: "HOST-METKA" (порт — default). Не применяется,
            # если "метка" содержит ':' (домен с дефисом) — regex ниже не
            # пропустит такой хвост.
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
                    lbl = ""
            else:
                lbl = ""

        if hostpart.count(':') >= 2:
            # Много двоеточий: должен быть IPv6-адрес (с/без порта).
            # Мусор вида "host:port:extra" или "Host:" отбрасываем с warning.
            probe6 = hostpart.strip()
            if ']' in probe6:
                probe6 = probe6.strip('[]')
            try:
                import ipaddress as _ipa
                _ipa.ip_address(probe6)
                _append(hostpart.strip(), default_port, lbl)
            except Exception:
                logger.warning("⚠️  Пропущен некорректный endpoint %r (не IPv6, лишние ':'): %s",
                               p, hostpart.strip())
                continue
            continue

        if ':' in hostpart:
            h, prt = hostpart.rsplit(":", 1)
            if prt.isdigit():
                prt_val = prt.strip()
                try:
                    prt_int = int(prt_val)
                    if 1 <= prt_int <= 65535:
                        _append(h.strip(), prt_int, lbl)
                    else:
                        logger.warning("⚠️  Порт %s вне диапазона 1..65535 (endpoint %r) — пропущен",
                                       prt_val, p)
                        continue
                except Exception:
                    logger.warning("⚠️  Некорректный порт в endpoint %r — пропущен", p)
                    continue
                continue
            else:
                logger.warning("⚠️  Некорректный endpoint %r (порт не число) — пропущен", p)
                continue
        else:
            _append(hostpart.strip(), default_port, lbl)
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

def parse_allowedips_config(text: str, server_addr: str = "") -> tuple[dict[str, str], set[str]]:
    """
    Парсит _allowedips.config. 
    Возвращает кортеж: (словарь {Имя: IPs}, множество имен для QR {Имя1, Имя2})
    """
    out_ips: dict[str, str] = {}
    out_qr: set[str] = set()
    
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
        # Безопасность имён (аудит: имя секции попадает в имя ФАЙЛА конфига
        # клиента; без whitelist ../ или '/' писали бы ключи вне conf/).
        if not re.fullmatch(r'[A-Za-z0-9_.\-]+', name) or name in ('.', '..'):
            logger.warning("⚠️  Пропущено имя с недопустимыми символами: %r", name)
            continue
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
        f"DsYt = <SERVER_ADDR>, {dsyt_ips};"
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


def calculate_client_masks(ipv4_net: ipaddress.IPv4Network, ipv6_net: ipaddress.IPv6Network | None) -> tuple[int, int, float]:
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
        ipv6_per_ipv4 = int(ratio)
        # Используем bit_length() вместо log2() для правильных масок!
        ipv6_bits = (ipv6_per_ipv4 - 1).bit_length() if ipv6_per_ipv4 > 0 else 0
        ipv6_client_mask = 128 - ipv6_bits
    else:
        # N IPv4 : 1 IPv6 (IPv4 подсеть шире)
        ipv6_client_mask = 128  # 1 адрес
        ipv4_per_ipv6 = int(1 / ratio)
        # Используем bit_length() вместо log2() для правильных масок!
        ipv4_bits = (ipv4_per_ipv6 - 1).bit_length() if ipv4_per_ipv6 > 0 else 0
        ipv4_client_mask = 32 - ipv4_bits

    return ipv4_client_mask, ipv6_client_mask, ratio


def validate_ipv4_ipv6_pair(ipv4_net: ipaddress.IPv4Network | None, ipv6_net: ipaddress.IPv6Network | None, ipv4_server_ip: str = "", ipv6_server_ip: str = "") -> bool:
    """
    Проверяет что IPv4 и IPv6 подсети совместимы.
    
    Проверки:
    1. Позиция сервера: оба на network или оба не на network
    2. Соотношение подсетей: не экстремальное (от 1:65536 до 65536:1)
    
    Возвращает True если валидация пройдена, иначе бросает RuntimeError.
    """
    if not ipv6_net or ipv4_net is None:
        return True  # IPv6 или IPv4 опционален (поддерживается IPv6-only)

    # Вычисляем маски клиентов и коэффициент кратности
    _, _, ratio = calculate_client_masks(ipv4_net, ipv6_net)
    
    # --- Проверка 1: Позиция сервера ---
    # Сервер должен занимать одинаковую позицию в обеих подсетях
    # (либо network address в обеих, либо не network address в обеих)
    
    # Сравниваем как IP адреса (не строки!) чтобы избежать проблем нормализации IPv6
    if ipv4_server_ip:
        try:
            ipv4_server_addr = ipaddress.ip_address(ipv4_server_ip)
            ipv4_is_network = (ipv4_server_addr == ipv4_net.network_address)
        except Exception:
            ipv4_is_network = True
    else:
        ipv4_is_network = True
        
    if ipv6_server_ip:
        try:
            ipv6_server_addr = ipaddress.ip_address(ipv6_server_ip)
            ipv6_is_network = (ipv6_server_addr == ipv6_net.network_address)
        except Exception:
            ipv6_is_network = True
    else:
        ipv6_is_network = True

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


def parse_ipaddr_argument(ipaddr_str: str) -> tuple[ipaddress.IPv4Network | None, ipaddress.IPv6Network | None, str]:
    """
    Парсит аргумент --ipaddr с поддержкой IPv4, IPv6 или IPv4+IPv6 через запятую.

    Формат: "10.1.0.1/24", "fd00::1/120" или "10.1.0.1/24, fd00::1/120"

    Возвращает кортеж: (ipv4_net, ipv6_net, display_string)
    где display_string — нормализованная строка для подстановки в конфиг.
    Хотя бы одна подсеть обязательна; IPv4 и IPv6 опциональны по отдельности.
    """
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
            raise RuntimeError(f'Некорректный IP адрес "{subnet_str}": {e}') from None

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

    # Хотя бы одна подсеть обязательна (IPv4 и IPv6 опциональны по отдельности)
    if ipaddr_ipv4 is None and ipaddr_ipv6 is None:
        raise RuntimeError('Укажите хотя бы одну подсеть (IPv4 или IPv6), например 10.1.0.1/24 или fd00::1/120')

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
        except Exception:
            pass

    # Валидация одинакового размера и позиции сервера
    validate_ipv4_ipv6_pair(ipaddr_ipv4, ipaddr_ipv6, ipv4_server_ip, ipv6_server_ip)

    # Формируем строку для up.sh (нормализованный формат с пробелом)
    if ipaddr_ipv4 and ipaddr_ipv6:
        ipaddr_display = f"{ipv4_server_ip}/{ipaddr_ipv4.prefixlen}, {ipv6_server_ip}/{ipaddr_ipv6.prefixlen}"
    elif ipaddr_ipv6:
        ipaddr_display = f"{ipv6_server_ip}/{ipaddr_ipv6.prefixlen}"
    else:
        ipaddr_display = f"{ipv4_server_ip}/{ipaddr_ipv4.prefixlen}"

    return ipaddr_ipv4, ipaddr_ipv6, ipaddr_display


# ----------------- Вспомогательные функции для handle_makecfg -----------------

def _process_interface_path(raw_input: str) -> tuple[pathlib.Path, str]:
    """Обработка пути к интерфейсу. Возвращает (target_path, tun_name)."""
    # Безопасность: имя туннеля попадает в shell-команды (PostUp, TUN="..."),
    # поэтому разрешаем только безопасный набор символов (аудит раунда-20).
    _SAFE_NAME = re.compile(r'[A-Za-z0-9_.\-]+')
    raw_input = raw_input.strip()
    if not raw_input:
        raise RuntimeError('Пустое имя интерфейса')

    if '/' not in raw_input and os.sep not in raw_input:
        # Простое имя файла в /etc/amnezia/amneziawg/
        name = raw_input
        if not _SAFE_NAME.fullmatch(name):
            raise RuntimeError(f'Недопустимое имя интерфейса "{raw_input}": '
                               f'разрешены только буквы, цифры, точка, дефис и подчёркивание')
        if not name.endswith('.conf'):
            name += '.conf'
        target_path = pathlib.Path('/etc/amnezia/amneziawg').joinpath(name)
    else:
        # Путь: разделяем строково (переносимо между ОС для тестов).
        if '/' in raw_input:
            path_part, base_part = raw_input.rsplit('/', 1)
        else:
            path_part, base_part = raw_input.rsplit(os.sep, 1)
        if not base_part:
            raise RuntimeError(f'Недопустимый путь к конфигу "{raw_input}"')
        if not _SAFE_NAME.fullmatch(base_part):
            raise RuntimeError(f'Недопустимое имя файла конфига "{base_part}": '
                               f'разрешены только буквы, цифры, точка, дефис и подчёркивание')
        # Проверка компонентов каталога (запрет '..' и спецсимволов)
        for comp in path_part.split('/') if '/' in path_part else path_part.split(os.sep):
            # '' — пустые компоненты (ведущий/хвостовой '/') — пропускаем
            if comp == '..' or (comp and comp != '.' and not _SAFE_NAME.fullmatch(comp)):
                raise RuntimeError(f'Недопустимый путь к конфигу "{raw_input}": '
                                   f'подозрительный компонент "{comp}"')
        target_path = pathlib.Path(raw_input)

    tun_name = target_path.stem
    return target_path, tun_name



def _generate_warp_if_needed(tun_name: str, warp_count: int, mtu: int, proxy: str, 
                              awg_version: str) -> list[str]:
    """Генерация WARP конфигов если нужно. Возвращает список конфигов."""
    warp_configs: list[str] = []
    if warp_count > 0:
        logger.info("🌀 Генерация %d WARP конфигов...", warp_count)
        try:
            warp_configs = generate_warp_configs(tun_name, warp_count, mtu, proxy, awg_version, for_server=True)
        except RuntimeError as e:
            error_msg = str(e)

            # Проверяем тип ошибки по тексту
            if "Не найден доступный endpoint" in error_msg:
                logger.error("❌ Не удалось сгенерировать WARP: проблема с доступом к Cloudflare Endpoint")
                logger.info("💡 Похоже WARP у вас не будет работать и лучше не используйте его, генерируйте интерфейс без флага --warp")
            elif "timed out" in error_msg or "timeout" in error_msg.lower():
                logger.error("❌ Не удалось сгенерировать WARP: таймаут подключения к Cloudflare API")
                if not proxy:
                    logger.info("💡 Попробуйте использовать прокси для обхода блокировок через флаг --proxy \"адрес прокси\"")
                else:
                    logger.info("💡 Попробуйте использовать другой прокси или запустите без --warp")
            elif "SSLError" in error_msg or "wrong version" in error_msg:
                logger.error("❌ Не удалось сгенерировать WARP: SSL ошибка (прокси не поддерживает HTTPS)")
                logger.info("💡 Используйте HTTP прокси или попробуйте другой прокси")
            elif "WARP API" in error_msg:
                logger.error("❌ Не удалось сгенерировать WARP: проблема с Cloudflare API")
                if not proxy:
                    logger.info("💡 Попробуйте использовать прокси через флаг --proxy \"адрес прокси\"")
                else:
                    logger.info("💡 Попробуйте другой прокси или запустите без --warp")
            else:
                logger.error("❌ Не удалось сгенерировать WARP: что-то пошло не так")
                logger.error("📝 Детали: %s", error_msg)
                logger.info("💡 Попробуйте использовать прокси через флаг --proxy \"адрес прокси\", если не выйдет то без --warp")

            raise RuntimeError("Генерация WARP не удалась — интерфейс не создан") from None

        for c in warp_configs:
            logger.info("📄 WARP конфиг: %s", c)
        logger.info("✅ WARP конфиги сгенерированы")
    
    return warp_configs


def _fill_i_lines(out: str, params: dict, comment: bool = False) -> str:
    """Заполняет плейсхолдеры <I1_LINE>..<I5_LINE> значениями из params.

    Если I1 отсутствует (или пуст) — все плейсхолдеры очищаются. При comment=True
    значения записываются закомментированными (для версий без поддержки I1-I5).
    """
    if params.get("I1"):
        for i in range(1, 6):
            key = f"I{i}"
            if params.get(key):
                line = f"{key} = {params[key]}\n"
                out = out.replace(f"<{key}_LINE>", f"# {line}" if comment else line)
            else:
                out = out.replace(f"<{key}_LINE>", "")
    else:
        for i in range(1, 6):
            out = out.replace(f"<I{i}_LINE>", "")
    return out


def _fill_param_lines(out: str, params: dict, keys: tuple, comment_key: str | None = None) -> str:
    """Заполняет плейсхолдеры <KEY_LINE> для набора ключей.

    Единая реализация для трёх прежних функций (_fill_param_lines /
    _fill_j_lines / _fill_or_clear_lines). Чистая семантика (намеренное
    улучшение vs старый код): ключ отсутствует или значение falsy (None/0/'')
    → плейсхолдер очищается — «KEY = None» больше никогда не попадает
    в конфиг; иначе — «KEY = value» (при наличии comment_key — с поясняющим
    # комментарием, для версий без поддержки параметра).
    """
    comment = params.get(comment_key) if comment_key is not None else None
    for key in keys:
        if not params.get(key):
            out = out.replace(f"<{key.upper()}_LINE>", "")
            continue
        if comment:
            out = out.replace(f"<{key.upper()}_LINE>", f"# {key} = {params[key]}  # {comment}\n")
        else:
            out = out.replace(f"<{key.upper()}_LINE>", f"{key} = {params[key]}\n")
    return out


def _fill_or_clear_lines(out: str, pairs: dict) -> str:
    """Заполняет или очищает плейсхолдеры — обёртка над _fill_param_lines."""
    return _fill_param_lines(out, pairs, tuple(pairs.keys()))


def _fill_j_lines(out: str, params: dict) -> str:
    """Заполняет <JC_LINE>/<JMIN_LINE>/<JMAX_LINE>.

    J-параметры самосогласованы: если Jc отсутствует/пуст — очищаются все три
    (историческая семантика), иначе — через общую _fill_param_lines."""
    if params.get("Jc") is None:
        for key in ("Jc", "Jmin", "Jmax"):
            out = out.replace(f"<{key.upper()}_LINE>", "")
        return out
    return _fill_param_lines(out, params, ("Jc", "Jmin", "Jmax"))


def _fill_awg3_lines(out: str, params: dict, server_params: dict | None = None) -> str:
    """Заполняет параметры AWG3.0/3.1 (<..._LINE> для новых ключей).

    server_params: если задан (клиентский конфиг) — HeaderProtectionKey берётся
    из серверного конфига: параметр server-side, обязан совпадать у всех сторон.
    Если server_params is None (серверный конфиг) — ключ берётся из params.

    ВАЖНО: comment-ключи берутся из ИСХОДНОГО params (иначе параметр, не
    поддерживаемый версией, выводился бы активной строкой — фикс).
    """
    merged = dict(params)
    if server_params is not None:
        _srv_hp = server_params.get("HeaderProtectionKey")
        if _srv_hp:
            merged["HeaderProtectionKey"] = _srv_hp
            # Значение пришло от сервера — выводим активной строкой, без
            # «не поддерживается» комментария.
            merged.pop("_HP_comment", None)
    out = _fill_param_lines(out, merged, ("HeaderProtectionKey",), "_HP_comment")
    out = _fill_param_lines(out, params, ("ContentPaddingAddition",), "_PADDING_comment")
    out = _fill_param_lines(out, params,
                            ("RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
                             "KeepaliveTimeout", "MaxHandshakeAttempts"),
                            "_TIMINGS_comment")
    out = _fill_param_lines(out, params, ("RandomTrailers",), "_TRAILERS_comment")
    out = _fill_param_lines(out, params, ("DisableCookies",), "_COOKIES_comment")
    return out


def _fill_obfuscation_params(out: str, obf_params: dict) -> str:
    """Заполнение параметров обфускации в шаблоне."""
    out = _fill_param_lines(out, obf_params, ("Jc", "Jmin", "Jmax"), "_J_comment")
    out = _fill_param_lines(out, obf_params, ("S1", "S2"), "_S12_comment")
    out = _fill_param_lines(out, obf_params, ("S3", "S4"), "_S34_comment")
    out = _fill_param_lines(out, obf_params, ("H1", "H2", "H3", "H4"), "_H_comment")
    out = _fill_i_lines(out, obf_params, comment=bool(obf_params.get("_I_comment")))
    out = _fill_awg3_lines(out, obf_params)
    return out


def _create_scripts(up_path: pathlib.Path, down_path: pathlib.Path, params_path: pathlib.Path,
                    main_iface: str, tun_name: str, opt, server_addr: str,
                    warp_configs: list[str]) -> None:
    """Создание up.sh, down.sh и файла параметров."""

    if warp_configs:
        warp_list_str = "\n".join([f'  \"{pathlib.Path(cfg).stem}\"' for cfg in warp_configs])
    else:
        warp_list_str = '  "none=0.0.0.0/0,::/0"'

    # Создаём файл параметров (.sh)
    params_script = params_script_template
    params_script = params_script.replace("<SERVER_PORT>", str(opt.port))
    params_script = params_script.replace("<SERVER_IFACE>", main_iface)
    params_script = params_script.replace("<SERVER_TUN>", tun_name)
    params_script = params_script.replace("<SERVER_ADDR>", server_addr)
    params_script = params_script.replace("<RATE_LIMIT>", f"{opt.limit}")
    params_script = params_script.replace("<WARP_LIST>", warp_list_str)

    # up.sh и down.sh больше не используют плейсхолдеры — всё читается из файлов
    up_script = up_script_template_warp
    down_script = down_script_template_warp

    # Резервное копирование существующих файлов
    _backup_file(up_path, '.sh.bak')
    _backup_file(down_path, '.sh.bak')
    _backup_file(params_path, '.sh.bak')

    atomic_write_text(params_path, params_script)
    atomic_write_text(up_path, up_script)
    atomic_write_text(down_path, down_script)
    os.chmod(str(params_path), 0o755)
    os.chmod(str(up_path), 0o755)
    os.chmod(str(down_path), 0o755)


# ----------------- Вспомогательные функции для handle_add/handle_confgen -----------------

def _get_server_ip_info(srvcfg: str, net_ipv4, net_ipv6):
    """Определение IP сервера и позиции в подсети.

    net_ipv4 может быть None (IPv6-only). В этом случае server_ip_int_ipv4=None,
    server_on_network_ipv4=False.
    """
    server_addr = srvcfg.split('[Peer]')[0]

    # IPv4 (опционален — при IPv6-only пропускается)
    server_ip_int_ipv4 = None
    server_on_network_ipv4 = False

    # IPv6
    server_on_network_ipv6 = False
    ipv6_server_ip_int = 0

    # Сканируем части Address по ВЕРСИИ адреса (не по позиции): порядок
    # "10.1.0.1/24, fd00::1/104" и "fd00::1/104, 10.1.0.1/24" обрабатываются
    # одинаково (раньше при ручной перестановке падало: IPv6Address('10.1.0.1'))
    for line in server_addr.split('\n'):
        if not line.strip().startswith('Address = '):
            continue
        for part in line.split('=')[1].split(','):
            part = part.strip()
            if not part:
                continue
            ip_part = part.split('/')[0].strip()
            try:
                ip = ipaddress.ip_address(ip_part)
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address):
                if server_ip_int_ipv4 is None:
                    server_ip_int_ipv4 = int(ip)
            else:
                if ipv6_server_ip_int == 0:
                    ipv6_server_ip_int = int(ip)
        break

    if net_ipv4 is not None:
        if server_ip_int_ipv4 is None:
            server_ip_int_ipv4 = int(net_ipv4.network_address)
        server_on_network_ipv4 = (server_ip_int_ipv4 == int(net_ipv4.network_address))

    if net_ipv6:
        if ipv6_server_ip_int == 0:
            ipv6_server_ip_int = int(net_ipv6.network_address)
        server_on_network_ipv6 = (ipv6_server_ip_int == int(net_ipv6.network_address))

    return server_ip_int_ipv4, server_on_network_ipv4, ipv6_server_ip_int, server_on_network_ipv6


def _check_client_manual_range(manual_ip_str: str, manual_ip, server_int: int,
                               used_ips: set, on_network: bool,
                               broadcast_int: int) -> None:
    """Общая диапазонная валидация ручного адреса клиента (v4 и v6).

    Ни один адрес запрошенного диапазона не должен пересекаться с адресом
    сервера, зарезервированным broadcast/multicast (если он работает) или
    уже выданными адресами. Одна реализация вместо дублей для IPv4/IPv6.
    """
    lo = int(manual_ip.network_address)
    hi = int(manual_ip.broadcast_address)
    if lo <= server_int <= hi:
        raise RuntimeError(f'Диапазон {manual_ip_str} содержит адрес сервера — выберите другой')
    if not on_network and lo <= broadcast_int <= hi:
        _kind = 'broadcast' if manual_ip.version == 4 else 'multicast'
        raise RuntimeError(f'Диапазон {manual_ip_str} содержит зарезервированный {_kind}-адрес')
    _fam = ipaddress.IPv4Address if manual_ip.version == 4 else ipaddress.IPv6Address
    for _u in used_ips:
        if isinstance(_u, tuple):
            # Ранее выданный ДИАПАЗОН (ручная маска; фикс аудита: used-сет
            # хранил только network_address, и ручной /16 не защищался)
            _ulo, _uhi = _u
            if lo <= _uhi and _ulo <= hi:
                raise RuntimeError(f'Диапазон {manual_ip_str} пересекается с ранее выданным '
                                   f'диапазоном {_fam(_ulo)}–{_fam(_uhi)}')
        else:
            if lo <= _u <= hi:
                raise RuntimeError(f'IPv{manual_ip.version} адрес {manual_ip_str} уже используется '
                                   f'(пересекается с {_fam(_u)})')


def _allocate_client_ip(opt, net_ipv4, net_ipv6, server_on_network_ipv4, server_on_network_ipv6,
                        server_ip_int_ipv4, ipv6_server_ip_int, broadcast_int_ipv4,
                        used_ips_ipv4: set, used_ips_ipv6: set) -> tuple[str | None, str | None]:
    """
    Выделение IP адреса для клиента.
    
    Возвращает: (ipaddr_ipv4, ipaddr_ipv6)
    """
    ipaddr_ipv4 = None
    ipaddr_ipv6 = None

    def _blocked(ip_int: int, used: set) -> bool:
        """Занят ли адрес: точкой или диапазоном (кортежем; фикс аудита)."""
        for _u in used:
            if isinstance(_u, tuple):
                if _u[0] <= ip_int <= _u[1]:
                    return True
            elif _u == ip_int:
                return True
        return False

    def _blocked_range(start: int, end: int, used: set) -> bool:
        """Занят ли ВЕСЬ диапазон блока: любой адрес внутри = блок занят
        (фикс: раньше проверялся только старт блока; занятая точка внутри
        группы — например, ручной клиент с точкой — могла остаться
        незамеченной при блоках из нескольких адресов)."""
        for _u in used:
            if isinstance(_u, tuple):
                if _u[0] <= end and _u[1] >= start:
                    return True
            elif start <= _u <= end:
                return True
        return False

    if opt.ipaddr:
        # --- РУЧНОЙ IP ---
        raw_manual_ips = [s.strip() for s in opt.ipaddr.split(',')]

        for manual_ip_str in raw_manual_ips:
            # Ручной IP/диапазон для КЛИЕНТА: допустима любая маска (как в old),
            # но с ПОЛНОЙ диапазонной валидацией: ни один адрес диапазона не должен
            # пересекаться с занятыми адресами, адресом сервера или broadcast
            # (старый код проверял только первый адрес — коллизии в диапазоне
            # проходили молча; теперь отказ с явным сообщением).
            manual_ip = ipaddress.ip_network(manual_ip_str, strict=False)

            if isinstance(manual_ip, ipaddress.IPv4Network):
                if net_ipv4 is None:
                    raise RuntimeError(f'IPv4 адрес {manual_ip_str} задан, но сервер использует только IPv6')

                # Проверяем что IPv4 клиента в подсети сервера
                if not manual_ip.subnet_of(net_ipv4):
                    raise RuntimeError(f'IPv4 адрес {manual_ip_str} не в подсети сервера {net_ipv4}')

                _check_client_manual_range(manual_ip_str, manual_ip,
                                            server_ip_int_ipv4, used_ips_ipv4,
                                            server_on_network_ipv4, broadcast_int_ipv4)

                ipaddr_ipv4 = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
                # Регистрируем ВЕСЬ диапазон как занятый (фикс аудита: ручной
                # /16 не защищал авто-выдачу внутри себя)
                used_ips_ipv4.add((int(manual_ip.network_address), int(manual_ip.broadcast_address)))
            else:
                if net_ipv6 is None:
                    raise RuntimeError(f'IPv6 адрес {manual_ip_str} задан, но сервер использует только IPv4')

                # Проверяем что IPv6 клиента в подсети сервера
                if not manual_ip.subnet_of(net_ipv6):
                    raise RuntimeError(f'IPv6 адрес {manual_ip_str} не в подсети сервера {net_ipv6}')

                _check_client_manual_range(manual_ip_str, manual_ip,
                                            ipv6_server_ip_int, used_ips_ipv6,
                                            server_on_network_ipv6,
                                            int(net_ipv6.broadcast_address))

                ipaddr_ipv6 = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
                used_ips_ipv6.add((int(manual_ip.network_address), int(manual_ip.broadcast_address)))
    else:
        # --- АВТОМАТИЧЕСКИЙ IP ---
        if net_ipv4 is None:
            # --- ТОЛЬКО IPv6 ---
            ipv6_client_mask = 128  # 1 адрес на клиента
            ipv6_block_size = 2 ** (128 - ipv6_client_mask)  # = 1
            ipv6_base = int(net_ipv6.network_address)
            max_ipv6_blocks = (int(net_ipv6.broadcast_address) - ipv6_base + 1) // ipv6_block_size
            chosen_ipv6 = None
            for block_idx in range(1, max_ipv6_blocks):
                ipv6_block_start = ipv6_base + block_idx
                # Пропускаем broadcast, если сервер НЕ на network
                if ipv6_block_start == int(net_ipv6.broadcast_address) and not server_on_network_ipv6:
                    continue
                # Пропускаем адрес сервера
                if ipv6_block_start == ipv6_server_ip_int:
                    continue
                # Пропускаем занятые адреса (точки и диапазоны)
                if _blocked(ipv6_block_start, used_ips_ipv6):
                    continue
                chosen_ipv6 = ipv6_block_start
                break
            if chosen_ipv6 is None:
                raise RuntimeError('Нет свободных IPv6 адресов')
            used_ips_ipv6.add(chosen_ipv6)
            ipaddr_ipv6 = f"{str(ipaddress.IPv6Address(chosen_ipv6))}/{ipv6_client_mask}"
        else:
            # --- АВТОМАТИЧЕСКИЙ IP (IPv4, опционально IPv6) ---
            # Вычисляем маски клиентов и коэффициент кратности
            ipv4_client_mask, ipv6_client_mask, _ = calculate_client_masks(net_ipv4, net_ipv6)

            # Вычисляем размеры блоков клиентов
            ipv4_block_size = 2 ** (32 - ipv4_client_mask)
            ipv6_block_size = 2 ** (128 - ipv6_client_mask)

            # Начинаем с network_address для правильного выравнивания
            ipv4_base = int(net_ipv4.network_address)
            ipv6_base = int(net_ipv6.network_address) if net_ipv6 else 0

            # Проходим по всем блокам IPv4
            max_ipv4_blocks = (int(net_ipv4.broadcast_address) - ipv4_base + 1) // ipv4_block_size
            server_on_network = server_on_network_ipv4

            chosen_ipv4 = None
            chosen_ipv6 = None
            saw_pair_blocked = False  # фикс аудита: честная диагностика пар

            for block_idx in range(max_ipv4_blocks):
                # Вычисляем начало IPv4 блока (выровнено!)
                ipv4_block_start = ipv4_base + (block_idx * ipv4_block_size)
                ipv4_block_end = ipv4_block_start + ipv4_block_size - 1

                # Вычисляем начало IPv6 блока (выровнено!)
                ipv6_block_start = 0
                ipv6_block_end = 0
                if net_ipv6:
                    ipv6_block_start = ipv6_base + (block_idx * ipv6_block_size)
                    ipv6_block_end = ipv6_block_start + ipv6_block_size - 1

                # Пропускаем network address (первый блок)
                if block_idx == 0:
                    continue

                # Проверяем что блок не заканчивается на broadcast
                if ipv4_block_end == int(net_ipv4.broadcast_address):
                    if not server_on_network:
                        continue

                # Проверяем IPv6 broadcast
                if net_ipv6 and ipv6_block_end == int(net_ipv6.broadcast_address):
                    if not server_on_network:
                        continue

                # Проверяем что блок не содержит адрес сервера (IPv4)
                if ipv4_block_start <= server_ip_int_ipv4 <= ipv4_block_end:
                    continue

                # Проверяем что блок не содержит адрес сервера (IPv6)
                if net_ipv6 and (ipv6_block_start <= ipv6_server_ip_int <= ipv6_block_end):
                    continue

                # Проверяем что ВЕСЬ диапазон пары свободен (не только старт:
                # занятая точка внутри блока отсекает весь блок целиком)
                ipv4_free = not _blocked_range(ipv4_block_start, ipv4_block_end, used_ips_ipv4)
                ipv6_free = True
                if net_ipv6:
                    ipv6_free = not _blocked_range(ipv6_block_start, ipv6_block_end, used_ips_ipv6)

                # Пропускаем если ХОТЯ БЫ ОДИН занят!
                if not ipv4_free or not ipv6_free:
                    if ipv4_free and net_ipv6 and not ipv6_free:
                        saw_pair_blocked = True
                    continue

                # Нашли пару! ОБА свободны!
                chosen_ipv4 = ipv4_block_start
                chosen_ipv6 = ipv6_block_start if net_ipv6 else None
                break

            if chosen_ipv4 is None:
                if saw_pair_blocked:
                    raise RuntimeError('Нет свободных пар IPv4+IPv6 (исчерпаны IPv6-блоки при свободных IPv4)')
                raise RuntimeError('Нет свободных IPv4 адресов')

            # Добавляем выделенные адреса в занятые
            used_ips_ipv4.add(chosen_ipv4)
            if chosen_ipv6:
                used_ips_ipv6.add(chosen_ipv6)

            # Формируем адрес с маской клиента
            ipaddr_ipv4 = f"{str(ipaddress.IPv4Address(chosen_ipv4))}/{ipv4_client_mask}"

            if net_ipv6 and chosen_ipv6 is not None:
                ipaddr_ipv6 = f"{str(ipaddress.IPv6Address(chosen_ipv6))}/{ipv6_client_mask}"
            elif net_ipv6:
                logger.warning('⚠  Нет свободных пар IPv4+IPv6, выдаём только IPv4')
                ipaddr_ipv6 = None

    return ipaddr_ipv4, ipaddr_ipv6


def _add_client_to_config(srv_path: pathlib.Path, c_name: str, ipaddr: str,
                          persistent_keepalive: int) -> str:
    """Добавление клиента в серверный конфиг.

    Фикс аудита-A1: НЕ пишет файл сам — возвращает новый полный текст;
    запись выполняет _atomic_rmw в handle_add (fresh load на каждой попытке).
    """
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()

    srvcfg = srv_path.read_text(encoding='utf-8')
    srvcfg += '\n'
    srvcfg += '[Peer]\n'
    srvcfg += f'#_Name = {c_name}\n'
    srvcfg += f'#_GenKeyTime = {datetime.datetime.now().isoformat()}\n'
    srvcfg += f'#_PrivateKey = {priv_key}\n'
    srvcfg += f'PublicKey = {pub_key}\n'
    srvcfg += f'PresharedKey = {psk}\n'
    srvcfg += f'PersistentKeepalive = {persistent_keepalive}\n'
    srvcfg += f'AllowedIPs = {ipaddr}\n'
    return srvcfg


def _backup_file(path: pathlib.Path, suffix: str = '.bak') -> pathlib.Path | None:
    """
    Создание резервной копии файла.
    
    Args:
        path: Путь к файлу для резервного копирования
        suffix: Суффикс для backup файла (по умолчанию '.bak')
    
    Returns:
        Путь к backup файлу или None если файл не существовал
    """
    if not path.exists():
        return None
    
    backup_path = path.with_suffix(path.suffix + suffix)
    shutil.copy2(path, backup_path)
    logger.info("📦 Создана резервная копия: %s", backup_path)
    return backup_path


# ─── Шаги поиска/передачи версии QR ─────────────────────────────
QR_FORWARD_DIGIT_STEP   = 1   # шаг вперёд по цифрам (1..40)
QR_BACKWARD_DIGIT_STEP  = 1   # шаг назад по цифрам
QR_BACKWARD_LETTER_STEP = 1   # шаг назад по буквам

# Полный список ступеней: H1..H40, Q40, M40, L40
_QR_STEPS: list[tuple[int, int]] = []
for v in range(1, 41):
    _QR_STEPS.append((v, qrcode.constants.ERROR_CORRECT_H if qrcode else -1))
if qrcode:
    for ec in [qrcode.constants.ERROR_CORRECT_Q, qrcode.constants.ERROR_CORRECT_M, qrcode.constants.ERROR_CORRECT_L]:
        _QR_STEPS.append((40, ec))
# ─────────────────────────────────────────────────────────────────

def _generate_qr_image(
    conf_text: str,
    output_path: pathlib.Path,
    start_version: int = 1,
    start_ec: int = -1,
) -> tuple[int, int]:
    """
    Генерация QR-кода из текста конфига — ручной перебор.

    1. Пробует start_version с start_ec (fit=False) — быстрое совпадение.
    2. Если не влез — перебирает version start_version..40 с H (30%).
    3. Если H не влез ни в один — Q (25%) → M (15%) → L (7%) с version 40.
    4. Если ничего не влезло — RuntimeError.

    Args:
        conf_text: Текст конфига для кодирования в QR
        output_path: Путь для сохранения PNG файла
        start_version: Версия, с которой начать (из предыдущей генерации)
        start_ec:  Уровень коррекции, с которого начать (из предыдущей)

    Returns:
        (version, ec) — подошедшие версия и уровень коррекции
    """
    if qrcode is None:
        raise RuntimeError('Пакет qrcode не установлен')

    # Шаг 0: пробуем предыдущие параметры (быстрый путь)
    if start_ec != -1 and start_version > 0:
        result = _try_qr(conf_text, output_path, start_version, start_ec)
        if result:
            return result

    # Шаг 1: перебор цифр 1..40 с шагом QR_FORWARD_DIGIT_STEP (все с H)
    for version in range(start_version, 41, max(1, QR_FORWARD_DIGIT_STEP)):
        result = _try_qr(conf_text, output_path, version, qrcode.constants.ERROR_CORRECT_H)
        if result:
            return result

    # Шаг 2: перебор букв Q→M→L (version=40)
    for ec in (qrcode.constants.ERROR_CORRECT_Q,
               qrcode.constants.ERROR_CORRECT_M,
               qrcode.constants.ERROR_CORRECT_L):
        result = _try_qr(conf_text, output_path, 40, ec)
        if result:
            return result

    raise RuntimeError("Конфиг слишком большой для QR кода")


def _try_qr(conf_text: str, output_path: pathlib.Path, version: int, ec: int) -> tuple[int, int] | None:
    """Пробует сгенерировать QR-код с заданными параметрами. Возвращает (version, ec) или None."""
    try:
        qr = qrcode.QRCode(
            version=version,
            error_correction=ec,
            box_size=5,  # 5 px на модуль (компактнее; сканируемость сохраняется)
            border=4,
        )
        qr.add_data(conf_text)
        qr.make(fit=False)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(str(output_path))
        # QR содержит ВЕСЬ конфиг (PrivateKey/PSK): права 0600, как у .conf/.zip
        # (фикс CLI-аудита: Pillow пишет с дефолтным umask → 0644, ключи читаемы
        # локальными пользователями на мульти-юзер хостах).
        os.chmod(str(output_path), 0o600)
        return version, ec
    except (qrcode.exceptions.DataOverflowError, ValueError):
        return None


def _add_file_to_zip(zipf: zipfile.ZipFile, file_path: str, arcname: str | None = None) -> bool:
    """
    Добавление файла в ZIP архив.
    
    Args:
        zipf: ZIP файл для добавления
        file_path: Путь к файлу
        arcname: Имя файла в архиве (по умолчанию = file_path)
    
    Returns:
        True если успешно, False если ошибка
    """
    try:
        zipf.write(str(file_path), arcname=arcname if arcname else file_path)
        return True
    except Exception as e:
        logger.warning("⚠  Не удалось добавить файл в архив: %s", e)
        return False


def _init_random_seed(extra_entropy: int | None = None) -> None:
    """
    Инициализация генератора случайных чисел уникальным seed.
    
    Args:
        extra_entropy: Дополнительная энтропия (например hash(peer_name))
    """
    seed = time.time_ns() ^ os.getpid()
    if extra_entropy is not None:
        seed ^= extra_entropy
    random.seed(seed)


def _read_server_protocol(conf_path: pathlib.Path) -> str:
    """Единая точка чтения версии протокола ('# Protocol: ...') из серверного
    конфига. Используется handle_add/handle_update/handle_confgen (ранее —
    три копии одного сниппета, 16.09.2026 сведены сюда). По умолчанию AWG1.0."""
    try:
        for line in conf_path.read_text(encoding='utf-8').splitlines():
            if line.startswith('# Protocol:'):
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return "AWG1.0"


def _generate_persistent_keepalive(version: str = "AWG2.0") -> str:
    """
    Генерация PersistentKeepalive.

    Для AWG3.0/3.1 — диапазон "a-b": a=3..6, b=a+a (итог 6..12) — ядро и тулсы
    поддерживают диапазоны (netlink.c: u16_range_t; tools: u16_range_from_string;
    проверено живьём: `awg set peer ... persistent-keepalive 3-9` → show
    "persistent keepalive: 3-9"). Для версий ниже 3.0 — число 3..9 (как раньше).
    Назначение прежнее: предотвращает закрытие NAT session timeout.
    """
    if version in ("AWG3.0", "AWG3.1"):
        a = random.randint(3, 6)
        return f"{a}-{a * 2}"
    return str(random.randint(3, 9))


def _get_param_value(conf_text: str, param: str, version: str, min_version: str) -> str | None:
    """
    Извлечь значение параметра из конфига.
    Поддерживает как активные так и закомментированные параметры.

    version: текущая версия протокола
    min_version: минимальная версия для поддержки этого параметра

    Возвращает None если версия < min_version.
    """
    # Проверяем поддержку параметра в данной версии
    version_order = {"WG": 0, "AWG": 1, "AWG1.0": 2, "AWG1.5": 3, "AWG2.0": 4, "AWG3.0": 5, "AWG3.1": 6}
    if version_order.get(version, 0) < version_order.get(min_version, 0):
        return None  # Параметр не поддерживается в этой версии

    for line in conf_text.split('\n'):
        line = line.strip()
        # Проверяем активный параметр: "S1 = 42"
        if line.startswith(f'{param} = '):
            # maxsplit=1: значение само может содержать '=' (base64
            # HeaderProtectionKey с паддингом) — без него терялся '='.
            return line.split('=', 1)[1].strip()
        # Проверяем закомментированный: "# S1 = 42  # AWG+"
        if line.startswith(f'# {param} = '):
            # Извлекаем значение между "# S1 = " и следующим "#"
            value_part = line[2:]  # Убираем "# "
            if '=' in value_part:
                value = value_part.split('=', 1)[1].strip()
                # Убираем комментарий после значения
                if '  #' in value:
                    value = value.split('  #')[0].strip()
                return value
        # Проверяем служебную запись с данными: "#_PublicKey = X"
        # (свой публичный ключ сервера хранится только так; раньше парсер
        # находил ключ ПЕРВОГО [Peer] — баг 1.1)
        if line.startswith(f'#_{param} = '):
            return line.split('=', 1)[1].strip()
    return None


def _get_server_params(server_conf_text: str, server_protocol: str) -> dict:
    """Получение параметров сервера (S1-S4, H1-H4, AWG3.x, PublicKey) из конфига.

    AWG3.x-параметры читаются с min_version: ContentPadding/тайминги/DisableCookies
    с AWG3.0, HeaderProtectionKey/RandomTrailers с AWG3.1. HeaderProtectionKey —
    server-side: обязан совпадать у сервера и всех клиентов, поэтому вшивается
    в клиентские конфиги именно отсюда.
    """
    return {
        'PublicKey': _get_param_value(server_conf_text, 'PublicKey', server_protocol, "WG"),
        'S1': _get_param_value(server_conf_text, 'S1', server_protocol, "AWG"),
        'S2': _get_param_value(server_conf_text, 'S2', server_protocol, "AWG"),
        'S3': _get_param_value(server_conf_text, 'S3', server_protocol, "AWG2.0"),
        'S4': _get_param_value(server_conf_text, 'S4', server_protocol, "AWG2.0"),
        'H1': _get_param_value(server_conf_text, 'H1', server_protocol, "AWG1.0"),
        'H2': _get_param_value(server_conf_text, 'H2', server_protocol, "AWG1.0"),
        'H3': _get_param_value(server_conf_text, 'H3', server_protocol, "AWG1.0"),
        'H4': _get_param_value(server_conf_text, 'H4', server_protocol, "AWG1.0"),
        # AWG3.0+
        'ContentPaddingAddition': _get_param_value(server_conf_text, 'ContentPaddingAddition', server_protocol, "AWG3.0"),
        'RekeyAfterTime': _get_param_value(server_conf_text, 'RekeyAfterTime', server_protocol, "AWG3.0"),
        'RekeyTimeout': _get_param_value(server_conf_text, 'RekeyTimeout', server_protocol, "AWG3.0"),
        'RejectAfterTime': _get_param_value(server_conf_text, 'RejectAfterTime', server_protocol, "AWG3.0"),
        'KeepaliveTimeout': _get_param_value(server_conf_text, 'KeepaliveTimeout', server_protocol, "AWG3.0"),
        'MaxHandshakeAttempts': _get_param_value(server_conf_text, 'MaxHandshakeAttempts', server_protocol, "AWG3.0"),
        'DisableCookies': _get_param_value(server_conf_text, 'DisableCookies', server_protocol, "AWG3.0"),
        # AWG3.1 (server-side ключ + механизм)
        'HeaderProtectionKey': _get_param_value(server_conf_text, 'HeaderProtectionKey', server_protocol, "AWG3.1"),
        'RandomTrailers': _get_param_value(server_conf_text, 'RandomTrailers', server_protocol, "AWG3.1"),
    }


def _fix_client_allowed_ips(client_allowed_ips: str, srv_addr: str) -> str:
    """
    Исправление маски клиента на маску подсети сервера.
    
    Замена происходит ТОЛЬКО если broadcast работает (сервер НЕ на network address).
    """
    allowed_ips_list = [ip.strip() for ip in client_allowed_ips.split(',')]
    fixed_allowed_ips = []
    
    # Получаем подсети сервера
    raw_subnets = [s.strip() for s in srv_addr.split(',')]
    net_ipv4 = None
    net_ipv6 = None
    
    for subnet_str in raw_subnets:
        net = ipaddress.ip_network(subnet_str, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            net_ipv4 = net
        else:
            net_ipv6 = net
    
    # Проверяем позицию сервера (на network address или нет).
    # Аудит-20: позиционный split(',')[idx] ломал порядок «IPv6, IPv4» —
    # теперь индекс определяется ПО ВЕРСИИ адреса сервера.
    def _server_on_network(net, family):
        if net is None:
            return False
        # находим запись сервера нужной версии по исходной строке
        for part in srv_addr.split(','):
            part = part.strip()
            if '/' not in part:
                continue
            ip_str = part.split('/')[0]
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if addr.version != family:
                continue
            return int(addr) == int(net.network_address)
        return False

    server_ipv4_on_network = _server_on_network(net_ipv4, 4)
    server_ipv6_on_network = _server_on_network(net_ipv6, 6)
    
    # Исправляем маски
    for ip_str in allowed_ips_list:
        if '/' in ip_str:
            ip_net = ipaddress.ip_network(ip_str, strict=False)
            if isinstance(ip_net, ipaddress.IPv4Network):
                # Защита от краша на IPv6-only сервере (нет IPv4-подсети): оставляем как есть
                if net_ipv4 is not None and not server_ipv4_on_network:
                    fixed_allowed_ips.append(f"{ip_net.network_address}/{net_ipv4.prefixlen}")
                else:
                    fixed_allowed_ips.append(ip_str)
            elif net_ipv6 is not None:
                if not server_ipv6_on_network:
                    fixed_allowed_ips.append(f"{ip_net.network_address}/{net_ipv6.prefixlen}")
                else:
                    fixed_allowed_ips.append(ip_str)
            else:
                fixed_allowed_ips.append(ip_str)
        else:
            fixed_allowed_ips.append(ip_str)
    
    return ', '.join(fixed_allowed_ips)


def _fill_client_obfuscation_params(out_base: str, client_obf_params: dict, server_params: dict) -> str:
    """Заполнение параметров обфускации в клиентском конфиге."""
    # Jc, Jmin, Jmax
    out_base = _fill_j_lines(out_base, client_obf_params)

    # S1, S2
    out_base = _fill_or_clear_lines(out_base, {"S1": server_params.get("S1"), "S2": server_params.get("S2")})

    # S3, S4
    out_base = _fill_or_clear_lines(out_base, {"S3": server_params.get("S3"), "S4": server_params.get("S4")})

    # H1-H4
    out_base = _fill_or_clear_lines(out_base, {"H1": server_params.get("H1"), "H2": server_params.get("H2"),
                                               "H3": server_params.get("H3"), "H4": server_params.get("H4")})

    # I1-I5
    out_base = _fill_i_lines(out_base, client_obf_params)

    # AWG3.0/3.1: новые параметры; HeaderProtectionKey — из server_params (server-side)
    out_base = _fill_awg3_lines(out_base, client_obf_params, server_params)

    return out_base


# ----------------- Обработчики команд -----------------

def _read_endpoint_proto() -> tuple[str, str]:
    """Читает _endpoint.config и возвращает (domain, proto) для имитации рукопожатия."""
    domain = ""
    proto = ""
    if g_endpoint_config_fn and g_endpoint_config_fn.exists():
        try:
            _ep_text = g_endpoint_config_fn.read_text('utf-8')
            # Точные значения из распарсенных endpoints (;domain=/;proto=),
            # фоллбэк на "голые" строки без ';' ('domain=yandex.ru' и т.п. —
            # легаси-формат из тестов и старых конфигов, см. ночной прогон).
            for ep in parse_endpoints_config(_ep_text, "51820"):
                if not domain and ep.get("domain"):
                    domain = ep["domain"]
                if not proto and ep.get("proto"):
                    proto = ep["proto"]
                if domain and proto:
                    break
            if not domain:
                m = re.search(r'(?:^|[\s;])domain=([^\s;]+)', _ep_text)
                if m:
                    domain = m.group(1)
            if not proto:
                m = re.search(r'(?:^|[\s;])proto=([^\s;]+)', _ep_text)
                if m:
                    proto = m.group(1)
        except Exception as e:
            logger.warning("Ошибка чтения %s: %s", g_endpoint_config_fn, e)
    return domain, proto


def handle_makecfg(opt) -> None:
    """Создание/обновление серверной конфигурации (--make).

    Побочные эффекты: генерирует/перезаписывает серверный конфиг, скрипты
    up/down и файл параметров рядом с конфигом; повторный --make пересоздаёт
    скрипты заново (исторический фикс N1). Требует подсеть (--ipaddr)
    и основной интерфейс сервера.
    """
    global g_main_config_fn

    raw_input = opt.makecfg

    # Логика "умного пути"
    target_path, tun_name = _process_interface_path(raw_input)

    init_interface_paths(tun_name)

    # Создаем родительскую директорию, если её нет
    if not target_path.parent.exists():
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"Не удалось создать директорию {target_path.parent}: {e}") from None

    g_main_config_fn = target_path.resolve()

    if g_main_config_fn.exists():
        # Обновление существующего: J, I, PersistentKeepalive
        logger.info('🔄 Конфиг %s уже существует — обновление Jc/Jmin/Jmax, I1-I5, PersistentKeepalive', g_main_config_fn)
        cfg = WGConfig(str(g_main_config_fn))

        # Определяем версию протокола из существующего конфига
        _file_version = "AWG1.0"
        _line_start = cfg.lines[0] if cfg.lines else ""
        if "# Protocol:" in _line_start:
            _file_version = _line_start.split(":")[-1].strip()

        srv = cfg.iface

        # Генерируем новые J и I параметры
        _server_domain, _server_proto = _read_endpoint_proto()
        # Seed для I1-I5 берём из уже записанного в конфиг ПУБЛИЧНОГО КЛЮЧА сервера,
        # чтобы новые I-параметры состыковались с ClientHello существующих клиентов
        # (16.09.2026: раньше S1+S2+pubkey — S выводились через session_id; см. 9578).
        _regen_seed = srv.get('PublicKey', '')
        obf_params = generate_all_params(_file_version, for_client=False, for_server=True, tun_name=tun_name, domain=_server_domain, proto=_server_proto, server_pubkey=srv.get('PublicKey', ''), seed_override=_regen_seed)
        _label = "Имитация рукопожатия" if _server_domain else "Случайные сигнатуры"
        logger.info("🎭 %s", _label)

        # Обновляем Jc/Jmin/Jmax
        for p in ['Jc', 'Jmin', 'Jmax']:
            val = obf_params.get(p)
            if val is not None:
                k = f"__this_server__|{p}"
                if k in cfg.idsline:
                    cfg.lines[cfg.idsline[k]] = f"{p} = {val}"
                elif p in srv:
                    srv[p] = val

        # Обновляем PersistentKeepalive у всех пиров (до I-lines, пока idsline актуален)
        for pname in list(cfg.peer.keys()):
            new_pk = _generate_persistent_keepalive(_file_version)
            pk_key = f"{pname}|PersistentKeepalive"
            if pk_key in cfg.idsline:
                cfg.lines[cfg.idsline[pk_key]] = f"PersistentKeepalive = {new_pk}"

        # Обновляем I1-I5: заменяем существующие, добавляем новые перед MTU.
        # ВАЖНО: закомментированные '#'-строки НЕ активируем (аудит-20: при
        # перегенерации WG-конфигов мёртвые '# I1 = ...' становились активными).
        new_lines = []
        i_added = set()
        mtu_pos = None
        for _idx, line in enumerate(cfg.lines):
            match = re.match(r'^\s*I([1-5])\s*=\s*(.+)$', line)
            if match:
                key_num = int(match.group(1))
                raw_key = f"I{key_num}"
                val = obf_params.get(raw_key)
                if val is not None:
                    new_lines.append(f"{raw_key} = {val}")
                    i_added.add(key_num)
            else:
                new_lines.append(line)
                if mtu_pos is None and re.match(r'^\s*MTU\s*=', line):
                    mtu_pos = len(new_lines) - 1  # позиция MTU

        # Добавляем новые I-строки перед MTU
        if mtu_pos is not None:
            for i in range(5, 0, -1):
                if i not in i_added and obf_params.get(f"I{i}") is not None:
                    new_lines.insert(mtu_pos, f"I{i} = {obf_params[f'I{i}']}")
        else:
            # Fallback: в конец
            for i in range(1, 6):
                if i not in i_added and obf_params.get(f"I{i}") is not None:
                    new_lines.append(f"I{i} = {obf_params[f'I{i}']}")
        cfg.lines = new_lines

        cfg.save()
        logger.info('✅ Конфиг %s обновлён', g_main_config_fn)

        # ВАЖНО (найдено при квотной доработке): повторный --make обязан
        # ПЕРЕСОЗДАВАТЬ up/down-скрипты — иначе новые фиксы/параметры
        # генератора не попадают в существующие конфиги.
        try:
            _up_path = g_main_config_fn.parent.joinpath(f"{tun_name}up.sh")
            _down_path = g_main_config_fn.parent.joinpath(f"{tun_name}down.sh")
            _params_path = _up_path.parent / f"{tun_name}.sh"
            # WARP-список переносим из СТАРОГО параметр-файла (не перегенерируем
            # WARP-конфиги и не теряем существующие конфигурации)
            _warp_cfgs = []
            try:
                _old_params = _params_path.read_text(encoding='utf-8')
                _m = re.search(r'WARP_LIST=\((.*?)\)', _old_params, re.S)
                if _m:
                    # Фикс аудита-C2: ручные формы «warp1=subnet» НЕ являются
                    # путями конфигов — при перегенерации они давали мусорные
                    # имена через Path.stem; переносим только имена.
                    _warp_cfgs = [x.strip().strip('"') for x in _m.group(1).splitlines()
                                  if x.strip().strip('"') and '=' not in x.strip().strip('"')]
            except Exception:
                pass
            main_iface = getattr(opt, 'iface', '') or get_main_iface() or 'net0'
            srv_addr = srv.get('Address', '')
            # Параметры перегенерации БЕРЁМ ИЗ СУЩЕСТВУЮЩЕГО КОНФИГА (порт),
            # а не из текущих аргументов CLI — иначе повторный --make с иным
            # портом/аргументами портит параметры (марафон уловил).
            _upd_port = srv.get('ListenPort') or getattr(opt, 'port', 4455)
            try:
                _upd_port = int(_upd_port)
            except (TypeError, ValueError):
                _upd_port = getattr(opt, 'port', 4455)
            _upd_opt = types.SimpleNamespace(port=_upd_port, limit=getattr(opt, 'limit', 0))
            # Фикс аудита-fresh: refresh-перегенерация с limit=0 (CLI-дефолт)
            # молча обнуляла SUBNETS_LIMITS/DDoS-полосу в params — лимиты
            # «пропадали» при каждом повторном --make. Переносим старый rate,
            # когда в CLI лимит явно не задан.
            if not _upd_opt.limit:
                _m2 = re.search(r'SUBNETS_LIMITS=\((.*?)\)', _old_params, re.S)
                if _m2:
                    _rates = re.findall(r':(\d+)"', _m2.group(1))
                    if _rates:
                        _upd_opt.limit = int(_rates[-1])
            _create_scripts(_up_path, _down_path, _params_path, main_iface, tun_name, _upd_opt, srv_addr, _warp_cfgs)
            logger.info('🔄 up/down-скрипты перегенерированы')
        except Exception as _se:
            logger.warning("⚠  Не удалось перегенерировать скрипты: %s", _se)
        return

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
    _, _, ipaddr_display = parse_ipaddr_argument(opt.ipaddr)

    # Определяем версию протокола из флага --version
    awg_version = getattr(opt, 'version', 'AWG1.0')

    # --- СНАЧАЛА ГЕНЕРИРУЕМ WARP (если нужен) ---
    warp_configs = _generate_warp_if_needed(tun_name, opt.warp, opt.mtu, opt.proxy, awg_version)

    # --- ТЕПЕРЬ СОЗДАЁМ СЕРВЕРНЫЙ КОНФИГ И СКРИПТЫ ---
    priv, pub = gen_pair_keys()

    # Инициализируем random уникальным seed
    _init_random_seed()

    # Определяем нужна ли имитация рукопожатия на сервере (есть ли domain= в _endpoint.config)
    _server_domain, _server_proto = _read_endpoint_proto()

    # Генерируем параметры обфускации для СЕРВЕРА
    obf_params = generate_all_params(awg_version, for_client=False, for_server=True, tun_name=tun_name, domain=_server_domain, proto=_server_proto, server_pubkey=pub)

    up_path = g_main_config_fn.parent.joinpath(f"{tun_name}up.sh")
    down_path = g_main_config_fn.parent.joinpath(f"{tun_name}down.sh")

    out = g_defserver_config
    out = out.replace("<PROTOCOL>", awg_version)
    out = out.replace("<SERVER_KEY_TIME>", datetime.datetime.now().isoformat())
    out = out.replace("<SERVER_PRIVATE_KEY>", priv)
    out = out.replace("<SERVER_PUBLIC_KEY>", pub)
    out = out.replace("<SERVER_ADDR>", ipaddr_display)
    out = out.replace("<SERVER_PORT>", str(opt.port))

    # Заполняем параметры обфускации
    out = _fill_obfuscation_params(out, obf_params)

    out = out.replace("<SERVER_IFACE>", main_iface)
    out = out.replace("<SERVER_TUN>", tun_name)
    # Пути в PostUp/PostDown — в кавычках: awg-quick исполняет строку через
    # shell, поэтому каталог с пробелами иначе разломает команду (проверено).
    out = out.replace("<SERVER_UP_SCRIPT>", '"' + str(up_path) + '"')
    out = out.replace("<SERVER_DOWN_SCRIPT>", '"' + str(down_path) + '"')
    out = out.replace("<MTU>", str(opt.mtu))

    atomic_write_text(g_main_config_fn, out)
    logger.info("✅ Серверный конфиг создан: %s", g_main_config_fn)

    # Создаём скрипты
    params_path = up_path.parent / f"{tun_name}.sh"
    _create_scripts(up_path, down_path, params_path, main_iface, tun_name, opt, ipaddr_display, warp_configs)

    atomic_write_text(g_main_config_src, str(g_main_config_fn))

    try:
        _ensure_endpoint_file_exists(str(get_ext_ipaddr()))
        ensure_allowedips_config(g_allowedips_config_fn)
    except Exception as e:
        logger.warning("⚠  Не удалось создать вспомогательные файлы: %s", e)

    sys.exit(0)


def _require_server_config(opt) -> None:
    """Гарантирует, что g_main_config_fn разрешён и существует (иначе RuntimeError)."""
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    if not g_main_config_fn.exists():
        raise RuntimeError(f'Конфиг интерфейса не найден: {g_main_config_fn}. Сначала создайте интерфейс (--make)')


def handle_add(opt) -> None:
    """Добавление клиента (-a): строгая валидация имени, автоматическая выдача
    IP из подсети (или ручная через --ipaddr), запись в серверный конфиг.
    Запись — через _atomic_rmw (фикс аудита-A1: параллельные -a не теряют
    клиента и не выдают один IP дважды)."""
    _require_server_config(opt)
    srv_path = pathlib.Path(g_main_config_fn)

    def _make_add() -> str:
        cfg = WGConfig(str(g_main_config_fn))
        srv = cfg.iface
        srv_proto = _read_server_protocol(srv_path)

        # Проверка: есть ли в конфиге сервера Address (подсеть)
        if not srv or 'Address' not in srv:
            raise RuntimeError(f'В конфиге {g_main_config_fn} отсутствует подсеть (Address). Проверьте конфиг или создайте интерфейс заново')

        c_name = opt.addcl
        # Валидация имени клиента: имя попадает в пути файлов и в структуру конфига
        # (аудит раундов-18/-20: инъекция секций, path traversal). Строгий whitelist.
        if (not c_name) or (len(c_name) > 64) or (c_name != c_name.strip()) \
                or (not re.fullmatch(r'[A-Za-z0-9_.\-]+', c_name)) \
                or c_name in ('..', '.', '__this_server__'):
            raise RuntimeError(f'Недопустимое имя клиента "{c_name}": разрешены только '
                               f'буквы/цифры/._-/ без пробелов (макс. 64), нельзя ".." и "__this_server__"')
        if c_name.lower() in (x.lower() for x in cfg.peer.keys()):
            raise RuntimeError(f'Пользователь "{c_name}" уже существует')

        # --- Парсинг LOCAL_SUBNETS (IPv4 + IPv6) ---
        net_ipv4, net_ipv6, _ = parse_ipaddr_argument(srv['Address'])

        # --- Собираем используемые IPv4 адреса (диапазонами; фикс аудита) ---
        used_ips_ipv4 = set()
        used_ips_ipv6 = set()

        for peer in cfg.peer.values():
            try:
                peer_ips = peer['AllowedIPs']
                for peer_ip_str in [s.strip() for s in peer_ips.split(',')]:
                    peer_ip = ipaddress.ip_network(peer_ip_str, strict=False)
                    if isinstance(peer_ip, ipaddress.IPv4Network):
                        used_ips_ipv4.add((int(peer_ip.network_address), int(peer_ip.broadcast_address)))
                    else:
                        used_ips_ipv6.add((int(peer_ip.network_address), int(peer_ip.broadcast_address)))
            except Exception:
                continue

        srvcfg = srv_path.read_text(encoding='utf-8')
        broadcast_int_ipv4 = int(net_ipv4.broadcast_address) if net_ipv4 is not None else None
        server_ip_int_ipv4, server_on_network_ipv4, ipv6_server_ip_int, server_on_network_ipv6 = _get_server_ip_info(srvcfg, net_ipv4, net_ipv6)

        if net_ipv4 is not None:
            used_ips_ipv4.add(server_ip_int_ipv4)
        if net_ipv6:
            used_ips_ipv6.add(ipv6_server_ip_int)
            if net_ipv4 is not None and server_on_network_ipv4 != server_on_network_ipv6:
                raise RuntimeError(
                    f'Позиция сервера в IPv4 и IPv6 подсетях должна совпадать!\n'
                    f'  IPv4: {ipaddress.IPv4Address(server_ip_int_ipv4)}/{net_ipv4.prefixlen} - '
                    f'{"на network address" if server_on_network_ipv4 else "НЕ на network address"}\n'
                    f'  IPv6: {ipaddress.IPv6Address(ipv6_server_ip_int)}/{net_ipv6.prefixlen} - '
                    f'{"на network address" if server_on_network_ipv6 else "НЕ на network address"}\n'
                    f'Исправьте: сервер должен быть или на network address в обеих подсетях, '
                    f'или НЕ на network address в обеих подсетях!'
                )

        ipaddr_ipv4, ipaddr_ipv6 = _allocate_client_ip(
            opt, net_ipv4, net_ipv6,
            server_on_network_ipv4, server_on_network_ipv6,
            server_ip_int_ipv4, ipv6_server_ip_int, broadcast_int_ipv4,
            used_ips_ipv4, used_ips_ipv6
        )

        # Формируем итоговый AllowedIPs
        if ipaddr_ipv4 and ipaddr_ipv6:
            ipaddr = f"{ipaddr_ipv4}, {ipaddr_ipv6}"
        elif ipaddr_ipv6:
            ipaddr = ipaddr_ipv6
        else:
            ipaddr = ipaddr_ipv4

        return _add_client_to_config(srv_path, c_name, ipaddr, _generate_persistent_keepalive(srv_proto))

    _atomic_rmw(srv_path, _make_add)
    c_name = opt.addcl
    peer_final = WGConfig(str(g_main_config_fn)).peer[c_name]
    logger.info('👤 Создан пользователь "%s". IP=%s PersistentKeepalive=%s',
                c_name, peer_final['AllowedIPs'], peer_final['PersistentKeepalive'])


def handle_update(opt) -> None:
    _require_server_config(opt)
    srv_path = pathlib.Path(g_main_config_fn)
    p_name = opt.update

    def _make_update() -> str:
        cfg = WGConfig(str(g_main_config_fn))
        srv_proto = _read_server_protocol(srv_path)
        actual_name = next((n for n in cfg.peer.keys() if n.lower() == p_name.lower()), None)
        if actual_name is None:
            raise RuntimeError(f'Клиент "{p_name}" не найден')
        logger.info('🔄 Сброс ключей для "%s"...', actual_name)
        priv_key, pub_key = gen_pair_keys()
        psk = gen_preshared_key()
        cfg.set_param(actual_name, '_PrivateKey', priv_key, force=True, offset=2)
        cfg.set_param(actual_name, 'PublicKey', pub_key)
        cfg.set_param(actual_name, 'PresharedKey', psk)
        gentime = datetime.datetime.now().isoformat()
        cfg.set_param(actual_name, '_GenKeyTime', gentime, force=True, offset=2)
        new_pk = _generate_persistent_keepalive(srv_proto)
        cfg.set_param(actual_name, 'PersistentKeepalive', str(new_pk), force=True, offset=3)
        ipaddr = cfg.peer[actual_name]['AllowedIPs']
        logger.info('✅ Ключи сброшены для "%s". IP=%s NewPK=%s', actual_name, ipaddr, new_pk)
        return "\n".join(cfg.lines) + "\n"  # та же сериализация, что WGConfig.save

    _atomic_rmw(srv_path, _make_update)


def handle_delete(opt) -> None:
    _require_server_config(opt)
    srv_path = pathlib.Path(g_main_config_fn)
    p_name = opt.delete

    def _make_delete() -> str:
        cfg = WGConfig(str(g_main_config_fn))
        actual_name = next((n for n in cfg.peer.keys() if n.lower() == p_name.lower()), None)
        if actual_name is None:
            raise RuntimeError(f'Клиент "{p_name}" не найден')
        logger.info('🗑️  Удаление пользователя "%s"...', actual_name)
        ipaddr = cfg.del_client(actual_name)
        logger.info('✅ Удалён "%s". Освобождён IP=%s', actual_name, ipaddr)
        return "\n".join(cfg.lines) + "\n"

    _atomic_rmw(srv_path, _make_delete)


def handle_warp_gen(opt) -> list[str]:
    """
    Автономная генерация WARP конфигов (без серверного интерфейса).
    Сохраняет в папку WARP/ рядом со скриптом.

    QR и ZIP генерация теперь в общем коде (generate_qr_codes).

    Returns:
        Список путей к сгенерированным WARP конфигам
    """
    # Определяем версию протокола
    awg_version = getattr(opt, 'version', 'AWG2.0')

    # Создаём папку WARP/ рядом со скриптом
    warp_dir = SCRIPT_DIR.joinpath("WARP")
    warp_dir.mkdir(parents=True, exist_ok=True)
    logger.info("📁 Папка WARP: %s", warp_dir)

    # Генерируем WARP конфиги
    num_warps = opt.warp if opt.warp > 0 else 1
    logger.info("🌀 Генерация %d WARP конфигов (версия: %s)...", num_warps, awg_version)

    def _warp_standalone_one(i: int) -> str:
        conf_text, _ = generate_warp_config(
            tun_name="",  # Без префикса интерфейса
            index=i,
            mtu=opt.mtu,
            proxy=opt.proxy if hasattr(opt, 'proxy') else "",
            version=awg_version,
            for_server=False  # Клиентский WARP (без Table = off)
        )
        name = f"warp{i}.conf"
        atomic_write_text(warp_dir.joinpath(name), conf_text)
        return name

    warp_configs = _generate_warps(num_warps, _warp_standalone_one, warp_dir)
    logger.info("✅ Сгенерировано WARP конфигов: %d", len(warp_configs))
    return [str(warp_dir.joinpath(n)) for n in warp_configs]


def handle_confgen(opt) -> set[str]:
    """
    Генерирует конфиги.
    Возвращает множество имен (например {'All', 'Tg'}), для которых нужно сгенерировать QR.
    """
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    logger.info('📝 Генерация клиентских конфигов...')
    
    if not g_defclient_config_fn.exists():
        logger.info('Шаблон не найден, создаю стандартный шаблон в %s...', g_defclient_config_fn)
        out = g_defclient_config
        atomic_write_text(g_defclient_config_fn, out)

    tmpcfg = g_defclient_config_fn.read_text(encoding='utf-8')
    
    # Читаем версию протокола из серверного конфига
    server_protocol = _read_server_protocol(g_main_config_fn)

    # Инициализируем random уникальным seed
    _init_random_seed()

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
            try:
                example_addr = get_ext_ipaddr()
            except Exception:
                example_addr = "203.0.113.1"
            logger.error("Пример: %s", example_addr)
            raise RuntimeError("Не удалось создать _endpoint.config — укажите Endpoint вручную") from None

    # Очистка (кроме серверного конфига) — ПОСЛЕ валидаций --only и endpoint
    # (фикс аудита-D2: раньше удаление было первым, сбой генерации оставлял
    # пустой conf/ — конфиги с PrivateKey терялись безвозвратно).
    for ext in ("conf", "png"):
        for fn in glob.glob(str(g_conf_dir.joinpath(f"*.{ext}"))):
            if ext == "conf" and fn.endswith(g_main_config_fn.name):
                continue
            try:
                os.remove(fn)
            except Exception:
                pass

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

    # Параметры сервера (S1, S2, S3, S4, H1-H4) одинаковы для всех клиентов — читаем один раз
    server_params = _get_server_params(g_main_config_fn.read_text(encoding='utf-8'), server_protocol)

    for peer_name, peer in peers:
        if 'Name' not in peer or 'PrivateKey' not in peer:
            logger.info('Пропуск peer с публичным ключом %s', peer.get("PublicKey", "<no>"))
            continue
        # Lazy-генерация PSK только при реальном отсутствии (аудит-20: дефолт в
        # dict.get вычислялся всегда, лишний вызов openssl на каждом пире).
        psk = peer.get('PresharedKey')
        if psk is None:
            psk = gen_preshared_key()
        if 'PresharedKey' not in peer:
            # set_param без force кидает RuntimeError для отсутствующего параметра
            # (битые конфиги/легаси-импорт) — добавляем с force.
            cfg.set_param(peer_name, 'PresharedKey', psk, force=True)
            psk_added = True

        # Инициализируем random уникальным seed для каждого клиента
        # time.time_ns() ^ os.getpid() ^ hash(peer_name) = уникальный seed даже для пакетной генерации
        _init_random_seed(hash(peer_name))

        persistent_keepalive = _generate_persistent_keepalive(server_protocol)
        mtu = srv.get('MTU', str(opt.mtu))

        # seed для cipher suite должен совпадать с серверным (публичный ключ сервера;
        # 16.09.2026: раньше S1+S2+pubkey — S выводились через session_id на проводе)
        # ВАЖНО: 'PublicKey' берём из cfg.iface (WGConfig парсит строку '#_PublicKey = ...'),
        # а не из _get_server_params — тот находит ПЕРВУЮ активную строку 'PublicKey ='
        # (ключ первого [Peer]), что ломало согласование session_id/cipher (баг 1.1).
        i_seed = srv.get('PublicKey', '')

        for idx, ep in enumerate(endpoints, start=1):
            host = ep.get('host', '')
            port = ep.get('port', default_port)
            raw_label = ep.get('label', '')

            # Per-endpoint MTU (если указан в _endpoint.config как ;mtu=N)
            ep_mtu = ep.get('mtu', '')
            use_mtu = ep_mtu if ep_mtu else mtu

            # Per-endpoint domain (маскировка под конкретный сервис)
            ep_domain = ep.get('domain', '')
            # Per-endpoint протокол имитации (dtls/quic)
            ep_proto = ep.get('proto', '')

            # Генерируем обфускацию для этого эндпоинта (с учётом domain)
            client_obf_params = generate_all_params(
                server_protocol,
                for_client=True,
                for_server=False,
                domain=ep_domain,
                seed_override=i_seed,
                proto=ep_proto,
            )

            if single_endpoint:
                ep_label = "" if not raw_label else raw_label
            else:
                ep_label = raw_label if raw_label else str(idx)

            out_base = tmpcfg[:]
            out_base = out_base.replace('<MTU>', use_mtu)
            out_base = out_base.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])

            # Исправляем маску клиента на маску подсети сервера
            client_allowed_ips = peer['AllowedIPs']
            try:
                srv_addr_line = srv.get('Address', '')
                client_allowed_ips = _fix_client_allowed_ips(client_allowed_ips, srv_addr_line)
            except Exception as e:
                logger.error('❌ Ошибка замены маски: %s', e)  # Оставляем как есть

            out_base = out_base.replace('<PROTOCOL>', server_protocol)
            out_base = out_base.replace('<CLIENT_TUNNEL_IP>', client_allowed_ips)

            # Заполняем параметры обфускации
            out_base = _fill_client_obfuscation_params(out_base, client_obf_params, server_params)

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
                # Двойная защита путей (аудит): whitelist на парсинге + проверка
                # при записи — конфиг клиента (с PrivateKey) обязан остаться
                # внутри g_conf_dir.
                if (not re.fullmatch(r'[A-Za-z0-9_.\-]+', f"{peer_name}{ip_list_name}{ep_label}")
                        or peer_name in ('.', '..') or ip_list_name in ('.', '..')):
                    logger.warning("⚠️  Пропуск файла с недопустимым именем: %s%s%s.conf",
                                   peer_name, ip_list_name, ep_label)
                    continue
                conf_name = f"{peer_name}{ip_list_name}{ep_label}.conf"
                final_conf = out_base.replace('<ALLOWED_IPS>', ip_list_value)
                try:
                    conf_path = g_conf_dir.joinpath(conf_name)
                    if not conf_path.resolve().is_relative_to(g_conf_dir.resolve()):
                        logger.error("❌ Путь конфига вне conf/: %s (пропуск)", conf_path)
                        continue
                    # Атомарная запись (аудит-20: обычный open мог оставить
                    # частичный файл с PrivateKey при сбое).
                    atomic_write_text(conf_path, final_conf)
                    # Конфиг содержит PrivateKey/PSK клиента — только владелец
                    try:
                        os.chmod(str(conf_path), 0o600)
                    except OSError:
                        pass
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


def _match_qr_tag(stem: str, qr_filter) -> tuple[str, str, str]:
    """Находит суффикс-тег (первый совпадающий из qr_filter) в имени клиента.

    Возвращает (suffix, client, ep_label): суффикс, имя клиента без суффикса и метку эндпоинта.
    """
    for tag in sorted(qr_filter, key=len, reverse=True):
        # Фикс аудита: подстрока «в любом месте» давала ложные совпадения
        # (имя «bobAll» + список All → client='bob'). Принимаем вхождение,
        # только если ПОСЛЕ него нет другого тега из набора (для «bobAllAll»
        # первое подходящее — вторая позиция: client='bob', tag='All').
        search_from = 0
        while True:
            pos = stem.find(tag, search_from)
            if tag and pos >= 0:
                rest = stem[pos + len(tag):]
                if not any(t and t in rest for t in qr_filter):
                    return tag, stem[:pos], rest
                search_from = pos + 1
            else:
                break
    return "", stem, ""


def generate_qr_codes(
    qr_filter: set[str] | None = None,
    warp_configs: list[str] | None = None,
) -> None:
    """
    Генерирует QR для клиентских и WARP конфигов.
    Один next_version для всех — ускорение перебора версий QR.

    Args:
        qr_filter: множество имен IP-списков для клиентских конфигов
        warp_configs: список путей к WARP конфигам
    """
    if qrcode is None:
        raise RuntimeError('Пакет qrcode не установлен')
    try:
        import PIL  # noqa: F401
    except ImportError:
        # Без Pillow make_image() падает на каждом конфиге (ошибки только в логах,
        # а clean_confdir_types затем удалял все .conf в режиме -q); баг 1.12
        raise RuntimeError(
            'Пакет pillow (PIL) не установлен — QR-коды генерировать нельзя. '
            'Установите: pip install pillow (или python3-pil через apt)'
        ) from None

    # Собираем все конфиги в один список
    all_configs: list[str] = []
    # Сортируем по (суффикс, метка_эндпоинта, клиент) — группируем по AllowedIPs/Endpoint
    client_configs: list[tuple[str, str, str, str]] = []

    # --- Клиентские конфиги (с фильтром) ---
    if qr_filter is None:
        try:
            if g_allowedips_config_fn.exists():
                _, qr_filter = parse_allowedips_config(g_allowedips_config_fn.read_text('utf-8'))
            else:
                qr_filter = {'All'}
        except Exception:
            qr_filter = {'All'}

    for p in g_conf_dir.glob("*.conf"):
        if g_main_config_fn and p.name == g_main_config_fn.name:
            continue
        stem = p.stem
        # Ищем суффикс (первый совпадающий тег из qr_filter)
        suffix, client, ep_label = _match_qr_tag(stem, qr_filter)
        if suffix:
            client_configs.append((suffix, ep_label, client, str(p)))

    # Сортируем по (суффикс, метка, клиент)
    client_configs.sort(key=lambda x: (x[0], x[1], x[2]))
    all_configs = [item[3] for item in client_configs]

    # --- WARP конфиги (все подряд) ---
    if warp_configs:
        all_configs.extend(warp_configs)

    if not all_configs:
        logger.warning('⚠  Нет файлов для генерации QR (фильтр: %s, WARP: %d)', qr_filter, len(warp_configs or []))
        return

    # Очистка старых PNG клиентских конфигов (WARP очищает handle_warp_gen)
    for png in g_conf_dir.glob("*.png"):
        try:
            os.remove(str(png))
        except Exception:
            pass

    # --- Единый цикл генерации QR ---
    logger.info('📱 Генерация QR-кодов (%d конфигов)...', len(all_configs))
    next_version = 1
    next_ec = -1
    last_group = ("", "")
    for fn in all_configs:
        try:
            # Определяем группу (суффикс, ep_label) для сброса при смене
            stem = pathlib.Path(fn).stem
            cur_suffix, _, cur_ep = _match_qr_tag(stem, qr_filter or {})
            group = (cur_suffix, cur_ep)
            if group != last_group:
                next_version = 1
                next_ec = -1
                last_group = group

            with open(fn, 'r', encoding='utf-8') as file:
                conf = file.read()
            png_path = pathlib.Path(fn).with_suffix('.png')
            next_version, next_ec = _generate_qr_image(
                conf, png_path,
                start_version=next_version,
                start_ec=next_ec,
            )
            # Уменьшаем на шаг для следующего конфига (backward)
            if _QR_STEPS:
                try:
                    idx = _QR_STEPS.index((next_version, next_ec))
                    step = QR_BACKWARD_DIGIT_STEP if idx <= 39 else QR_BACKWARD_LETTER_STEP
                    new_idx = max(0, idx - step)
                    next_version, next_ec = _QR_STEPS[new_idx]
                except ValueError:
                    pass  # не найдено в списке — оставляем как есть
        except Exception as e:
            logger.error('❌ Ошибка генерации QR для %s: %s', fn, e)


def zip_client_files(client_name: str, base_dir: pathlib.Path | None = None) -> None:
    if base_dir is None:
        base_dir = g_conf_dir
    zip_filename = base_dir.joinpath(f"{client_name}.zip")
    
    suffixes = []
    if g_allowedips_config_fn.exists():
        try:
            ips_dict, _ = parse_allowedips_config(g_allowedips_config_fn.read_text('utf-8'))
            suffixes = list(ips_dict.keys())
        except Exception: pass

    # Суффиксы AllowedIPs (All/DsYt/...) имеют смысл только для клиентского
    # каталога conf/. Для других каталогов (например WARP/ в автономном
    # режиме) имена файлов вида "warp0.conf" не содержат суффиксов — иначе
    # архив получался бы пустым при существующем _allowedips.config.
    if suffixes and base_dir == g_conf_dir:
        suffixes.sort(key=len, reverse=True)
        suffixes_pattern = "|".join([re.escape(s) for s in suffixes])
        pattern_str = rf'^{re.escape(client_name)}({suffixes_pattern}).*\.(conf|png)$'
    else:
        # Точное имя файла (имя + расширение), без префиксного матча: иначе
        # «warp1.zip» забирал бы warp10..warp19.conf (фикс аудита-T7).
        pattern_str = rf'^{re.escape(client_name)}\.(conf|png)$'

    pattern_file = re.compile(pattern_str)
    
    with zipfile.ZipFile(str(zip_filename), 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for file in sorted(base_dir.iterdir()):
            if not file.is_file():
                continue
            if pattern_file.match(file.name):
                _add_file_to_zip(zipf, str(file), file.name)

        if g_file_dir.exists() and g_file_dir.is_dir():
            for root, _dirs, files in os.walk(g_file_dir):
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

    # Zip содержит приватные ключи — только владелец
    try:
        os.chmod(str(zip_filename), 0o600)
    except OSError:
        pass


def zip_all(warp_configs: list[str] | None = None) -> None:
    logger.info('📦 Упаковка конфигов в ZIP...')
    names = list(dict.fromkeys(clients_for_zip))
    for name in names:
        zip_client_files(name)
    if warp_configs:
        for cp in warp_configs:
            p = pathlib.Path(cp)
            zip_client_files(p.stem, base_dir=p.parent)


def clean_confdir_types(keep_conf: bool = False, keep_qr: bool = False, keep_zip: bool = False,
                        allowed_names: list[str] | None = None) -> None:
    keep_files = set()
    # Серверный конфиг НИКОГДА не удаляется этой очисткой (он — хранилище
    # ключей интерфейса и клиентов; фикс CLI-аудита: -q/-z без -c могли
    # снести серверный conf, лежащий в g_conf_dir).
    if g_main_config_fn is not None:
        keep_files.add(g_main_config_fn.name)
    for f in os.listdir(g_conf_dir):
        if allowed_names and not any(f.startswith(name) for name in allowed_names):
            continue
        if keep_conf and f.endswith('.conf'):
            keep_files.add(f)
        if keep_qr and f.endswith('.png'):
            keep_files.add(f)
        if keep_zip:
            if allowed_names:
                if any(f == f"{name}.zip" for name in allowed_names):
                    keep_files.add(f)
            elif f.endswith('.zip'):
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
parser.add_argument("-r", "--reload", action="store_true", help="Перезагрузить конфиг интерфейса без отключения (awg syncconf)")
parser.add_argument("-i", "--ipaddr", default="", help="IP адрес")
parser.add_argument("-p", "--port", type=int, default=4455, help="Порт")
parser.add_argument("-l", "--limit", type=int, default=0, help="Limit (Mbit)")
parser.add_argument("-f", "--iface", default="", help="Сетевой интерфейс (например ens3)")
parser.add_argument("-v", "--version", type=str, default="AWG2.0", choices=["WG", "AWG", "AWG1.0", "AWG1.5", "AWG2.0", "AWG3.0", "AWG3.1"], help="Версия протокола")
parser.add_argument("--make", dest="makecfg", default="", help="Создать серверный конфиг")
parser.add_argument("--mtu", type=int, default=1400, help="MTU")
parser.add_argument("--warp", type=int, default=0, help="WARP конфиги")
parser.add_argument("--proxy", default="", help="Proxy сервер для WARP API (например http://proxy:8080, socks5://127.0.0.1:9050, или 'tor')")
# При импорте модуля НЕ читаем sys.argv (баг 2.3): только дефолты.
# Реальный разбор аргументов выполняется в main().
opt = parser.parse_args([])


# ----------------- Нормализация прокси -----------------
def normalize_proxy(proxy: str) -> str:
    """
    Нормализует строку прокси:
    - 'tor' → 'socks5://127.0.0.1:9050'
    - '127.0.0.1:9050' → 'socks5://127.0.0.1:9050' (автоподстановка socks5://)
    - 'proxy:8080' → 'socks5://proxy:8080' (если нет схемы)
    - 'http://...' или 'socks5://...' → без изменений
    """
    if not proxy:
        return ""
    
    proxy = proxy.strip()
    
    # Алиас 'tor'
    if proxy.lower() == "tor":
        return "socks5://127.0.0.1:9050"
    
    # Если уже есть схема (http://, https://, socks4://, socks5://)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", proxy):
        return proxy
    
    # Нет схемы — подставляем socks5:// по умолчанию
    return f"socks5://{proxy}"


# Применяем нормализацию к прокси (дефолты при импорте; реальное значение — в main)
opt.proxy = normalize_proxy(opt.proxy)


def get_only_list() -> list[str]:
    if not opt.only:
        return []
    return [x.strip() for x in opt.only.split(",") if x.strip()]


def resolve_server_config_candidate(name: str | None) -> str | None:
    if not name:
        return None

    def resolve_file(p: pathlib.Path) -> str | None:
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


def get_main_config_path(check: bool = True, override: str | None = None) -> str | None:
    global g_main_config_fn
    
    if override:
        resolved = resolve_server_config_candidate(override)
        if resolved:
            g_main_config_fn = pathlib.Path(resolved)
            init_interface_paths(g_main_config_fn.stem)
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

    # Поддержка коротких имён: 10awg1, 10awg1.conf, /полный/путь
    resolved = resolve_server_config_candidate(str(g_main_config_fn))
    if resolved:
        g_main_config_fn = pathlib.Path(resolved)
    cfg_exists = g_main_config_fn.exists()
    
    if check and not cfg_exists:
        raise RuntimeError(f'Основной конфиг "{g_main_config_fn}" не найден')
        
    init_interface_paths(g_main_config_fn.stem)
    return str(g_main_config_fn)


def _handle_reload(override: str | None = None) -> None:
    """Перезагрузить конфиг работающего интерфейса без отключения (strip + syncconf)."""
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=override)
    if g_main_config_fn is None or not g_main_config_fn.exists():
        raise RuntimeError("Не найден серверный конфиг")

    tun = g_main_config_fn.stem
    temp_dir = g_main_config_fn.parent / ".data" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    # Уникальный temp-файл на процесс: параллельные -r не должны затирать
    # друг друга (аудит-20).
    temp_conf = temp_dir / f"{tun}.{os.getpid()}.conf"

    logger.info("🔄 Перезагрузка конфига %s без отключения...", tun)

    # Если интерфейс не запущен — предупреждаем и выходим ДО syncconf
    # (иначе awg syncconf падает с неоднозначной ошибкой)
    rc_if, _ = exec_cmd(["ip", "link", "show", tun])
    if rc_if != 0:
        logger.warning("⚠  Интерфейс %s не запущен — syncconf пропущен", tun)
        return

    try:
        # strip — приводим КОНФИГ-ФАЙЛ к формату wg setconf (по имени интерфейса
        # awg-quick ищет файл только в /etc/amnezia/amneziawg/, что ломало -r для
        # конфигов в произвольных путях; баг 1.11)
        with open(temp_conf, "w", encoding="utf-8") as f:
            os.chmod(str(temp_conf), 0o600)  # ключи/PSK в strip-выводе (фикс CLI-аудита)
            subprocess.run(
                ["awg-quick", "strip", str(g_main_config_fn)],
                stdout=f, stderr=subprocess.PIPE, text=True,
                check=True, timeout=15,
            )
        # syncconf — применяем новый конфиг на работающий интерфейс без отключения
        subprocess.run(
            ["awg", "syncconf", tun, str(temp_conf)],
            check=True, capture_output=True, text=True, timeout=30,
        )
        logger.info("✅ Конфиг %s обновлён", tun)
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        if "not found" in err.lower() or "does not exist" in err.lower() \
                or "no such device" in err.lower() or "unable to access" in err.lower():
            logger.warning("⚠  Интерфейс %s не запущен — syncconf пропущен", tun)
        else:
            logger.error("❌ Ошибка обновления конфига %s: %s", tun, err)
            raise
    finally:
        # Убираем временный конфиг (идемпотентно, при любом исходе)
        try:
            if temp_conf.exists():
                temp_conf.unlink()
        except OSError:
            pass


def _remove_files_by_suffix(directory: pathlib.Path, suffixes: tuple[str, ...]) -> None:
    """Удаляет файлы в директории, чьи имена заканчиваются на любой из suffixes."""
    if not directory.is_dir():
        return  # каталога нет (например, автономный WARP без -z) — нечего чистить
    for f in os.listdir(directory):
        if f.endswith(suffixes):
            try:
                os.remove(directory.joinpath(f))
            except Exception:
                pass


def main() -> None:
    # Реальный разбор аргументов CLI (при импорте модуля — только дефолты)
    global opt
    opt = parser.parse_args()
    opt.proxy = normalize_proxy(opt.proxy)

    # Проверка на Windows
    if sys.platform == "win32":
        logger.error("❌ Этот скрипт работает только на Linux. Windows не поддерживается.")
        sys.exit(1)

    if not (1280 <= opt.mtu <= 1440):
        raise ValueError("MTU должен быть в диапазоне 1280..1440")

    # Валидация порта и лимита (аудит-20: 0/70000/отрицательные шли в правила)
    if not (1 <= opt.port <= 65535):
        raise ValueError(f"Порт {opt.port} вне диапазона 1..65535")
    if opt.limit < 0:
        raise ValueError(f"Лимит {opt.limit} не может быть отрицательным")
    if opt.warp < 0:
        raise ValueError(f"--warp не может быть отрицательным ({opt.warp})")

    # Взаимоисключающие действия над клиентами
    actions = [x for x in (opt.addcl, opt.update, opt.delete) if x]
    if len(actions) >= 2:
        raise RuntimeError('Слишком много действий одновременно')
    if opt.makecfg and actions:
        raise RuntimeError('--make нельзя совмещать с -a/-u/-d')
    if opt.makecfg and (opt.confgen or opt.qrcode or opt.zip):
        # Фикс аудита-D1: -c/-q/-z при --make тихо не выполнялись
        logger.warning('⚠️  --make игнорирует -c/-q/-z (клиентские конфиги генерируются отдельно через -c)')

    if opt.reload:
        # Фикс аудита: -r молча побеждал остальные флаги — предупреждаем
        if opt.addcl or opt.update or opt.delete or opt.confgen or opt.qrcode or opt.zip:
            logger.warning('⚠️  -r (reload) игнорирует остальные флаги (-a/-u/-d/-c/-q/-z)')
        _handle_reload(override=opt.server_cfg)
        return

    want_conf = opt.confgen
    want_qr = opt.qrcode
    want_zip = opt.zip
    need_conf = want_conf or want_qr or want_zip
    need_qr = want_qr or (want_zip and not want_conf)

    # Автономная генерация WARP конфигов (без серверного интерфейса)
    if opt.warp > 0 and not opt.makecfg and not opt.server_cfg:
        # Фикс аудита-D1: молчаливые игнорируемые флаги в автономной ветке
        if opt.addcl or opt.update or opt.delete or opt.confgen or opt.only:
            logger.warning('⚠️  Автономный --warp игнорирует флаги -a/-u/-d/-c/-o')
        warp_configs = handle_warp_gen(opt)

        # QR для WARP через общую функцию (единый next_v)
        if need_qr:
            generate_qr_codes(
                qr_filter=None,
                warp_configs=warp_configs,
            )

        # ZIP для WARP через общий механизм
        if want_zip:
            zip_all(warp_configs=warp_configs)

        # Очистка лишних файлов после генерации (для WARP своя логика)
        warp_dir = SCRIPT_DIR.joinpath("WARP")

        # Для WARP: -z сохраняет только .zip, -q сохраняет .conf+.png, -c сохраняет .conf
        if want_zip and not opt.qrcode and not opt.confgen:
            # Только -z → удаляем .conf и .png
            _remove_files_by_suffix(warp_dir, ('.conf', '.png'))
        elif opt.qrcode and not want_zip and not opt.confgen:
            # Только -q → удаляем .zip (если есть)
            _remove_files_by_suffix(warp_dir, ('.zip',))
        # В остальных случаях оставляем всё

        return

    if opt.makecfg:
        handle_makecfg(opt)
        return

    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)

    actions_done = False
    if opt.addcl:
        handle_add(opt)
        actions_done = True
    if opt.update:
        handle_update(opt)
        actions_done = True
    if opt.delete:
        handle_delete(opt)
        actions_done = True
    # Фикс аудита: после -a/-u/-d не делаем return сразу — если запрошены
    # -c/-q/-z, продолжаем генерацию (раньше `-a bob -c` молча не генерировал).
    if actions_done and not (need_conf or need_qr or want_zip):
        return

    # Сначала генерируем конфиги (если нужно),
    # и получаем список имен для QR
    qr_filter = None
    if need_conf:
        qr_filter = handle_confgen(opt)

    if need_qr:
        generate_qr_codes(qr_filter)

    if want_zip:
        zip_all()

    # Очистка конфиг-каталога производится ТОЛЬКО при активных флагах
    # генерации (аудит-20: запуск без флагов удалял все клиентские файлы).
    if want_conf or want_qr or want_zip:
        only_list = get_only_list()
        allowed_names = None
        if only_list:
            allowed_names = clients_for_zip if clients_for_zip else only_list

        clean_confdir_types(
            # Ожидаемое поведение: клиентские .conf используются для QR/ZIP и
            # затем УДАЛЯЮТСЯ (остаются только png/zip); .conf остаются лишь
            # при -c. Серверный конфиг защищён отдельно (clean исключает его
            # по имени). Безопасность: clean выполняется только ПОСЛЕ успешной
            # генерации QR/zip — при сбое исключение прерывает поток раньше,
            # и свежие .conf сохраняются (не теряются с PrivateKey).
            keep_conf=want_conf,
            keep_qr=want_qr,
            keep_zip=want_zip,
            allowed_names=allowed_names
        )
    logger.info('✅ Готово')


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as e:
        # Ожидаемая ошибка: неудачная генерация WARP, неверные аргументы
        # CLI (порт/MTU/лимит/имя) и т.п. — аккуратное сообщение без traceback.
        logger.error("❌ %s", e)
        sys.exit(1)
    except Exception:
        # Неожиданная ошибка
        logger.exception("❌ Фатальная ошибка")
        sys.exit(1)
