#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AmneziaWG Helper Script
"""

from __future__ import annotations
import argparse
import base64
import datetime
import glob
import ipaddress
import logging
import math
import os
import pathlib
import random
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
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

try:
    import cryptography
except ImportError:
    cryptography = None

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
clients_for_zip: List[str] = []


# ----------------- Шаблоны -----------------

g_defserver_config = """# Protocol: <PROTOCOL>
[Interface]
#_GenKeyTime = <SERVER_KEY_TIME>
#_PublicKey = <SERVER_PUBLIC_KEY>
Address = <SERVER_ADDR>
ListenPort = <SERVER_PORT>
<JC_LINE><JMIN_LINE><JMAX_LINE><S1_LINE><S2_LINE><S3_LINE><S4_LINE><H1_LINE><H2_LINE><H3_LINE><H4_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE>MTU = <MTU>
PrivateKey = <SERVER_PRIVATE_KEY>

PostUp = bash <SERVER_UP_SCRIPT>
PostDown = bash <SERVER_DOWN_SCRIPT>
"""

g_defclient_config = """
[Interface]
Address = <CLIENT_TUNNEL_IP>
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
<JC_LINE><JMIN_LINE><JMAX_LINE><S1_LINE><S2_LINE><S3_LINE><S4_LINE><H1_LINE><H2_LINE><H3_LINE><H4_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE>MTU = <MTU>
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
<JC_LINE><JMIN_LINE><JMAX_LINE><I1_LINE><I2_LINE><I3_LINE><I4_LINE><I5_LINE><TABLE_LINE>MTU = <MTU>
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
BRIDGE="9999:10000mbit:4400"

# --- WARP маршрутизация ---
# "interface1[,interface2][=subnet1[,subnet2]]"
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
    python3 -c "
import ipaddress, sys
try:
    ip = ipaddress.ip_network('$1', strict=False)
    t4 = ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False) if '$LOCAL_SUBNETS_IPV4' else None
    t6 = ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False) if '$LOCAL_SUBNETS_IPV6' else None
    if (t4 and ip.overlaps(t4)) or (t6 and ip.overlaps(t6)):
        sys.exit(0)
    sys.exit(1)
except: sys.exit(1)
" 2>/dev/null
}

# Проверка: является ли IP адресом сети (network address)
is_network_address() {
    python3 -c "
import ipaddress, sys
try:
    ip = ipaddress.ip_address('$1')
    net = ipaddress.ip_network('$2', strict=False)
    print(1 if ip == net.network_address else 0)
except: print(0)
" 2>/dev/null
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
                    m = int(v, 0) if v.startswith('0x') else int(v)
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
    eval $(python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV4', strict=False)
    srv = ipaddress.ip_address('$LOCAL_SERVER_IP')
    print(f'BROADCAST_ADDR=\"{net.broadcast_address}\"')
    print(f'SERVER_ON_NETWORK={int(srv == net.network_address)}')
except Exception as e:
    print(f'echo \"❌ Ошибка расчёта IPv4: {e}\"; exit 1', file=sys.stderr)
    sys.exit(1)
")
}

# Проверка статуса IPv6 подсети
calc_ipv6_status() {
    eval $(python3 -c "
import ipaddress
try:
    net = ipaddress.ip_network('$LOCAL_SUBNETS_IPV6', strict=False)
    srv = ipaddress.ip_address('$LOCAL_SERVER_IP_IPV6')
    print(f'SERVER_ON_NETWORK_IPV6={int(srv == net.network_address)}')
except:
    print('SERVER_ON_NETWORK_IPV6=0')
")
}

# Валидация маски подсети для лимитов скорости
validate_subnet_mask() {
    python3 -c "
import ipaddress, sys
try:
    ip_str = '$1'.strip()
    net = ipaddress.ip_network(ip_str, strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        ok = 8 <= net.prefixlen <= 32
    else:
        # Для IPv6 разрешаем /96 до /128, но /112 допустима
        ok = 96 <= net.prefixlen <= 128
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f'Ошибка проверки подсети: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Расчёт broadcast адреса
get_broadcast_addr() {
    python3 -c "
import ipaddress
try:
    print(ipaddress.ip_network('$1', strict=False).broadcast_address)
except: pass
" 2>/dev/null
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
      overlaps=$(python3 -c "import ipaddress, sys; ip1 = ipaddress.ip_network('$target_subnet', strict=False); ip2 = ipaddress.ip_network('$subnet', strict=False); sys.exit(0 if ip1.overlaps(ip2) else 1)" 2>/dev/null)
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
      overlaps=$(python3 -c "import ipaddress, sys; ip1 = ipaddress.ip_network('$target_subnet', strict=False); ip2 = ipaddress.ip_network('$addr', strict=False); sys.exit(0 if ip1.overlaps(ip2) else 1)" 2>/dev/null)
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
    overlaps=$(python3 -c "import ipaddress, sys; ip1 = ipaddress.ip_network('$ip_or_subnet', strict=False); ip2 = ipaddress.ip_network('$tun_subnet', strict=False); sys.exit(0 if ip1.overlaps(ip2) else 1)" 2>/dev/null)
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
  local lock_dir="${ref_file}.d"
  local pid_file="$lock_dir/pid"
  local max_attempts=90
  local attempt=0
  
  acquire_lock() {
    if mkdir "$lock_dir" 2>/dev/null; then
      echo "$$" > "$pid_file"
      return 0
    fi
    return 1
  }
  
  check_and_cleanup_stale_lock() {
    local locked_pid
    locked_pid=$(cat "$pid_file" 2>/dev/null)
    
    if [ -z "$locked_pid" ]; then
      rm -rf "$lock_dir" 2>/dev/null || true
      return 1
    fi
    if ! kill -0 "$locked_pid" 2>/dev/null; then
      rm -rf "$lock_dir" 2>/dev/null || true
      return 1
    fi
    
    return 2
  }
  
  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))
    
    if acquire_lock; then
      trap 'rm -rf "$lock_dir" 2>/dev/null || true' EXIT INT TERM
      
      local result=""
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
      
      rm -rf "$lock_dir" 2>/dev/null || true
      echo "$result"
      return 0
    fi
    
    local check_result=0
    check_and_cleanup_stale_lock || check_result=$?
    
    if [ $check_result -eq 1 ]; then
      continue
    elif [ $check_result -eq 2 ]; then
      sleep 0.1
      continue
    fi
    
sleep 0.1
  done
   
  local locked_pid_final=$(cat "$pid_file" 2>/dev/null)
  echo "⚠️ Lock для $ref_file занят процессом $locked_pid_final — принудительное удаление" >&2
  rm -rf "$lock_dir" 2>/dev/null || true
  
  local result=""
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
  
  echo "$result"
  return 0
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
        print(f"# ⚠️ Внимание: {subnet} содержит {num_ips} адресов - это может занять время", file=sys.stderr)
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
    python3 -c "import ipaddress; print(ipaddress.ip_network('$1', strict=False))" 2>/dev/null
}

# Парсинг строки SUBNETS_LIMITS (subnet1,subnet2:LIM или subnet1:LIM_D:LIM_U или просто подсеть)
# Формат вывода: subnet|rate|type
#   type = "none" (нет лимита), "mix" (одно значение), "separate" (down:up)
parse_entry() {
  local entry="$1"
  python3 -c "
import sys
entry = sys.argv[1]
last_slash = entry.rfind('/')
rate_part = entry[last_slash+1:]
colon_pos = rate_part.find(':')
if colon_pos >= 0:
    prefix = rate_part[:colon_pos]
    subnet = entry[:last_slash] + '/' + prefix
    rate = rate_part[colon_pos+1:]
else:
    subnet = entry
    rate = ''
if not rate:
    print(f'{subnet}|{rate}|none')
elif ':' in rate:
    print(f'{subnet}|{rate}|separate')
else:
    print(f'{subnet}|{rate}|mix')
" "$entry"
}

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
  echo "$((1000 + (tun_hash % 900) * 10))"
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

  # Проверка ip rules с prio 100 (маршрутизация VPN трафика через TUN)
  echo "   📋 ip rules prio 100 (маршрутизация через TUN):"
  _ip4_rules=$(ip rule show 2>/dev/null | grep -E "^100:")
  if [ -n "$_ip4_rules" ]; then
    echo "   ✅ IPv4:"
    echo "$_ip4_rules" | while IFS= read -r _rline; do echo "        $_rline"; done
  else
    echo "   ❌ IPv4: правила prio 100 не созданы"
  fi
  _ip6_rules=$(ip -6 rule show 2>/dev/null | grep -E "^100:")
  if [ -n "$_ip6_rules" ]; then
    echo "   ✅ IPv6:"
    echo "$_ip6_rules" | while IFS= read -r _rline; do echo "        $_rline"; done
  else
    echo "   ❌ IPv6: правила prio 100 не созданы"
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

  echo "═══════════════════════════════════════════════════════════"
  echo "✅ Проверка завершена"
  echo "═══════════════════════════════════════════════════════════"
  echo ""
  echo "📄 Лог сохранён: $LOG_FILE"
fi
'''

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################


# Шаблоны up/down с поддержкой WARP, пробросов портов и лимитов скорости
up_script_template_warp = r'''#!/bin/bash

# --- Опеределение пути и имени---
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

# rp_filter settings for proper WireGuard operation
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

if [ -n "$LOCAL_SUBNETS_IPV6" ]; then
  LOCAL_SERVER_IP_IPV6="$(echo "$LOCAL_SUBNETS_IPV6" | cut -d'/' -f1)"
  calc_ipv6_status

  if [ "$SERVER_ON_NETWORK_IPV6" -eq 1 ]; then
    echo "📍 IPv6: Сервер на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast НЕ работает"
  else
    echo "📍 IPv6: Сервер НЕ на network адресе ($LOCAL_SERVER_IP_IPV6) — multicast работает"
  fi
fi

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
# Диапазон MARK: 1000-9990 (максимум 900 уникальных значений для tc)
MARK_BASE=$(calc_mark_base "$TUN")

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
    if awg-quick up "$warp" 2>/dev/null; then
      atomic_ref_update "$WARP_REF_FILE" "set" "1" >/dev/null
      echo "✅ WARP $warp запущен (ref=1)"
    else
      echo "❌ Ошибка запуска $warp: $?"
    fi
  elif [ "$WARP_RUNNING" -eq 0 ] && [ -f "$WARP_REF_FILE" ]; then
    # Случай 2: Нет интерфейса + Есть .ref → Запускаем интерфейс, пересоздаём .ref=1
    ref_count=$(atomic_ref_update "$WARP_REF_FILE" "get")
    echo "🔧 Перезапуск WARP: $warp (интерфейс не активен, ref=$ref_count)"
    if awg-quick up "$warp" 2>/dev/null; then
      atomic_ref_update "$WARP_REF_FILE" "set" "1" >/dev/null
      echo "✅ WARP $warp перезапущен (ref=1)"
    else
      echo "❌ Ошибка запуска $warp: $?"
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
  
  # Применяем все исключения
  if [ ${#ALL_WARP_EXCLUSIONS[@]} -gt 0 ]; then
    echo "🔒 Исключение ${#ALL_WARP_EXCLUSIONS[@]} IP/подсетей из WARP (локальная сеть + none=)"
    for subnet in "${ALL_WARP_EXCLUSIONS[@]}"; do
      # Определяем тип подсети (IPv4 или IPv6) и применяем правило только к нужной таблице
      if [[ "$subnet" == *:* ]]; then
        # IPv6 подсеть — применяем только к ip6tables
        ip6tables -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d "$subnet" -j RETURN 2>/dev/null || true
      else
        # IPv4 подсеть — применяем только к iptables
        iptables -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d "$subnet" -j RETURN 2>/dev/null || true
      fi
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
    # Создаём правила для ОБЕИХ версий IP (IPv4 и IPv6)

    if [ "$HAS_SUBNETS" -eq 1 ] && [ ${#SUBNET_GROUP[@]} -gt 0 ]; then
      # --- Трафик на конкретные подсети через эту группу WARP ---
      for subnet in "${SUBNET_GROUP[@]}"; do
        # Определяем тип подсети и применяем правило только к нужной таблице
        if [[ "$subnet" == *:* ]]; then
          # IPv6 подсеть — применяем только к ip6tables
          for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
            MARK=$((MARK_BASE + MARK_OFFSET + i))
            ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -m conntrack --ctstate NEW \
              -m statistic --mode nth --every $WARP_GROUP_COUNT --packet $i \
              -j CONNMARK --set-mark $MARK
          done
        else
          # IPv4 подсеть — применяем только к iptables
          for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
            MARK=$((MARK_BASE + MARK_OFFSET + i))
            iptables -t mangle -A "$RANDOM_WARP_CHAIN" -d "$subnet" -m conntrack --ctstate NEW \
              -m statistic --mode nth --every $WARP_GROUP_COUNT --packet $i \
              -j CONNMARK --set-mark $MARK
          done
        fi
      done
    fi

    # Увеличиваем MARK_OFFSET для следующей группы
    MARK_OFFSET=$((MARK_OFFSET + WARP_GROUP_COUNT))
  done

  # --- Обработка всех интерфейсов БЕЗ подсетей (для всего остального трафика) ---
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    # Сначала создаём RETURN для всех специфичных подсетей (IPv4 и IPv6) - В НАЧАЛО цепи!
    for subnet in "${ALL_SPECIFIC_SUBNETS[@]}"; do
      # Определяем тип подсети (IPv4 или IPv6) и применяем правило только к нужной таблице
      if [[ "$subnet" == *:* ]]; then
        # IPv6 подсеть — применяем только к ip6tables
        ip6tables -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d "$subnet" -j RETURN 2>/dev/null || true
      else
        # IPv4 подсеть — применяем только к iptables
        iptables -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d "$subnet" -j RETURN 2>/dev/null || true
      fi
    done

    # Балансировка для всего остального трафика между ВСЕМИ интерфейсами без подсетей
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      # IPv4 маркировка
      iptables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW \
        -m statistic --mode nth --every $DEFAULT_WARP_COUNT --packet $i \
        -j CONNMARK --set-mark $MARK
      # IPv6 маркировка
      ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW \
        -m statistic --mode nth --every $DEFAULT_WARP_COUNT --packet $i \
        -j CONNMARK --set-mark $MARK
    done
    MARK_OFFSET=$((MARK_OFFSET + DEFAULT_WARP_COUNT))
  fi

  # --- Восстанавливаем mark для всех пакетов ---
  iptables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark
  ip6tables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark

  # --- Добавляем ip rule для каждого MARK -> TABLE ---
  # Обрабатываем ВСЕ записи WARP_LIST (и с подсетями и без)
  # MARK для записей с подсетями идут первыми, потом для записей без подсетей
  WARP_MARK_OFFSET=0
  
  # Сначала обрабатываем записи С подсетями
  for entry in "${WARP_LIST[@]}"; do
    if [ "$entry" = "none" ] || [ -z "$entry" ]; then
      continue
    fi

    # Разбираем запись
    if [[ "$entry" == *"="* ]]; then
      interfaces_part="${entry%%=*}"
    else
      continue  # Записи без подсетей обрабатываем ниже
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

    WARP_MARK_OFFSET=$((WARP_MARK_OFFSET + WARP_GROUP_COUNT))
  done
  
  # Теперь обрабатываем записи БЕЗ подсетей (DEFAULT_WARP_GROUP)
  # Они используют те же MARK что и при маркировке
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + WARP_MARK_OFFSET + i))
      warp_iface="${DEFAULT_WARP_GROUP[$i]}"
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
  fi

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
# ВАЖНО: Проверяем что ссылка ещё не добавлена (защита от дубликатов!)
iptables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || iptables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -C PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || ip6tables -t nat -A PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true

# FORWARD и POSTROUTING для текущего туннеля
# ВАЖНО: Проверяем что ссылка ещё не добавлена (защита от дубликатов!)
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
# Работает ТОЛЬКО если сервер НЕ занимает ПЕРВЫЙ IP в подсети
# Broadcast/Multicast разрешается ТОЛЬКО между участниками ОДНОЙ группы LAN_ALLOW
# Используем mark для полной изоляции — broadcast доходит только до участников группы
# Mark уникальны для каждого туннеля (на основе MARK_BASE) чтобы избежать коллизий
# Диапазон: MARK_BASE+1000 до MARK_BASE+1099 (не пересекается с WARP mark)

# IPv4 Broadcast
if [ -n "$LOCAL_SUBNETS_IPV4" ] && [ -n "$BROADCAST_ADDR" ] && [ "$SERVER_ON_NETWORK" -eq 0 ]; then
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

      # Если в группе есть IPv4 участники — настраиваем broadcast
      if [ ${#IPV4_PARTS[@]} -gt 0 ]; then
        [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
        # 1. Маркируем broadcast от каждого участника группы (накапливаем биты через --or-mark)
        for src in "${IPV4_PARTS[@]}"; do
          iptables -t mangle -A FORWARD -i "$TUN" -s "$src" -d "$BROADCAST_ADDR" -j MARK --or-mark $BIT 2>/dev/null || true
          iptables -t mangle -A FORWARD -i "$TUN" -s "$src" -d 255.255.255.255 -j MARK --or-mark $BIT 2>/dev/null || true
        done

        # 2. Разрешаем получать broadcast ТОЛЬКО участникам этой группы
        # --mark BIT/BIT проверяет только свой бит, остальные игнорирует
        for dst in "${IPV4_PARTS[@]}"; do
          iptables -I FORWARD -i "$TUN" -o "$TUN" -m mark --mark $BIT/$BIT -d "$dst" -j ACCEPT 2>/dev/null || true
        done
      fi

      GROUP_IDX=$((GROUP_IDX + 1))
    done
    
    # DROP не нужен — если mark не разрешён через ACCEPT, он блокируется автоматически
fi

# IPv6 Multicast (работает аналогично IPv4 broadcast)
# ff02::1 - all nodes multicast (аналог 255.255.255.255)
# Используем mark для полной изоляции — multicast доходит только до участников группы
# Используем ТЕ ЖЕ mark что и для IPv4 (на основе MARK_BASE), так как это разные таблицы (ip6tables)
# ВАЖНО: Multicast работает ТОЛЬКО если сервер НЕ на network адресе (как и broadcast)
# ВАЖНО: MARK должен увеличиваться для КАЖДОЙ группы чтобы быть синхронным с down.sh
if [ -n "$LOCAL_SUBNETS_IPV6" ] && [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
    GROUP_IDX=0
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
        [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
        # 1. Маркируем multicast от каждого участника группы (накапливаем биты через --or-mark)
        for src in "${IPV6_PARTS[@]}"; do
          ip6tables -t mangle -A FORWARD -i "$TUN" -s "$src" -d "ff02::1" -j MARK --or-mark $BIT 2>/dev/null || true
        done

        # 2. Разрешаем получать multicast ТОЛЬКО участникам этой группы
        for dst in "${IPV6_PARTS[@]}"; do
          ip6tables -I FORWARD -i "$TUN" -o "$TUN" -m mark --mark $BIT/$BIT -d "$dst" -j ACCEPT 2>/dev/null || true
        done
      fi

      GROUP_IDX=$((GROUP_IDX + 1))
    done
fi

# --- Добавление правил для каждого проброса ---

# Обработка правил проброски портов
declare -A GLOBAL_SNAT_RULES_ADDED
for rule in "${PORT_FORWARDING_RULES[@]}"; do

  # Разбор правила: новый формат CLIENT_IP:PORT[>PORT]:PROTO[:FLAGS][:SUBNETS]
  # FLAGS: SNAT,интерфейс или интерфейс,SNAT (порядок не важен)
  # Подсети через : (содержат /)

  # Ищем подсети (содержат /) — они всегда в конце
  ALLOWED_SUBNETS=""
  MAIN_PART="$rule"

  if [[ "$rule" == *"/"* ]]; then
    # Находим последнюю часть с / и всё после неё — подсети
    # Разделяем по : и ищем первую часть с /
    IFS=':' read -ra rule_parts <<< "$rule"
    MAIN_PART=""
    SUBNET_START=0
    for i in "${!rule_parts[@]}"; do
      if [[ "${rule_parts[$i]}" == *"/"* ]]; then
        SUBNET_START=$i
        break
      fi
    done

    # Собираем MAIN_PART (всё до подсетей)
    for ((i=0; i<SUBNET_START; i++)); do
      if [ $i -gt 0 ]; then
        MAIN_PART+=":"
      fi
      MAIN_PART+="${rule_parts[$i]}"
    done

    # Собираем ALLOWED_SUBNETS (всё с подсетями)
    for ((i=SUBNET_START; i<${#rule_parts[@]}; i++)); do
      if [ $i -gt $SUBNET_START ]; then
        ALLOWED_SUBNETS+=":"
      fi
      ALLOWED_SUBNETS+="${rule_parts[$i]}"
    done

    # Удаляем trailing ':' из MAIN_PART (от обработки '::')
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
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
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
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -j ACCEPT
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
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PORT_NUM" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:INT_PORT:PROTO (используем внутренний порт!)
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
              if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
                $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
                GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
              fi
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -j ACCEPT
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
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -s "$ALLOWED_SUBNET" -j ACCEPT
              $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT_NUM" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
            done
          else
            $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PORT_NUM"
            # SNAT добавляем только один раз для комбинации CLIENT_IP:PORT_NUM:PROTO
            snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PORT_NUM}:${PF_PROTO}"
            if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
              $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT_NUM" -j SNAT --to-source "$SERVER_IP"
              GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
            fi
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT_NUM" -j ACCEPT
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
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
            $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
          done
        else
          $IPT_CMD -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" $IFACE_OPT --dport "$PF_PORT_EXT" -j DNAT --to-destination "$CLIENT_IP_DNAT:$PF_PORT_INT"
          # SNAT добавляем только один раз для комбинации CLIENT_IP:PF_PORT_INT:PROTO
          snat_key="${SNAT_IP_PREFIX}${CLIENT_IP}:${PF_PORT_INT}:${PF_PROTO}"
          if [ "$(echo "$SNAT_FLAG" | tr '[:lower:]' '[:upper:]')" = "SNAT" ] && [ -n "$SERVER_IP" ] && [ -z "${GLOBAL_SNAT_RULES_ADDED[$snat_key]}" ]; then
            $IPT_CMD -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$SERVER_IP"
            GLOBAL_SNAT_RULES_ADDED[$snat_key]=1
          fi
          $IPT_CMD -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -j ACCEPT
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

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
# Применяется только если SUBNETS_LIMITS не пустой
# Примечание: для больших подсетей (/16 и больше) этот цикл может работать долго
# Если лимит = 0 для подсети — эта подсеть пропускается (лимит отключен)
# Формат: "subnet:rate" или "subnet:rate_in:rate_out" или "subnet" (без лимита)
# ВАЖНО: валидация через validate_subnet_mask() которая уже есть в скрипте!
if [ ${#SUBNETS_LIMITS[@]} -gt 0 ]; then
  echo "⚡ Настройка лимитов скорости"
  
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
      _rate="${_rate//[kmgtpKMGTP:]/}"
      case "$_rate" in
        ''|*[!0-9]*) ;;
        *) HAS_ACTIVE_LIMIT=1; break ;;
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

  # Удаляем ip rules с prio 100
  ip rule del from "$TUN_SUBNET4" table main prio 100 2>/dev/null || true
  ip rule del to "$TUN_SUBNET4" table main prio 100 2>/dev/null || true
  ip -6 rule del from "$TUN_SUBNET6" table main prio 100 2>/dev/null || true
  ip -6 rule del to "$TUN_SUBNET6" table main prio 100 2>/dev/null || true

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

  tc qdisc add dev "$TUN" root handle 1: htb
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
              _needs_out=1
              _up="${_rate##*:}"
              if [ "$_up" != "0" ]; then
                  _needs_in=1
              fi
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
  _rest="${BRIDGE#*:}"
  MAX_CLIENTS_PER_HIERARCHY="${BRIDGE%%:*}"
  BRIDGE_RATE="${_rest%%:*}"
  QUANT="${_rest##*:}"

  # Отдельные счётчики для каждого IFB
  _mix_client_num=0
  _out_client_num=0
  _in_client_num=0

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

      # Добавляем фильтры на root 1: для маршрутизации в указанный мост
      # DST матч — для download трафика (пакет на IFB имеет dst=клиент VPN)
      tc filter add dev "$_ifb" parent 1: protocol $_proto prio $_current_root_prio u32 match $_match dst "$_sub" flowid $_major 2>/dev/null || true
      # SRC матч — для upload трафика (пакет на IFB имеет src=клиент VPN)
      tc filter add dev "$_ifb" parent 1: protocol $_proto prio $_current_root_prio u32 match $_match src "$_sub" flowid $_major 2>/dev/null || true
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
    tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
    tc filter add dev "$TUN" parent 1: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
    tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
    tc filter add dev "$TUN" parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
  fi
  if [ "$_needs_out" = "1" ]; then
    tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT" 2>/dev/null || true
    tc filter add dev "$TUN" parent 1: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT" 2>/dev/null || true
  fi
  if [ "$_needs_in" = "1" ]; then
    tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN" 2>/dev/null || true
    tc filter add dev "$TUN" parent ffff: protocol ipv6 u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN" 2>/dev/null || true
  fi

  echo "📊 Установка лимитов скорости для подсетей"

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
            # MIX: оба направления на IFB_MIX
            tc filter add dev "$TUN" parent 1: protocol $_mirred_proto u32 match $_mirred_match dst "$_mirred_sub" action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
            tc filter add dev "$TUN" parent ffff: protocol $_mirred_proto u32 match $_mirred_match src "$_mirred_sub" action mirred egress redirect dev "$IFB_MIX" 2>/dev/null || true
        else
            # Separate: OUT на parent 1: (egress=download=dst), IN на parent ffff: (ingress=upload=src)
            if [ "$_create_down" = "1" ]; then
                tc filter add dev "$TUN" parent 1: protocol $_mirred_proto u32 match $_mirred_match dst "$_mirred_sub" action mirred egress redirect dev "$IFB_OUT" 2>/dev/null || true
            fi
            if [ "$_create_up" = "1" ]; then
                tc filter add dev "$TUN" parent ffff: protocol $_mirred_proto u32 match $_mirred_match src "$_mirred_sub" action mirred egress redirect dev "$IFB_IN" 2>/dev/null || true
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

      # Принудительный перенос на новую иерархию для каждого правила
      # Это разносит разные правила SUBNETS_LIMITS по разным иерархиям
      _mix_client_num=0
      _mix_major=$((_mix_major + 1))
      _mix_minor=1
      create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"

      # Одна подсеть = 1 класс на КАЖДЫЙ IP (без маскирования!)
      IPS=$(list_subnet_ips "$SUBNET")

      # Принудительный перенос на новую иерархию для separate режима (ОДИН раз на правило)
      if [ "$_rule_type" != "mix" ]; then
          _out_client_num=0
          _out_major=$((_out_major + 1))
          _out_minor=1
          create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
          _in_client_num=0
          _in_major=$((_in_major + 1))
          _in_minor=1
          create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
      fi

      for ip in $IPS; do
          if [ "$_rule_type" = "mix" ]; then
              _mix_client_num=$((_mix_client_num + 1))
              _mix_major=$((_mix_major + (_mix_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
              _mix_minor=$(((_mix_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
              if [ "$_mix_major" -gt 2 ] && [ "$_mix_minor" -eq 1 ]; then
                  create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
              fi
              _classid="${_mix_major}:${_mix_minor}"
              _major="${_mix_major}:"

              if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                  tc class add dev "$IFB_MIX" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 1 u32 match ip6 dst $ip flowid $_classid 2>/dev/null || true
                      tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 1 u32 match ip6 src $ip flowid $_classid 2>/dev/null || true
                  else
                      tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip dst $ip flowid $_classid 2>/dev/null || true
                      tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip src $ip flowid $_classid 2>/dev/null || true
                  fi
                  tc qdisc add dev "$IFB_MIX" parent $_classid fq_codel 2>/dev/null || true
              fi
          else
              _out_client_num=$((_out_client_num + 1))
              _out_major=$((_out_major + (_out_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
              _out_minor=$(((_out_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
              if [ "$_out_major" -gt 2 ] && [ "$_out_minor" -eq 1 ]; then
                  create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
              fi
              _classid="${_out_major}:${_out_minor}"
              _major="${_out_major}:"

              if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                  tc class add dev "$IFB_OUT" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      # OUT на parent 1: (egress) = download = dst клиента
                      tc filter add dev "$IFB_OUT" protocol ipv6 parent ${_out_major}: prio 1 u32 match ip6 dst $ip flowid $_classid 2>/dev/null || true
                  else
                      tc filter add dev "$IFB_OUT" protocol ip parent ${_out_major}: prio 1 u32 match ip dst $ip flowid $_classid 2>/dev/null || true
                  fi
                  tc qdisc add dev "$IFB_OUT" parent $_classid fq_codel 2>/dev/null || true
              fi

              _in_client_num=$((_in_client_num + 1))
              _in_major=$((_in_major + (_in_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
              _in_minor=$(((_in_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
              if [ "$_in_major" -gt 2 ] && [ "$_in_minor" -eq 1 ]; then
                  create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
              fi
              _classid="${_in_major}:${_in_minor}"
              _major="${_in_major}:"

              if [ "$_create_up" = "1" ] && [ "$_orig_up" != "0" ]; then
                  tc class add dev "$IFB_IN" parent $_major classid $_classid htb rate "${LIM_UP}"mbit ceil "${LIM_UP}"mbit quantum "$QUANT" 2>/dev/null || true
                  if [ "$IP_VERSION" = "ipv6" ]; then
                      # IN на parent ffff: (ingress) = upload = src клиента
                      tc filter add dev "$IFB_IN" protocol ipv6 parent ${_in_major}: prio 1 u32 match ip6 src $ip flowid $_classid 2>/dev/null || true
                  else
                      tc filter add dev "$IFB_IN" protocol ip parent ${_in_major}: prio 1 u32 match ip src $ip flowid $_classid 2>/dev/null || true
                  fi
                  tc qdisc add dev "$IFB_IN" parent $_classid fq_codel 2>/dev/null || true
              fi
          fi
      done
      if [ "$_rule_type" = "mix" ]; then
          echo "⚡ $SUBNET -> ${_orig_down}mbit (MIX)"
      else
          echo "⚡ $SUBNET -> ↓${_orig_down}mbit ↑${_orig_up}mbit"
      fi
  else
      # Принудительный перенос на новую иерархию для каждого правила
      # Это разносит разные правила SUBNETS_LIMITS по разным иерархиям
      _mix_client_num=0
      _mix_major=$((_mix_major + 1))
      _mix_minor=1
      create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
      if [ "$_rule_type" != "mix" ]; then
          _out_client_num=0
          _out_major=$((_out_major + 1))
          _out_minor=1
          create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
          _in_client_num=0
          _in_major=$((_in_major + 1))
          _in_minor=1
          create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
      fi

      # Несколько подсетей — поддерживаем кратные соотношения
      # MULTIPLIER из Bash передаётся как параметр
      RATIO_INFO=$(calc_subnet_ratios "$SUBNETS_PART" "$SUBNETS_LIMITS_STR")
          NUM_CLASSES=$(echo "$RATIO_INFO" | cut -d'|' -f1)

          # Подсчёт общего количества классов
          if [ "$_rule_type" = "mix" ]; then
              _total_classes="$NUM_CLASSES"
          else
              _total_classes=0
              [ "$_create_down" = "1" ] && _total_classes=$((_total_classes + NUM_CLASSES))
              [ "$_create_up" = "1" ] && _total_classes=$((_total_classes + NUM_CLASSES))
          fi

for idx in $(seq 0 $((NUM_CLASSES - 1))); do
                if [ "$_rule_type" = "mix" ]; then
                    _mix_client_num=$((_mix_client_num + 1))
                    _mix_major=$((_mix_major + (_mix_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
                    _mix_minor=$(((_mix_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
                    if [ "$_mix_major" -gt 2 ] && [ "$_mix_minor" -eq 1 ]; then
                        create_tc_hierarchy_for "$IFB_MIX" "$_mix_major" "$SUBNETS_PART"
                    fi
                    _classid="${_mix_major}:${_mix_minor}"
                    _major="${_mix_major}:"

                    if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                        tc class add dev "$IFB_MIX" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi
                else
                    _out_client_num=$((_out_client_num + 1))
                    _out_major=$((_out_major + (_out_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
                    _out_minor=$(((_out_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
                    if [ "$_out_major" -gt 2 ] && [ "$_out_minor" -eq 1 ]; then
                        create_tc_hierarchy_for "$IFB_OUT" "$_out_major" "$SUBNETS_PART"
                    fi
                    _classid="${_out_major}:${_out_minor}"
                    _major="${_out_major}:"

                    if [ "$_create_down" = "1" ] && [ "$_orig_down" != "0" ]; then
                        tc class add dev "$IFB_OUT" parent $_major classid $_classid htb rate "${LIM_DOWN}"mbit ceil "${LIM_DOWN}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi

                    _in_client_num=$((_in_client_num + 1))
                    _in_major=$((_in_major + (_in_client_num - 1) / MAX_CLIENTS_PER_HIERARCHY))
                    _in_minor=$(((_in_client_num - 1) % MAX_CLIENTS_PER_HIERARCHY + 1))
                    if [ "$_in_major" -gt 2 ] && [ "$_in_minor" -eq 1 ]; then
                        create_tc_hierarchy_for "$IFB_IN" "$_in_major" "$SUBNETS_PART"
                    fi
                    _classid="${_in_major}:${_in_minor}"
                    _major="${_in_major}:"

                    if [ "$_create_up" = "1" ] && [ "$_orig_up" != "0" ]; then
                        tc class add dev "$IFB_IN" parent $_major classid $_classid htb rate "${LIM_UP}"mbit ceil "${LIM_UP}"mbit quantum "$QUANT" 2>/dev/null || true
                    fi
                fi

                i=0
                for sub_info in $(echo "$RATIO_INFO" | cut -d'|' -f2-); do
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
                                  tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 dst $BLOCK_BASE flowid $_classid 2>/dev/null || true
                                  tc filter add dev "$IFB_MIX" protocol ipv6 parent ${_mix_major}: prio 2 u32 match ip6 src $BLOCK_BASE flowid $_classid 2>/dev/null || true
                              else
                                  tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip dst $BLOCK_BASE flowid $_classid 2>/dev/null || true
                                  tc filter add dev "$IFB_MIX" protocol ip parent ${_mix_major}: prio 1 u32 match ip src $BLOCK_BASE flowid $_classid 2>/dev/null || true
                              fi
                          fi
                      else
                          if [ "$_create_down" = "1" ]; then
                              # OUT на parent 1: (egress) = download = dst клиента
                              if [ "$ip_type" = "ipv6" ]; then
                                  tc filter add dev "$IFB_OUT" protocol ipv6 parent ${_out_major}: prio 2 u32 match ip6 dst $BLOCK_BASE flowid $_classid 2>/dev/null || true
                              else
                                  tc filter add dev "$IFB_OUT" protocol ip parent ${_out_major}: prio 1 u32 match ip dst $BLOCK_BASE flowid $_classid 2>/dev/null || true
                              fi
                          fi
                          if [ "$_create_up" = "1" ]; then
                              # IN на parent ffff: (ingress) = upload = src клиента
                              if [ "$ip_type" = "ipv6" ]; then
                                  tc filter add dev "$IFB_IN" protocol ipv6 parent ${_in_major}: prio 2 u32 match ip6 src $BLOCK_BASE flowid $_classid 2>/dev/null || true
                              else
                                  tc filter add dev "$IFB_IN" protocol ip parent ${_in_major}: prio 1 u32 match ip src $BLOCK_BASE flowid $_classid 2>/dev/null || true
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
              echo "⚡ $SUBNETS_PART -> ${_orig_down}mbit (MIX) (${_total_classes} классов)"
          else
              echo "⚡ $SUBNETS_PART -> ↓${_orig_down}mbit ↑${_orig_up}mbit (${_total_classes} классов)"
          fi
        fi
    done
    echo "✅ Лимиты скорости настроены"
  fi
fi
echo "————————————————————————————————"

exit 0
'''

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################

#####################################################################################################################################################################################


down_script_template_warp = r'''#!/bin/bash

# --- Опеределение пути и имени ---
DOWN_SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$DOWN_SCRIPT_PATH")"
SCRIPT_NAME="$(basename "$DOWN_SCRIPT_PATH" down.sh)"

# --- Чтение параметров из файла сохранённого up.sh ---
STATE_BASE_DIR="$SCRIPT_DIR/.data"
TUNNELS_STATE_DIR="$STATE_BASE_DIR/temp"
TUNNEL_PARAMS_FILE="$TUNNELS_STATE_DIR/${SCRIPT_NAME}.sh"

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

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
# Должен совпадать с расчётом из up скрипта (диапазон 1000-9990)
if command -v calc_mark_base &>/dev/null 2>/dev/null; then
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
  MARK_BASE=$((1000 + (TUN_HASH % 900) * 10))
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

  # Проверяем .ref файл
  if [ -f "$WARP_REF_FILE" ]; then
    ref_count=$(atomic_ref_update "$WARP_REF_FILE" "get")

    if [ "$ref_count" -le 1 ]; then
      # Последний пользователь — закрываем WARP (если он запущен)
      STOPPED_WARP_ZERO_REFS["$warp"]=1
      if [ "$WARP_RUNNING" -eq 1 ]; then
        if awg-quick down "$warp" 2>/dev/null; then
          : # WARP остановлен
        else
          echo "Ошибка остановки $warp: $?"
        fi
      else
        echo "⚠️  WARP $warp не запущен (ref=$ref_count) — очистка..."
      fi

      # Очищаем таблицу маршрутизации (только если последний пользователь)
      TABLE_ID=$(awk -v name="$warp" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
      if [ -n "$TABLE_ID" ]; then
        ip route flush table "$TABLE_ID" 2>/dev/null || true
        sed -i "/^${TABLE_ID}[[:space:]]\+${warp}$/d" /etc/iproute2/rt_tables 2>/dev/null || true
        echo "🗑️  Таблица маршрутизации $warp (ID $TABLE_ID) очищена"
      fi

      rm -f "$WARP_REF_FILE"
    else
      # Уменьшаем счётчик — таблица остаётся для других
      new_count=$(atomic_ref_update "$WARP_REF_FILE" "dec")
      echo "📋 WARP $warp используется другими туннелями (ref=$ref_count → $new_count)"
    fi
  else
    # .ref нет — проверяем запущен ли WARP и закрываем если да
    STOPPED_WARP_ZERO_REFS["$warp"]=1
    if [ "$WARP_RUNNING" -eq 1 ]; then
      echo "⚠️  WARP $warp запущен но .ref не найден — очистка..."
      if awg-quick down "$warp" 2>/dev/null; then
        : # WARP остановлен
      else
        echo "Ошибка остановки $warp: $?"
      fi

      # Очищаем таблицу маршрутизации
      TABLE_ID=$(awk -v name="$warp" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
      if [ -n "$TABLE_ID" ]; then
        ip route flush table "$TABLE_ID" 2>/dev/null || true
        sed -i "/^${TABLE_ID}[[:space:]]\+${warp}$/d" /etc/iproute2/rt_tables 2>/dev/null || true
        echo "🗑️  Таблица маршрутизации $warp (ID $TABLE_ID) очищена"
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

# Удаляем файлы активности WARP для всех остановленных интерфейсов
# (простое и надёжное решение - как в старой версии)
for warp in "${!STOPPED_WARP_INTERFACES[@]}"; do
  rm -f "$STATE_BASE_DIR/warp/${warp}.active" 2>/dev/null || true
done

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

    # Удаляем ip rule для каждого MARK в группе (IPv4 и IPv6)
    for i in $(seq 0 $((WARP_GROUP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${WARP_GROUP[$i]}"
      # Получаем TABLE_ID из rt_tables (так же как в up.sh)
      TABLE_ID=$(awk -v name="$warp_iface" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
      if [ -n "$TABLE_ID" ]; then
        # Удаляем IPv4 правило
        ip rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        # Удаляем IPv6 правило
        ip -6 rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        # Удаляем маршрут
        ip route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
        ip -6 route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
      else
        # Fallback: пробуем удалить по имени интерфейса
        ip rule del fwmark $MARK table "$warp_iface" 2>/dev/null || true
        ip -6 rule del fwmark $MARK table "$warp_iface" 2>/dev/null || true
        ip route del default dev "$warp_iface" table "$warp_iface" 2>/dev/null || true
        ip -6 route del default dev "$warp_iface" table "$warp_iface" 2>/dev/null || true
      fi
    done

    MARK_OFFSET=$((MARK_OFFSET + WARP_GROUP_COUNT))
  done

  # --- Удаляем ip rule для интерфейсов БЕЗ подсетей (IPv4 и IPv6) ---
  DEFAULT_WARP_COUNT=${#DEFAULT_WARP_GROUP[@]}
  if [ "$DEFAULT_WARP_COUNT" -gt 0 ]; then
    for i in $(seq 0 $((DEFAULT_WARP_COUNT-1))); do
      MARK=$((MARK_BASE + MARK_OFFSET + i))
      warp_iface="${DEFAULT_WARP_GROUP[$i]}"
      # Получаем TABLE_ID из rt_tables
      TABLE_ID=$(awk -v name="$warp_iface" '$2==name{print $1; exit}' /etc/iproute2/rt_tables 2>/dev/null)
      if [ -n "$TABLE_ID" ]; then
        # Удаляем IPv4 правило
        ip rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        # Удаляем IPv6 правило
        ip -6 rule del fwmark $MARK table "$TABLE_ID" 2>/dev/null || true
        # Удаляем маршрут
        ip route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
        ip -6 route del default dev "$warp_iface" table "$TABLE_ID" 2>/dev/null || true
      fi
    done
  fi
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
# УЖЕ очищенО в блоке выше (строки 3050-3059) — НЕ дублируем!

# --- Удаляем Hairpin NAT (IPv4 + IPv6) ---
iptables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
iptables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
iptables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true

ip6tables -t nat -D POSTROUTING -j "$HAIRPIN_CHAIN" 2>/dev/null || true
ip6tables -t nat -F "$HAIRPIN_CHAIN" 2>/dev/null || true
ip6tables -t nat -X "$HAIRPIN_CHAIN" 2>/dev/null || true

# --- Очистка broadcast/multicast правил (mangle + filter) ---
# Очищаем mark правила для broadcast (IPv4) и multicast (IPv6)
# Используем MARK_BASE для расчёта mark (так же как в up.sh)
# Диапазон: MARK_BASE+1000 до MARK_BASE+1099 (не пересекается с WARP mark)
# ВАЖНО: Правила созданы БЕЗ -i/-o, поэтому удаляем БЕЗ интерфейсов!

# Вычисляем BROADCAST_ADDR для очистки (так же как в up.sh)
# Вычисляем Broadcast только если он нужен (для очистки broadcast mark)
BROADCAST_ADDR=""
if [ -n "$LOCAL_SUBNETS_IPV4" ]; then
  BROADCAST_ADDR=$(get_broadcast_addr "$LOCAL_SUBNETS_IPV4")
fi

# IPv4 Broadcast очистка (mangle mark) — с --or-mark + -i "$TUN"
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

    [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
    for src in "${IPV4_PARTS[@]}"; do
      iptables -t mangle -D FORWARD -i "$TUN" -s "$src" -d "$BROADCAST_ADDR" -j MARK --or-mark $BIT 2>/dev/null || true
      iptables -t mangle -D FORWARD -i "$TUN" -s "$src" -d 255.255.255.255 -j MARK --or-mark $BIT 2>/dev/null || true
    done

    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

# Очищаем ACCEPT правила для broadcast (filter таблица) — с --mark BIT/BIT
GROUP_IDX=0
for rule in "${LAN_ALLOW[@]}"; do
  IFS=',' read -ra PARTS <<< "$rule"

  IPV4_PARTS=()
  for part in "${PARTS[@]}"; do
    part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$part" ] && continue
    [[ "$part" != *:* ]] && IPV4_PARTS+=("$part")
  done

  [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
  for dst in "${IPV4_PARTS[@]}"; do
    iptables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $BIT/$BIT -d "$dst" -j ACCEPT 2>/dev/null || true
  done

  GROUP_IDX=$((GROUP_IDX + 1))
done

# IPv6 Multicast очистка (mangle mark) — с --or-mark + -i "$TUN"
if [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
  GROUP_IDX=0
  for rule in "${LAN_ALLOW[@]}"; do
    IFS=',' read -ra PARTS <<< "$rule"

    IPV6_PARTS=()
    for part in "${PARTS[@]}"; do
      part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -z "$part" ] && continue
      [[ "$part" == *:* ]] && IPV6_PARTS+=("$part")
    done

    [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
    for src in "${IPV6_PARTS[@]}"; do
      ip6tables -t mangle -D FORWARD -i "$TUN" -s "$src" -d "ff02::1" -j MARK --or-mark $BIT 2>/dev/null || true
    done

    GROUP_IDX=$((GROUP_IDX + 1))
  done
fi

# Очищаем ACCEPT правила для multicast (filter таблица) — с --mark BIT/BIT
if [ "$SERVER_ON_NETWORK_IPV6" -eq 0 ]; then
   GROUP_IDX=0
   for rule in "${LAN_ALLOW[@]}"; do
     IFS=',' read -ra PARTS <<< "$rule"

     IPV6_PARTS=()
     for part in "${PARTS[@]}"; do
       part="$(echo "$part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
       [ -z "$part" ] && continue
       [[ "$part" == *:* ]] && IPV6_PARTS+=("$part")
     done

     [ $GROUP_IDX -lt 31 ] && BIT=$((1 << GROUP_IDX)) || continue
     for dst in "${IPV6_PARTS[@]}"; do
       ip6tables -D FORWARD -i "$TUN" -o "$TUN" -m mark --mark $BIT/$BIT -d "$dst" -j ACCEPT 2>/dev/null || true
     done

     GROUP_IDX=$((GROUP_IDX + 1))
   done
fi

# --- Полное удаление цепочек проброса портов (специфично для туннеля) ---
# IPv4 + IPv6 очистка
echo "🧹 Очистка проброса портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_SNAT, $PF_CHAIN_FILTER)"

# СНАЧАЛА удаляем ссылки из глобальных цепочек (IPv4 + IPv6)
echo "   Удаление ссылок из PREROUTING, FORWARD, POSTROUTING..."

# PREROUTING → PF_CHAIN_NAT
iptables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -D PREROUTING -j "$PF_CHAIN_NAT" 2>/dev/null || true

# FORWARD → PF_CHAIN_FILTER
iptables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true

# POSTROUTING → PF_CHAIN_SNAT
iptables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true

# ПОТОМ очищаем цепочки (IPv4 + IPv6)
echo "   Очистка цепочек..."

# PF_CHAIN_NAT
iptables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true

# PF_CHAIN_SNAT
iptables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true

# PF_CHAIN_FILTER
iptables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
ip6tables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true

# В КОНЦЕ удаляем цепочки (IPv4 + IPv6)
echo "   Удаление цепочек..."

# PF_CHAIN_NAT
iptables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true
ip6tables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true

# PF_CHAIN_SNAT
iptables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true
ip6tables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true

# PF_CHAIN_FILTER
iptables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true
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
    # IPv4 - очищаем ВСЕ комбинации src/dst
    if [ ${#IPV4_PARTS[@]} -ge 1 ] && [ -n "$MAIN_TUN" ]; then
      for src in "${IPV4_PARTS[@]}"; do
        # Очищаем intra-subnet правило (src=dst)
        iptables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
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
        # Очищаем intra-subnet правило (src=dst)
        ip6tables -D FORWARD -i "$MAIN_TUN" -o "$MAIN_TUN" -s "$src" -d "$src" -j ACCEPT 2>/dev/null || true
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
iptables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true
ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j DROP 2>/dev/null || true

# Очищаем старые универсальные правила (если вдруг они есть)
iptables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true
ip6tables -D FORWARD -i "$TUN" -o "$TUN" -j ACCEPT 2>/dev/null || true

# Очищаем правила FORWARD для трафика напрямую через внешний интерфейс
# IFACE может быть пустым если файл параметров не найден
if [ -n "$IFACE" ]; then
  iptables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  ip6tables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
  ip6tables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
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

# Удаляем ip rules с prio 100
ip rule del from "$TUN_SUBNET4" table main prio 100 2>/dev/null || true
ip rule del to "$TUN_SUBNET4" table main prio 100 2>/dev/null || true
ip -6 rule del from "$TUN_SUBNET6" table main prio 100 2>/dev/null || true
ip -6 rule del to "$TUN_SUBNET6" table main prio 100 2>/dev/null || true

tc qdisc del dev "$IFB_IN" root 2>/dev/null || true
ip link set "$IFB_IN" down 2>/dev/null || true
ip link delete "$IFB_IN" 2>/dev/null || true
tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
ip link set "$IFB_OUT" down 2>/dev/null || true
ip link delete "$IFB_OUT" 2>/dev/null || true
tc qdisc del dev "$IFB_MIX" root 2>/dev/null || true
ip link set "$IFB_MIX" down 2>/dev/null || true
ip link delete "$IFB_MIX" 2>/dev/null || true

# --- Удаляем файл параметров ---
rm -f "$TUNNEL_PARAMS_FILE" 2>/dev/null || true

echo "————————————————————————————————"
'''

# ----------------- Генерация параметров обфускации -----------------

def generate_cps_packet(
    static_bytes: str = None,
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
    if random_bytes_range > 0:
        actual_random_bytes = random.randint(random_bytes, random_bytes + random_bytes_range)
    else:
        actual_random_bytes = random_bytes

    if actual_random_bytes > 0:
        parts.append(f"<r {actual_random_bytes}>")

    # Если указан диапазон, генерируем случайное значение
    if random_ascii_range > 0:
        actual_random_ascii = random.randint(random_ascii, random_ascii + random_ascii_range)
    else:
        actual_random_ascii = random_ascii

    if actual_random_ascii > 0:
        parts.append(f"<rc {actual_random_ascii}>")

    # Если указан диапазон, генерируем случайное значение для цифр
    if random_digits_range > 0:
        actual_random_digits = random.randint(random_digits, random_digits + random_digits_range)
    else:
        actual_random_digits = random_digits

    if actual_random_digits > 0:
        parts.append(f"<rd {actual_random_digits}>")

    return "".join(parts)


def _generate_j_params() -> Tuple[int, int, int]:
    """Генерация Jc, Jmin, Jmax (junk-пакеты)."""
    Jc = random.randint(80, 120)
    Jmin = random.randint(48, 64)
    Jmax = random.randint(Jmin + 8, 80)
    return Jc, Jmin, Jmax


def _generate_s_params() -> Tuple[int, int, int, int]:
    """Генерация S1, S2, S3, S4 (случайные префиксы).
    
    Все S-параметры отличаются минимум на 3 единицы.
    S1+56 ≠ S2 (требование AmneziaWG).
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
            break
    
    return S1, S2, S3, S4


def _generate_h_params_static() -> Tuple[int, int, int, int]:
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


def _generate_h_params_ranges() -> Tuple[str, str, str, str]:
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
    ranges = [(s, s + sz) for s, sz in zip(h_starts, h_sizes)]
    random.shuffle(ranges)

    return (f"{ranges[0][0]}-{ranges[0][1]}",
            f"{ranges[1][0]}-{ranges[1][1]}",
            f"{ranges[2][0]}-{ranges[2][1]}",
            f"{ranges[3][0]}-{ranges[3][1]}")


def _generate_i_params(for_client: bool = False, for_server: bool = True, domain: str = "", seed: str = "") -> Dict[str, str]:
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
    I_SNI_TEXT_MIN = 20
    I_SNI_TEXT_MAX = 800
    I_SNI_TRAFFIC_MIN = 100
    I_SNI_TRAFFIC_MAX = 600
    I_SNI_COUNT_MIN = 3     # Количество I-строк для single-pool
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
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import hmac, hashlib

        def _hkdf_extract(salt, ikm):
            return hmac.new(salt, ikm, hashlib.sha256).digest()

        def _hkdf_expand(prk, info, length):
            hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info, backend=default_backend())
            return hkdf.derive(prk)

        def _quic_encrypt_initial(dcid_hex: str, scid_hex: str, plaintext_hex: str) -> str:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            dcid = bytes.fromhex(dcid_hex)
            scid = bytes.fromhex(scid_hex)
            prk = _hkdf_extract(_QUIC_INITIAL_SALT, dcid)
            key = _hkdf_expand(prk, b'tls13 quic key', 16)
            iv  = _hkdf_expand(prk, b'tls13 quic iv', 12)
            hp  = _hkdf_expand(prk, b'tls13 quic hp', 16)

            plaintext = bytes.fromhex(plaintext_hex)
            pn = 0
            pn_bytes = pn.to_bytes(1, 'big')
            # AAD = type + version + DCID_len + DCID + SCID_len + SCID + Token_len + Length
            aad = (b'\xc0\x00\x00\x00\x01'
                   b'\x08' + dcid +
                   b'\x08' + scid +
                   b'\x00')
            payload_len = len(plaintext) + 1 + 16  # +1 PN byte, +16 GCM tag
            aad += payload_len.to_bytes(2, 'big')
            # Nonce = IV[0..n] XOR PN, IV[n+1..11] без изменений (n=0 для 1-byte PN)
            nonce = bytearray(iv)
            nonce[0] ^= pn
            nonce = bytes(nonce)
            # AES-128-GCM encrypt
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext, aad)
            encrypted = ct[:-16]
            tag = ct[-16:]
            # Header Protection: sample = encrypted bytes 0..15
            sample = encrypted[:16]
            ecb_cipher = Cipher(algorithms.AES(hp), modes.ECB(), backend=default_backend())
            ecb_enc = ecb_cipher.encryptor()
            mask = ecb_enc.update(sample) + ecb_enc.finalize()

            first_byte = 0xc0 ^ (mask[0] & 0x0f)
            pn_protected = bytes([pn_bytes[0] ^ (mask[1] if len(mask) > 1 else 0)])

            result_hex = (
                first_byte.to_bytes(1, 'big').hex() +
                aad[1:].hex() +
                pn_protected.hex() +
                encrypted.hex() +
                tag.hex()
            )
            return result_hex

        try_AESGCM = _quic_encrypt_initial

    def _build_quic_packet(crypto_hex: str, default_range: int = 60,
                           scid_hex_preset: str = "") -> Tuple[str, int]:
        """Оборачивает hex CRYPTO frame в QUIC Long Header (с шифрованием если доступно)."""
        dcid_hex = secrets.token_hex(8)
        scid_hex = scid_hex_preset or secrets.token_hex(8)
        if try_AESGCM is not None:
            return try_AESGCM(dcid_hex, scid_hex, crypto_hex), 0
        payload_len = len(crypto_hex) // 2 + 1
        quic_hex = (f"c000000001"
                    f"08{dcid_hex}"
                    f"08{scid_hex}"
                    f"00"
                    f"{payload_len:04x}"
                    f"00"
                    f"{crypto_hex}")
        return quic_hex, default_range

    # ────────────────────────────────────────────────────────────────

    def _gen_quic_client():
        """QUIC Initial с полноценным TLS 1.2 ClientHello + SNI."""
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
        # SNI extension
        sni_ext_hex = f"0000{len(sni_bytes)+5:04x}00{len(sni_bytes):04x}{sni_hex}"
        # supported_groups (x25519, secp256r1, secp384r1)
        groups_hex = ("000a00140012001d0017001800190100"
                      "1c000b000a000900080007")
        # signature_algorithms (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ...)
        sigalgs_hex = ("000d0020001e06010602060305010502"
                       "050304010402040308040804050806")
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
        # QUIC CRYPTO Frame (plaintext для шифрования)
        crypto_hex = f"06" + "00000000" + f"{len(ch_hex)//2:08x}{ch_hex}"
        quic_hex, qr_static_range = _build_quic_packet(crypto_hex, scid_hex_preset=scid_hex)
        if try_AESGCM is not None:
            # random не обнуляются — DPI игнорирует мусор после GCM tag (QUIC padding)
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
        handshake_hex = (f"e000000001{secrets.token_hex(8)}{secrets.token_hex(8)}"
                         f"00"                                           # Token_len=0
                         f"{len(payload)//2:04x}"                        # Length
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
        """QUIC с TLS 1.2 ServerHello."""
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
        crypto_hex = f"06" + "00000000" + f"{len(sh_hex)//2:08x}{sh_hex}"
        quic_hex, qr_static_range = _build_quic_packet(crypto_hex, default_range=40)

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
        """QUIC серверное завершение handshake."""
        payload = secrets.token_hex(48)
        handshake_hex = (f"e000000001{secrets.token_hex(8)}{secrets.token_hex(8)}"
                         f"00"
                         f"{len(payload)//2:04x}"
                         f"00"
                         f"{payload}")
        return generate_cps_packet(
            static_bytes=f"0x{handshake_hex}", static_bytes_range=30,
            use_timestamp=True,
            random_bytes=200, random_bytes_range=100,
            random_ascii=150, random_ascii_range=100,
            random_digits=10, random_digits_range=5,
        )

    # Определяем пул в зависимости от направления и domain
    if for_server:
        # Сервер — всегда сигнатуры ответа
        pool_fns = [_gen_quic_server, _gen_quic_server_handshake]
    elif domain:
        pool_fns = [_gen_quic_client, _gen_quic_client_handshake]
    else:
        # Стандартный случайный пул
        pool_fns = [_gen_dns, _gen_quic, _gen_dtls, _gen_ntp, _gen_random, _gen_srtp]

    # Генерация с валидацией диапазонов
    # Флаг для неслучайных пулов (domain / server) — строгий порядок Initial→Handshake
    is_imitation_pool = for_server or bool(domain)

    selected = []
    best_selected = None
    best_distance = float('inf')
    for attempt in range(MAX_ATTEMPTS):
        if is_imitation_pool:
            # Циклическое заполнение: I1=Initial, I2=Handshake, I3=Initial, I4=Handshake...
            count = random.randint(I_SNI_COUNT_MIN, I_SNI_COUNT_MAX)
            current = [pool_fns[i % len(pool_fns)]() for i in range(count)]
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
        use_sni_ranges = is_imitation_pool or (len(pool_fns) == 1)
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



def generate_all_params(version: str, for_client: bool = False, for_server: bool = True, for_warp: bool = False, domain: str = "", tun_name: str = "", seed_override: str = "") -> dict:
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
    S1, S2, S3, S4 = _generate_s_params()
    _i_seed = seed_override if seed_override else f"{S1}{S2}"

    # H1-H4: статичные для AWG1.0/1.5, диапазоны для AWG2.0
    if version == "AWG2.0":
        H1, H2, H3, H4 = _generate_h_params_ranges()
    else:
        H1, H2, H3, H4 = _generate_h_params_static()

    # Определяем какие параметры поддерживаются в данной версии
    supports_jc = version in ["AWG", "AWG1.0", "AWG1.5", "AWG2.0"]
    supports_s1_s2 = version in ["AWG", "AWG1.0", "AWG1.5", "AWG2.0"]
    supports_h = version in ["AWG1.0", "AWG1.5", "AWG2.0"]
    supports_i = version in ["AWG1.5", "AWG2.0"]  # I1-I5 для сервера и клиента
    supports_s3_s4 = version == "AWG2.0"

    # Формируем результат
    result = {}

    # Jc, Jmin, Jmax
    if supports_jc:
        result.update({"Jc": Jc, "Jmin": Jmin, "Jmax": Jmax})
    else:
        if for_server and not for_warp:
            result.update({"Jc": Jc, "Jmin": Jmin, "Jmax": Jmax, "_J_comment": "AWG+"})
        else:
            result.update({"Jc": None, "Jmin": None, "Jmax": None})

    # S1, S2 — не генерируются для WARP
    if supports_s1_s2 and not for_warp:
        # с/к:одинаковые — клиент получает те же значения
        result.update({"S1": S1, "S2": S2})
    else:
        if for_server and not for_warp:
            result.update({"S1": S1, "S2": S2, "_S12_comment": "AWG+"})
        else:
            result.update({"S1": None, "S2": None})

    # S3, S4 — не генерируются для WARP
    if supports_s3_s4 and not for_warp:
        # с/к:одинаковые — клиент получает те же значения
        result.update({"S3": S3, "S4": S4})
    else:
        if for_server and not for_warp:
            result.update({"S3": S3, "S4": S4, "_S34_comment": "AWG2.0"})
        else:
            result.update({"S3": None, "S4": None})

    # H1-H4 — не генерируются для WARP
    if supports_h and not for_warp:
        # с/к:одинаковые — клиент получает те же значения
        result.update({"H1": H1, "H2": H2, "H3": H3, "H4": H4})
    else:
        if for_server and not for_warp:
            result.update({"H1": H1, "H2": H2, "H3": H3, "H4": H4, "_H_comment": "AWG1.0+"})
        else:
            result.update({"H1": None, "H2": None, "H3": None, "H4": None})

    # I1-I5 — пакеты-приманки
    # AWG1.5, AWG2.0: активные значения для всех конфигов
    # WG, AWG, AWG1.0: коммент для сервера, нет для клиента/WARP
    if supports_i:
        result.update(_generate_i_params(for_client=for_client, for_server=for_server, domain=domain, seed=_i_seed))
    else:
        if for_server and not for_warp:
            i_params = _generate_i_params(for_client=for_client, for_server=for_server, domain=domain, seed=_i_seed)
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

    return result

# ----------------- Генерация ключей -----------------

def gen_pair_keys() -> Tuple[str, str]:
    """Генерация пары ключей (PrivateKey + PublicKey) через awg > wg > Python."""
    # Всегда сначала пробуем awg, потом wg, потом Python fallback
    for wgtool in ["awg", "wg"]:
        rc, out = exec_cmd([wgtool, "genkey"])
        if rc == 0 and out:
            priv = out.strip()
            rc, out = exec_cmd([wgtool, "pubkey"], input=priv + "\n")
            if rc == 0 and out:
                return priv, out.strip()

    # Python fallback через cryptography
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64
        from cryptography.hazmat.primitives import serialization

        priv_key = X25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.raw,
            format=serialization.Format.raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        priv = base64.b64encode(priv_bytes).decode().rstrip('=')
        pub_key = priv_key.public_key()
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.raw,
            format=serialization.Format.raw
        )
        pub = base64.b64encode(pub_bytes).decode().rstrip('=')
        return priv, pub
    except ImportError:
        raise RuntimeError("Не удалось сгенерировать ключи: нет awg/wg и нет cryptography")


def gen_preshared_key() -> str:
    """Генерация preshared key через openssl rand или os.urandom."""
    rc, out = exec_cmd(["openssl", "rand", "-base64", "32"])
    if rc == 0 and out:
        return out.strip()
    try:
        return base64.b64encode(os.urandom(32)).decode("ascii")
    except Exception:
        raise RuntimeError("Не удалось сгенерировать preshared key")


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


def get_main_iface() -> Optional[str]:
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

    last_error = None

    # Первый прогон: ищем IPv4
    for service_url in services:
        try:
            r = requests.get(service_url, timeout=6)
            r.raise_for_status()
            ip = r.text.strip()
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                return ip
        except requests.exceptions.RequestException as e:
            last_error = f"{service_url}: {e}"
            continue
        except ValueError:
            last_error = f"{service_url}: неверный формат IP"
            continue

    # Второй прогон: ищем IPv6 (если первый неудался)
    for service_url in services:
        try:
            r = requests.get(service_url, timeout=6)
            r.raise_for_status()
            ip = r.text.strip()
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                return ip
        except requests.exceptions.RequestException as e:
            last_error = f"{service_url}: {e}"
            continue
        except ValueError:
            last_error = f"{service_url}: неверный формат IP"
            continue

    # Ни один сервис не сработал
    raise RuntimeError(f"Не удалось получить внешний IP. Последняя ошибка: {last_error}")


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


def _select_endpoint_from_api_result(result: dict) -> Optional[object]:
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
                        # Создаём endpoint'ы для каждого порта
                        v4_host = v4.split(':')[0] if ':' in v4 else v4
                        for port in ports:
                            endpoints.append(f"{v4_host}:{port}")
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


def generate_warp_config(tun_name: str, index: int, mtu: int, proxy: str = "", version: str = "AWG2.0", for_server: bool = True) -> Tuple[str, str]:
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
        api_endpoint = _select_endpoint_from_api_result(result_obj)
    except Exception as e:
        raise RuntimeError(f"Ошибка WARP API: {e}")

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
            if check_endpoint(ep, timeout=0.6):
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

    # Генерируем все параметры обфускации через общую функцию
    # WARP это клиентский конфиг, поэтому for_client=True
    # for_warp=True — чтобы соответствовать таблице (S1,S2, H1-H4, S3,S4 = нет для WARP)
    warp_obf_params = generate_all_params(version, for_client=True, for_server=False, for_warp=True)

    persistent_keepalive = _generate_persistent_keepalive()
    out = g_warp_config
    out = out.replace("<WARP_PRIVATE_KEY>", priv_key)
    
    # Jc, Jmin, Jmax
    if warp_obf_params.get("Jc") is not None:
        out = out.replace("<JC_LINE>", f"Jc = {warp_obf_params['Jc']}\n")
        out = out.replace("<JMIN_LINE>", f"Jmin = {warp_obf_params['Jmin']}\n")
        out = out.replace("<JMAX_LINE>", f"Jmax = {warp_obf_params['Jmax']}\n")
    else:
        # WG не поддерживает Jc, Jmin, Jmax — удаляем
        out = out.replace("<JC_LINE>", "")
        out = out.replace("<JMIN_LINE>", "")
        out = out.replace("<JMAX_LINE>", "")
    
    out = out.replace("<MTU>", str(mtu))
    out = out.replace("<WARP_ADDRESS>", ", ".join([x for x in (client_ipv4, client_ipv6) if x]))
    out = out.replace("<WARP_PEER_PUBLIC_KEY>", peer_pub)
    out = out.replace("<PERSISTENT_KEEPALIVE>", str(persistent_keepalive))
    out = out.replace("<WARP_ENDPOINT>", chosen)

    # I1-I5
    if warp_obf_params.get("I1") is not None:
        for i in range(1, 6):
            key = f"I{i}"
            if warp_obf_params.get(key):
                out = out.replace(f"<{key}_LINE>", f"{key} = {warp_obf_params[key]}\n")
            else:
                out = out.replace(f"<{key}_LINE>", "")
    else:
        # Без I1-I5 для WG, AWG, AWG1.0 — удаляем всё включая переносы
        out = out.replace("<I1_LINE>", "")
        out = out.replace("<I2_LINE>", "")
        out = out.replace("<I3_LINE>", "")
        out = out.replace("<I4_LINE>", "")
        out = out.replace("<I5_LINE>", "")
    
    # Table = off только для серверного WARP (любой версии)
    out = out.replace("<TABLE_LINE>", "Table = off\n" if for_server else "")

    filename = f"{tun_name}warp{index}.conf"
    return out, filename


def generate_warp_configs(tun_name: str, num_warps: int, mtu: int, proxy: str = "", version: str = "AWG2.0", for_server: bool = True) -> List[str]:
    """
    Генерация N WARP-конфигов с попытками и откатом при неудаче.
    
    for_server=True  → Серверный WARP (с Table = off)
    for_server=False → Клиентский WARP (без Table = off)
    """
    warp_configs: List[str] = []
    last_error = None  # Сохраняем последнюю ошибку

    for i in range(num_warps):
        success = False
        for attempt in range(3):  # 3 попытки достаточно
            try:
                conf_text, fname = generate_warp_config(tun_name, i, mtu, proxy, version, for_server)
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
                    last_error = str(he)
                    break
            except Exception as e:
                logger.warning("⚠  Попытка генерации WARP %d не удалась: %s", attempt + 1, e)
                last_error = str(e)
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
            # Перебрасываем последнюю ошибку
            if last_error:
                raise RuntimeError(f"Ошибка WARP API: {last_error}")
            else:
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
        mtu_val = ""
        domain_val = ""

        # Парсинг ;key=value,key=value
        if ";" in p:
            p, param_str = p.split(";", 1)
            params = {}
            for pair in param_str.split(","):
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
                out.append({"host": host, "port": str(port), "label": label, "mtu": mtu_val, "domain": domain_val})
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
            out.append({"host": hostpart.strip(), "port": default_port, "label": lbl, "mtu": mtu_val, "domain": domain_val})
            continue

        if ':' in hostpart:
            h, prt = hostpart.rsplit(":", 1)
            if prt.isdigit():
                prt_val = prt.strip()
                try:
                    prt_int = int(prt_val)
                    if 1 <= prt_int <= 65535:
                        out.append({"host": h.strip(), "port": str(prt_int), "label": lbl, "mtu": mtu_val, "domain": domain_val})
                    else:
                        out.append({"host": h.strip(), "port": default_port, "label": lbl, "mtu": mtu_val, "domain": domain_val})
                except Exception:
                    out.append({"host": h.strip(), "port": default_port, "label": lbl, "mtu": mtu_val, "domain": domain_val})
                continue
            else:
                out.append({"host": hostpart.strip(), "port": default_port, "label": lbl, "mtu": mtu_val, "domain": domain_val})
                continue
        else:
            h = hostpart.strip()
            out.append({"host": h, "port": default_port, "label": lbl, "mtu": mtu_val, "domain": domain_val})
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
    
    # Сравниваем как IP адреса (не строки!) чтобы избежать проблем нормализации IPv6
    if ipv4_server_ip:
        try:
            ipv4_server_addr = ipaddress.ip_address(ipv4_server_ip)
            ipv4_is_network = (ipv4_server_addr == ipv4_net.network_address)
        except:
            ipv4_is_network = True
    else:
        ipv4_is_network = True
        
    if ipv6_server_ip:
        try:
            ipv6_server_addr = ipaddress.ip_address(ipv6_server_ip)
            ipv6_is_network = (ipv6_server_addr == ipv6_net.network_address)
        except:
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


# ----------------- Вспомогательные функции для handle_makecfg -----------------

def _process_interface_path(raw_input: str) -> Tuple[pathlib.Path, str]:
    """Обработка пути к интерфейсу. Возвращает (target_path, tun_name)."""
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
    return target_path, tun_name


def _generate_warp_if_needed(tun_name: str, warp_count: int, mtu: int, proxy: str, 
                              awg_version: str) -> List[str]:
    """Генерация WARP конфигов если нужно. Возвращает список конфигов."""
    warp_configs: List[str] = []
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

            raise RuntimeError("Генерация WARP не удалась — интерфейс не создан")

        for c in warp_configs:
            logger.info("📄 WARP конфиг: %s", c)
        logger.info("✅ WARP конфиги сгенерированы")
    
    return warp_configs


def _fill_obfuscation_params(out: str, obf_params: dict) -> str:
    """Заполнение параметров обфускации в шаблоне."""
    # Jc, Jmin, Jmax
    if "_J_comment" in obf_params:
        out = out.replace("<JC_LINE>", f"# Jc = {obf_params['Jc']}  # {obf_params['_J_comment']}\n")
        out = out.replace("<JMIN_LINE>", f"# Jmin = {obf_params['Jmin']}  # {obf_params['_J_comment']}\n")
        out = out.replace("<JMAX_LINE>", f"# Jmax = {obf_params['Jmax']}  # {obf_params['_J_comment']}\n")
    else:
        out = out.replace("<JC_LINE>", f"Jc = {obf_params['Jc']}\n")
        out = out.replace("<JMIN_LINE>", f"Jmin = {obf_params['Jmin']}\n")
        out = out.replace("<JMAX_LINE>", f"Jmax = {obf_params['Jmax']}\n")

    # S1, S2
    if "_S12_comment" in obf_params:
        out = out.replace("<S1_LINE>", f"# S1 = {obf_params['S1']}  # {obf_params['_S12_comment']}\n")
        out = out.replace("<S2_LINE>", f"# S2 = {obf_params['S2']}  # {obf_params['_S12_comment']}\n")
    else:
        out = out.replace("<S1_LINE>", f"S1 = {obf_params['S1']}\n")
        out = out.replace("<S2_LINE>", f"S2 = {obf_params['S2']}\n")

    # S3, S4
    if "_S34_comment" in obf_params:
        out = out.replace("<S3_LINE>", f"# S3 = {obf_params['S3']}  # {obf_params['_S34_comment']}\n")
        out = out.replace("<S4_LINE>", f"# S4 = {obf_params['S4']}  # {obf_params['_S34_comment']}\n")
    else:
        out = out.replace("<S3_LINE>", f"S3 = {obf_params['S3']}\n")
        out = out.replace("<S4_LINE>", f"S4 = {obf_params['S4']}\n")

    # H1-H4
    if "_H_comment" in obf_params:
        out = out.replace("<H1_LINE>", f"# H1 = {obf_params['H1']}  # {obf_params['_H_comment']}\n")
        out = out.replace("<H2_LINE>", f"# H2 = {obf_params['H2']}  # {obf_params['_H_comment']}\n")
        out = out.replace("<H3_LINE>", f"# H3 = {obf_params['H3']}  # {obf_params['_H_comment']}\n")
        out = out.replace("<H4_LINE>", f"# H4 = {obf_params['H4']}  # {obf_params['_H_comment']}\n")
    else:
        out = out.replace("<H1_LINE>", f"H1 = {obf_params['H1']}\n")
        out = out.replace("<H2_LINE>", f"H2 = {obf_params['H2']}\n")
        out = out.replace("<H3_LINE>", f"H3 = {obf_params['H3']}\n")
        out = out.replace("<H4_LINE>", f"H4 = {obf_params['H4']}\n")

    # I1-I5
    if obf_params.get("I1") and not obf_params.get("_I_comment"):
        # AWG1.5, AWG2.0 — активные I1-I5 (поштучно)
        for i in range(1, 6):
            key = f"I{i}"
            if obf_params.get(key):
                out = out.replace(f"<{key}_LINE>", f"{key} = {obf_params[key]}\n")
            else:
                out = out.replace(f"<{key}_LINE>", "")
    elif obf_params.get("I1"):
        # WG, AWG, AWG1.0 — закомментированные значения (поштучно)
        for i in range(1, 6):
            key = f"I{i}"
            if obf_params.get(key):
                out = out.replace(f"<{key}_LINE>", f"# {key} = {obf_params[key]}\n")
            else:
                out = out.replace(f"<{key}_LINE>", "")
    else:
        # Клиент без I1-I5
        out = out.replace("<I1_LINE>", "")
        out = out.replace("<I2_LINE>", "")
        out = out.replace("<I3_LINE>", "")
        out = out.replace("<I4_LINE>", "")
        out = out.replace("<I5_LINE>", "")

    return out


def _create_scripts(up_path: pathlib.Path, down_path: pathlib.Path, params_path: pathlib.Path,
                    main_iface: str, tun_name: str, opt, normalized_string: str, 
                    warp_configs: List[str]) -> None:
    """Создание up.sh, down.sh и файла параметров."""
    import shutil
    
    if warp_configs:
        warp_list_str = "\n".join([f'  \"{pathlib.Path(cfg).stem}\"' for cfg in warp_configs])
    else:
        warp_list_str = '  "none=0.0.0.0/0,::/0"'

    # Создаём файл параметров (.sh)
    params_script = params_script_template
    params_script = params_script.replace("<SERVER_PORT>", str(opt.port))
    params_script = params_script.replace("<SERVER_IFACE>", main_iface)
    params_script = params_script.replace("<SERVER_TUN>", tun_name)
    params_script = params_script.replace("<SERVER_ADDR>", normalized_string)
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
    """Определение IP сервера и позиции в подсети."""
    server_addr_ipv4 = srvcfg.split('[Peer]')[0]
    
    # IPv4
    for line in server_addr_ipv4.split('\n'):
        if line.strip().startswith('Address = '):
            addr_part = line.split('=')[1].strip().split(',')[0].strip()
            server_ip_int_ipv4 = int(ipaddress.IPv4Address(addr_part.split('/')[0]))
            break
    else:
        server_ip_int_ipv4 = int(net_ipv4.network_address)
    
    server_on_network_ipv4 = (server_ip_int_ipv4 == int(net_ipv4.network_address))
    
    # IPv6
    server_on_network_ipv6 = False
    ipv6_server_ip_int = 0

    if net_ipv6:
        server_addr_ipv6 = srvcfg.split('[Peer]')[0]
        for line in server_addr_ipv6.split('\n'):
            if line.strip().startswith('Address = '):
                addr_part = line.split('=')[1].strip()
                if ',' in addr_part:
                    addr_part = addr_part.split(',')[1].strip()
                ipv6_server_ip_str = addr_part.split('/')[0]
                ipv6_server_ip_int = int(ipaddress.IPv6Address(ipv6_server_ip_str))
                break
        else:
            ipv6_server_ip_int = int(net_ipv6.network_address)

        server_on_network_ipv6 = (ipv6_server_ip_int == int(net_ipv6.network_address))

    return server_ip_int_ipv4, server_on_network_ipv4, ipv6_server_ip_int, server_on_network_ipv6


def _allocate_client_ip(opt, net_ipv4, net_ipv6, server_on_network_ipv4, server_on_network_ipv6,
                        server_ip_int_ipv4, ipv6_server_ip_int, broadcast_int_ipv4,
                        used_ips_ipv4: set, used_ips_ipv6: set) -> Tuple[str, Optional[str]]:
    """
    Выделение IP адреса для клиента.
    
    Возвращает: (ipaddr_ipv4, ipaddr_ipv6)
    """
    ipaddr_ipv4 = None
    ipaddr_ipv6 = None

    if opt.ipaddr:
        # --- РУЧНОЙ IP ---
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

                # Проверка: если сервер НЕ на network, broadcast (multicast) работает и зарезервирован
                if net_ipv6 and not server_on_network_ipv6 and ip_int == int(net_ipv6.broadcast_address):
                    raise RuntimeError(f'IPv6 адрес {manual_ip_str} зарезервирован для multicast (broadcast)')

                ipaddr_ipv6 = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
    else:
        # --- АВТОМАТИЧЕСКИЙ IP ---
        # Вычисляем маски клиентов и коэффициент кратности
        ipv4_client_mask, ipv6_client_mask, ratio = calculate_client_masks(net_ipv4, net_ipv6)

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

        for block_idx in range(0, max_ipv4_blocks):
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

            # Проверяем что ОБА адреса в паре свободны!
            ipv4_free = (ipv4_block_start not in used_ips_ipv4)
            ipv6_free = True
            if net_ipv6:
                ipv6_free = (ipv6_block_start not in used_ips_ipv6)

            # Пропускаем если ХОТЯ БЫ ОДИН занят!
            if not ipv4_free or not ipv6_free:
                continue

            # Нашли пару! ОБА свободны!
            chosen_ipv4 = ipv4_block_start
            chosen_ipv6 = ipv6_block_start if net_ipv6 else None
            break

        if chosen_ipv4 is None:
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
                          persistent_keepalive: int) -> None:
    """Добавление клиента в серверный конфиг."""
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()

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


def _backup_file(path: pathlib.Path, suffix: str = '.bak') -> Optional[pathlib.Path]:
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
QR_FORWARD_LETTER_STEP  = 1   # шаг вперёд по буквам (Q→M→L)
QR_BACKWARD_DIGIT_STEP  = 1   # шаг назад по цифрам
QR_BACKWARD_LETTER_STEP = 1   # шаг назад по буквам

# Полный список ступеней: H1..H40, Q40, M40, L40
_QR_STEPS: List[Tuple[int, int]] = []
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
) -> Tuple[int, int]:
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
        try:
            qr = qrcode.QRCode(
                version=start_version,
                error_correction=start_ec,
                box_size=10,
                border=4,
            )
            qr.add_data(conf_text)
            qr.make(fit=False)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(output_path))
            return start_version, start_ec
        except (qrcode.exceptions.DataOverflowError, ValueError):
            pass

    # Шаг 1: перебор цифр 1..40 с шагом QR_FORWARD_DIGIT_STEP (все с H)
    for version in range(start_version, 41, max(1, QR_FORWARD_DIGIT_STEP)):
        try:
            qr = qrcode.QRCode(
                version=version,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(conf_text)
            qr.make(fit=False)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(output_path))
            return version, qrcode.constants.ERROR_CORRECT_H
        except (qrcode.exceptions.DataOverflowError, ValueError):
            continue

    # Шаг 2: перебор букв Q→M→L (version=40) с шагом QR_FORWARD_LETTER_STEP
    letters = [
        qrcode.constants.ERROR_CORRECT_Q,
        qrcode.constants.ERROR_CORRECT_M,
        qrcode.constants.ERROR_CORRECT_L,
    ]
    for i in range(0, len(letters), max(1, QR_FORWARD_LETTER_STEP)):
        ec = letters[i]
        try:
            qr = qrcode.QRCode(
                version=40,
                error_correction=ec,
                box_size=10,
                border=4,
            )
            qr.add_data(conf_text)
            qr.make(fit=False)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(output_path))
            return 40, ec
        except (qrcode.exceptions.DataOverflowError, ValueError):
            continue

    raise RuntimeError("Конфиг слишком большой для QR кода")


def _add_file_to_zip(zipf: zipfile.ZipFile, file_path: str, arcname: Optional[str] = None) -> bool:
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


def _init_random_seed(extra_entropy: Optional[int] = None) -> None:
    """
    Инициализация генератора случайных чисел уникальным seed.
    
    Args:
        extra_entropy: Дополнительная энтропия (например hash(peer_name))
    """
    seed = time.time_ns() ^ os.getpid()
    if extra_entropy is not None:
        seed ^= extra_entropy
    random.seed(seed)


def _generate_persistent_keepalive() -> int:
    """
    Генерация persistent_keepalive для WireGuard конфига.

    Возвращает случайное значение от 3 до 9 секунд.
    Это предотвращает закрытие NAT session timeout.
    """
    return random.randint(3, 9)


def _get_param_value(conf_text: str, param: str, version: str, min_version: str) -> Optional[str]:
    """
    Извлечь значение параметра из конфига.
    Поддерживает как активные так и закомментированные параметры.

    version: текущая версия протокола
    min_version: минимальная версия для поддержки этого параметра

    Возвращает None если версия < min_version.
    """
    # Проверяем поддержку параметра в данной версии
    version_order = {"WG": 0, "AWG": 1, "AWG1.0": 2, "AWG1.5": 3, "AWG2.0": 4}
    if version_order.get(version, 0) < version_order.get(min_version, 0):
        return None  # Параметр не поддерживается в этой версии

    for line in conf_text.split('\n'):
        line = line.strip()
        # Проверяем активный параметр: "S1 = 42"
        if line.startswith(f'{param} = '):
            return line.split('=')[1].strip()
        # Проверяем закомментированный: "# S1 = 42  # AWG+"
        if line.startswith(f'# {param} = '):
            # Извлекаем значение между "# S1 = " и следующим "#"
            value_part = line[2:]  # Убираем "# "
            if '=' in value_part:
                value = value_part.split('=')[1].strip()
                # Убираем комментарий после значения
                if '  #' in value:
                    value = value.split('  #')[0].strip()
                return value
    return None


def _get_server_params(server_conf_text: str, server_protocol: str) -> dict:
    """Получение параметров сервера (S1-S4, H1-H4) из конфига."""
    return {
        'S1': _get_param_value(server_conf_text, 'S1', server_protocol, "AWG"),
        'S2': _get_param_value(server_conf_text, 'S2', server_protocol, "AWG"),
        'S3': _get_param_value(server_conf_text, 'S3', server_protocol, "AWG2.0"),
        'S4': _get_param_value(server_conf_text, 'S4', server_protocol, "AWG2.0"),
        'H1': _get_param_value(server_conf_text, 'H1', server_protocol, "AWG1.0"),
        'H2': _get_param_value(server_conf_text, 'H2', server_protocol, "AWG1.0"),
        'H3': _get_param_value(server_conf_text, 'H3', server_protocol, "AWG1.0"),
        'H4': _get_param_value(server_conf_text, 'H4', server_protocol, "AWG1.0"),
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
    
    # Проверяем позицию сервера
    server_ipv4_on_network = False
    if net_ipv4:
        srv_ipv4_part = srv_addr.split(',')[0].strip() if ',' in srv_addr else srv_addr.strip()
        if '/' in srv_ipv4_part:
            srv_ip_str = srv_ipv4_part.split('/')[0]
            srv_ip_int = int(ipaddress.ip_address(srv_ip_str))
            server_ipv4_on_network = (srv_ip_int == int(net_ipv4.network_address))
    
    server_ipv6_on_network = False
    if net_ipv6:
        srv_ipv6_part = srv_addr.split(',')[1].strip() if ',' in srv_addr else srv_addr.strip()
        if '/' in srv_ipv6_part:
            srv_ip_str = srv_ipv6_part.split('/')[0]
            srv_ip_int = int(ipaddress.ip_address(srv_ip_str))
            server_ipv6_on_network = (srv_ip_int == int(net_ipv6.network_address))
    
    # Исправляем маски
    for ip_str in allowed_ips_list:
        if '/' in ip_str:
            ip_net = ipaddress.ip_network(ip_str, strict=False)
            if isinstance(ip_net, ipaddress.IPv4Network):
                if not server_ipv4_on_network:
                    fixed_allowed_ips.append(f"{ip_net.network_address}/{net_ipv4.prefixlen}")
                else:
                    fixed_allowed_ips.append(ip_str)
            elif net_ipv6:
                if not server_ipv6_on_network:
                    fixed_allowed_ips.append(f"{ip_net.network_address}/{net_ipv6.prefixlen}")
                else:
                    fixed_allowed_ips.append(ip_str)
        else:
            fixed_allowed_ips.append(ip_str)
    
    return ', '.join(fixed_allowed_ips)


def _fill_client_obfuscation_params(out_base: str, client_obf_params: dict,
                                     server_s1, server_s2, server_s3, server_s4,
                                     server_h1, server_h2, server_h3, server_h4) -> str:
    """Заполнение параметров обфускации в клиентском конфиге."""
    # Jc, Jmin, Jmax
    if client_obf_params.get("Jc") is not None:
        out_base = out_base.replace("<JC_LINE>", f"Jc = {client_obf_params['Jc']}\n")
        out_base = out_base.replace("<JMIN_LINE>", f"Jmin = {client_obf_params['Jmin']}\n")
        out_base = out_base.replace("<JMAX_LINE>", f"Jmax = {client_obf_params['Jmax']}\n")
    else:
        out_base = out_base.replace("<JC_LINE>", "")
        out_base = out_base.replace("<JMIN_LINE>", "")
        out_base = out_base.replace("<JMAX_LINE>", "")

    # S1, S2
    if server_s1:
        out_base = out_base.replace("<S1_LINE>", f"S1 = {server_s1}\n")
        out_base = out_base.replace("<S2_LINE>", f"S2 = {server_s2}\n")
    else:
        out_base = out_base.replace("<S1_LINE>", "")
        out_base = out_base.replace("<S2_LINE>", "")

    # S3, S4
    if server_s3:
        out_base = out_base.replace("<S3_LINE>", f"S3 = {server_s3}\n")
        out_base = out_base.replace("<S4_LINE>", f"S4 = {server_s4}\n")
    else:
        out_base = out_base.replace("<S3_LINE>", "")
        out_base = out_base.replace("<S4_LINE>", "")

    # H1-H4
    if server_h1:
        out_base = out_base.replace("<H1_LINE>", f"H1 = {server_h1}\n")
        out_base = out_base.replace("<H2_LINE>", f"H2 = {server_h2}\n")
        out_base = out_base.replace("<H3_LINE>", f"H3 = {server_h3}\n")
        out_base = out_base.replace("<H4_LINE>", f"H4 = {server_h4}\n")
    else:
        out_base = out_base.replace("<H1_LINE>", "")
        out_base = out_base.replace("<H2_LINE>", "")
        out_base = out_base.replace("<H3_LINE>", "")
        out_base = out_base.replace("<H4_LINE>", "")

    # I1-I5
    if client_obf_params.get("I1") is not None:
        for i in range(1, 6):
            key = f"I{i}"
            if client_obf_params.get(key):
                out_base = out_base.replace(f"<{key}_LINE>", f"{key} = {client_obf_params[key]}\n")
            else:
                out_base = out_base.replace(f"<{key}_LINE>", "")
    else:
        out_base = out_base.replace("<I1_LINE>", "")
        out_base = out_base.replace("<I2_LINE>", "")
        out_base = out_base.replace("<I3_LINE>", "")
        out_base = out_base.replace("<I4_LINE>", "")
        out_base = out_base.replace("<I5_LINE>", "")
    
    return out_base


# ----------------- Обработчики команд -----------------

def handle_makecfg(opt) -> None:
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
            raise RuntimeError(f"Не удалось создать директорию {target_path.parent}: {e}")

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
        _server_domain = ""
        if g_endpoint_config_fn and g_endpoint_config_fn.exists():
            try:
                _ep_text = g_endpoint_config_fn.read_text('utf-8')
                if ";domain=" in _ep_text:
                    _server_domain = "any"
            except Exception:
                pass
        obf_params = generate_all_params(_file_version, for_client=False, for_server=True, tun_name=tun_name, domain=_server_domain)

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
            new_pk = _generate_persistent_keepalive()
            pk_key = f"{pname}|PersistentKeepalive"
            if pk_key in cfg.idsline:
                cfg.lines[cfg.idsline[pk_key]] = f"PersistentKeepalive = {new_pk}"

        # Обновляем I1-I5: добавляем/удаляем/заменяем строки
        new_lines = []
        i_added = set()
        for line in cfg.lines:
            match = re.match(r'^(#\s*)?(I[1-5])\s*=\s*(.+)$', line)
            if match:
                raw_key = match.group(2)
                key_num = int(raw_key[1:])
                val = obf_params.get(raw_key)
                if val is not None:
                    new_lines.append(f"{raw_key} = {val}")
                    i_added.add(key_num)
            else:
                new_lines.append(line)
        for i in range(1, 6):
            if i not in i_added and obf_params.get(f"I{i}") is not None:
                new_lines.append(f"I{i} = {obf_params[f'I{i}']}")
        cfg.lines = new_lines

        cfg.save()
        logger.info('✅ Конфиг %s обновлён', g_main_config_fn)
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
    ipaddr_ipv4_net, ipaddr_ipv6_net, ipaddr_display, normalized_string = parse_ipaddr_argument(opt.ipaddr)

    # Определяем версию протокола из флага --version
    awg_version = getattr(opt, 'version', 'AWG1.0')

    # --- СНАЧАЛА ГЕНЕРИРУЕМ WARP (если нужен) ---
    warp_configs = _generate_warp_if_needed(tun_name, opt.warp, opt.mtu, opt.proxy, awg_version)

    # --- ТЕПЕРЬ СОЗДАЁМ СЕРВЕРНЫЙ КОНФИГ И СКРИПТЫ ---
    priv, pub = gen_pair_keys()

    # Инициализируем random уникальным seed
    _init_random_seed()

    # Определяем нужна ли имитация рукопожатия на сервере (есть ли domain= в _endpoint.config)
    _server_domain = ""
    if g_endpoint_config_fn and g_endpoint_config_fn.exists():
        try:
            _ep_text = g_endpoint_config_fn.read_text('utf-8')
            if ";domain=" in _ep_text:
                _server_domain = "any"  # любое непустое значение — включает imitation pool
        except Exception:
            pass

    # Генерируем параметры обфускации для СЕРВЕРА
    obf_params = generate_all_params(awg_version, for_client=False, for_server=True, tun_name=tun_name, domain=_server_domain)

    up_path = g_main_config_fn.parent.joinpath(f"{tun_name}up.sh")
    down_path = g_main_config_fn.parent.joinpath(f"{tun_name}down.sh")

    out = g_defserver_config
    out = out.replace("<PROTOCOL>", awg_version)
    out = out.replace("<SERVER_KEY_TIME>", datetime.datetime.now().isoformat())
    out = out.replace("<SERVER_PRIVATE_KEY>", priv)
    out = out.replace("<SERVER_PUBLIC_KEY>", pub)
    out = out.replace("<SERVER_ADDR>", normalized_string)
    out = out.replace("<SERVER_PORT>", str(opt.port))

    # Заполняем параметры обфускации
    out = _fill_obfuscation_params(out, obf_params)

    out = out.replace("<SERVER_IFACE>", main_iface)
    out = out.replace("<SERVER_TUN>", tun_name)
    out = out.replace("<SERVER_UP_SCRIPT>", str(up_path))
    out = out.replace("<SERVER_DOWN_SCRIPT>", str(down_path))
    out = out.replace("<MTU>", str(opt.mtu))

    atomic_write_text(g_main_config_fn, out)
    logger.info("✅ Серверный конфиг создан: %s", g_main_config_fn)

    # Создаём скрипты
    params_path = up_path.parent / f"{tun_name}.sh"
    _create_scripts(up_path, down_path, params_path, main_iface, tun_name, opt, normalized_string, warp_configs)

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

    # Проверка: существует ли конфиг сервера
    if not g_main_config_fn.exists():
        raise RuntimeError(f'Конфиг интерфейса не найден: {g_main_config_fn}. Сначала создайте интерфейс (--make)')

    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    
    # Проверка: есть ли в конфиге сервера Address (подсеть)
    if not srv or 'Address' not in srv:
        raise RuntimeError(f'В конфиге {g_main_config_fn} отсутствует подсеть (Address). Повредите конфиг или создайте интерфейс заново')
    
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

    # Получаем информацию о сервере
    server_ip_int_ipv4, server_on_network_ipv4, ipv6_server_ip_int, server_on_network_ipv6 = _get_server_ip_info(srvcfg, net_ipv4, net_ipv6)

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
        
        # Добавляем IP сервера в занятые!
        used_ips_ipv6.add(ipv6_server_ip_int)

        # Последний usable зависит от позиции сервера
        if server_on_network_ipv6:
            # Сервер на network → "broadcast" НЕ работает → можно выдать
            last_usable_int_ipv6 = int(net_ipv6.network_address) + net_ipv6.num_addresses - 1
        else:
            # Сервер НЕ на network → "broadcast" РАБОТАЕТ → зарезервирован
            last_usable_int_ipv6 = int(net_ipv6.network_address) + net_ipv6.num_addresses - 2

        # ВАЖНО: Проверяем что позиция сервера в IPv4 и IPv6 совпадает!
        # (оба на network или оба НЕ на network)
        if server_on_network_ipv4 != server_on_network_ipv6:
            raise RuntimeError(
                f'Позиция сервера в IPv4 и IPv6 подсетях должна совпадать!\n'
                f'  IPv4: {ipaddress.IPv4Address(server_ip_int_ipv4)}/{net_ipv4.prefixlen} - '
                f'{"на network address" if server_on_network_ipv4 else "НЕ на network address"}\n'
                f'  IPv6: {ipaddress.IPv6Address(ipv6_server_ip_int)}/{net_ipv6.prefixlen} - '
                f'{"на network address" if server_on_network_ipv6 else "НЕ на network address"}\n'
                f'Исправьте: сервер должен быть или на network address в обеих подсетях, '
                f'или НЕ на network address в обеих подсетях!'
            )

    # --- Обработка ручного IP или автоматический выбор ---
    ipaddr_ipv4, ipaddr_ipv6 = _allocate_client_ip(
        opt, net_ipv4, net_ipv6, 
        server_on_network_ipv4, server_on_network_ipv6,
        server_ip_int_ipv4, ipv6_server_ip_int, broadcast_int_ipv4,
        used_ips_ipv4, used_ips_ipv6
    )

    # Формируем итоговый AllowedIPs
    if ipaddr_ipv6:
        ipaddr = f"{ipaddr_ipv4}, {ipaddr_ipv6}"
    else:
        ipaddr = ipaddr_ipv4

    persistent_keepalive = _generate_persistent_keepalive()
    srv_path = pathlib.Path(g_main_config_fn)

    # Добавляем клиента в конфиг
    _add_client_to_config(srv_path, c_name, ipaddr, persistent_keepalive)
    
    logger.info('✅ Пользователь "%s" создан. IP=%s PersistentKeepalive=%s', c_name, ipaddr, persistent_keepalive)


def handle_update(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    
    # Проверка: существует ли конфиг сервера
    if not g_main_config_fn.exists():
        raise RuntimeError(f'Конфиг интерфейса не найден: {g_main_config_fn}. Сначала создайте интерфейс (--make)')
    
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.update
    
    # Проверка: существует ли клиент
    if p_name.lower() not in (x.lower() for x in cfg.peer.keys()):
        raise RuntimeError(f'Клиент "{p_name}" не найден')
    
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
    
    # Проверка: существует ли конфиг сервера
    if not g_main_config_fn.exists():
        raise RuntimeError(f'Конфиг интерфейса не найден: {g_main_config_fn}. Сначала создайте интерфейс (--make)')
    
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.delete
    
    # Проверка: существует ли клиент
    if p_name.lower() not in (x.lower() for x in cfg.peer.keys()):
        raise RuntimeError(f'Клиент "{p_name}" не найден')
    
    logger.info('🗑️  Удаление пользователя "%s"...', p_name)
    ipaddr = cfg.del_client(p_name)
    cfg.save()
    logger.info('✅ Удалён "%s". Освобождён IP=%s', p_name, ipaddr)


def handle_warp_gen(opt, need_conf: bool = True) -> List[str]:
    """
    Автономная генерация WARP конфигов (без серверного интерфейса).
    Сохраняет в папку WARP/ рядом со скриптом.

    QR и ZIP генерация теперь в общем коде (generate_qr_codes).

    Args:
        opt: аргументы командной строки
        need_conf: нужны ли конфиги

    Returns:
        Список путей к сгенерированным WARP конфигам
    """
    # Определяем версию протокола
    awg_version = getattr(opt, 'version', 'AWG2.0')

    # Создаём папку WARP/ рядом со скриптом
    warp_dir = SCRIPT_DIR.joinpath("WARP")
    warp_dir.mkdir(parents=True, exist_ok=True)
    logger.info("📁 Папка WARP: %s", warp_dir)

    # Очистка старых WARP конфигов, QR и ZIP
    for fn in glob.glob(str(warp_dir.joinpath("warp*.conf"))):
        try:
            os.remove(fn)
        except Exception:
            pass
    for fn in glob.glob(str(warp_dir.joinpath("warp*.png"))):
        try:
            os.remove(fn)
        except Exception:
            pass
    for fn in glob.glob(str(warp_dir.joinpath("warp*.zip"))):
        try:
            os.remove(fn)
        except Exception:
            pass

    # Генерируем WARP конфиги
    num_warps = opt.warp if opt.warp > 0 else 1
    logger.info("🌀 Генерация %d WARP конфигов (версия: %s)...", num_warps, awg_version)

    warp_configs: List[str] = []
    last_error = None

    for i in range(num_warps):
        success = False
        for attempt in range(3):
            try:
                conf_text, fname = generate_warp_config(
                    tun_name="",  # Без префикса интерфейса
                    index=i,
                    mtu=opt.mtu,
                    proxy=opt.proxy if hasattr(opt, 'proxy') else "",
                    version=awg_version,
                    for_server=False  # Клиентский WARP (без Table = off)
                )
                # Сохраняем в папку WARP/
                path = warp_dir.joinpath(f"warp{i}.conf")
                atomic_write_text(path, conf_text)
                warp_configs.append(str(path))
                success = True
                break
            except Exception as e:
                last_error = str(e)
                time.sleep(1 + attempt)
                continue

        if not success:
            logger.error("❌ Не удалось сгенерировать WARP %d", i)
            if last_error:
                logger.error("📝 Ошибка: %s", last_error)

    if not warp_configs:
        raise RuntimeError("Не удалось сгенерировать WARP конфиги")

    logger.info("✅ Сгенерировано WARP конфигов: %d", len(warp_configs))
    return warp_configs


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
        atomic_write_text(g_defclient_config_fn, out)

    tmpcfg = g_defclient_config_fn.read_text(encoding='utf-8')
    
    # Читаем версию протокола из серверного конфига
    server_protocol = "AWG1.0"  # По умолчанию
    try:
        server_conf_text = g_main_config_fn.read_text(encoding='utf-8')
        for line in server_conf_text.split('\n'):
            if line.startswith('# Protocol:'):
                server_protocol = line.split(':')[1].strip()
                break
    except Exception as e:
        logger.warning("⚠  Не удалось прочитать версию протокола: %s", e)

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

        # Инициализируем random уникальным seed для каждого клиента
        # time.time_ns() ^ os.getpid() ^ hash(peer_name) = уникальный seed даже для пакетной генерации
        _init_random_seed(hash(peer_name))

        persistent_keepalive = _generate_persistent_keepalive()
        mtu = srv.get('MTU', str(opt.mtu))

        # Читаем серверный конфиг для получения параметров S1, S2, S3, S4, H1-H4
        server_conf_text = g_main_config_fn.read_text(encoding='utf-8')

        # Получаем параметры сервера
        server_params = _get_server_params(server_conf_text, server_protocol)

        # seed для cipher suite должен совпадать с серверным (S1 + S2)
        i_seed = f"{server_params.get('S1', '')}{server_params.get('S2', '')}"

        for idx, ep in enumerate(endpoints, start=1):
            host = ep.get('host', '')
            port = ep.get('port', default_port)
            raw_label = ep.get('label', '')

            # Per-endpoint MTU (если указан в _endpoint.config как ;mtu=N)
            ep_mtu = ep.get('mtu', '')
            use_mtu = ep_mtu if ep_mtu else mtu

            # Per-endpoint domain (маскировка под конкретный сервис)
            ep_domain = ep.get('domain', '')

            # Генерируем обфускацию для этого эндпоинта (с учётом domain)
            client_obf_params = generate_all_params(
                server_protocol,
                for_client=True,
                for_server=False,
                domain=ep_domain,
                seed_override=i_seed,
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
                logger.error('❌ Ошибка замены маски: %s', e)
                pass  # Если ошибка, оставляем как есть

            out_base = out_base.replace('<PROTOCOL>', server_protocol)
            out_base = out_base.replace('<MTU>', mtu)
            out_base = out_base.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])
            out_base = out_base.replace('<CLIENT_TUNNEL_IP>', client_allowed_ips)

            # Заполняем параметры обфускации
            out_base = _fill_client_obfuscation_params(
                out_base, client_obf_params,
                server_params['S1'], server_params['S2'],
                server_params['S3'], server_params['S4'],
                server_params['H1'], server_params['H2'],
                server_params['H3'], server_params['H4']
            )

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


def generate_qr_codes(
    qr_filter: Optional[Set[str]] = None,
    warp_configs: Optional[List[str]] = None,
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

    # Собираем все конфиги в один список
    all_configs: List[str] = []
    client_matched_stems: Set[str] = set()
    # Сортируем по (суффикс, метка_эндпоинта, клиент) — группируем по AllowedIPs/Endpoint
    client_configs: List[Tuple[str, str, str, str]] = []

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
        suffix = ""
        client = stem
        ep_label = ""
        for tag in sorted(qr_filter, key=len, reverse=True):
            if tag and tag in stem:
                pos = stem.index(tag)
                if pos >= 0:
                    suffix = tag
                    client = stem[:pos]
                    ep_label = stem[pos + len(tag):]
                    break
        if suffix:
            client_configs.append((suffix, ep_label, client, str(p)))
            client_matched_stems.add(stem)

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
            cur_suffix = ""
            cur_ep = ""
            for tag in sorted(qr_filter, key=len, reverse=True) if qr_filter else []:
                if tag and tag in stem:
                    pos = stem.index(tag)
                    if pos >= 0:
                        cur_suffix = tag
                        cur_ep = stem[pos + len(tag):]
                        break
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


def zip_client_files(client_name: str, base_dir: Optional[pathlib.Path] = None) -> None:
    if base_dir is None:
        base_dir = g_conf_dir
    zip_filename = base_dir.joinpath(f"{client_name}.zip")
    
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
        for file in sorted(base_dir.iterdir()):
            if not file.is_file():
                continue
            if pattern_file.match(file.name):
                _add_file_to_zip(zipf, str(file), file.name)

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


def zip_all(warp_configs: Optional[List[str]] = None) -> None:
    logger.info('📦 Упаковка конфигов в ZIP...')
    names = list(dict.fromkeys(clients_for_zip))
    for name in names:
        zip_client_files(name)
    if warp_configs:
        for cp in warp_configs:
            p = pathlib.Path(cp)
            zip_client_files(p.stem, base_dir=p.parent)


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
parser.add_argument("-r", "--reload", action="store_true", help="Перезагрузить конфиг интерфейса без отключения (awg syncconf)")
parser.add_argument("-i", "--ipaddr", default="", help="IP адрес")
parser.add_argument("-p", "--port", type=int, default=4455, help="Порт")
parser.add_argument("-l", "--limit", type=int, default=0, help="Limit (Mbit)")
parser.add_argument("-f", "--iface", default="", help="Сетевой интерфейс (например ens3)")
parser.add_argument("-v", "--version", type=str, default="AWG2.0", choices=["WG", "AWG", "AWG1.0", "AWG1.5", "AWG2.0"], help="Версия протокола")
parser.add_argument("--make", dest="makecfg", default="", help="Создать серверный конфиг")
parser.add_argument("--mtu", type=int, default=1400, help="MTU")
parser.add_argument("--warp", type=int, default=0, help="WARP конфиги")
parser.add_argument("--proxy", default="", help="Proxy сервер для WARP API (например http://proxy:8080, socks5://127.0.0.1:9050, или 'tor')")
opt = parser.parse_args()


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


# Применяем нормализацию к прокси
opt.proxy = normalize_proxy(opt.proxy)


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


def _handle_reload(override: Optional[str] = None) -> None:
    """Перезагрузить конфиг работающего интерфейса без отключения (strip + syncconf)."""
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=override)
    if g_main_config_fn is None or not g_main_config_fn.exists():
        raise RuntimeError("Не найден серверный конфиг")

    tun = g_main_config_fn.stem
    temp_dir = g_main_config_fn.parent / ".data" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_conf = temp_dir / f"{tun}.conf"

    logger.info("🔄 Перезагрузка конфига %s без отключения...", tun)

    try:
        # strip — сохраняем текущий конфиг работающего интерфейса
        with open(temp_conf, "w") as f:
            subprocess.run(
                ["awg-quick", "strip", tun],
                stdout=f, stderr=subprocess.PIPE, text=True,
                check=True, timeout=15,
            )
        # syncconf — применяем новый конфиг
        subprocess.run(
            ["awg", "syncconf", tun, str(temp_conf)],
            check=True, capture_output=True, text=True, timeout=30,
        )
        logger.info("✅ Конфиг %s обновлён", tun)
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else str(e)
        if "not found" in err.lower() or "does not exist" in err.lower():
            logger.warning("⚠  Интерфейс %s не запущен — syncconf пропущен", tun)
        else:
            logger.error("❌ Ошибка syncconf: %s", err)
            raise


def main() -> None:
    # Проверка на Windows
    if sys.platform == "win32":
        logger.error("❌ Этот скрипт работает только на Linux. Windows не поддерживается.")
        sys.exit(1)

    if not (1280 <= opt.mtu <= 1440):
        raise ValueError("MTU должен быть в диапазоне 1280..1440")

    if opt.reload:
        _handle_reload(override=opt.server_cfg)
        return

    want_conf = opt.confgen
    want_qr = opt.qrcode
    want_zip = opt.zip
    need_conf = want_conf or want_qr or want_zip
    need_qr = want_qr or (want_zip and not want_conf)

    # Автономная генерация WARP конфигов (без серверного интерфейса)
    if opt.warp > 0 and not opt.makecfg and not opt.server_cfg:
        warp_configs = handle_warp_gen(opt, need_conf=need_conf)

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
            for f in os.listdir(warp_dir):
                if f.endswith('.conf') or f.endswith('.png'):
                    try:
                        os.remove(warp_dir.joinpath(f))
                    except Exception:
                        pass
        elif opt.qrcode and not want_zip and not opt.confgen:
            # Только -q → удаляем .zip (если есть)
            for f in os.listdir(warp_dir):
                if f.endswith('.zip'):
                    try:
                        os.remove(warp_dir.joinpath(f))
                    except Exception:
                        pass
        # В остальных случаях оставляем всё

        return

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
    except RuntimeError as e:
        # Ожидаемая ошибка (неудачная генерация WARP и т.п.)
        logger.error("❌ %s", e)
        sys.exit(1)
    except Exception as e:
        # Неожиданная ошибка
        logger.exception("❌ Фатальная ошибка: %s", e)
        sys.exit(1)
