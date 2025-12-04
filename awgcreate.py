#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"""

from __future__ import annotations
import argparse
import datetime
import glob
import ipaddress
import logging
import os
import pathlib
import random
import requests
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Dict, List, Optional, Tuple
# Опциональная генерация QR
try:
    import qrcode
except Exception:
    qrcode = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("awgcreate")

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
CONF_DIR = SCRIPT_DIR.joinpath("conf")
CONF_DIR.mkdir(parents=True, exist_ok=True)

g_main_config_src = SCRIPT_DIR.joinpath(".main.config")
g_main_config_fn: Optional[pathlib.Path] = None
g_main_config_type: Optional[str] = None  # 'WG' or 'AWG'
g_defclient_config_fn = "_defclient.config"

clients_for_zip: List[str] = []

# ----------------- Утилиты -----------------


def atomic_write_text(path: pathlib.Path, text: str, encoding: str = "utf-8") -> None:
    """
    Атомарная запись текста в файл через временный файл + os.replace
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as f:
            f.write(text)
        os.replace(tmpname, str(path))
    finally:
        if os.path.exists(tmpname):
            try:
                os.remove(tmpname)
            except Exception:
                pass


def exec_cmd(cmd, input: Optional[str] = None, shell: bool = False, timeout: Optional[int] = None) -> Tuple[int, str]:
    """
    Выполнение внешней команды. Всегда возвращает (returncode, output).
    Поддерживает и список аргументов, и строку (если нужно shell=True).
    """
    try:
        if shell:
            proc = subprocess.run(
                cmd,
                input=input,
                shell=True,
                check=False,
                timeout=timeout,
                encoding="utf8",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        else:
            if isinstance(cmd, str):
                proc = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    check=False,
                    timeout=timeout,
                    encoding="utf8",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
            else:
                proc = subprocess.run(
                    cmd,
                    input=input,
                    shell=False,
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


def is_windows() -> bool:
    return sys.platform == "win32"


def gen_pair_keys(cfg_type: Optional[str] = None) -> Tuple[str, str]:
    global g_main_config_type
    if is_windows():
        return "priv_dummy", "pub_dummy"
    if not cfg_type:
        cfg_type = g_main_config_type
    if not cfg_type:
        raise RuntimeError("Неизвестный тип конфига для генерации ключей")
    wgtool = "wg" if cfg_type.lower().startswith("w") else "awg"
    rc, out = exec_cmd([wgtool, "genkey"])
    if rc != 0 or not out:
        raise RuntimeError(f"Не удалось сгенерировать приватный ключ через {wgtool}: {out.strip()}")
    priv = out.strip()
    rc, out = exec_cmd([wgtool, "pubkey"], input=priv + "\n")
    if rc != 0 or not out:
        raise RuntimeError(f"Не удалось сгенерировать публичный ключ через {wgtool}: {out.strip()}")
    pub = out.strip()
    return priv, pub


def gen_preshared_key() -> str:
    if is_windows():
        import base64, os as _os
        return base64.b64encode(_os.urandom(24)).decode("ascii")
    rc, out = exec_cmd(["openssl", "rand", "-base64", "32"])
    if rc != 0:
        raise RuntimeError("Не удалось сгенерировать preshared key")
    return out.strip()


def get_main_iface() -> Optional[str]:
    rc, out = exec_cmd(["ip", "link", "show"])
    if rc != 0:
        logger.warning("Не удалось выполнить 'ip link show': %s", out.strip())
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


# ----------------- Шаблоны -----------------

g_defserver_config = """
[Interface]
#_GenKeyTime = <SERVER_KEY_TIME>
#_PublicKey = <SERVER_PUBLIC_KEY>
PrivateKey = <SERVER_PRIVATE_KEY>
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
Endpoint = <SERVER_ADDR>:<SERVER_PORT>
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

# Полные шаблоны up/down с поддержкой WARP (сохранены целиком)
up_script_template_warp = '''#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"
QUANT="4400"

# --- Подсеть и локальный IP сервера в ней ---
LOCAL_SUBNETS="<SERVER_ADDR>"                                  # Подсеть VPN (пример: 10.1.0.0/23)
LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS" | cut -d'/' -f1)"     # Первый IP из подсети = IP сервера

# --- Ограничения скорости для подсетей ---
SUBNETS_LIMITS=(
  "<SERVER_ADDR>:<RATE_LIMIT>"
)
# --- Список WARP-интерфейсов ---
WARP_LIST=(
<WARP_LIST>
)
# --- Подсети исключения (ходят мимо WARP) ---
EXCLUDE_SUBNETS=(
<INTERNET_SUBNETS>
)
# --- Пробросы портов ---
PORT_FORWARDING_RULES=(
  # Формат: "VPN_IP:ВнешнийПорт[>ВнутреннийПорт]:TCP/UDP:Список_разрешённых_подсетей[:SNAT]"
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

echo "————————————————————————————————"

# MARK специфичен для туннеля — берем небольшой оффсет от имени туннеля
TUN_HASH=$(echo -n "$TUN" | od -An -t u1 2>/dev/null | tr -s ' ' '\n' | awk '{s+=$1} END{print s}')
MARK_BASE=$((1000 + (TUN_HASH % 100) * 10))

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
for warp in "${WARP_LIST[@]}"; do
  # если в WARP_LIST окажется "none" — запуск всё равно попытается, но awg-quick "none" не найдёт и выведет ошибку
  echo "Запуск WARP-туннеля: $warp"
  awg-quick up "$warp" || echo "Ошибка запуска $warp: $?"
done

# --- WARP-маршрутизация и балансировка трафика через WARP интерфейсы ---
for i in "${!WARP_LIST[@]}"; do
  TABLE_NAME="${WARP_LIST[$i]}"
  TABLE_ID=$(find_table_id "$TABLE_NAME")
  if [ "$TABLE_ID" = "0" ]; then
    echo "Ошибка: не удалось найти свободный TABLE_ID для $TABLE_NAME"
  else
    grep -q "^$TABLE_ID[[:space:]]$TABLE_NAME$" /etc/iproute2/rt_tables || echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
    ip route replace default dev "$TABLE_NAME" table "$TABLE_NAME"
    ip rule add fwmark $((MARK_BASE+i)) table "$TABLE_NAME" 2>/dev/null || true
  fi
done

# --- iptables для балансировки WARP (случайное распределение новых соединений) ---
iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -N "$RANDOM_WARP_CHAIN"
iptables -t mangle -C PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || iptables -t mangle -A PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN"

# --- Исключение подсетей из маркировки (будут идти напрямую через основной интерфейс) ---
for subnet in "${EXCLUDE_SUBNETS[@]}"; do
  iptables -t mangle -I "$RANDOM_WARP_CHAIN" 1 -d $subnet -j RETURN
done

CNT=${#WARP_LIST[@]}
for i in $(seq 0 $((CNT-1))); do
  MARK=$((MARK_BASE+i))
  iptables -t mangle -A "$RANDOM_WARP_CHAIN" -m conntrack --ctstate NEW -m statistic --mode nth --every $CNT --packet $i -j CONNMARK --set-mark $MARK
done
iptables -t mangle -A "$RANDOM_WARP_CHAIN" -j CONNMARK --restore-mark

# --- Настройка FORWARD и NAT для трафика через WARP ---
for warp in "${WARP_LIST[@]}"; do
  iptables -C FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  iptables -C FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/[...]
  iptables -t nat -C POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
done

# --- Настройка FORWARD и NAT для трафика напрямую через внешний интерфейс (EXCLUDE_SUBNETS) ---
iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
iptables -C FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
iptables -C FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/[...]
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# --- Hairpin NAT ---
iptables -t nat -C POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE

# --- Проброс портов через отдельные цепочки (DNAT + SNAT + ACCEPT) ---
echo "Проброс портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_FILTER, $PF_CHAIN_SNAT)"
iptables -t nat -N "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t filter -N "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t nat -N "$PF_CHAIN_SNAT" 2>/dev/null || true
iptables -t nat -C PREROUTING -i "$IFACE" -j "$PF_CHAIN_NAT" 2>/dev/null || iptables -t nat -A PREROUTING -i "$IFACE" -j "$PF_CHAIN_NAT"
iptables -t filter -C FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || iptables -t filter -A FORWARD -j "$PF_CHAIN_FILTER"
iptables -t nat -C POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || iptables -t nat -A POSTROUTING -j "$PF_CHAIN_SNAT"

# --- Добавление правил для каждого проброса ---
for rule in "${PORT_FORWARDING_RULES[@]}"; do
  IFS=":" read -r CLIENT_IP PF_PORT_PROTO PF_PROTO ALLOWED_SUBNETS SNAT_FLAG <<< "$rule"
  IFS='>' read -r PF_PORT_EXT PF_PORT_INT <<< "$PF_PORT_PROTO"
  [ -z "$PF_PORT_INT" ] && PF_PORT_INT="$PF_PORT_EXT"
  IFS=',' read -ra SUBNETS_ARRAY <<< "$ALLOWED_SUBNETS"

  SNAT_EN=0
  if [ -n "$SNAT_FLAG" ] && [ "${SNAT_FLAG^^}" = "SNAT" ]; then
    SNAT_EN=1
  fi
  if [[ "$PF_PORT_EXT" == *"-"* ]] && [[ "$PF_PORT_INT" == *"-"* ]]; then
    PF_PORT_EXT_START="${PF_PORT_EXT%-*}"
    PF_PORT_EXT_END="${PF_PORT_EXT#*-}"
    PF_PORT_INT_START="${PF_PORT_INT%-*}"
    PF_PORT_INT_END="${PF_PORT_INT#*-}"
    RANGE_LEN=$((PF_PORT_EXT_END - PF_PORT_EXT_START))
    [ $RANGE_LEN -ne $((PF_PORT_INT_END - PF_PORT_INT_START)) ] && { echo "Ошибка: диапазоны портов должны быть одинаковой длины"; continue; }
    for ((i=0; i<=RANGE_LEN; i++)); do
      EXT_PORT=$((PF_PORT_EXT_START + i))
      INT_PORT=$((PF_PORT_INT_START + i))
      for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
        iptables -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$EXT_PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$INT_PORT"
        if [ "$SNAT_EN" -eq 1 ]; then
          iptables -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        fi
        iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      if [ "$SNAT_EN" -eq 1 ]; then
        echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (SNAT)"
      else
        echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (no SNAT)"
      fi
    done
  else
    if [[ "$PF_PORT_EXT" == *"-"* ]]; then
      PF_PORT_START="${PF_PORT_EXT%-*}"
      PF_PORT_END="${PF_PORT_EXT#*-}"
      for ((PORT=PF_PORT_START; PORT<=PF_PORT_END; PORT++)); do
        for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
          iptables -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PORT"
          if [ "$SNAT_EN" -eq 1 ]; then
            iptables -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
          fi
          iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
          iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
        done
        if [ "$SNAT_EN" -eq 1 ]; then
          echo "$PF_PROTO порт $PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (SNAT)"
        else
          echo "$PF_PROTO порт $PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (no SNAT)"
        fi
      done
    else
      for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
        iptables -t nat -A "$PF_CHAIN_NAT" -p "$PF_PROTO" --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PF_PORT_INT"
        if [ "$SNAT_EN" -eq 1 ]; then
          iptables -t nat -A "$PF_CHAIN_SNAT" -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        fi
        iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A "$PF_CHAIN_FILTER" -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      if [ "$SNAT_EN" -eq 1 ]; then
        echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (SNAT)"
      else
        echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]} (no SNAT)"
      fi
    fi
  fi
done

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
modprobe ifb

ip link set "$IFB_IN" down 2>/dev/null || true
ip link delete "$IFB_IN" 2>/dev/null || true
ip link set "$IFB_OUT" down 2>/dev/null || true
ip link delete "$IFB_OUT" 2>/dev/null || true
ip link add "$IFB_OUT" type ifb 2>/dev/null || true
ip link set "$IFB_OUT" up
ip link add "$IFB_IN" type ifb 2>/dev/null || true
ip link set "$IFB_IN" up

tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" ingress 2>/dev/null || true
tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
tc qdisc del dev "$IFB_IN" root 2>/dev/null || true

tc qdisc add dev "$TUN" root handle 1: htb
tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_OUT"
tc qdisc add dev "$IFB_OUT" root handle 1: htb default 2
tc qdisc add dev "$TUN" handle ffff: ingress
tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev "$IFB_IN"
tc qdisc add dev "$IFB_IN" root handle 1: htb default 2

major_class=1
minor_id=1000
echo "Установка лимитов скорости для подсетей"
for entry in "${SUBNETS_LIMITS[@]}"; do
    SUBNET="${entry%%:*}"
    LIM="${entry##*:}"
    IPS=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$SUBNET', strict=False)
for ip in net:
    print(ip)
")
    for ip in $IPS; do
        if [ "$minor_id" -gt 9999 ]; then
            major_class=$((major_class + 1))
            minor_id=1000
            tc class add dev "$IFB_OUT" parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc class add dev "$IFB_OUT" parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc qdisc add dev "$IFB_OUT" parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
            tc class add dev "$IFB_IN" parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc class add dev "$IFB_IN" parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc qdisc add dev "$IFB_IN" parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
        fi
        classid="${major_class}:${minor_id}"
        major="${major_class}:"
        tc class add dev "$IFB_OUT" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
        tc filter add dev "$IFB_OUT" protocol ip parent ${major_class}: prio 1 u32 match ip dst $ip flowid $classid
        tc qdisc add dev "$IFB_OUT" parent $classid fq_codel
        tc class add dev "$IFB_IN" parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
        tc filter add dev "$IFB_IN" protocol ip parent ${major_class}: prio 1 u32 match ip src $ip flowid $classid
        tc qdisc add dev "$IFB_IN" parent $classid fq_codel
        minor_id=$((minor_id + 1))
    done
    echo "$SUBNET -> ${LIM}mbit"
done
echo "————————————————————————————————"
'''

down_script_template_warp = '''#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"

LOCAL_SUBNETS="<SERVER_ADDR>"
LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS" | cut -d'/' -f1)"

WARP_LIST=(
<WARP_LIST>
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

echo "————————————————————————————————"

# --- Остановка WARP-туннелей ---
for warp in "${WARP_LIST[@]}"; do
  echo "Остановка WARP-туннеля: $warp"
  awg-quick down "$warp" || echo "Ошибка остановки $warp: $?"
done

# --- Удаляем Hairpin NAT ---
iptables -t nat -D POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE 2>/dev/null || true

# --- Полное удаление цепочек проброса портов (специфично для туннеля) ---
echo "Очистка проброса портов (цепочки: $PF_CHAIN_NAT, $PF_CHAIN_SNAT, $PF_CHAIN_FILTER)"
iptables -t nat -D PREROUTING -i "$IFACE" -j "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t nat -F "$PF_CHAIN_NAT" 2>/dev/null || true
iptables -t nat -X "$PF_CHAIN_NAT" 2>/dev/null || true

iptables -t nat -D POSTROUTING -j "$PF_CHAIN_SNAT" 2>/dev/null || true
iptables -t nat -F "$PF_CHAIN_SNAT" 2>/dev/null || true
iptables -t nat -X "$PF_CHAIN_SNAT" 2>/dev/null || true

iptables -t filter -D FORWARD -j "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t filter -F "$PF_CHAIN_FILTER" 2>/dev/null || true
iptables -t filter -X "$PF_CHAIN_FILTER" 2>/dev/null || true

# --- Очистка iptables для балансировки WARP (цепочка специфична для туннеля) ---
iptables -t mangle -F "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -D PREROUTING -i "$TUN" -j "$RANDOM_WARP_CHAIN" 2>/dev/null || true
iptables -t mangle -X "$RANDOM_WARP_CHAIN" 2>/dev/null || true

# --- Очистка FORWARD и NAT для трафика через WARP ---
for warp in "${WARP_LIST[@]}"; do
  iptables -D FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
done

# --- Очистка FORWARD и NAT для трафика напрямую через внешний интерфейс (EXCLUDE_SUBNETS) ---
iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# --- Удаление правил маршрутизации и таблиц для WARP ---
for i in "${!WARP_LIST[@]}"; do
  TABLE_NAME="${WARP_LIST[$i]}"
  ip rule del fwmark $((1000 + i)) table "$TABLE_NAME" 2>/dev/null || true
  ip route flush table "$TABLE_NAME" 2>/dev/null || true
done

# --- Откат лимитов скорости (tc и ifb) ---
echo "Очистка лимитов"
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" ingress 2>/dev/null || true
tc qdisc del dev "$IFB_IN" root 2>/dev/null || true
ip link set "$IFB_IN" down 2>/dev/null || true
ip link delete "$IFB_IN" 2>/dev/null || true
tc qdisc del dev "$IFB_OUT" root 2>/dev/null || true
ip link set "$IFB_OUT" down 2>/dev/null || true
ip link delete "$IFB_OUT" 2>/dev/null || true
echo "————————————————————————————————"
'''

# ----------------- Вспомогательный класс IPAddr -----------------


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


# ----------------- WGConfig -----------------


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
                raise RuntimeError(f'Некорректная строка в конфиге #{n+1}: {line}')
            xv = parsed.find('=')
            vname = parsed[:xv].strip()
            value = parsed[xv + 1 :].strip()
            if not secitem or not lineitem:
                raise RuntimeError(f'Параметр без секции #{n+1}: {line}')
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
                    raise RuntimeError("Peer без Name/PublicKey")
                if 'AllowedIPs' not in item:
                    raise RuntimeError(f'Peer {pname} не содержит AllowedIPs')
                if pname in self.peer:
                    raise RuntimeError(f'Дублирование peer {pname}')
                self.peer[pname] = item
            if pname in self.idsline:
                raise RuntimeError(f'Дублирование idline для {pname}')
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
    "engage.cloudflareclient.com:2408",
    "engage.cloudflareclient.com:4500",
    "162.159.192.1:500",
    "162.159.192.9:3138",
    "188.114.98.124:3581",
    "188.114.98.36:7559",
    "188.114.99.224:1002",
]

FALLBACK_DSYT_ALLOWEDIPS = (
    "162.159.0.0/16, 66.22.0.0/16, 8.8.4.0/24, 8.8.8.0/24, 8.34.208.0/20, 8.35.192.0/20, "
    "23.236.48.0/20, 23.251.128.0/19, 34.0.0.0/10, 35.184.0.0/13, 35.192.0.0/14, 35.196.0.0/15, "
    "35.198.0.0/16, 35.199.0.0/17, 35.199.128.0/18, 35.200.0.0/13, 35.208.0.0/12, 64.18.0.0/20, "
    "64.233.160.0/19, 66.102.0.0/20, 66.249.64.0/19, 70.32.128.0/19, 72.14.192.0/18, 74.114.24.0/21, "
    "74.125.0.0/16, 104.132.0.0/23, 104.133.0.0/23, 104.134.0.0/15, 104.156.64.0/18, 104.237.160.0/19, "
    "108.59.80.0/20, 108.170.192.0/18, 108.177.0.0/17, 130.211.0.0/16, 136.112.0.0/12, 142.250.0.0/15, "
    "146.148.0.0/17, 162.216.148.0/22, 162.222.176.0/21, 172.110.32.0/21, 172.217.0.0/16, 172.253.0.0/16, "
    "173.194.0.0/16, 173.255.112.0/20, 192.158.28.0/22, 192.178.0.0/15, 193.186.4.0/24, 199.36.154.0/23, "
    "199.36.156.0/24, 199.192.112.0/22, 199.223.232.0/21, 207.223.160.0/20, 208.65.152.0/22, 208.68.108.0/22, "
    "208.81.188.0/22, 208.117.224.0/19, 209.85.128.0/17, 216.58.192.0/19, 216.239.32.0/19, 216.239.36.0/24, "
    "216.239.38.0/23, 216.239.40.0/22"
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

    # UDP probe
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


def generate_warp_config(tun_name: str, index: int, mtu: int) -> Tuple[str, str]:
    """
    Генерация одного WARP-конфига. Пытается получить данные из Cloudflare API,
    выбирает рабочий endpoint из ответа или из списка запасных, проверяя достижимость.
    Если не удаётся найти доступный endpoint — возбуждает исключение.
    """
    api = "https://api.cloudflareclient.com/v0i1909051800"
    headers = {"user-agent": "amneziawg-script/1.0", "content-type": "application/json"}

    try:
        priv_key, pub_key = gen_pair_keys("AWG")
        data = {
            "install_id": "",
            "tos": datetime.datetime.utcnow().isoformat() + "Z",
            "key": pub_key,
            "fcm_token": "",
            "type": "ios",
            "locale": "en_US",
        }
        resp = requests.post(f"{api}/reg", headers=headers, json=data, timeout=10)
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
            timeout=10,
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

    # Список кандидатов: сначала endpoint из API (если есть), затем запасные
    candidates = []
    if api_endpoint:
        candidates.append(api_endpoint)
    candidates.extend(CANDIDATE_WARP_ENDPOINTS)

    chosen = None
    for ep in candidates:
        try:
            if check_endpoint(ep, timeout=1.5):
                chosen = ep
                break
        except Exception:
            continue

    if not chosen:
        raise RuntimeError("Не найден доступный endpoint для WARP")

    jc = random.randint(80, 120)
    jmin = random.randint(48, 64)
    jmax = random.randint(jmin + 8, 80)
    persistent_keepalive = random.randint(3, 30)

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


def generate_warp_configs(tun_name: str, num_warps: int, mtu: int) -> List[str]:
    """
    Генерация N WARP-конфигов с попытками и откатом при неудаче.
    Возвращает список имён сгенерированных файлов. Если не удалось сгенерировать хотя бы один —
    функция возвращает пустой список (вызывающая сторона должна продолжить без WARP).
    """
    warp_configs: List[str] = []
    for i in range(num_warps):
        success = False
        for attempt in range(5):
            try:
                conf_text, fname = generate_warp_config(tun_name, i, mtu)
                path = pathlib.Path(g_main_config_fn).parent.joinpath(fname)
                atomic_write_text(path, conf_text)
                warp_configs.append(fname)
                success = True
                break
            except requests.exceptions.HTTPError as he:
                status = getattr(he.response, "status_code", None)
                if status == 429:
                    backoff = 5 + attempt * 5
                    logger.warning("Cloudflare API rate-limited; ожидаю %d сек", backoff)
                    time.sleep(backoff)
                    continue
                else:
                    logger.warning("HTTP ошибка при генерации WARP: %s", he)
                    break
            except Exception as e:
                logger.warning("Попытка генерации WARP %d не удалась: %s", attempt + 1, e)
                time.sleep(1 + attempt)
                continue
        if not success:
            logger.warning("Отмена генерации WARP; продолжаем без WARP.")
            # удалить всё, что было создано ранее
            for created in warp_configs:
                try:
                    p = pathlib.Path(g_main_config_fn).parent.joinpath(created)
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
            return []
    return warp_configs


# ----------------- fetch DsYt с fallback -----------------


def fetch_allowed_dsyt() -> str:
    """
    Загружает CIDR-листы для набора сайтов. Если не удалось получить ни одной записи —
    возвращает заранее подготовленный FALLBACK_DSYT_ALLOWEDIPS.
    """
    sites = [
        "youtube.com",
        "discord.com",
        "discord.gg",
        "discord.media",
        "chatgpt.com",
        "pornhub.com",
    ]
    protocols = ["cidr4", "cidr6"]
    ip_set = set()
    any_success = False
    for site in sites:
        for proto in protocols:
            url = f"https://iplist.opencck.org/?format=comma&data={proto}&site={site}"
            try:
                r = requests.get(url, timeout=8)
                r.raise_for_status()
                data = r.text.strip()
                if not data:
                    continue
                any_success = True
                for item in data.split(","):
                    item = item.strip()
                    if not item:
                        continue
                    try:
                        ipaddress.ip_network(item, strict=False)
                        ip_set.add(item)
                    except Exception:
                        logger.debug("Неверный CIDR %s от %s/%s", item, site, proto)
                        continue
            except Exception as e:
                logger.warning("Не удалось получить IP-адреса для %s (%s): %s", site, proto, e)
    if not any_success or not ip_set:
        logger.warning("Используется fallback AllowedIPs для DsYt конфигов")
        return FALLBACK_DSYT_ALLOWEDIPS
    return ", ".join(sorted(ip_set))


# ----------------- Обработчики (make/create/add/update/delete/confgen и пр.) -----------------


def handle_makecfg(opt) -> None:
    global g_main_config_fn, g_main_config_type
    g_main_config_fn = pathlib.Path(opt.makecfg)
    if g_main_config_fn.exists():
        raise RuntimeError(f'Файл уже существует: {g_main_config_fn}')
    mtype = "AWG" if g_main_config_fn.name.startswith("a") else "WG"
    main_iface = get_main_iface()
    if not main_iface:
        raise RuntimeError("Не удалось определить основной сетевой интерфейс")
    if not opt.ipaddr:
        raise RuntimeError("Укажите --ipaddr")
    ipaddr = IPAddr(opt.ipaddr)
    if not ipaddr.mask:
        raise RuntimeError("IP должен содержать маску")
    tun_name = opt.tun if opt.tun else g_main_config_fn.stem
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
    out = out.replace("<SERVER_ADDR>", str(ipaddr))
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
    logger.info("Серверный конфиг создан: %s", g_main_config_fn)

    warp_configs: List[str] = []
    if opt.warp > 0:
        logger.info("Генерация %d WARP конфигов...", opt.warp)
        try:
            warp_configs = generate_warp_configs(tun_name, opt.warp, opt.mtu)
        except Exception as e:
            logger.warning("Генерация WARP не удалась: %s", e)
            warp_configs = []
        for c in warp_configs:
            logger.info("WARP конфиг: %s", c)

    if warp_configs:
        warp_list_str = "\n".join([f'  \"{pathlib.Path(cfg).stem}\"' for cfg in warp_configs])
        internet_subnets_str = ""
    else:
        warp_list_str = '  "none"'
        internet_subnets_str = '  "0.0.0.0/0"\n  "::/0"'

    replacements = {
        "<SERVER_PORT>": str(opt.port),
        "<SERVER_IFACE>": main_iface,
        "<SERVER_TUN>": tun_name,
        "<SERVER_ADDR>": str(ipaddr),
        "<RATE_LIMIT>": f"{opt.limit}",
        "<WARP_LIST>": warp_list_str,
        "<INTERNET_SUBNETS>": internet_subnets_str,
    }
    up_script = up_script_template_warp
    down_script = down_script_template_warp
    for k, v in replacements.items():
        up_script = up_script.replace(k, v)
        down_script = down_script.replace(k, v)
    atomic_write_text(up_path, up_script)
    atomic_write_text(down_path, down_script)
    os.chmod(str(up_path), 0o755)
    os.chmod(str(down_path), 0o755)
    atomic_write_text(g_main_config_src, str(g_main_config_fn))
    sys.exit(0)


def handle_create(opt) -> None:
    tmpcfg_path = SCRIPT_DIR.joinpath(opt.tmpcfg)
    if tmpcfg_path.exists():
        raise RuntimeError(f'Файл уже существует: {tmpcfg_path}')
    logger.info("Создание шаблона клиентских конфигов: %s", tmpcfg_path)
    ipaddr = opt.ipaddr or get_ext_ipaddr()
    if "/" not in ipaddr:
        ipaddr += "/32"
    ipaddr_obj = IPAddr(ipaddr)
    raw_ip = f"{ipaddr_obj.ip[0]}.{ipaddr_obj.ip[1]}.{ipaddr_obj.ip[2]}.{ipaddr_obj.ip[3]}"
    out = g_defclient_config.replace("<SERVER_ADDR>", raw_ip)
    if g_main_config_type != "AWG":
        out = out.replace("\nJc = <", "\n# ")
        out = out.replace("\nJmin = <", "\n# ")
        out = out.replace("\nJmax = <", "\n# ")
        out = out.replace("\nS1 = <", "\n# ")
        out = out.replace("\nS2 = <", "\n# ")
        out = out.replace("\nH1 = <", "\n# ")
        out = out.replace("\nH2 = <", "\n# ")
        out = out.replace("\nH3 = <", "\n# ")
        out = out.replace("\nH4 = <", "\n# ")
    atomic_write_text(tmpcfg_path, out)
    logger.info("Шаблон клиентских конфигов записан: %s", tmpcfg_path)
    sys.exit(0)


def handle_add(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    c_name = opt.addcl
    logger.info('Создание нового пользователя "%s"...', c_name)
    if c_name.lower() in (x.lower() for x in cfg.peer.keys()):
        raise RuntimeError(f'Пользователь "{c_name}" уже существует')
    net = ipaddress.ip_network(srv['Address'], strict=False)
    used_ips = set()
    for peer in cfg.peer.values():
        try:
            ip = peer['AllowedIPs'].split('/')[0]
            used_ips.add(int(ipaddress.IPv4Address(ip)))
        except Exception:
            continue
    if opt.ipaddr:
        manual_ip = ipaddress.ip_network(opt.ipaddr, strict=False)
        ip_int = int(manual_ip.network_address)
        if ip_int in used_ips:
            raise RuntimeError(f'IP {opt.ipaddr} уже используется')
        ipaddr = f"{str(manual_ip.network_address)}/{manual_ip.prefixlen}"
    else:
        first_ip_int = int(net.network_address) + 1
        last_ip_int = int(net.broadcast_address) - 1
        chosen = None
        for ip_int in range(first_ip_int, last_ip_int + 1):
            if ip_int not in used_ips:
                chosen = ip_int
                break
        if chosen is None:
            raise RuntimeError('Нет свободных IP-адресов')
        ipaddr = f"{str(ipaddress.IPv4Address(chosen))}/32"
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()
    persistent_keepalive = random.randint(3, 30)
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
    logger.info('Пользователь "%s" создан. IP=%s PersistentKeepalive=%s', c_name, ipaddr, persistent_keepalive)


def handle_update(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.update
    logger.info('Сброс ключей для "%s"...', p_name)
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()
    cfg.set_param(p_name, '_PrivateKey', priv_key, force=True, offset=2)
    cfg.set_param(p_name, 'PublicKey', pub_key)
    cfg.set_param(p_name, 'PresharedKey', psk)
    gentime = datetime.datetime.now().isoformat()
    cfg.set_param(p_name, '_GenKeyTime', gentime, force=True, offset=2)
    new_pk = random.randint(3, 30)
    cfg.set_param(p_name, 'PersistentKeepalive', str(new_pk), force=True, offset=3)
    ipaddr = cfg.peer[p_name]['AllowedIPs']
    cfg.save()
    logger.info('Ключи сброшены для "%s". IP=%s NewPK=%s', p_name, ipaddr, new_pk)


def handle_delete(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    p_name = opt.delete
    logger.info('Удаление пользователя "%s"...', p_name)
    ipaddr = cfg.del_client(p_name)
    cfg.save()
    logger.info('Удалён "%s". Освобождён IP=%s', p_name, ipaddr)


def handle_confgen(opt) -> None:
    if g_main_config_fn is None:
        get_main_config_path(check=True, override=opt.server_cfg)
    cfg = WGConfig(str(g_main_config_fn))
    srv = cfg.iface
    logger.info('Генерация клиентских конфигов...')
    tmpcfg_path = SCRIPT_DIR.joinpath(opt.tmpcfg)
    if not tmpcfg_path.exists():
        logger.info('Шаблон не найден, создаю стандартный шаблон...')
        ipaddr = opt.ipaddr or get_ext_ipaddr()
        if '/' not in ipaddr:
            ipaddr += '/32'
        ipobj = IPAddr(ipaddr)
        raw_ip = f"{ipobj.ip[0]}.{ipobj.ip[1]}.{ipobj.ip[2]}.{ipobj.ip[3]}"
        out = g_defclient_config.replace("<SERVER_ADDR>", raw_ip)
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
        atomic_write_text(tmpcfg_path, out)
        logger.info('Шаблон клиента создан: %s', tmpcfg_path)
    tmpcfg = tmpcfg_path.read_text(encoding='utf-8')
    # Очистка conf-папки (кроме awg0.conf)
    for fn in glob.glob(str(CONF_DIR.joinpath("*.conf"))):
        if fn.endswith('awg0.conf'):
            continue
        try:
            os.remove(fn)
        except Exception:
            pass
    for fn in glob.glob(str(CONF_DIR.joinpath("*.png"))):
        try:
            os.remove(fn)
        except Exception:
            pass
    random.seed()
    fetched_dsyt_ips = fetch_allowed_dsyt()
    only_list = get_only_list()
    peers = list(cfg.peer.items())
    if only_list:
        peers = [(name, peer) for name, peer in peers if name.lower() in [x.lower() for x in only_list]]
        if not peers:
            raise RuntimeError('Ни одного клиента не найдено для --only')
    for peer_name, peer in peers:
        if 'Name' not in peer or 'PrivateKey' not in peer:
            logger.info('Пропуск peer с публичным ключом %s', peer.get("PublicKey", "<no>"))
            continue
        psk = peer.get('PresharedKey', gen_preshared_key())
        if 'PresharedKey' not in peer:
            cfg.set_param(peer_name, 'PresharedKey', psk)
        jc = random.randint(80, 120)
        jmin = random.randint(48, 64)
        jmax = random.randint(jmin + 8, 80)
        persistent_keepalive = random.randint(3, 30)
        out = tmpcfg[:]
        mtu = srv.get('MTU', str(opt.mtu))
        out = out.replace('<MTU>', mtu)
        out = out.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])
        out = out.replace('<CLIENT_TUNNEL_IP>', peer['AllowedIPs'])
        out = out.replace('<JC>', str(jc))
        out = out.replace('<JMIN>', str(jmin))
        out = out.replace('<JMAX>', str(jmax))
        out = out.replace('<S1>', srv.get('S1', ''))
        out = out.replace('<S2>', srv.get('S2', ''))
        out = out.replace('<H1>', srv.get('H1', ''))
        out = out.replace('<H2>', srv.get('H2', ''))
        out = out.replace('<H3>', srv.get('H3', ''))
        out = out.replace('<H4>', srv.get('H4', ''))
        out = out.replace('<SERVER_PORT>', srv.get('ListenPort', ''))
        out = out.replace('<SERVER_PUBLIC_KEY>', srv.get('PublicKey', ''))
        out = out.replace('<PRESHARED_KEY>', psk)
        out = out.replace('<SERVER_ADDR>', srv.get('Address', ''))
        out = out.replace('<PERSISTENT_KEEPALIVE>', str(persistent_keepalive))
        out_all = out.replace('<ALLOWED_IPS>', '0.0.0.0/0, ::/0')
        with open(CONF_DIR.joinpath(f'{peer_name}All.conf'), 'w', newline='\n', encoding='utf-8') as file:
            file.write(out_all)
        out_dsyt = out.replace('<ALLOWED_IPS>', fetched_dsyt_ips)
        with open(CONF_DIR.joinpath(f'{peer_name}DsYt.conf'), 'w', newline='\n', encoding='utf-8') as file:
            file.write(out_dsyt)
        clients_for_zip.append(peer_name)


def generate_qr_codes() -> None:
    logger.info('Генерация QR-кодов...')
    if qrcode is None:
        raise RuntimeError('Пакет qrcode не установлен')
    for fn in glob.glob(str(CONF_DIR.joinpath("*.png"))):
        try:
            os.remove(fn)
        except Exception:
            pass
    flst = [f for f in glob.glob(str(CONF_DIR.joinpath("*All.conf")))]
    if not flst:
        raise RuntimeError('Нет All.conf файлов для генерации QR')
    def generate_qr(conf, fn):
        if os.path.getsize(fn) > 2048:
            logger.warning('Конфиг %s >2KB, возможно QR не получится', fn)
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
        raise ValueError("Данных слишком много для QR")
    for fn in flst:
        if fn.endswith('awg0.conf'):
            continue
        with open(fn, 'r', encoding='utf-8') as file:
            conf = file.read()
        name = os.path.splitext(os.path.basename(fn))[0]
        png_path = CONF_DIR.joinpath(f"{name}.png")
        try:
            img = generate_qr(conf, fn)
            img.save(str(png_path))
        except Exception as e:
            logger.error('Ошибка генерации QR для %s: %s', fn, e)


def zip_client_files(client_name: str) -> None:
    zip_filename = CONF_DIR.joinpath(f"{client_name}.zip")
    with zipfile.ZipFile(str(zip_filename), 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
        for suffix in ['All.conf', 'DsYt.conf', 'All.png']:
            file = CONF_DIR.joinpath(f"{client_name}{suffix}")
            if file.exists():
                zipf.write(str(file), arcname=file.name)


def zip_all() -> None:
    logger.info('Упаковка конфигов в ZIP...')
    for name in clients_for_zip:
        zip_client_files(name)


def clean_confdir_types(keep_conf: bool = False, keep_qr: bool = False, keep_zip: bool = False,
                        allowed_names: Optional[List[str]] = None) -> None:
    keep_files = set()
    if allowed_names:
        for name in allowed_names:
            if keep_conf:
                keep_files.add(f"{name}All.conf")
                keep_files.add(f"{name}DsYt.conf")
            if keep_qr:
                keep_files.add(f"{name}All.png")
            if keep_zip:
                keep_files.add(f"{name}.zip")
    else:
        for f in os.listdir(CONF_DIR):
            if keep_conf and (f.endswith('All.conf') or f.endswith('DsYt.conf')):
                keep_files.add(f)
            if keep_qr and f.endswith('All.png'):
                keep_files.add(f)
            if keep_zip and f.endswith('.zip'):
                keep_files.add(f)
    for f in os.listdir(CONF_DIR):
        if f not in keep_files and (f.endswith('.conf') or f.endswith('.png') or f.endswith('.zip')):
            try:
                os.remove(CONF_DIR.joinpath(f))
            except Exception:
                logger.debug('Не удалось удалить %s', f)


# ----------------- CLI -----------------

parser = argparse.ArgumentParser(description="AmneziaWG инструмент для конфигов")
parser.add_argument("-s", "--serv-cfg", dest="server_cfg", default="", help="Server config (awg0/conf или путь). Используется .main.config если пусто")
parser.add_argument("-a", "--add", dest="addcl", default="", help="Добавить клиента с именем")
parser.add_argument("-u", "--update", default="", help="Сбросить ключи для клиента")
parser.add_argument("-d", "--delete", default="", help="Удалить клиента")
parser.add_argument("-c", "--conf", dest="confgen", action="store_true", help="Сгенерировать клиентские конфиги")
parser.add_argument("-q", "--qrcode", action="store_true", help="Сгенерировать QR-коды")
parser.add_argument("-z", "--zip", action="store_true", help="Создать ZIP-архивы")
parser.add_argument("-o", "--only", help="Генерировать только для указанных клиентов (через запятую)", default="")
parser.add_argument("-t", "--tmpcfg", default=g_defclient_config_fn, help="Путь к шаблону клиентского конфига")
parser.add_argument("-i", "--ipaddr", default="", help="IP адрес сервера с маской")
parser.add_argument("-p", "--port", type=int, default=44567, help="Порт сервера")
parser.add_argument("-l", "--limit", type=int, default=99, help="Ограничение скорости (Mbit)")
parser.add_argument("--make", dest="makecfg", default="", help="Создать новый серверный конфиг")
parser.add_argument("--tun", default="", help="Имя туннеля")
parser.add_argument("--create", action="store_true", help="Создать шаблон клиента")
parser.add_argument("--mtu", type=int, default=1388, help="MTU (1280-1420)")
parser.add_argument("--warp", type=int, default=0, help="Количество WARP конфигов для генерации")
opt = parser.parse_args()


def get_only_list() -> List[str]:
    if not opt.only:
        return []
    return [x.strip() for x in opt.only.split(",") if x.strip()]


# проверка одновременных действий
xopt = [opt.addcl, opt.update, opt.delete]
copt = [x for x in xopt if len(x) > 0]
if copt and len(copt) >= 2:
    raise RuntimeError('Слишком много действий одновременно')


def resolve_server_config_candidate(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    p = pathlib.Path(name)
    if p.is_absolute() and p.exists():
        return str(p)
    if p.exists():
        return str(p.resolve())
    candidates = []
    if not name.endswith(".conf"):
        candidates.append(name + ".conf")
    candidates.append(name)
    standard_dir = pathlib.Path("/etc/amnezia/amneziawg")
    for cand in candidates:
        p1 = pathlib.Path.cwd().joinpath(cand)
        if p1.exists():
            return str(p1.resolve())
        p2 = pathlib.Path(cand)
        if p2.exists():
            return str(p2.resolve())
        p3 = standard_dir.joinpath(cand)
        if p3.exists():
            return str(p3.resolve())
    p4 = standard_dir.joinpath(name)
    if p4.exists():
        return str(p4.resolve())
    return None


def get_main_config_path(check: bool = True, override: Optional[str] = None) -> Optional[str]:
    global g_main_config_fn, g_main_config_type
    if override:
        resolved = resolve_server_config_candidate(override)
        if resolved:
            g_main_config_fn = pathlib.Path(resolved)
            g_main_config_type = "AWG" if g_main_config_fn.name.startswith("a") else "WG"
            return str(g_main_config_fn)
        else:
            if check:
                raise RuntimeError(f'Не найден серверный конфиг "{override}"')
            g_main_config_fn = None
            g_main_config_type = None
            return None
    if not g_main_config_src.exists():
        if check:
            raise RuntimeError(f'{g_main_config_src} не найден')
        g_main_config_fn = None
        g_main_config_type = None
        return None
    content = g_main_config_src.read_text(encoding="utf-8").strip()
    if not content:
        if check:
            raise RuntimeError(f'{g_main_config_src} пустой')
        g_main_config_fn = None
        g_main_config_type = None
        return None
    g_main_config_fn = pathlib.Path(content.splitlines()[0].strip())
    cfg_exists = g_main_config_fn.exists()
    g_main_config_type = "AWG" if g_main_config_fn.name.startswith("a") else "WG"
    if check and not cfg_exists:
        raise RuntimeError(f'Основной {g_main_config_type} конфиг "{g_main_config_fn}" не найден')
    return str(g_main_config_fn)


def main() -> None:
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
    if opt.create:
        handle_create(opt)
        return
    if opt.addcl:
        handle_add(opt)
        return
    if opt.update:
        handle_update(opt)
        return
    if opt.delete:
        handle_delete(opt)
        return
    if need_conf:
        if g_main_config_fn is None:
            get_main_config_path(check=True, override=opt.server_cfg)
        handle_confgen(opt)
    if need_qr:
        generate_qr_codes()
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
    logger.info('Готово')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Фатальная ошибка: %s", e)
        sys.exit(1)
