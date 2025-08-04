import os
import sys
import glob
import subprocess
import argparse
import random
import datetime
import requests
import zipfile
import qrcode
import urllib.request


# === ДОБАВЛЕНО: директория для всех клиентских файлов ===
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_DIR = os.path.join(SCRIPT_DIR, "conf")
os.makedirs(CONF_DIR, exist_ok=True)

def clean_confdir_types(keep_conf=False, keep_qr=False, keep_zip=False, allowed_names=None):
    """
    Оставляет только нужные типы файлов в conf.
    allowed_names — если не None, то оставляет только файлы клиентов из этого списка.
    """
    suffixes = {
        "conf": ['All.conf', 'DsYt.conf'],
        "qr": ['All.png'],
        "zip": ['.zip']
    }

    # Составляем список файлов, которые нужно оставить
    keep_files = set()
    if allowed_names:
        for name in allowed_names:
            if keep_conf:
                for suf in suffixes["conf"]:
                    keep_files.add(f"{name}{suf}")
            if keep_qr:
                for suf in suffixes["qr"]:
                    keep_files.add(f"{name}{suf}")
            if keep_zip:
                for suf in suffixes["zip"]:
                    keep_files.add(f"{name}{suf}")
    else:
        for f in os.listdir(CONF_DIR):
            if keep_conf and (f.endswith('All.conf') or f.endswith('DsYt.conf')):
                keep_files.add(f)
            if keep_qr and f.endswith('All.png'):
                keep_files.add(f)
            if keep_zip and f.endswith('.zip'):
                keep_files.add(f)

    # Теперь удаляем всё лишнее
    for f in os.listdir(CONF_DIR):
        if f not in keep_files and (f.endswith('.conf') or f.endswith('.png') or f.endswith('.zip')):
            try:
                os.remove(os.path.join(CONF_DIR, f))
            except Exception:
                pass

def get_only_list():
    """
    Возвращает список имён клиентов, если указан --only, иначе []
    """
    if not opt.only:
        return []
    # Разбиваем по запятым, убираем пробелы
    return [x.strip() for x in opt.only.split(",") if x.strip()]

def main():
    # Проверка MTU перенесена сюда, чтобы выполнялась всегда
    if not (1280 <= opt.mtu <= 1420):
        raise ValueError("Ошибка: MTU должен быть в диапазоне от 1280 до 1420.")

    want_conf = opt.confgen
    want_qr = opt.qrcode
    want_zip = opt.zip

    need_conf = want_conf or want_qr or want_zip
    need_qr = want_qr or want_zip

    if opt.makecfg:
        handle_makecfg()
        return

    get_main_config_path(check=True)

    if opt.create:
        handle_create()
        return
    if opt.addcl:
        handle_add()
        return
    if opt.update:
        handle_update()
        return
    if opt.delete:
        handle_delete()
        return

    if need_conf:
        handle_confgen()
    if need_qr:
        generate_qr_codes()
    if want_zip:
        zip_all()

    # Универсальная очистка по выбранным флагам (работает с --only и без)
    only_list = get_only_list()
    allowed_names = None
    # Определяем имена клиентов для очистки, если --only используется
    if only_list:
        # Нам нужно получить точный набор имён, которые реально были сгенерированы
        # Это те же имена, что использовались в handle_confgen — то есть список clients_for_zip
        allowed_names = clients_for_zip if clients_for_zip else only_list

    clean_confdir_types(
        keep_conf=want_conf,
        keep_qr=want_qr,
        keep_zip=want_zip,
        allowed_names=allowed_names
    )

    print('===== Готово! =====')

g_main_config_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.main.config')
g_main_config_fn = None
g_main_config_type = None

g_defclient_config_fn = "_defclient.config"

clients_for_zip = []

parser = argparse.ArgumentParser(description="AmneziaWG config tool")
parser.add_argument("-t", "--tmpcfg", default=g_defclient_config_fn)
parser.add_argument("-c", "--conf", dest="confgen", action="store_true")
parser.add_argument("-q", "--qrcode", action="store_true")
parser.add_argument("-a", "--add", dest="addcl", default="")
parser.add_argument("-u", "--update", default="")
parser.add_argument("-d", "--delete", default="")
parser.add_argument("-i", "--ipaddr", default="")
parser.add_argument("-p", "--port", type=int)
parser.add_argument("-l", "--limit", type=int, default=44)
parser.add_argument("-z", "--zip", action="store_true")
parser.add_argument("--make", dest="makecfg", default="")
parser.add_argument("--tun", default="")
parser.add_argument("--create", action="store_true")
parser.add_argument("--only", help="Генерировать конфиг только для указанного клиента", default="")
parser.add_argument("--mtu", type=int, default=1388, help="Значение MTU для конфигураций (по умолчанию: 1388, диапазон: 1280-1420)")
parser.add_argument("--warp", type=int, default=0, help="Количество генерируемых конфигураций WARP (по умолчанию: 0)")
opt = parser.parse_args()

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
PrivateKey = <CLIENT_PRIVATE_KEY>
MTU = <MTU>

[Peer]
Endpoint = <SERVER_ADDR>:<SERVER_PORT>
PersistentKeepalive = 60
PresharedKey = <PRESHARED_KEY>
PublicKey = <SERVER_PUBLIC_KEY>
AllowedIPs = <ALLOWED_IPS>
"""

g_warp_config = """
[Interface]
PrivateKey = <WARP_PRIVATE_KEY>
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
H1 = 1
H2 = 2
H3 = 3
H4 = 4
MTU = <MTU>
Address = <WARP_ADDRESS>
Table = off

[Peer]
PublicKey = <WARP_PEER_PUBLIC_KEY>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 188.114.99.224:1002
"""

class IPAddr():
    def __init__(self, ipaddr=None):
        self.ip = [0, 0, 0, 0]
        self.mask = None
        if ipaddr:
            self.init(ipaddr)
    
    def init(self, ipaddr):
        _ipaddr = ipaddr
        if not ipaddr:
            raise RuntimeError(f'Ошибка: некорректный IP-адрес: "{_ipaddr}"')
        if ' ' in ipaddr or ',' in ipaddr:
            raise RuntimeError(f'Ошибка: некорректный IP-адрес: "{_ipaddr}"')
        if '/' in ipaddr:
            self.mask = int(ipaddr.split('/')[1])
            ipaddr = ipaddr.split('/')[0]
        nlist = ipaddr.split('.')
        if len(nlist) != 4:
            raise RuntimeError(f'Ошибка: некорректный IP-адрес: "{_ipaddr}"')
        for n, num in enumerate(nlist):
            self.ip[n] = int(num)
        
    def __str__(self):
        out = f'{self.ip[0]}.{self.ip[1]}.{self.ip[2]}.{self.ip[3]}'
        if self.mask:
            out += '/' + str(self.mask)
        return out

class WGConfig():
    def __init__(self, filename=None):
        self.lines = []
        self.iface = {}
        self.peer = {}
        self.idsline = {}
        self.cfg_fn = None
        if filename:
            self.load(filename)
    
    def load(self, filename):
        self.cfg_fn = None
        self.lines = []
        self.iface = {}
        self.peer = {}
        self.idsline = {}
        with open(filename, 'r') as file:
            lines = file.readlines()

        iface = None
        secdata = []
        secdata_item = None
        secline = []
        secline_item = None

        for n, line in enumerate(lines):
            line = line.rstrip()
            self.lines.append(line)

            if line.strip() == '' or (line.startswith('#') and not line.startswith('#_')):
                continue

            if line.startswith(' ') and not line.strip().startswith('#'):
                raise RuntimeError(f'Ошибка: некорректная строка #{n} в конфиге "{filename}"')

            if line.startswith('[') and line.endswith(']'):
                section_name = line[1:-1]
                if not section_name:
                    raise RuntimeError(f'Ошибка: некорректное имя секции: "{section_name}" (#{n+1})')
                secdata_item = {"_section_name": section_name.lower()}
                secline_item = {"_section_name": n}
                if section_name.lower() == 'interface':
                    if iface:
                        raise RuntimeError(f'Ошибка: найдена вторая секция Interface в строке #{n+1}')
                    iface = secdata_item
                elif section_name.lower() == 'peer':
                    pass
                else:
                    raise RuntimeError(f'Ошибка: найдена некорректная секция "{section_name}" в строке #{n+1}')
                secdata.append(secdata_item)
                secline.append(secline_item)
                continue
            
            if line.startswith('#_') and '=' in line:
                line = line[2:]
            
            if line.startswith('#'):
                continue
            
            if '=' not in line:
                raise RuntimeError(f'Ошибка: некорректная строка в конфиге: "{line}"  (#{n+1})')
            
            xv = line.find('=')
            if xv <= 0:
                raise RuntimeError(f'Ошибка: некорректная строка в конфиге: "{line}"  (#{n+1})')
            
            vname = line[:xv].strip()
            value = line[xv+1:].strip()
            if not secdata_item:
                raise RuntimeError(f'Ошибка: параметр "{vname}" не имеет секции! (#{n+1})')
            
            section_name = secdata_item['_section_name']
            if vname in secdata_item:
                raise RuntimeError(f'Ошибка: дублирование параметра "{vname}" в секции "{section_name}" (#{n+1})')
            
            secdata_item[vname] = value
            secline_item[vname] = n
        
        if not iface:
            raise RuntimeError(f'Ошибка: не найдена секция Interface!')
        
        for i, item in enumerate(secdata):
            line = secline[i]
            peer_name = ""
            if item['_section_name'] == 'interface':
                self.iface = item
                peer_name = "__this_server__"
                if 'PrivateKey' not in item:
                    raise RuntimeError(f'Ошибка: не найден PrivateKey в Interface')
            else:    
                if 'Name' in item:
                    peer_name = item['Name']
                    if not peer_name:
                        raise RuntimeError(f'Ошибка: некорректное имя peer в строке #{line["Name"]}')
                elif 'PublicKey' in item:
                    peer_name = item['PublicKey']
                    if not peer_name:
                        raise RuntimeError(f'Ошибка: некорректный PublicKey peer в строке #{line["PublicKey"]}')
                else:
                    raise RuntimeError(f'Ошибка: некорректные данные peer в строке #{line["_section_name"]}')
                
                if 'AllowedIPs' not in item:
                    raise RuntimeError(f'Ошибка: не найден параметр "AllowedIPs" в peer "{peer_name}"')
                    
                if peer_name in self.peer:
                    raise RuntimeError(f'Ошибка: дублирование peer с именем "{peer_name}"')
                
                self.peer[peer_name] = item
                
            if peer_name in self.idsline:
                raise RuntimeError(f'Ошибка: дублирование peer с именем "{peer_name}"')
            
            min_line = line['_section_name']
            max_line = min_line
            self.idsline[f'{peer_name}'] = min_line
            for vname in item:
                self.idsline[f'{peer_name}|{vname}'] = line[vname]
                if line[vname] > max_line:
                    max_line = line[vname]
            
            item['_lines_range'] = (min_line, max_line)
        
        self.cfg_fn = filename
        return len(self.peer)

    def save(self, filename=None):
        if not filename:
            filename = self.cfg_fn

        if not self.lines:
            raise RuntimeError(f'Ошибка: нет данных для сохранения')
        
        with open(filename, 'w', newline='\n') as file:
            for line in self.lines:
                file.write(line + '\n')
    
    def del_client(self, c_name):
        if c_name not in self.peer:
            raise RuntimeError(f'Ошибка: не найден клиент "{c_name}" в списке peer!')

        client = self.peer[c_name]
        ipaddr = client['AllowedIPs']
        min_line, max_line = client['_lines_range']
        del self.lines[min_line:max_line+1]
        del self.peer[c_name]
        secsize = max_line - min_line + 1
        dél_list = []
        for k, v in self.idsline.items():
            if v >= min_line and v <= max_line:
                dél_list.append(k)
            elif v > max_line:
                self.idsline[k] = v - secsize
        for k in dél_list:
            del self.idsline[k]
        return ipaddr
        
    def set_param(self, c_name, param_name, param_value, force=False, offset=0):
        if c_name not in self.peer:
            raise RuntimeError(f'Ошибка: не найден клиент "{c_name}" в списке peer!')

        line_prefix = "" if not param_name.startswith('_') else "#_"
        param_name = param_name[1:] if param_name.startswith('_') else param_name
        
        client = self.peer[c_name]
        min_line, max_line = client['_lines_range']
        if param_name in client:
            nline = self.idsline[f'{c_name}|{param_name}']
            line = self.lines[nline]
            if line.startswith('#_'):
                line_prefix = "#_"            
            self.lines[nline] = f'{line_prefix}{param_name} = {param_value}'
            return
        
        if not force:
            raise RuntimeError(f'Ошибка: параметр "{param_name}" не найден у клиента "{c_name}"')
        
        new_line = f'{line_prefix}{param_name} = {param_value}'
        client[param_name] = param_value
        secsize = max_line - min_line + 1
        if offset >= secsize or offset < 0:
            offset = 0
       
        pos = max_line + 1 if offset <= 0 else min_line + offset
        for k, v in self.idsline.items():
            if v >= pos:
                self.idsline[k] = v + 1
        
        self.idsline[f'{c_name}|{param_name}'] = pos   
        self.lines.insert(pos, new_line)
        return

def exec_cmd(cmd, input=None, shell=True, check=True, timeout=None):
    proc = subprocess.run(cmd, input=input, shell=shell, check=check,
                          timeout=timeout, encoding='utf8',
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rc = proc.returncode
    out = proc.stdout
    return rc, out

def get_main_iface():
    rc, out = exec_cmd('ip link show')
    if rc:
        raise RuntimeError(f'Ошибка: невозможно получить список сетевых интерфейсов')
    
    for line in out.split('\n'):
        if '<BROADCAST' in line and 'state UP' in line:
            xv = line.split(':')
            return xv[1].strip()
    
    return None

def get_ext_ipaddr():
    rc, out = exec_cmd('curl -4 -s icanhazip.com')
    if rc:
        raise RuntimeError(f'Ошибка: невозможно получить внешний IP-адрес')
    
    lines = out.split('\n')
    ipaddr = lines[-1] if lines[-1] else lines[-2]
    ipaddr = IPAddr(ipaddr)
    return str(ipaddr)

def gen_pair_keys(cfg_type=None):
    global g_main_config_type    
    if sys.platform == 'win32':
        return 'client_priv_key', 'client_pub_key'
        
    if not cfg_type:
        cfg_type = g_main_config_type
        
    if not cfg_type:
        raise RuntimeError("Ошибка: неизвестный тип конфига для генерации ключей")
   
    wgtool = cfg_type.lower()
    rc, out = exec_cmd(f'{wgtool} genkey')
    if rc:
        raise RuntimeError(f'Ошибка: не удалось сгенерировать приватный ключ')

    priv_key = out.strip()
    if not priv_key:
        raise RuntimeError(f'Ошибка: не удалось сгенерировать приватный ключ')

    rc, out = exec_cmd(f'{wgtool} pubkey', input=priv_key + '\n')
    if rc:
        raise RuntimeError(f'Ошибка: не удалось сгенерировать публичный ключ')

    pub_key = out.strip()
    if not pub_key:
        raise RuntimeError(f'Ошибка: не удалось сгенерировать публичный ключ')

    return priv_key, pub_key

def gen_preshared_key():
    rc, out = exec_cmd('openssl rand -base64 32', shell=True)
    if rc:
        raise RuntimeError(f'Ошибка: не удалось сгенерировать pre-shared key')
    return out.strip()

def get_main_config_path(check=True):
    global g_main_config_fn, g_main_config_type
    if not os.path.exists(g_main_config_src):
        raise RuntimeError(f'Ошибка: файл "{g_main_config_src}" не найден!')
    
    with open(g_main_config_src, 'r') as file:
        lines = file.readlines()
    
    g_main_config_fn = lines[0].strip()
    cfg_exists = os.path.exists(g_main_config_fn)
    g_main_config_type = 'WG'
    if os.path.basename(g_main_config_fn).startswith('a'):
        g_main_config_type = 'AWG'

    if check and not cfg_exists:
        raise RuntimeError(f'Ошибка: основной {g_main_config_type} конфиг "{g_main_config_fn}" не найден!')
        
    return g_main_config_fn

def generate_warp_config(tun_name, index, mtu):
    priv_key, pub_key = gen_pair_keys('AWG')
    api = "https://api.cloudflareclient.com/v0i1909051800"
    headers = {
        'user-agent': '',
        'content-type': 'application/json'
    }
    data = {
        "install_id": "",
        "tos": datetime.datetime.now().isoformat() + "Z",
        "key": pub_key,
        "fcm_token": "",
        "type": "ios",
        "locale": "en_US"
    }
    # Регистрация устройства
    response = requests.post(f"{api}/reg", headers=headers, json=data)
    response.raise_for_status()
    result = response.json()['result']
    id = result['id']
    token = result['token']
    # Активация WARP
    response = requests.patch(f"{api}/reg/{id}", headers={**headers, 'authorization': f'Bearer {token}'}, json={"warp_enabled": True})
    response.raise_for_status()
    config = response.json()['result']['config']
    peer_pub = config['peers'][0]['public_key']
    # Извлечение IP-адресов из ответа API
    client_ipv4 = config['interface']['addresses']['v4']
    client_ipv6 = config['interface']['addresses']['v6']

    jc = random.randint(80, 120)
    jmin = random.randint(48, 64)
    jmax = random.randint(jmin + 8, 80)

    out = g_warp_config
    out = out.replace('<WARP_PRIVATE_KEY>', priv_key)
    out = out.replace('<JC>', str(jc))
    out = out.replace('<JMIN>', str(jmin))
    out = out.replace('<JMAX>', str(jmax))
    out = out.replace('<MTU>', str(mtu))
    # Использование IP-адресов от Cloudflare
    out = out.replace('<WARP_ADDRESS>', f"{client_ipv4}, {client_ipv6}")
    out = out.replace('<WARP_PEER_PUBLIC_KEY>', peer_pub)

    filename = f"{tun_name}warp{index}.conf"
    return out, filename

def generate_warp_configs(tun_name, num_warps, mtu):
    warp_configs = []
    for i in range(num_warps):
        warp_conf, warp_filename = generate_warp_config(tun_name, i, mtu)
        warp_path = os.path.join(os.path.dirname(os.path.abspath(g_main_config_fn)), warp_filename)
        with open(warp_path, 'w', newline='\n') as f:
            f.write(warp_conf)
        warp_configs.append(warp_filename)
    return warp_configs

up_script_template_no_warp = '''
#!/bin/bash
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

# --- Пробросы портов ---
PORT_FORWARDING_RULES=(
  # Формат: "VPN_IP:ВнешнийПорт[>ВнутреннийПорт]:TCP/UDP:Список_разрешённых_подсетей"
  # Пример: "10.66.66.2:25565>25555:TCP:0.0.0.0/0"
)

echo "————————————————————————————————"

# --- Базовые iptables для работы туннеля и NAT ---
iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT --wait 10
iptables -A FORWARD -i "$IFACE" -o "$TUN" -j ACCEPT --wait 10
iptables -A FORWARD -i "$TUN" -j ACCEPT --wait 10
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE --wait 10
ip6tables -A FORWARD -i "$TUN" -j ACCEPT --wait 10
ip6tables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE --wait 10

# --- Hairpin NAT: позволяет клиентам VPN общаться между собой через внешний IP ---
iptables -t nat -A POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE

# --- Проброс портов через отдельные цепочки (DNAT + SNAT + ACCEPT) ---
echo "Проброс портов"
iptables -t nat -N PORT_FORWARD_NAT 2>/dev/null || true
iptables -t filter -N PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t nat -N PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$IFACE" -j PORT_FORWARD_NAT
iptables -t filter -A FORWARD -j PORT_FORWARD_FILTER
iptables -t nat -A POSTROUTING -j PORT_FORWARD_SNAT

# --- Добавление правил для каждого проброса ---
for rule in "${PORT_FORWARDING_RULES[@]}"; do
  IFS=":" read -r CLIENT_IP PF_PORT_PROTO PF_PROTO ALLOWED_SUBNETS <<< "$rule"
  IFS='>' read -r PF_PORT_EXT PF_PORT_INT <<< "$PF_PORT_PROTO"
  [ -z "$PF_PORT_INT" ] && PF_PORT_INT="$PF_PORT_EXT"
  IFS=',' read -ra SUBNETS_ARRAY <<< "$ALLOWED_SUBNETS"

  # --- Диапазон портов (если указан) ---
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
        # DNAT: перенаправление входящего порта на внутренний IP:порт клиента
        iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$EXT_PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$INT_PORT"
        # SNAT: подмена исходного адреса на IP VPN-сервера (теперь в PORT_FORWARD_SNAT!)
        iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        # FORWARD: разрешение прохождения трафика
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
    done
  # --- Диапазон только на внешней стороне (или одиночный порт) ---
  else
    if [[ "$PF_PORT_EXT" == *"-"* ]]; then
      PF_PORT_START="${PF_PORT_EXT%-*}"
      PF_PORT_END="${PF_PORT_EXT#*-}"
      for ((PORT=PF_PORT_START; PORT<=PF_PORT_END; PORT++)); do
        for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
          iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PORT"
          iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
          iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
          iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
        done
        echo "$PF_PROTO порт $PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
      done
    else
      for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
        iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PF_PORT_INT"
        iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
    fi
  fi
done

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
modprobe ifb
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" ingress 2>/dev/null || true
tc qdisc del dev ifb0 root 2>/dev/null || true
ip link set ifb0 down 2>/dev/null || true
ip link delete ifb0 2>/dev/null || true
tc qdisc del dev ifb1 root 2>/dev/null || true
ip link set ifb1 down 2>/dev/null || true
ip link delete ifb1 2>/dev/null || true
ip link add ifb1 type ifb 2>/dev/null || true
ip link set ifb1 up
ip link add ifb0 type ifb 2>/dev/null || true
ip link set ifb0 up

tc qdisc add dev "$TUN" root handle 1: htb
tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb1
tc qdisc add dev ifb1 root handle 1: htb default 2
tc qdisc add dev "$TUN" handle ffff: ingress
tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root handle 1: htb default 2

# --- Применение лимитов скорости для каждой подсети из SUBNETS_LIMITS ---
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
            tc class add dev ifb1 parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc class add dev ifb1 parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc qdisc add dev ifb1 parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
            tc class add dev ifb0 parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc class add dev ifb0 parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
            tc qdisc add dev ifb0 parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
        fi
        classid="${major_class}:${minor_id}"
        major="${major_class}:"
        tc class add dev ifb1 parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
        tc filter add dev ifb1 protocol ip parent ${major_class}: prio 1 u32 match ip dst $ip flowid $classid
        tc qdisc add dev ifb1 parent $classid fq_codel
        tc class add dev ifb0 parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
        tc filter add dev ifb0 protocol ip parent ${major_class}: prio 1 u32 match ip src $ip flowid $classid
        tc qdisc add dev ifb0 parent $classid fq_codel
        minor_id=$((minor_id + 1))
    done
    echo "$SUBNET -> ${LIM}mbit"
done
echo "————————————————————————————————"
'''

down_script_template_no_warp = '''
#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"

LOCAL_SUBNETS="<SERVER_ADDR>"
LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS" | cut -d'/' -f1)"

echo "————————————————————————————————"
# --- Откатываем базовые iptables для туннеля и NAT ---
iptables -D INPUT -p udp --dport "$PORT" -j ACCEPT --wait 10
iptables -D FORWARD -i "$IFACE" -o "$TUN" -j ACCEPT --wait 10
iptables -D FORWARD -i "$TUN" -j ACCEPT --wait 10
iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE --wait 10
ip6tables -D FORWARD -i "$TUN" -j ACCEPT --wait 10
ip6tables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE --wait 10

# --- Удаляем Hairpin NAT ---
iptables -t nat -D POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE 2>/dev/null || true

# --- Полное удаление цепочек проброса портов ---
echo "Очистка проброса портов"
iptables -t nat -D PREROUTING -i "$IFACE" -j PORT_FORWARD_NAT 2>/dev/null || true
iptables -t nat -F PORT_FORWARD_NAT 2>/dev/null || true
iptables -t nat -X PORT_FORWARD_NAT 2>/dev/null || true

iptables -t nat -D POSTROUTING -j PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -F PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -X PORT_FORWARD_SNAT 2>/dev/null || true

iptables -t filter -D FORWARD -j PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t filter -F PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t filter -X PORT_FORWARD_FILTER 2>/dev/null || true

# --- Откат лимитов скорости (tc и ifb) ---
echo "Очистка лимитов"
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" ingress 2>/dev/null || true
tc qdisc del dev ifb0 root 2>/dev/null || true
ip link set ifb0 down 2>/dev/null || true
ip link delete ifb0 2>/dev/null || true
tc qdisc del dev ifb1 root 2>/dev/null || true
ip link set ifb1 down 2>/dev/null || true
ip link delete ifb1 2>/dev/null || true
echo "————————————————————————————————"
'''

up_script_template_warp = '''
#!/bin/bash
#set -x

# --- Основные переменные ---
PORT="<SERVER_PORT>"
IFACE="<SERVER_IFACE>"
TUN="<SERVER_TUN>"
QUANT="4400"

# --- Подсеть и локальный IP сервера в ней ---
LOCAL_SUBNETS="<SERVER_ADDR>"
LOCAL_SERVER_IP="$(echo "$LOCAL_SUBNETS" | cut -d'/' -f1)"

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
  "<SERVER_ADDR>"
)
# --- Пробросы портов ---
PORT_FORWARDING_RULES=(
  # Пример: "10.66.66.2:25565>25555:TCP:0.0.0.0/0"
)

MARK_BASE=1000

echo "————————————————————————————————"
# --- Запуск WARP-интерфейсов (дополнительные WireGuard-интерфейсы для мульти-WARP) ---
for warp in "${WARP_LIST[@]}"; do
  echo "Запуск WARP-туннеля: $warp"
  awg-quick up "$warp" || echo "Ошибка запуска $warp: $?"
done

# --- WARP-маршрутизация и балансировка трафика через WARP интерфейсы ---
for i in "${!WARP_LIST[@]}"; do
  TABLE_ID=$((201+i))
  TABLE_NAME="${WARP_LIST[$i]}"
  grep -q "^$TABLE_ID[[:space:]]$TABLE_NAME$" /etc/iproute2/rt_tables || echo "$TABLE_ID $TABLE_NAME" >> /etc/iproute2/rt_tables
  ip route replace default dev "$TABLE_NAME" table "$TABLE_NAME"
  ip rule add fwmark $((MARK_BASE+i)) table "$TABLE_NAME" 2>/dev/null || true
done

# --- iptables для балансировки WARP (случайное распределение новых соединений) ---
iptables -t mangle -F RANDOM_WARP 2>/dev/null || iptables -t mangle -N RANDOM_WARP
iptables -t mangle -A PREROUTING -i "$TUN" -j RANDOM_WARP

# --- Исключение подсетей из маркировки (будут идти напрямую через основной интерфейс) ---
for subnet in "${EXCLUDE_SUBNETS[@]}"; do
  iptables -t mangle -I RANDOM_WARP 1 -d $subnet -j RETURN
done

CNT=${#WARP_LIST[@]}
for i in $(seq 0 $((CNT-1))); do
  MARK=$((MARK_BASE+i))
  iptables -t mangle -A RANDOM_WARP -m conntrack --ctstate NEW -m statistic --mode nth --every $CNT --packet $i -j CONNMARK --set-mark $MARK
done
iptables -t mangle -A RANDOM_WARP -j CONNMARK --restore-mark

# --- Настройка FORWARD и NAT для трафика через WARP ---
for warp in "${WARP_LIST[@]}"; do
  iptables -A FORWARD -i "$TUN" -o "$warp" -j ACCEPT 2>/dev/null || true
  iptables -A FORWARD -i "$warp" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -t nat -A POSTROUTING -o "$warp" -j MASQUERADE 2>/dev/null || true
done

# --- Настройка FORWARD и NAT для трафика напрямую через внешний интерфейс (EXCLUDE_SUBNETS) ---
iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
iptables -A FORWARD -i "$TUN" -o "$IFACE" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$IFACE" -o "$TUN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# --- Hairpin NAT ---
iptables -t nat -A POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE

# --- Проброс портов через отдельные цепочки (DNAT + SNAT + ACCEPT) ---
echo "Проброс портов"
iptables -t nat -N PORT_FORWARD_NAT 2>/dev/null || true
iptables -t filter -N PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t nat -N PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$IFACE" -j PORT_FORWARD_NAT
iptables -t filter -A FORWARD -j PORT_FORWARD_FILTER
iptables -t nat -A POSTROUTING -j PORT_FORWARD_SNAT

# --- Добавление правил для каждого проброса ---
for rule in "${PORT_FORWARDING_RULES[@]}"; do
  IFS=":" read -r CLIENT_IP PF_PORT_PROTO PF_PROTO ALLOWED_SUBNETS <<< "$rule"
  IFS='>' read -r PF_PORT_EXT PF_PORT_INT <<< "$PF_PORT_PROTO"
  [ -z "$PF_PORT_INT" ] && PF_PORT_INT="$PF_PORT_EXT"
  IFS=',' read -ra SUBNETS_ARRAY <<< "$ALLOWED_SUBNETS"
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
        iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$EXT_PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$INT_PORT"
        iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$INT_PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$INT_PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$INT_PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      echo "$PF_PROTO порт $EXT_PORT->$INT_PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
    done
  else
    if [[ "$PF_PORT_EXT" == *"-"* ]]; then
      PF_PORT_START="${PF_PORT_EXT%-*}"
      PF_PORT_END="${PF_PORT_EXT#*-}"
      for ((PORT=PF_PORT_START; PORT<=PF_PORT_END; PORT++)); do
        for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
          iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$PORT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PORT"
          iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PORT" -j SNAT --to-source "$LOCAL_SERVER_IP"
          iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PORT" -s "$ALLOWED_SUBNET" -j ACCEPT
          iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PORT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
        done
        echo "$PF_PROTO порт $PORT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
      done
    else
      for ALLOWED_SUBNET in "${SUBNETS_ARRAY[@]}"; do
        iptables -t nat -A PORT_FORWARD_NAT -p "$PF_PROTO" --dport "$PF_PORT_EXT" -s "$ALLOWED_SUBNET" -j DNAT --to-destination "$CLIENT_IP:$PF_PORT_INT"
        iptables -t nat -A PORT_FORWARD_SNAT -d "$CLIENT_IP" -p "$PF_PROTO" --dport "$PF_PORT_INT" -j SNAT --to-source "$LOCAL_SERVER_IP"
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -d "$CLIENT_IP" --dport "$PF_PORT_INT" -s "$ALLOWED_SUBNET" -j ACCEPT
        iptables -t filter -A PORT_FORWARD_FILTER -p "$PF_PROTO" -s "$CLIENT_IP" --sport "$PF_PORT_INT" -d "$ALLOWED_SUBNET" -m state --state RELATED,ESTABLISHED -j ACCEPT
      done
      echo "$PF_PROTO порт $PF_PORT_EXT->$PF_PORT_INT на $CLIENT_IP открыт для ${SUBNETS_ARRAY[*]}"
    fi
  fi
done

# --- Traffic shaping (ограничение скорости) с помощью ifb и tc ---
modprobe ifb
ip link add ifb0 type ifb 2>/dev/null || true
ip link set ifb0 up
ip link add ifb1 type ifb 2>/dev/null || true
ip link set ifb1 up
tc qdisc add dev "$TUN" root handle 1: htb 2>/dev/null || true
tc filter add dev "$TUN" parent 1: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb1
tc qdisc add dev ifb1 root handle 1: htb default 2
tc qdisc add dev "$TUN" handle ffff: ingress
tc filter add dev "$TUN" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root handle 1: htb default 2

# --- Применение лимитов скорости для каждой подсети из SUBNETS_LIMITS ---
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
      tc class add dev ifb1 parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
      tc class add dev ifb1 parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
      tc qdisc add dev ifb1 parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
      tc class add dev ifb0 parent $((major_class - 1)): classid $((major_class - 1)):1 htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
      tc class add dev ifb0 parent $((major_class - 1)):1 classid $((major_class - 1)):${major_class} htb rate 10000mbit ceil 10000mbit quantum "$QUANT"
      tc qdisc add dev ifb0 parent $((major_class - 1)):${major_class} handle ${major_class}: htb default $((major_class + 1))
    fi
    classid="${major_class}:${minor_id}"
    major="${major_class}:"
    tc class add dev ifb1 parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
    tc filter add dev ifb1 protocol ip parent ${major_class}: prio 1 u32 match ip dst $ip flowid $classid
    tc qdisc add dev ifb1 parent $classid fq_codel
    tc class add dev ifb0 parent $major classid $classid htb rate "${LIM}"mbit ceil "${LIM}"mbit quantum "$QUANT"
    tc filter add dev ifb0 protocol ip parent ${major_class}: prio 1 u32 match ip src $ip flowid $classid
    tc qdisc add dev ifb0 parent $classid fq_codel
    minor_id=$((minor_id + 1))
  done
  echo "$SUBNET -> ${LIM}mbit"
done

# --- Проверка внешних IP WARP-интерфейсов (для диагностики) ---
echo "Проверка внешних IP WARP"
for warp in "${WARP_LIST[@]}"; do
  ip=$(curl --interface "$warp" https://api.ipify.org 2>/dev/null)
  if [ $? -eq 0 ]; then
    echo "$warp -> $ip"
  else
    echo "Ошибка: Не удалось получить IP для $warp"
  fi
done
echo "————————————————————————————————"
'''

down_script_template_warp = '''
#!/bin/bash
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

MARK_BASE=1000

echo "————————————————————————————————"
# --- Останов WARP-туннелей ---
for warp in "${WARP_LIST[@]}"; do
  echo "Остановка WARP-туннеля: $warp"
  awg-quick down "$warp" || echo "Ошибка остановки $warp: $?"
done

# --- Удаляем Hairpin NAT ---
iptables -t nat -D POSTROUTING -s "$LOCAL_SUBNETS" -d "$LOCAL_SUBNETS" -j MASQUERADE 2>/dev/null || true

# --- Полное удаление цепочек проброса портов ---
echo "Очистка проброса портов"
iptables -t nat -D PREROUTING -i "$IFACE" -j PORT_FORWARD_NAT 2>/dev/null || true
iptables -t nat -F PORT_FORWARD_NAT 2>/dev/null || true
iptables -t nat -X PORT_FORWARD_NAT 2>/dev/null || true

iptables -t nat -D POSTROUTING -j PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -F PORT_FORWARD_SNAT 2>/dev/null || true
iptables -t nat -X PORT_FORWARD_SNAT 2>/dev/null || true

iptables -t filter -D FORWARD -j PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t filter -F PORT_FORWARD_FILTER 2>/dev/null || true
iptables -t filter -X PORT_FORWARD_FILTER 2>/dev/null || true

# --- Очистка iptables для балансировки WARP ---
iptables -t mangle -F RANDOM_WARP 2>/dev/null || true
iptables -t mangle -D PREROUTING -i "$TUN" -j RANDOM_WARP 2>/dev/null || true
iptables -t mangle -X RANDOM_WARP 2>/dev/null || true

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
  MARK=$((MARK_BASE+i))
  TABLE_NAME="${WARP_LIST[$i]}"
  ip rule del fwmark $MARK table "$TABLE_NAME" 2>/dev/null || true
  ip route flush table "$TABLE_NAME" 2>/dev/null || true
done

# --- Откат лимитов скорости (tc и ifb) ---
echo "Очистка лимитов"
tc qdisc del dev "$TUN" root 2>/dev/null || true
tc qdisc del dev "$TUN" ingress 2>/dev/null || true
tc qdisc del dev ifb0 root 2>/dev/null || true
ip link set ifb0 down 2>/dev/null || true
ip link delete ifb0 2>/dev/null || true
tc qdisc del dev ifb1 root 2>/dev/null || true
ip link set ifb1 down 2>/dev/null || true
ip link delete ifb1 2>/dev/null || true
echo "————————————————————————————————"
'''

def handle_makecfg():
    global g_main_config_fn
    g_main_config_fn = opt.makecfg
    if os.path.exists(g_main_config_fn):
        raise RuntimeError(f'Ошибка: файл "{g_main_config_fn}" уже существует!')

    m_cfg_type = 'WG'
    if os.path.basename(g_main_config_fn).startswith('a'):
        m_cfg_type = 'AWG'

    print(f'Создание {m_cfg_type} серверного конфига: "{g_main_config_fn}"...')
    main_iface = get_main_iface()
    if not main_iface:
        raise RuntimeError(f'Ошибка: невозможно получить основной сетевой интерфейс!')

    print(f'Основная сеть: "{main_iface}"')

    if not (1 <= opt.port <= 65535):
        raise RuntimeError(f'Ошибка: неправильный порт = {opt.port}. Используйте порт от 1 до 65535')

    if not opt.ipaddr:
        raise RuntimeError(f'Ошибка: неверный аргумент ipaddr = "{opt.ipaddr}"')
    
    ipaddr = IPAddr(opt.ipaddr)
    if not ipaddr.mask:
        raise RuntimeError(f'Ошибка: неверный аргумент ipaddr = "{opt.ipaddr}"')

    if opt.tun:
        tun_name = opt.tun
    else:
        cfg_name = os.path.basename(g_main_config_fn)
        tun_name = os.path.splitext(cfg_name)[0].strip()

    print(f'Туннельный интерфейс: "{tun_name}"')

    priv_key, pub_key = gen_pair_keys(m_cfg_type)

    random.seed()
    jc = random.randint(80, 120)
    jmin = random.randint(48, 64)
    jmax = random.randint(jmin + 8, 80)

    up_script_path = os.path.join(os.path.dirname(os.path.abspath(g_main_config_fn)), f"{tun_name}up.sh")
    down_script_path = os.path.join(os.path.dirname(os.path.abspath(g_main_config_fn)), f"{tun_name}down.sh")

    out = g_defserver_config
    out = out.replace('<SERVER_KEY_TIME>', datetime.datetime.now().isoformat())
    out = out.replace('<SERVER_PRIVATE_KEY>', priv_key)
    out = out.replace('<SERVER_PUBLIC_KEY>', pub_key)
    out = out.replace('<SERVER_ADDR>', str(ipaddr))
    out = out.replace('<SERVER_PORT>', str(opt.port))
    if m_cfg_type == 'AWG':
        out = out.replace('<JC>', str(jc))
        out = out.replace('<JMIN>', str(jmin))
        out = out.replace('<JMAX>', str(jmax))
        out = out.replace('<S1>', str(random.randint(3, 127)))
        out = out.replace('<S2>', str(random.randint(3, 127)))
        out = out.replace('<H1>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H2>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H3>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H4>', str(random.randint(0x10000011, 0x7FFFFF00)))
    else:
        out = out.replace('\nJc = <', '\n# ')
        out = out.replace('\nJmin = <', '\n# ')
        out = out.replace('\nJmax = <', '\n# ')
        out = out.replace('\nS1 = <', '\n# ')
        out = out.replace('\nS2 = <', '\n# ')
        out = out.replace('\nH1 = <', '\n# ')
        out = out.replace('\nH2 = <', '\n# ')
        out = out.replace('\nH3 = <', '\n# ')
        out = out.replace('\nH4 = <', '\n# ')
    
    out = out.replace('<SERVER_IFACE>', main_iface)
    out = out.replace('<SERVER_TUN>', tun_name)
    out = out.replace('<SERVER_UP_SCRIPT>', up_script_path)
    out = out.replace('<SERVER_DOWN_SCRIPT>', down_script_path)
    out = out.replace('<MTU>', str(opt.mtu))

    with open(g_main_config_fn, 'w', newline='\n') as file:
        file.write(out)

    print(f'{m_cfg_type} Серверный конфиг "{g_main_config_fn}" создан!')

    warp_configs = []
    if opt.warp > 0:
        print(f"Генерация {opt.warp} WARP конфигов...")
        try:
            warp_configs = generate_warp_configs(tun_name, opt.warp, opt.mtu)
            for config in warp_configs:
                print(f"WARP конфиг создан: {config}")
        except Exception as e:
            raise RuntimeError(f"Ошибка при генерации WARP-конфигов: {e}")

    up_script_template = up_script_template_warp if opt.warp > 0 else up_script_template_no_warp
    down_script_template = down_script_template_warp if opt.warp > 0 else down_script_template_no_warp
    
    # Формируем WARP_LIST с названиями интерфейсов без .conf
    warp_list_str = "\n".join([f'  "{os.path.splitext(cfg)[0]}"' for cfg in warp_configs]) if opt.warp > 0 else ""

    replacements = {
        '<SERVER_PORT>': str(opt.port),
        '<SERVER_IFACE>': main_iface,
        '<SERVER_TUN>': tun_name,
        '<SERVER_ADDR>': str(ipaddr),
        '<RATE_LIMIT>': f'{opt.limit}',
        '<WARP_LIST>': warp_list_str
    }

    for key, value in replacements.items():
        up_script_template = up_script_template.replace(key, value)
        down_script_template = down_script_template.replace(key, value)

    with open(up_script_path, 'w', newline='\n') as f:
        f.write(up_script_template)
    with open(down_script_path, 'w', newline='\n') as f:
        f.write(down_script_template)

    os.chmod(up_script_path, 0o755)
    os.chmod(down_script_path, 0o755)

    print(f"PostUp и PostDown скрипты созданы:\n  {up_script_path}\n  {down_script_path}")

    with open(g_main_config_src, 'w', newline='\n') as file:
        file.write(g_main_config_fn)
    
    sys.exit(0)

def handle_create():
    tmpcfg_path = os.path.join(SCRIPT_DIR, opt.tmpcfg)
    if os.path.exists(tmpcfg_path):
        raise RuntimeError(f'Ошибка: файл "{tmpcfg_path}" уже существует!')

    print(f'Создание шаблона для клиентских конфигов: "{tmpcfg_path}"...')
    if opt.ipaddr:
        ipaddr = opt.ipaddr
    else:
        ext_ipaddr = get_ext_ipaddr()
        print(f'Внешний IP-адрес: "{ext_ipaddr}"')
        ipaddr = ext_ipaddr

    if '/' not in ipaddr:
        ipaddr += '/32'
    ipaddr = IPAddr(ipaddr)

    print(f'Серверный IP-адрес: "{ipaddr}"')

    raw_ip = f"{ipaddr.ip[0]}.{ipaddr.ip[1]}.{ipaddr.ip[2]}.{ipaddr.ip[3]}"
    out = g_defclient_config
    out = out.replace('<SERVER_ADDR>', raw_ip)
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

    with open(tmpcfg_path, 'w', newline='\n') as file:
        file.write(out)

    print(f'Шаблон клиентских конфигов "{tmpcfg_path}" создан!')
    sys.exit(0)

xopt = [opt.addcl, opt.update, opt.delete]
copt = [x for x in xopt if len(x) > 0]
if copt and len(copt) >= 2:
    raise RuntimeError(f'Ошибка: неверные аргументы! Слишком много действий!')

def handle_add():
    cfg = WGConfig(g_main_config_fn)
    srv = cfg.iface
    c_name = opt.addcl
    print(f'Создание нового пользователя "{c_name}"...')

    if c_name.lower() in (x.lower() for x in cfg.peer.keys()):
        raise RuntimeError(f'Ошибка: peer с именем "{c_name}" уже существует!')

    network = IPAddr(srv['Address'])
    net_mask = network.mask
    base_ip_int = int.from_bytes(network.ip, byteorder='big')

    host_bits = 32 - net_mask
    total_hosts = (1 << host_bits)
    first_ip_int = base_ip_int + 1
    last_ip_int = base_ip_int + total_hosts - 2

    used_ips = set()
    for peer in cfg.peer.values():
        ip = IPAddr(peer['AllowedIPs'])
        ip_int = int.from_bytes(ip.ip, byteorder='big')
        used_ips.add(ip_int)

    if opt.ipaddr:
        manual_ip = IPAddr(opt.ipaddr)
        ip_int = int.from_bytes(manual_ip.ip, byteorder='big')
        if ip_int in used_ips:
            raise RuntimeError(f'Ошибка: IP-адрес "{opt.ipaddr}" уже используется!')
        ipaddr = str(manual_ip)
    else:
        for ip_int in range(first_ip_int, last_ip_int + 1):
            if ip_int not in used_ips:
                ip_bytes = ip_int.to_bytes(4, byteorder='big')
                ipaddr = '.'.join(map(str, ip_bytes)) + '/32'
                break
        else:
            raise RuntimeError('Ошибка: больше нет свободных IP-адресов!')

    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()

    with open(g_main_config_fn, 'rb') as file:
        srvcfg = file.read().decode('utf8')

    srvcfg += f'\n'
    srvcfg += f'[Peer]\n'
    srvcfg += f'#_Name = {c_name}\n'
    srvcfg += f'#_GenKeyTime = {datetime.datetime.now().isoformat()}\n'
    srvcfg += f'#_PrivateKey = {priv_key}\n'
    srvcfg += f'PublicKey = {pub_key}\n'
    srvcfg += f'PresharedKey = {psk}\n'
    srvcfg += f'AllowedIPs = {ipaddr}\n'

    with open(g_main_config_fn, 'w', newline='\n') as file:
        file.write(srvcfg)

    print(f'Новый пользователь "{c_name}" создан! IP-адрес: "{ipaddr}"')

def handle_update():
    cfg = WGConfig(g_main_config_fn)
    p_name = opt.update
    print(f'Сброс ключей пользователя "{p_name}"...')
    priv_key, pub_key = gen_pair_keys()
    psk = gen_preshared_key()
    cfg.set_param(p_name, '_PrivateKey', priv_key, force=True, offset=2)
    cfg.set_param(p_name, 'PublicKey', pub_key)
    cfg.set_param(p_name, 'PresharedKey', psk)
    gentime = datetime.datetime.now().isoformat()
    cfg.set_param(p_name, '_GenKeyTime', gentime, force=True, offset=2)
    ipaddr = cfg.peer[p_name]['AllowedIPs']
    cfg.save()
    print(f'Ключи пользователя "{p_name}" сброшены! IP-адрес: "{ipaddr}"')

def handle_delete():
    cfg = WGConfig(g_main_config_fn)
    p_name = opt.delete
    print(f'Удаление пользователя "{p_name}"...')
    ipaddr = cfg.del_client(p_name)
    cfg.save()
    print(f'Пользователь "{p_name}" удалён! IP-адрес: "{ipaddr}"')

def fetch_allowed_dsyt():

    sites = [
        "youtube.com",
        "discord.com",
        "discord.gg",
        "discord.media",
        "chatgpt.com",
        "pornhub.com"
    ]

    protocols = ["cidr4", "cidr6"]
    ip_set = set()

    for site in sites:
        for proto in protocols:
            url = f"https://iplist.opencck.org/?format=comma&data={proto}&site={site}"
            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    data = response.read().decode("utf-8").strip()
                    if data:
                        ip_set.update(map(str.strip, data.split(",")))
            except Exception as e:
                print(f"[!] Не удалось получить IP-адреса для {site} ({proto}): {e}")

    return ", ".join(sorted(ip_set))

def handle_confgen():
    cfg = WGConfig(g_main_config_fn)
    srv = cfg.iface
    print('Генерация клиентских конфигов...')

    tmpcfg_path = os.path.join(SCRIPT_DIR, opt.tmpcfg)
    if not os.path.exists(tmpcfg_path):
        print(f'Внимание: файл "{tmpcfg_path}" не найден, создаю стандартный шаблон клиента...')
        # Вызов handle_create создаст файл и завершит программу, что нам не подходит.
        # Поэтому вставляем логику создания шаблона прямо здесь:
        ipaddr = opt.ipaddr or get_ext_ipaddr()
        if '/' not in ipaddr:
            ipaddr += '/32'
        ipaddr_obj = IPAddr(ipaddr)
        raw_ip = f"{ipaddr_obj.ip[0]}.{ipaddr_obj.ip[1]}.{ipaddr_obj.ip[2]}.{ipaddr_obj.ip[3]}"
        out = g_defclient_config
        out = out.replace('<SERVER_ADDR>', raw_ip)
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
        with open(tmpcfg_path, 'w', newline='\n') as file:
            file.write(out)
        print(f'Шаблон клиентских конфигов "{tmpcfg_path}" автоматически создан!')

    with open(tmpcfg_path, 'r') as file:
        tmpcfg = file.read()

    # Чистим только в conf-папке!
    flst = glob.glob(os.path.join(CONF_DIR, "*.conf"))
    for fn in flst:
        if fn.endswith('awg0.conf'):
            continue
        if os.path.exists(fn):
            os.remove(fn)

    flst = glob.glob(os.path.join(CONF_DIR, "*.png"))
    for fn in flst:
        if os.path.exists(fn):
            os.remove(fn)

    random.seed()

    fetched_dsyt_ips = fetch_allowed_dsyt()

    only_list = get_only_list()
    peers = cfg.peer.items()
    if only_list:
        # Фильтруем только указанные имена (без учета регистра)
        peers = [(name, peer) for name, peer in peers if name.lower() in [x.lower() for x in only_list]]
        if not peers:
            raise RuntimeError(f'Ошибка: ни одного клиента из --only не найдено!')

    for peer_name, peer in peers:
        if 'Name' not in peer or 'PrivateKey' not in peer:
            print(f'Пропуск peer с публичным ключом "{peer["PublicKey"]}"')
            continue
        psk = peer.get('PresharedKey', gen_preshared_key())
        if 'PresharedKey' not in peer:
            cfg.set_param(peer_name, 'PresharedKey', psk)

        jc = random.randint(80, 120)
        jmin = random.randint(48, 64)
        jmax = random.randint(jmin + 8, 80)
        out = tmpcfg[:]
        mtu = srv.get('MTU', str(opt.mtu))
        out = out.replace('<MTU>', mtu)
        out = out.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])
        out = out.replace('<CLIENT_TUNNEL_IP>', peer['AllowedIPs'])
        out = out.replace('<JC>', str(jc))
        out = out.replace('<JMIN>', str(jmin))
        out = out.replace('<JMAX>', str(jmax))
        out = out.replace('<S1>', srv['S1'])
        out = out.replace('<S2>', srv['S2'])
        out = out.replace('<H1>', srv['H1'])
        out = out.replace('<H2>', srv['H2'])
        out = out.replace('<H3>', srv['H3'])
        out = out.replace('<H4>', srv['H4'])
        out = out.replace('<SERVER_PORT>', srv['ListenPort'])
        out = out.replace('<SERVER_PUBLIC_KEY>', srv['PublicKey'])
        out = out.replace('<PRESHARED_KEY>', psk)
        out = out.replace('<SERVER_ADDR>', srv['Address'])

        out_all = out.replace('<ALLOWED_IPS>', '0.0.0.0/0, ::/0')
        with open(os.path.join(CONF_DIR, f'{peer_name}All.conf'), 'w', newline='\n') as file:
            file.write(out_all)

        out_dsyt = out.replace('<ALLOWED_IPS>', fetched_dsyt_ips)
        with open(os.path.join(CONF_DIR, f'{peer_name}DsYt.conf'), 'w', newline='\n') as file:
            file.write(out_dsyt)

        clients_for_zip.append(peer_name)

def generate_qr_codes():
    print('Генерация QR-кодов...')
    # Удаляем png только в conf-папке
    flst = glob.glob(os.path.join(CONF_DIR, "*.png"))
    for fn in flst:
        if os.path.exists(fn):
            os.remove(fn)

    flst = [f for f in glob.glob(os.path.join(CONF_DIR, "*All.conf"))]
    if not flst:
        raise RuntimeError(f'Ошибка: не найдены All-конфиги для генерации QR-кодов!')


    def generate_qr(conf, fn):
        if os.path.getsize(fn) > 2048:
            print(f'⚠️ Конфигурация {fn} превышает 2KB, возможно, QR не сгенерируется!')

        max_version = 40
        error_correction = qrcode.constants.ERROR_CORRECT_L

        for version in range(1, max_version + 1):
            try:
                qr = qrcode.QRCode(
                    version=version,
                    error_correction=error_correction,
                    box_size=10,
                    border=4,
                )
                qr.add_data(conf)
                qr.make(fit=False)
                return qr.make_image(fill="black", back_color="white")
            except (qrcode.exceptions.DataOverflowError, ValueError):
                continue
        raise ValueError("Данные слишком большие для QR-кода даже с максимальной версией.")

    for fn in flst:
        if fn.endswith('awg0.conf'):
            continue
        with open(fn, 'r', encoding='utf-8') as file:
            conf = file.read()
        name = os.path.splitext(os.path.basename(fn))[0]
        png_path = os.path.join(CONF_DIR, f"{name}.png")
        try:
            img = generate_qr(conf, fn)
            img.save(png_path)
        except ValueError as e:
            print(f'Ошибка при генерации QR для {fn}: {e}')

def zip_client_files(client_name):
    zip_filename = os.path.join(CONF_DIR, f"{client_name}.zip")
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        for suffix in ['All.conf', 'DsYt.conf', 'All.png']:
            file = os.path.join(CONF_DIR, f"{client_name}{suffix}")
            if os.path.exists(file):
                zipf.write(file, arcname=os.path.basename(file))

def zip_all():
    print('Упаковка конфигов в ZIP-архивы...')
    for name in clients_for_zip:
        zip_client_files(name)

if __name__ == "__main__":
    main()
