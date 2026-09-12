#!/bin/bash
#
# AmneziaWG Installer v6.6
# Ubuntu 20.04-26.04 | Debian 11-13
# Режимы: --go/-g (go из исходников), --kernel/-k (dkms), без флага (meta-пакет)
# Чистый код с учётом всех ошибок
#

set -e

# Неинтерактивный режим (сразу в начало!)
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# Режим установки: go | kernel | default
INSTALL_MODE="default"
# Патч I6..I10 (расширенный DTLS-флайт сервера) — только с -g
PATCH_I10=false
# DNS/DNS-resolver: вмешивались ли мы в систему (для cleanup; аудит-DNS)
DNS_TOUCHED=0
RESOLVED_WAS_ACTIVE=0

# ─── Флаги ─────────────────────────────────────────
parse_flags() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --go|-g)
                INSTALL_MODE="go"
                shift
                ;;
            --kernel|-k)
                INSTALL_MODE="kernel"
                shift
                ;;
            --patch|-p)
                PATCH_I10=true
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                log_error "$MSG_UNKNOWN_FLAG $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

# ─── Справка ───────────────────────────────────────
print_usage() {
    echo
    printf "${GREEN}%s${NC}\n" "$MSG_USAGE_HEADER"
    printf "$MSG_USAGE_DEFAULT\n" "$0"
    printf "$MSG_USAGE_GO\n" "$0"
    printf "$MSG_USAGE_KERNEL\n" "$0"
    printf "$MSG_USAGE_PATCH\n" "$0"
    printf "$MSG_USAGE_HELP\n" "$0"
    echo
}

# ─── Проверка root ─────────────────────────────────
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "$MSG_ROOT_REQUIRED"
        exit 1
    fi
}

# Определение и проверка ОС
check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "$MSG_NO_OS"
        exit 1
    fi

    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION="$VERSION_ID"

    log_info "$MSG_DETECTED" "$NAME $VERSION"

    # Блокируем старые ОС (ядро < 5.6)
    if [ "$OS_ID" = "debian" ]; then
        case "$OS_VERSION" in
            10)
                log_error "$MSG_DEB10_UNSUP"
                log_error "$MSG_DEB11_REQ"
                exit 1
                ;;
        esac
    fi

    if [ "$OS_ID" = "ubuntu" ]; then
        case "$OS_VERSION" in
            18.04|19.04|19.10)
                log_error "$MSG_UBU_UNSUP" "$OS_VERSION"
                log_error "$MSG_UBU20_REQ"
                exit 1
                ;;
        esac
    fi
}

# Кодовое имя репозитория
get_codename() {
    if [ "$OS_ID" = "ubuntu" ]; then
        case "$OS_VERSION" in
            20.04) echo "focal" ;;
            22.04) echo "jammy" ;;
            24.04) echo "noble" ;;
            24.10) echo "oracular" ;;
            25.04) echo "plucky" ;;
            25.10|26.04) echo "noble" ;;
            *) echo "focal" ;;
        esac
    else
        # Debian всегда использует focal репозиторий (официально от Amnezia)
        echo "focal"
    fi
}

# ─── Отключение systemd-resolved ───────────────────
disable_systemd_resolved() {
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        RESOLVED_WAS_ACTIVE=1
        DNS_TOUCHED=1
        log_info "$MSG_DISABLE_RESOLVED"
        systemctl disable --now systemd-resolved 2>/dev/null || true
        systemctl mask systemd-resolved 2>/dev/null || true
        log_success "$MSG_RESOLVED_DISABLED"
    fi
}

# ─── Очистка заглушек resolvconf ───────────────────
purge_resolvconf() {
    log_info "$MSG_PURGE_RESOLVCONF"

    # Проверяем если openresolv уже установлен — пропускаем очистку
    if [ -x /usr/sbin/resolvconf ] && [ ! -L /usr/sbin/resolvconf ]; then
        log_info "$MSG_OPENRESOLV_PRESENT"
        return 0
    fi

    # Удаляем ВСЕ симлинки resolvconf (включая битые)
    for path in /sbin/resolvconf /usr/sbin/resolvconf /usr/bin/resolvconf; do
        if [ -L "$path" ]; then
            # Проверяем не битый ли симлинк
            local target
            target=$(readlink -f "$path" 2>/dev/null) || target=""
            if [ ! -e "$target" ]; then
                log_info "$MSG_RM_BROKEN_SYMLINK" "$path"
                rm -f "$path" 2>/dev/null || true
            fi
        elif [ -f "$path" ] && grep -q "exit 0" "$path" 2>/dev/null; then
            # Удаляем заглушки
            rm -f "$path" 2>/dev/null || true
        fi
    done

    # Удаляем пакет resolvconf если есть (не openresolv!)
    if dpkg -l | grep -q "^ii[[:space:]]*resolvconf[[:space:]]" 2>/dev/null; then
        log_info "$MSG_RM_RESOLVCONF_PKG"
        apt-get remove -y --purge resolvconf 2>/dev/null || true
    fi

    log_success "$MSG_PURGE_DONE"
}

# ─── Разблокировка dpkg ────────────────────────────
unlock_dpkg() {
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || {
        apt-get remove -y --purge amneziawg amneziawg-dkms 2>/dev/null || true
        dpkg --configure -a 2>/dev/null || true
    }
}

# ─── Подготовка модулей ядра ───────────────────────
setup_kernel_modules() {
    log_info "$MSG_CHECK_MODULES"

    # Модуль ifb нужен для Ingress Shaping (tc)
    if ! lsmod | grep -q "^ifb " 2>/dev/null; then
        log_info "$MSG_LOAD_IFB"
        if modprobe ifb 2>/dev/null; then
            log_success "$MSG_IFB_LOADED"
            # Добавляем в автозагрузку
            mkdir -p /etc/modules-load.d
            echo "ifb" > /etc/modules-load.d/ifb.conf
        else
            log_warning "$MSG_IFB_UNAVAILABLE"
        fi
    else
        log_success "$MSG_IFB_ALREADY"
    fi
}

# ─── Обновление и установка зависимостей ───────────
install_deps() {
    log_info "$MSG_INSTALL_DEPS"

    apt-get update -qq

    apt-get install -y -qq \
        gnupg \
        curl \
        ca-certificates \
        iptables \
        ipset \
        coreutils \
        kmod \
        git \
        make

    log_success "$MSG_DEPS_INSTALLED"
}

# ─── Создание симлинков для resolvconf ─────────────
create_resolvconf_symlinks() {
    log_info "$MSG_CREATE_SYMLINKS"

    # Проверяем что /usr/sbin/resolvconf существует и это не битый симлинк
    if [ -L /usr/sbin/resolvconf ]; then
        # Это симлинк — проверяем куда указывает
        local target
        target=$(readlink -f /usr/sbin/resolvconf 2>/dev/null)
        if [ ! -x "$target" ]; then
            log_warning "$MSG_SYMLINK_BROKEN"
            # Пробуем определить какой пакет установлен и переустановить его
            if dpkg -l | grep -q "^ii[[:space:]]*openresolv[[:space:]]" 2>/dev/null; then
                apt-get install -y --reinstall openresolv 2>/dev/null || true
            elif dpkg -l | grep -q "^ii[[:space:]]*resolvconf[[:space:]]" 2>/dev/null; then
                apt-get install -y --reinstall resolvconf 2>/dev/null || true
            else
                # Неизвестно — пробуем оба
                apt-get install -y --reinstall openresolv 2>/dev/null || \
                apt-get install -y --reinstall resolvconf 2>/dev/null || true
            fi
        fi
    elif [ ! -x /usr/sbin/resolvconf ]; then
        log_warning "$MSG_RESOLVCONF_MISSING"
        apt-get install -y openresolv 2>/dev/null || apt-get install -y resolvconf 2>/dev/null || true
    fi

    # Финальная проверка
    if [ ! -e /usr/sbin/resolvconf ]; then
        log_error "$MSG_RESOLVCONF_RESTORE_FAIL"
        exit 1
    fi

    # Убеждаемся что директории существуют
    mkdir -p /sbin /usr/bin 2>/dev/null || true

    # Создаём симлинки
    ln -sf /usr/sbin/resolvconf /sbin/resolvconf 2>/dev/null || true
    ln -sf /usr/sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true

    # Проверяем что симлинки работают
    if [ -e /sbin/resolvconf ] || [ -e /usr/bin/resolvconf ] || [ -x /usr/sbin/resolvconf ]; then
        log_success "$MSG_SYMLINKS_CREATED"
    else
        log_error "$MSG_SYMLINKS_FAIL"
        exit 1
    fi
}

# ─── Установка openresolv или resolvconf ───────────
install_resolvconf() {
    log_info "$MSG_INSTALL_RESOLVCONF"

    # Проверяем если уже всё работает
    if [ -x /usr/sbin/resolvconf ] && [ ! -L /usr/sbin/resolvconf ]; then
        log_success "$MSG_RESOLVCONF_PRESENT"
        create_resolvconf_symlinks
        return 0
    fi

    # Попытка 1: openresolv (предпочтительно)
    log_info "$MSG_INSTALL_OPENRESOLV"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if apt-get install -y --reinstall openresolv 2>/dev/null; then
        log_success "$MSG_OPENRESOLV_INSTALLED"
        create_resolvconf_symlinks
        return 0
    fi

    # Попытка 2: resolvconf
    log_info "$MSG_INSTALL_RESOLVCONF_PKG"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if apt-get install -y --reinstall resolvconf 2>/dev/null; then
        log_success "$MSG_RESOLVCONF_INSTALLED"
        create_resolvconf_symlinks
        return 0
    fi

    # Заглушка (последний вариант)
    log_warning "$MSG_CREATE_STUB"
    printf '#!/bin/bash\nexit 0\n' > /usr/sbin/resolvconf
    chmod +x /usr/sbin/resolvconf
    create_resolvconf_symlinks
    log_success "$MSG_STUB_CREATED"
}

# ─── Настройка DNS ─────────────────────────────────
setup_dns() {
    log_info "$MSG_SETUP_DNS"
    DNS_TOUCHED=1

    # Бэкап оригинального resolv.conf (аудит-DNS: раньше терялся навсегда)
    if [ ! -f /etc/resolv.conf.original ] && [ ! -L /etc/resolv.conf ]; then
        cp -a /etc/resolv.conf /etc/resolv.conf.original 2>/dev/null || true
    fi

    # Снимаем защиту (если была от предыдущего запуска или restore_resolvconf)
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Отключаем systemd-resolved (чтобы не перезаписывал DNS)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "$MSG_DISABLE_RESOLVED"
        systemctl stop systemd-resolved 2>/dev/null || true
        systemctl disable systemd-resolved 2>/dev/null || true
        systemctl mask systemd-resolved 2>/dev/null || true
        log_success "$MSG_RESOLVED_DISABLED"
    fi

    # Удаляем symlink на systemd stub
    rm -f /etc/resolv.conf 2>/dev/null || true

    # Создаём статический resolv.conf
    cat > /etc/resolv.conf <<EOF
# Статический DNS для AmneziaWG
# Оригинальный файл сохранён в /etc/resolv.conf.original
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
EOF

    log_info "$MSG_FIX_RESOLV_CONF"
    log_success "$MSG_RESOLV_CONF_FIXED"

    log_success "$MSG_DNS_SETUP_DONE"
}

# ─── Добавление репозитория Amnezia ────────────────
add_repo() {
    local codename="$1"
    log_info "$MSG_ADD_REPO" "$codename"

    mkdir -p /usr/share/keyrings

    # Импортируем ключ (основной или альтернативный)
    if ! curl -sSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x57290828" | \
         gpg --dearmor --yes -o /usr/share/keyrings/amnezia-ppa.gpg 2>/dev/null; then
        curl -sSL "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/$codename/Release.gpg" | \
            gpg --dearmor --yes -o /usr/share/keyrings/amnezia-ppa.gpg 2>/dev/null
    fi

    # Добавляем репозиторий
    cat > /etc/apt/sources.list.d/amnezia.list <<EOF
deb [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu $codename main
EOF

    apt-get update -qq
    log_success "$MSG_REPO_ADDED"
}

# ─── Установка AmneziaWG ───────────────────────────
install_amneziawg() {
    case "$INSTALL_MODE" in
        go)      install_go_mode ;;
        kernel)  install_kernel_mode ;;
        default) install_default_mode ;;
    esac
}

# ─── Остановка всех amneziawg интерфейсов ──────────
stop_interfaces() {
    for iface in "$@"; do
        log_info "$MSG_STOP_IFACE" "$iface"
        awg-quick down "$iface" 2>/dev/null || true
    done
}

# ─── Запуск списка amneziawg интерфейсов ───────────
start_interfaces() {
    for iface in "$@"; do
        log_info "$MSG_START_IFACE" "$iface"
        awg-quick up "$iface" 2>/dev/null || true
    done
}

# ─── Получение активных интерфейсов ────────────────
get_active_interfaces() {
    local ifaces=()
    
    # Способ 1: Через команду awg (универсальный, видит и kernel, и go)
    # Вывод имеет вид: "interface: <name>"
    while IFS= read -r line; do
        if [[ "$line" == interface:* ]]; then
            local name=$(echo "$line" | awk '{print $2}')
            if [ -n "$name" ]; then
                ifaces+=("$name")
            fi
        fi
    done < <(awg show 2>/dev/null)
    
    # Способ 2: Fallback через ip link (если awg по какой-то причине не сработал)
    if [ ${#ifaces[@]} -eq 0 ]; then
        for iface in $(ip -o link show type amneziawg 2>/dev/null | awk -F': ' '{print $2}'); do
            ifaces+=("$iface")
        done
    fi

    echo "${ifaces[@]}"
}

# ─── Патч I6..I10 (расширенный DTLS-флайт сервера) ──
# Расширяет ipackets[5] → ipackets[10] (device/device.go) и добавляет case i6..i10
# в UAPI-парсер (device/uapi.go). Применяется при каждой установке/обновлении
# amneziawg-go (после git clone, перед make).
# Идемпотентен: повторный запуск ничего не ломает. Если патч не лёг (апстрим
# изменил исходники) — возвращает 1, вызывающий продолжает со стандартным демоном.
apply_i10_patch() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_warning "$MSG_I10_NO_PYTHON"
        return 1
    fi
    if python3 - <<'AWG_I10_PATCH'
import sys

MAX = 10  # итоговое число I-пакетов (стандарт — 5)

def main():
    # device.go: ipackets [5] -> [MAX]
    p1 = "device/device.go"
    s1 = open(p1).read()
    if "ipackets [%d]*obfChain" % MAX in s1:
        print("device.go: уже пропатчен")
    elif "ipackets [5]*obfChain" in s1:
        open(p1, "w").write(s1.replace("ipackets [5]*obfChain", "ipackets [%d]*obfChain" % MAX, 1))
        print("device.go: ipackets 5 -> %d" % MAX)
    else:
        print("device.go: якорь 'ipackets [5]*obfChain' не найден")
        return 1

    # uapi.go: добавляем case i6..i10 после блока i5
    p2 = "device/uapi.go"
    s2 = open(p2).read()
    if all('case "i%d":' % i in s2 for i in range(6, MAX + 1)):
        print("uapi.go: уже пропатчен")
    else:
        anchor = '\t\tdevice.ipackets[4] = chain\n'
        lines = ['\t\tdevice.ipackets[4] = chain\n']
        for i in range(6, MAX + 1):
            lines.append('\n')
            lines.append('\tcase "i%d":\n' % i)
            lines.append('\t\tchain, err := newObfChain(value)\n')
            lines.append('\t\tif err != nil {\n')
            lines.append('\t\t\treturn ipcErrorf(ipc.IpcErrorInvalid, "failed to parse I%d: %%w", err)\n' % i)
            lines.append('\t\t}\n')
            lines.append('\t\tdevice.ipackets[%d] = chain\n' % (i - 1))
        addition = ''.join(lines)
        if anchor in s2:
            open(p2, "w").write(s2.replace(anchor, addition, 1))
            print("uapi.go: i6..i%d добавлены" % MAX)
        else:
            print("uapi.go: якорь 'device.ipackets[4] = chain' не найден")
            return 1
    return 0

sys.exit(main())
AWG_I10_PATCH
    then
        log_success "$MSG_I10_APPLIED"
        return 0
    else
        log_warning "$MSG_I10_FAILED"
        log_warning "$MSG_I10_STAY_STANDARD"
        return 1
    fi
}

# ─── Режим GO: amneziawg-go + amneziawg-tools ──────
install_go_mode() {
    log_info "$MSG_MODE_GO"

    # 1. СНАЧАЛА гарантируем наличие инструментов (чтобы awg/awg-quick работали)
    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_info "$MSG_INSTALL_TOOLS"
        apt-get install -y amneziawg-tools 2>&1 || true
    fi

    # Сохраняем список активных интерфейсов (теперь инструменты точно есть)
    read -ra INTERFACES <<< "$(get_active_interfaces)"

    if [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "$MSG_IFACES_FOUND" "${INTERFACES[*]}"
    fi

    # Собираем/обновляем amneziawg-go
    log_info "$MSG_BUILD_GO"

    INSTALL_GO=false

    # 1. Проверяем, есть ли у нас уже свежий Go в /usr/local/go (от прошлых запусков)
    if [ -x /usr/local/go/bin/go ]; then
        export PATH=/usr/local/go/bin:$PATH
        log_info "$MSG_GO_FOUND"
    fi

    # 2. Проверяем версию
    GO_VER_STR=$(go version 2>/dev/null || true)
    if [ -z "$GO_VER_STR" ]; then
        log_info "$MSG_GO_NOT_FOUND"
        INSTALL_GO=true
    else
        # Извлекаем версию (например, 1.19.8)
        GO_VER=$(echo "$GO_VER_STR" | grep -oE 'go[0-9]+\.[0-9.]+' | head -1 | sed 's/go//')
        log_info "$MSG_GO_VER" "$GO_VER"
        
        # Сравниваем с требуемой (1.21)
        REQUIRED="1.21"
        # sort -V вернет меньшую версию первой
        LOWEST=$(printf '%s\n%s' "$REQUIRED" "$GO_VER" | sort -V | head -n1)
        
        # Если LOWEST равен нашей текущей версии (и она не равна требуемой), значит она старая
        if [ "$LOWEST" = "$GO_VER" ] && [ "$GO_VER" != "$REQUIRED" ]; then
            log_info "$MSG_GO_OLD"
            INSTALL_GO=true
        fi
    fi

    # 3. Скачиваем и ставим Go, если нужно
    if [ "$INSTALL_GO" = true ]; then
        log_info "$MSG_GO_DOWNLOAD"
        
        # Получаем актуальную версию
        LATEST_VER=$(curl -sL https://go.dev/VERSION?m=text 2>/dev/null | head -1)
        if [[ "$LATEST_VER" != go* ]]; then
            LATEST_VER="go1.23.6" # Фоллбэк
        fi
        
        case "$(uname -m)" in
            aarch64|arm64) GO_ARCH="arm64" ;;
            *)             GO_ARCH="amd64" ;;
        esac
        GO_URL="https://dl.google.com/go/${LATEST_VER}.linux-${GO_ARCH}.tar.gz"
        GO_TAR=$(mktemp)
        
        curl -sSL -o "$GO_TAR" "$GO_URL" || {
            log_error "$MSG_GO_DL_FAIL" "$GO_URL"
            rm -f "$GO_TAR"
            exit 1
        }
        
        rm -rf /usr/local/go 2>/dev/null || true
        tar -C /usr/local -xzf "$GO_TAR" 2>/dev/null || {
            log_error "$MSG_GO_EXTRACT_FAIL"
            rm -f "$GO_TAR"
            exit 1
        }
        rm -f "$GO_TAR"
        export PATH=/usr/local/go/bin:$PATH
        log_success "$MSG_GO_UPDATED" "$(go version)"
    fi

    # 4. Сборка
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    git clone https://github.com/amnezia-vpn/amneziawg-go 2>&1 || {
        log_error "$MSG_GO_CLONE_FAIL"
        cd / && rm -rf "$TMPDIR"
        exit 1
    }
    cd amneziawg-go

    # Патч I6..I10 (расширенный DTLS-флайт сервера, до 10 I-пакетов)
    # Включается флагом -p (--patch), работает только в go-режиме (-g)
    if [ "$PATCH_I10" = true ]; then
        apply_i10_patch || true
    else
        log_info "$MSG_I10_SKIPPED"
    fi

    # Гарантируем использование свежего Go
    export PATH=/usr/local/go/bin:$PATH
    export GOTOOLCHAIN=local

    make 2>&1 || {
        log_error "$MSG_GO_BUILD_FAIL"
        cd / && rm -rf "$TMPDIR"
        exit 1
    }

    # Если бинарник уже существует (обновление), нужно остановить интерфейсы ПЕРЕД заменой
    # Иначе будет ошибка "Text file busy"
    if [ -f /usr/local/bin/amneziawg-go ] && [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "$MSG_GO_OLD_STOP_IFACES"
        stop_interfaces "${INTERFACES[@]}"
        INTERFACES_WAS_STOPPED=true
    else
        INTERFACES_WAS_STOPPED=false
    fi

    # Заменяем бинарник
    cp amneziawg-go /usr/local/bin/
    chmod +x /usr/local/bin/amneziawg-go
    cd / && rm -rf "$TMPDIR"
    log_success "$MSG_GO_INSTALLED"

    # Останавливаем интерфейсы (только если они были и мы их ещё не остановили ради обновления бинарника)
    if [ "${INTERFACES_WAS_STOPPED:-false}" = false ] && [ ${#INTERFACES[@]} -gt 0 ]; then
        stop_interfaces "${INTERFACES[@]}"
    fi

    # Выгружаем kernel модуль
    log_info "$MSG_RM_MODULE"
    rmmod amneziawg 2>/dev/null || true

    # Удаляем dkms
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_info "$MSG_RM_DKMS"
        apt-get remove -y --purge amneziawg-dkms 2>/dev/null || true
    fi

    # Запускаем интерфейсы обратно (через go)
    if [ ${#INTERFACES[@]} -gt 0 ]; then
        start_interfaces "${INTERFACES[@]}"
    fi

    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null && command -v amneziawg-go &>/dev/null; then
        log_success "$MSG_GO_READY"
        awg --version 2>&1 | head -n1
    else
        log_error "$MSG_GO_INSTALL_FAIL"
        exit 1
    fi
}

# ─── Проверка заголовков ядра ──────────────────────
check_kernel_headers() {
    if [ -d "/lib/modules/$(uname -r)/build" ]; then
        return 0
    fi
    log_info "$MSG_HEADERS_INSTALLING"
    apt-get install -y linux-headers-$(uname -r) 2>/dev/null || {
        apt-get install -y pve-headers-$(uname -r) 2>/dev/null || {
            log_warning "$MSG_HEADERS_FAIL"
            log_warning "$MSG_HEADERS_HINT1" "$(uname -r)"
            log_warning "$MSG_HEADERS_HINT2"
        }
    }
    if [ -d "/lib/modules/$(uname -r)/build" ]; then
        log_success "$MSG_HEADERS_OK"
        return 0
    else
        log_warning "$MSG_HEADERS_NOT_INSTALLED"
        return 1
    fi
}

# ─── Режим KERNEL: amneziawg-dkms + amneziawg-tools ──
install_kernel_mode() {
    log_info "$MSG_MODE_KERNEL"

    check_kernel_headers

    # 1. СНАЧАЛА гарантируем наличие инструментов
    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_info "$MSG_INSTALL_TOOLS"
        apt-get install -y amneziawg-tools 2>&1 || true
    fi

    # Сохраняем список активных интерфейсов (теперь инструменты точно есть)
    read -ra INTERFACES <<< "$(get_active_interfaces)"

    if [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "$MSG_IFACES_FOUND" "${INTERFACES[*]}"
    fi

    # Ставим dkms (tools уже стоит из шага 1)
    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        apt-get install -y amneziawg-dkms 2>&1 || true
    fi

    # Останавливаем интерфейсы (только если они были)
    if [ ${#INTERFACES[@]} -gt 0 ]; then
        stop_interfaces "${INTERFACES[@]}"
    fi

    # Выгружаем kernel модуль (перезагрузится после установки dkms)
    rmmod amneziawg 2>/dev/null || true

    # Удаляем amneziawg-go
    if command -v amneziawg-go &>/dev/null; then
        log_info "$MSG_RM_GO_BIN"
        rm -f /usr/local/bin/amneziawg-go
    fi

    # Запускаем интерфейсы обратно (через kernel)
    if [ ${#INTERFACES[@]} -gt 0 ]; then
        start_interfaces "${INTERFACES[@]}"
    fi

    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_success "$MSG_KERNEL_READY"
        awg --version 2>&1 | head -n1
    else
        log_error "$MSG_KERNEL_INSTALL_FAIL"
        exit 1
    fi
}

# ─── Режим DEFAULT: мета-пакет amneziawg ───────────
install_default_mode() {
    log_info "$MSG_MODE_DEFAULT"

    check_kernel_headers

    # Пробуем установить мета-пакет (он сам подтянет dkms и tools)
    apt-get install -y amneziawg 2>&1 | grep -v "Error\|dpkg:\|Errors were" || true

    # Проверяем, встал ли dkms
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_success "$MSG_AMNEZIAWG_INSTALLED"
        awg --version 2>&1 | head -n1
    else
        # Фоллбэк: если мета-пакет не вытянул dkms, ставим компоненты вручную
        log_info "$MSG_META_NO_DKMS"
        apt-get install -y amneziawg-dkms amneziawg-tools 2>/dev/null || true

        if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
            log_success "$MSG_AMNEZIAWG_INSTALLED"
            awg --version 2>&1 | head -n1
        else
            log_error "$MSG_DKMS_INSTALL_FAIL"
            exit 1
        fi
    fi
}

# ─── Восстановление resolv.conf ────────────────────
restore_resolvconf() {
    log_info "$MSG_RESTORE_DNS"

    # Снимаем защиту
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Возвращаем ОРИГИНАЛ если он был сохранён (аудит-DNS), иначе — статику
    if [ -f /etc/resolv.conf.original ]; then
        cp -a /etc/resolv.conf.original /etc/resolv.conf 2>/dev/null || true
    else
        # Создаём рабочий статический DNS (не systemd stub!)
        cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
EOF
    fi

    # Возвращаем systemd-resolved, если он был активен до нас (аудит-DNS)
    if [ "${RESOLVED_WAS_ACTIVE:-0}" = "1" ]; then
        systemctl unmask systemd-resolved 2>/dev/null || true
        systemctl enable --now systemd-resolved 2>/dev/null || true
    fi

    log_success "$MSG_DNS_RESTORED"
}

# ─── Проверка установки ────────────────────────────
verify() {
    log_info "$MSG_VERIFY"

    case "$INSTALL_MODE" in
        go)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "$MSG_TOOLS_MISSING"
                exit 1
            fi
            if ! command -v amneziawg-go &>/dev/null; then
                log_error "$MSG_GO_BIN_MISSING"
                exit 1
            fi
            ;;
        kernel)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "$MSG_TOOLS_MISSING"
                exit 1
            fi
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
                log_error "$MSG_DKMS_MISSING"
                exit 1
            fi
            lsmod | grep -q amneziawg 2>/dev/null || \
                log_info "$MSG_MODULE_ON_START"
            ;;
        default)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "$MSG_TOOLS_MISSING"
                exit 1
            fi
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
                log_error "$MSG_DKMS_MISSING"
                exit 1
            fi
            lsmod | grep -q amneziawg 2>/dev/null || \
                log_info "$MSG_MODULE_ON_START"
            ;;
    esac

    [ ! -d /etc/amnezia/amneziawg ] && mkdir -p /etc/amnezia/amneziawg
    log_success "$MSG_VERIFY_DONE"
}

# ─── Финальный вывод ───────────────────────────────
print_info() {
    echo
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "${GREEN}       %s      ${NC}\n" "$MSG_INSTALLED_OK"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    printf "%s: ${INSTALL_MODE}\n" "$MSG_MODE"
    printf "%s: %s\n" "$MSG_VERSION" "$(awg --version 2>&1 | head -n1)"
    echo

    case "$INSTALL_MODE" in
        go)
            echo "$MSG_GO_SAFE"
            echo "$MSG_GO_BUILT"
            echo
            echo "$MSG_CMDS_GO:"
            ;;
        kernel)
            echo "$MSG_REBOOT_WARN"
            echo "  apt-get upgrade -y    # $MSG_UPGRADE_COMMENT"
            echo "  reboot                # $MSG_REBOOT_COMMENT"
            echo "$MSG_REBOOT_AUTO"
            echo
            echo "$MSG_CMDS_KERNEL:"
            ;;
        default)
            echo "$MSG_REBOOT_WARN"
            echo "  apt-get upgrade -y    # $MSG_UPGRADE_COMMENT"
            echo "  reboot                # $MSG_REBOOT_COMMENT"
            echo "$MSG_REBOOT_AUTO"
            echo
            echo "$MSG_CMDS_DEFAULT:"
            ;;
    esac

    echo "  # $MSG_CMDS_BASIC"
    echo "  awg-quick up awg                       # $MSG_UP_IFACE"
    echo "  awg-quick down awg                     # $MSG_DOWN_IFACE"
    echo "  awg                                    # $MSG_STATUS"
    echo "  # $MSG_CMDS_SERVICE"
    echo "  systemctl enable awg-quick@awg         # $MSG_ENABLE_BOOT"
    echo "  systemctl disable awg-quick@awg        # $MSG_DISABLE_BOOT"
    echo "  systemctl restart awg-quick@awg        # $MSG_RESTART"
    echo "  systemctl status awg-quick@awg         # $MSG_CHECK_STATE"
    echo "  # $MSG_CMDS_CONFIG"
    echo "  awg-quick strip awg > /tmp/awg.conf    # $MSG_SAVE_CLEAN_CONF"
    echo "  awg syncconf awg /tmp/awg.conf         # $MSG_SYNC_CONF"
    echo
    printf "%s:\n" "$MSG_CONFIG"
    echo "  /etc/amnezia/amneziawg/"
    echo
}

# ─── Cleanup при ошибке ────────────────────────────
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "$MSG_ERROR_CODE" "$exit_code"
        # Восстанавливаем DNS только если реально вмешивались (аудит-DNS:
        # раньше cleanup переписывал resolv.conf даже при опечатке флага)
        if [ "${DNS_TOUCHED:-0}" = "1" ]; then
            restore_resolvconf 2>/dev/null || true
        fi
    fi
}

# ─── Главная ──────────────────────────────────────
main() {
    trap cleanup EXIT

    # Парсим флаги ПЕРЕД всем остальным
    init_lang
    parse_flags "$@"

    echo
    echo -e "${GREEN}╔══════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   AmneziaWG Installer v6.6       ║${NC}"
    echo -e "${GREEN}║   Ubuntu 20-26 | Debian 11-13    ║${NC}"
    echo -e "${GREEN}║   + disable systemd-resolved     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════╝${NC}"
    printf "    %s: ${INSTALL_MODE}\n" "$MSG_MODE"
    echo

    check_root
    check_os

    local codename
    codename=$(get_codename)

    # Порядок ВАЖЕН!
    disable_systemd_resolved
    purge_resolvconf
    setup_dns              # 1. DNS (ДО install_deps — systemd-resolved уже отключён)
    unlock_dpkg
    install_deps           # 2. apt update + зависимости (kmod, lsmod, git, make)
    setup_kernel_modules   # 3. ПОДГОТОВКА МОДУЛЕЙ ЯДРА (ifb для лимитов) — после kmod
    install_resolvconf     # 4. openresolv/resolvconf
    add_repo "$codename"   # 5. Репозиторий Amnezia
    install_amneziawg      # 6. AmneziaWG
    restore_resolvconf     # 7. Восстановление resolv.conf
    verify                 # 8. Проверка
    print_info             # 9. Вывод
}

# ─── Оформление вывода ─────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Логирование (в stderr чтобы не ломать переменные)
log_info()    { printf "${GREEN}>>> [Amnezia]${NC} $1\n" "${@:2}" >&2; }
log_success() { printf "${GREEN}>>> [Amnezia]${NC} ✅ $1\n" "${@:2}" >&2; }
log_warning() { printf "${YELLOW}>>> [Amnezia]${NC} ⚠️  $1\n" "${@:2}" >&2; }
log_error()   { printf "${RED}>>> [Amnezia]${NC} ❌ $1\n" "${@:2}" >&2; }

# ─── Локализация ───────────────────────────────────
init_lang() {
    if [[ "$LANG" == ru_RU* ]]; then
        MSG_UNKNOWN_FLAG="Неизвестный флаг:"
        MSG_USAGE_HEADER="Использование:"
        MSG_USAGE_DEFAULT="  %s                    # Установить amneziawg (dkms + tools)"
        MSG_USAGE_GO="  %s --go       (-g)    # Собрать amneziawg-go из исходников + amneziawg-tools (удалить dkms)"
        MSG_USAGE_KERNEL="  %s --kernel   (-k)    # Установить amneziawg-dkms + amneziawg-tools (удалить go)"
        MSG_USAGE_PATCH="  %s --patch    (-p)    # Применить патч I6..I10 (только вместе с -g)"
        MSG_USAGE_HELP="  %s --help     (-h)    # Показать эту справку"
        MSG_ROOT_REQUIRED="Требуется root (sudo)"
        MSG_NO_OS="Не удалось определить ОС"
        MSG_DETECTED="Обнаружена: %s"
        MSG_DEB10_UNSUP="Debian 10 не поддерживается (ядро 4.19 < 5.6)"
        MSG_DEB11_REQ="Требуется Debian 11+ или Ubuntu 20.04+"
        MSG_UBU_UNSUP="Ubuntu %s не поддерживается (ядро < 5.6)"
        MSG_UBU20_REQ="Требуется Ubuntu 20.04+"
        MSG_DISABLE_RESOLVED="Отключаем systemd-resolved..."
        MSG_RESOLVED_DISABLED="systemd-resolved отключён"
        MSG_PURGE_RESOLVCONF="Очистка resolvconf заглушек..."
        MSG_OPENRESOLV_PRESENT="openresolv уже установлен (корректный бинарник)"
        MSG_RM_BROKEN_SYMLINK="Удаление битого симлинка: %s"
        MSG_RM_RESOLVCONF_PKG="Удаляем пакет resolvconf..."
        MSG_PURGE_DONE="Очистка завершена"
        MSG_CHECK_MODULES="Проверка модулей ядра..."
        MSG_LOAD_IFB="Загрузка модуля ifb (для лимитов скорости)..."
        MSG_IFB_LOADED="Модуль ifb загружен"
        MSG_IFB_UNAVAILABLE="Модуль ifb недоступен (лимиты входящей скорости могут не работать)"
        MSG_IFB_ALREADY="Модуль ifb уже загружен"
        MSG_INSTALL_DEPS="Обновление и установка зависимостей..."
        MSG_DEPS_INSTALLED="Зависимости установлены"
        MSG_CREATE_SYMLINKS="Создание симлинков resolvconf..."
        MSG_SYMLINK_BROKEN="/usr/sbin/resolvconf — битый симлинк, переустанавливаем..."
        MSG_RESOLVCONF_MISSING="/usr/sbin/resolvconf не найден, пробуем установить..."
        MSG_RESOLVCONF_RESTORE_FAIL="Не удалось восстановить /usr/sbin/resolvconf"
        MSG_SYMLINKS_CREATED="Симлинки созданы"
        MSG_SYMLINKS_FAIL="Не удалось создать симлинки"
        MSG_INSTALL_RESOLVCONF="Установка openresolv / resolvconf..."
        MSG_RESOLVCONF_PRESENT="resolvconf уже установлен"
        MSG_INSTALL_OPENRESOLV="Устанавливаем openresolv..."
        MSG_OPENRESOLV_INSTALLED="openresolv установлен"
        MSG_INSTALL_RESOLVCONF_PKG="Устанавливаем resolvconf..."
        MSG_RESOLVCONF_INSTALLED="resolvconf установлен"
        MSG_CREATE_STUB="Создаём заглушку..."
        MSG_STUB_CREATED="Заглушка создана"
        MSG_SETUP_DNS="Настройка DNS..."
        MSG_FIX_RESOLV_CONF="Фиксация resolv.conf..."
        MSG_RESOLV_CONF_FIXED="resolv.conf зафиксирован"
        MSG_DNS_SETUP_DONE="DNS настроен"
        MSG_ADD_REPO="Добавление репозитория Amnezia (%s)..."
        MSG_REPO_ADDED="Репозиторий добавлен"
        MSG_STOP_IFACE="Остановка интерфейса %s..."
        MSG_START_IFACE="Запуск интерфейса %s..."
        MSG_I10_NO_PYTHON="python3 не найден — патч I6..I10 пропущен (демон останется стандартным, 5 I-пакетов)"
        MSG_I10_APPLIED="Патч I6..I10 применён (демон поддерживает до 10 I-пакетов)"
        MSG_I10_FAILED="Патч I6..I10 не применился (исходники amneziawg-go изменились?)"
        MSG_I10_STAY_STANDARD="Демон останется стандартным (5 I-пакетов). Обновите патч в AmneziaWG.sh."
        MSG_I10_SKIPPED="Патч I6..I10 пропущен (добавьте -p для расширенного DTLS-флайта)"
        MSG_MODE_GO="Режим: amneziawg-go + amneziawg-tools (без dkms)..."
        MSG_INSTALL_TOOLS="Установка amneziawg-tools..."
        MSG_IFACES_FOUND="Найдены активные интерфейсы: %s"
        MSG_BUILD_GO="Сборка amneziawg-go из исходников..."
        MSG_GO_FOUND="Найден Go в /usr/local/go, используем его."
        MSG_GO_NOT_FOUND="Go не найден в системе."
        MSG_GO_VER="Обнаружена версия Go: %s"
        MSG_GO_OLD="Версия Go устарела (требуется >= 1.21), скачиваем свежую..."
        MSG_GO_DOWNLOAD="Скачиваю последнюю версию Golang..."
        MSG_GO_DL_FAIL="Не удалось скачать Golang с %s"
        MSG_GO_EXTRACT_FAIL="Ошибка распаковки Golang"
        MSG_GO_UPDATED="Golang обновлён до %s"
        MSG_GO_CLONE_FAIL="Не удалось склонировать amneziawg-go"
        MSG_GO_BUILD_FAIL="Ошибка сборки amneziawg-go"
        MSG_GO_OLD_STOP_IFACES="Обнаружена старая версия amneziawg-go, останавливаем интерфейсы для обновления..."
        MSG_GO_INSTALLED="amneziawg-go установлен/обновлён в /usr/local/bin/"
        MSG_RM_MODULE="Выгрузка kernel модуля..."
        MSG_RM_DKMS="Удаление amneziawg-dkms..."
        MSG_RM_GO_BIN="Удаление amneziawg-go..."
        MSG_GO_READY="Go версия готова (amneziawg-go + amneziawg-tools)"
        MSG_GO_INSTALL_FAIL="Не удалось установить go версию"
        MSG_HEADERS_INSTALLING="Заголовки ядра не найдены, устанавливаю..."
        MSG_HEADERS_FAIL="Не удалось установить заголовки ядра. dkms может не собраться."
        MSG_HEADERS_HINT1="Попробуйте: apt install linux-headers-%s"
        MSG_HEADERS_HINT2="Или используйте: AmneziaWG.sh -g (go-режим)"
        MSG_HEADERS_OK="Заголовки ядра установлены"
        MSG_HEADERS_NOT_INSTALLED="Заголовки ядра не установлены — dkms может не собраться"
        MSG_MODE_KERNEL="Режим: amneziawg-dkms + amneziawg-tools (без go)..."
        MSG_KERNEL_READY="Kernel версия готова (dkms + tools)"
        MSG_KERNEL_INSTALL_FAIL="Не удалось установить kernel версию"
        MSG_MODE_DEFAULT="Режим: установка пакета amneziawg (dkms + tools)..."
        MSG_AMNEZIAWG_INSTALLED="amneziawg установлен (dkms + tools)"
        MSG_META_NO_DKMS="Мета-пакет не подтянул dkms, ставим отдельно..."
        MSG_DKMS_INSTALL_FAIL="Не удалось установить amneziawg-dkms"
        MSG_RESTORE_DNS="Восстановление DNS..."
        MSG_DNS_RESTORED="DNS восстановлен"
        MSG_VERIFY="Проверка установки..."
        MSG_TOOLS_MISSING="amneziawg-tools не найден"
        MSG_GO_BIN_MISSING="amneziawg-go не найден"
        MSG_DKMS_MISSING="amneziawg-dkms не найден"
        MSG_MODULE_ON_START="Модуль ядра загрузится при первом запуске"
        MSG_VERIFY_DONE="Проверка завершена"
        MSG_INSTALLED_OK="AmneziaWG успешно установлен!"
        MSG_MODE="Режим"
        MSG_VERSION="Версия"
        MSG_GO_SAFE="Go версия — безопасная, без kernel panic!"
        MSG_GO_BUILT="amneziawg-go собран из исходников"
        MSG_CMDS_GO="Команды (go версия — без kernel модуля)"
        MSG_REBOOT_WARN="ВАЖНО! Для завершения установки на старых системах выполните:"
        MSG_UPGRADE_COMMENT="Установить обновления ядра"
        MSG_REBOOT_COMMENT="Перезагрузиться"
        MSG_REBOOT_AUTO="После перезагрузки модуль ядра соберётся автоматически!"
        MSG_CMDS_KERNEL="Команды (kernel версия)"
        MSG_CMDS_DEFAULT="Команды"
        MSG_CMDS_BASIC="основные"
        MSG_UP_IFACE="Поднять интерфейс"
        MSG_DOWN_IFACE="Опустить интерфейс"
        MSG_STATUS="Статус"
        MSG_CMDS_SERVICE="сервис"
        MSG_ENABLE_BOOT="Добавить в автозагрузки"
        MSG_DISABLE_BOOT="Удалить из автозагрузки"
        MSG_RESTART="Перезапустить"
        MSG_CHECK_STATE="Проверить состояние"
        MSG_CMDS_CONFIG="конфигурация"
        MSG_SAVE_CLEAN_CONF="Сохранить конфиг в чистом формате во временный файл"
        MSG_SYNC_CONF="Загрузить конфиг для обновления пользователей без перезапуска интерфейса"
        MSG_CONFIG="Конфигурация"
        MSG_ERROR_CODE="Ошибка (код: %s)"
    else
        MSG_UNKNOWN_FLAG="Unknown flag:"
        MSG_USAGE_HEADER="Usage:"
        MSG_USAGE_DEFAULT="  %s                    # Install amneziawg (dkms + tools)"
        MSG_USAGE_GO="  %s --go       (-g)    # Build amneziawg-go from sources + amneziawg-tools (remove dkms)"
        MSG_USAGE_KERNEL="  %s --kernel   (-k)    # Install amneziawg-dkms + amneziawg-tools (remove go)"
        MSG_USAGE_PATCH="  %s --patch    (-p)    # Apply I6..I10 patch (only with -g)"
        MSG_USAGE_HELP="  %s --help     (-h)    # Show this help"
        MSG_ROOT_REQUIRED="Root required (sudo)"
        MSG_NO_OS="Failed to detect OS"
        MSG_DETECTED="Detected: %s"
        MSG_DEB10_UNSUP="Debian 10 is not supported (kernel 4.19 < 5.6)"
        MSG_DEB11_REQ="Debian 11+ or Ubuntu 20.04+ required"
        MSG_UBU_UNSUP="Ubuntu %s is not supported (kernel < 5.6)"
        MSG_UBU20_REQ="Ubuntu 20.04+ required"
        MSG_DISABLE_RESOLVED="Disabling systemd-resolved..."
        MSG_RESOLVED_DISABLED="systemd-resolved disabled"
        MSG_PURGE_RESOLVCONF="Cleaning resolvconf stubs..."
        MSG_OPENRESOLV_PRESENT="openresolv already installed (correct binary)"
        MSG_RM_BROKEN_SYMLINK="Removing broken symlink: %s"
        MSG_RM_RESOLVCONF_PKG="Removing resolvconf package..."
        MSG_PURGE_DONE="Cleanup complete"
        MSG_CHECK_MODULES="Checking kernel modules..."
        MSG_LOAD_IFB="Loading ifb module (for speed limits)..."
        MSG_IFB_LOADED="ifb module loaded"
        MSG_IFB_UNAVAILABLE="ifb module unavailable (ingress speed limits may not work)"
        MSG_IFB_ALREADY="ifb module already loaded"
        MSG_INSTALL_DEPS="Updating and installing dependencies..."
        MSG_DEPS_INSTALLED="Dependencies installed"
        MSG_CREATE_SYMLINKS="Creating resolvconf symlinks..."
        MSG_SYMLINK_BROKEN="/usr/sbin/resolvconf is a broken symlink, reinstalling..."
        MSG_RESOLVCONF_MISSING="/usr/sbin/resolvconf not found, trying to install..."
        MSG_RESOLVCONF_RESTORE_FAIL="Failed to restore /usr/sbin/resolvconf"
        MSG_SYMLINKS_CREATED="Symlinks created"
        MSG_SYMLINKS_FAIL="Failed to create symlinks"
        MSG_INSTALL_RESOLVCONF="Installing openresolv / resolvconf..."
        MSG_RESOLVCONF_PRESENT="resolvconf already installed"
        MSG_INSTALL_OPENRESOLV="Installing openresolv..."
        MSG_OPENRESOLV_INSTALLED="openresolv installed"
        MSG_INSTALL_RESOLVCONF_PKG="Installing resolvconf..."
        MSG_RESOLVCONF_INSTALLED="resolvconf installed"
        MSG_CREATE_STUB="Creating stub..."
        MSG_STUB_CREATED="Stub created"
        MSG_SETUP_DNS="Setting up DNS..."
        MSG_FIX_RESOLV_CONF="Fixing resolv.conf..."
        MSG_RESOLV_CONF_FIXED="resolv.conf fixed"
        MSG_DNS_SETUP_DONE="DNS configured"
        MSG_ADD_REPO="Adding Amnezia repository (%s)..."
        MSG_REPO_ADDED="Repository added"
        MSG_STOP_IFACE="Stopping interface %s..."
        MSG_START_IFACE="Starting interface %s..."
        MSG_I10_NO_PYTHON="python3 not found — I6..I10 patch skipped (daemon stays standard, 5 I-packets)"
        MSG_I10_APPLIED="I6..I10 patch applied (daemon supports up to 10 I-packets)"
        MSG_I10_FAILED="I6..I10 patch did not apply (amneziawg-go sources changed?)"
        MSG_I10_STAY_STANDARD="Daemon stays standard (5 I-packets). Update the patch in AmneziaWG.sh."
        MSG_I10_SKIPPED="I6..I10 patch skipped (add -p for extended DTLS flight)"
        MSG_MODE_GO="Mode: amneziawg-go + amneziawg-tools (no dkms)..."
        MSG_INSTALL_TOOLS="Installing amneziawg-tools..."
        MSG_IFACES_FOUND="Active interfaces found: %s"
        MSG_BUILD_GO="Building amneziawg-go from sources..."
        MSG_GO_FOUND="Go found in /usr/local/go, using it."
        MSG_GO_NOT_FOUND="Go not found in the system."
        MSG_GO_VER="Detected Go version: %s"
        MSG_GO_OLD="Go version is outdated (required >= 1.21), downloading fresh..."
        MSG_GO_DOWNLOAD="Downloading latest Golang..."
        MSG_GO_DL_FAIL="Failed to download Golang from %s"
        MSG_GO_EXTRACT_FAIL="Failed to extract Golang"
        MSG_GO_UPDATED="Golang updated to %s"
        MSG_GO_CLONE_FAIL="Failed to clone amneziawg-go"
        MSG_GO_BUILD_FAIL="Failed to build amneziawg-go"
        MSG_GO_OLD_STOP_IFACES="Old amneziawg-go detected, stopping interfaces for update..."
        MSG_GO_INSTALLED="amneziawg-go installed/updated in /usr/local/bin/"
        MSG_RM_MODULE="Unloading kernel module..."
        MSG_RM_DKMS="Removing amneziawg-dkms..."
        MSG_RM_GO_BIN="Removing amneziawg-go..."
        MSG_GO_READY="Go version ready (amneziawg-go + amneziawg-tools)"
        MSG_GO_INSTALL_FAIL="Failed to install go version"
        MSG_HEADERS_INSTALLING="Kernel headers not found, installing..."
        MSG_HEADERS_FAIL="Failed to install kernel headers. dkms may not build."
        MSG_HEADERS_HINT1="Try: apt install linux-headers-%s"
        MSG_HEADERS_HINT2="Or use: AmneziaWG.sh -g (go mode)"
        MSG_HEADERS_OK="Kernel headers installed"
        MSG_HEADERS_NOT_INSTALLED="Kernel headers not installed — dkms may not build"
        MSG_MODE_KERNEL="Mode: amneziawg-dkms + amneziawg-tools (no go)..."
        MSG_KERNEL_READY="Kernel version ready (dkms + tools)"
        MSG_KERNEL_INSTALL_FAIL="Failed to install kernel version"
        MSG_MODE_DEFAULT="Mode: installing amneziawg package (dkms + tools)..."
        MSG_AMNEZIAWG_INSTALLED="amneziawg installed (dkms + tools)"
        MSG_META_NO_DKMS="Meta package did not pull dkms, installing components manually..."
        MSG_DKMS_INSTALL_FAIL="Failed to install amneziawg-dkms"
        MSG_RESTORE_DNS="Restoring DNS..."
        MSG_DNS_RESTORED="DNS restored"
        MSG_VERIFY="Verifying installation..."
        MSG_TOOLS_MISSING="amneziawg-tools not found"
        MSG_GO_BIN_MISSING="amneziawg-go not found"
        MSG_DKMS_MISSING="amneziawg-dkms not found"
        MSG_MODULE_ON_START="Kernel module will load on first start"
        MSG_VERIFY_DONE="Verification complete"
        MSG_INSTALLED_OK="AmneziaWG successfully installed!"
        MSG_MODE="Mode"
        MSG_VERSION="Version"
        MSG_GO_SAFE="Go version — safe, no kernel panic!"
        MSG_GO_BUILT="amneziawg-go built from sources"
        MSG_CMDS_GO="Commands (go version — no kernel module)"
        MSG_REBOOT_WARN="IMPORTANT! To finish installation on old systems run:"
        MSG_UPGRADE_COMMENT="Install kernel updates"
        MSG_REBOOT_COMMENT="Reboot"
        MSG_REBOOT_AUTO="After reboot the kernel module builds automatically!"
        MSG_CMDS_KERNEL="Commands (kernel version)"
        MSG_CMDS_DEFAULT="Commands"
        MSG_CMDS_BASIC="basic"
        MSG_UP_IFACE="Bring interface up"
        MSG_DOWN_IFACE="Bring interface down"
        MSG_STATUS="Status"
        MSG_CMDS_SERVICE="service"
        MSG_ENABLE_BOOT="Enable on boot"
        MSG_DISABLE_BOOT="Disable on boot"
        MSG_RESTART="Restart"
        MSG_CHECK_STATE="Check state"
        MSG_CMDS_CONFIG="configuration"
        MSG_SAVE_CLEAN_CONF="Save config in clean format to temporary file"
        MSG_SYNC_CONF="Load config to update users without interface restart"
        MSG_CONFIG="Configuration"
        MSG_ERROR_CODE="Error (code: %s)"
    fi
}

main "$@"
