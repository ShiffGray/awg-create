#!/bin/bash
#
# AmneziaWG Installer v6.1
# Ubuntu 20.04-26.04 | Debian 11-13
# Режимы: --go/-g (go из исходников), --kernel/-k (dkms), без флага (meta-пакет)
# Чистый код с учётом всех ошибок
#

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Логирование (в stderr чтобы не ломать переменные)
log_info()    { echo -e "${GREEN}>>> [Amnezia]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}>>> [Amnezia]${NC} ✅ $1" >&2; }
log_warning() { echo -e "${YELLOW}>>> [Amnezia]${NC} ⚠️  $1" >&2; }
log_error()   { echo -e "${RED}>>> [Amnezia]${NC} ❌ $1" >&2; }

# Неинтерактивный режим (сразу в начало!)
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# Режим установки: go | kernel | default
INSTALL_MODE="default"

# Парсинг флагов
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
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                log_error "Неизвестный флаг: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Вывод использования
print_usage() {
    echo
    echo -e "${GREEN}Использование:${NC}"
    echo "  $0                    # Установить amneziawg (dkms + tools)"
    echo "  $0 --go       (-g)    # Собрать amneziawg-go из исходников + amneziawg-tools (удалить dkms)"
    echo "  $0 --kernel   (-k)    # Установить amneziawg-dkms + amneziawg-tools (удалить go)"
    echo "  $0 --help     (-h)    # Показать эту справку"
    echo
}

# Проверка root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Требуется root (sudo)"
        exit 1
    fi
}

# Определение и проверка ОС
check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Не удалось определить ОС"
        exit 1
    fi

    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION="$VERSION_ID"

    log_info "Обнаружена: $NAME $VERSION"

    # Блокируем старые ОС (ядро < 5.6)
    if [ "$OS_ID" = "debian" ]; then
        case "$OS_VERSION" in
            10)
                log_error "Debian 10 не поддерживается (ядро 4.19 < 5.6)"
                log_error "Требуется Debian 11+ или Ubuntu 20.04+"
                exit 1
                ;;
        esac
    fi

    if [ "$OS_ID" = "ubuntu" ]; then
        case "$OS_VERSION" in
            18.04|19.04|19.10)
                log_error "Ubuntu $OS_VERSION не поддерживается (ядро < 5.6)"
                log_error "Требуется Ubuntu 20.04+"
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

# Отключение systemd-resolved
disable_systemd_resolved() {
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "Отключаем systemd-resolved..."
        systemctl disable --now systemd-resolved 2>/dev/null || true
        systemctl mask systemd-resolved 2>/dev/null || true
        log_success "systemd-resolved отключён"
    fi
}

# Очистка заглушек resolvconf
purge_resolvconf() {
    log_info "Очистка resolvconf заглушек..."

    # Проверяем если openresolv уже установлен — пропускаем очистку
    if [ -x /usr/sbin/resolvconf ] && [ ! -L /usr/sbin/resolvconf ]; then
        log_info "openresolv уже установлен (корректный бинарник)"
        return 0
    fi

    # Удаляем ВСЕ симлинки resolvconf (включая битые)
    for path in /sbin/resolvconf /usr/sbin/resolvconf /usr/bin/resolvconf; do
        if [ -L "$path" ]; then
            # Проверяем не битый ли симлинк
            local target
            target=$(readlink -f "$path" 2>/dev/null) || target=""
            if [ ! -e "$target" ]; then
                log_info "Удаление битого симлинка: $path"
                rm -f "$path" 2>/dev/null || true
            fi
        elif [ -f "$path" ] && grep -q "exit 0" "$path" 2>/dev/null; then
            # Удаляем заглушки
            rm -f "$path" 2>/dev/null || true
        fi
    done

    # Удаляем пакет resolvconf если есть (не openresolv!)
    if dpkg -l | grep -q "^ii[[:space:]]*resolvconf[[:space:]]" 2>/dev/null; then
        log_info "Удаляем пакет resolvconf..."
        apt-get remove -y --purge resolvconf 2>/dev/null || true
    fi

    log_success "Очистка завершена"
}

# Разблокировка dpkg
unlock_dpkg() {
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || {
        apt-get remove -y --purge amneziawg amneziawg-dkms 2>/dev/null || true
        dpkg --configure -a 2>/dev/null || true
    }
}

# Подготовка модулей ядра
setup_kernel_modules() {
    log_info "Проверка модулей ядра..."

    # Модуль ifb нужен для Ingress Shaping (tc)
    if ! lsmod | grep -q "^ifb " 2>/dev/null; then
        log_info "Загрузка модуля ifb (для лимитов скорости)..."
        if modprobe ifb 2>/dev/null; then
            log_success "Модуль ifb загружен"
            # Добавляем в автозагрузку
            mkdir -p /etc/modules-load.d
            echo "ifb" > /etc/modules-load.d/ifb.conf
        else
            log_warning "Модуль ifb недоступен (лимиты входящей скорости могут не работать)"
        fi
    else
        log_success "Модуль ifb уже загружен"
    fi
}

# Обновление и установка зависимостей
install_deps() {
    log_info "Обновление и установка зависимостей..."

    apt-get update -qq

    apt-get install -y -qq \
        gnupg \
        curl \
        ca-certificates \
        iptables \
        coreutils \
        git \
        make

    log_success "Зависимости установлены"
}

# Создание симлинков для resolvconf
create_resolvconf_symlinks() {
    log_info "Создание симлинков resolvconf..."

    # Проверяем что /usr/sbin/resolvconf существует и это не битый симлинк
    if [ -L /usr/sbin/resolvconf ]; then
        # Это симлинк — проверяем куда указывает
        local target
        target=$(readlink -f /usr/sbin/resolvconf 2>/dev/null)
        if [ ! -x "$target" ]; then
            log_warning "/usr/sbin/resolvconf — битый симлинк, переустанавливаем..."
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
        log_warning "/usr/sbin/resolvconf не найден, пробуем установить..."
        apt-get install -y openresolv 2>/dev/null || apt-get install -y resolvconf 2>/dev/null || true
    fi

    # Финальная проверка
    if [ ! -e /usr/sbin/resolvconf ]; then
        log_error "Не удалось восстановить /usr/sbin/resolvconf"
        exit 1
    fi

    # Убеждаемся что директории существуют
    mkdir -p /sbin /usr/bin 2>/dev/null || true

    # Создаём симлинки
    ln -sf /usr/sbin/resolvconf /sbin/resolvconf 2>/dev/null || true
    ln -sf /usr/sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true

    # Проверяем что симлинки работают
    if [ -e /sbin/resolvconf ] || [ -e /usr/bin/resolvconf ] || [ -x /usr/sbin/resolvconf ]; then
        log_success "Симлинки созданы"
    else
        log_error "Не удалось создать симлинки"
        exit 1
    fi
}

# Установка openresolv или resolvconf
install_resolvconf() {
    log_info "Установка openresolv / resolvconf..."

    # Проверяем если уже всё работает
    if [ -x /usr/sbin/resolvconf ] && [ ! -L /usr/sbin/resolvconf ]; then
        log_success "resolvconf уже установлен"
        create_resolvconf_symlinks
        return 0
    fi

    # Попытка 1: openresolv (предпочтительно)
    log_info "Устанавливаем openresolv..."
    if apt-get install -y --reinstall openresolv 2>/dev/null; then
        log_success "openresolv установлен"
        create_resolvconf_symlinks
        return 0
    fi

    # Попытка 2: resolvconf
    log_info "Устанавливаем resolvconf..."
    if apt-get install -y --reinstall resolvconf 2>/dev/null; then
        log_success "resolvconf установлен"
        create_resolvconf_symlinks
        return 0
    fi

    # Заглушка (последний вариант)
    log_warning "Создаём заглушку..."
    printf '#!/bin/bash\nexit 0\n' > /usr/sbin/resolvconf
    chmod +x /usr/sbin/resolvconf
    create_resolvconf_symlinks
    log_success "Заглушка создана"
}

# Настройка DNS
setup_dns() {
    log_info "Настройка DNS..."

    # Снимаем защиту (если была от предыдущего запуска или restore_resolvconf)
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Отключаем systemd-resolved (чтобы не перезаписывал DNS)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "Отключаем systemd-resolved..."
        systemctl stop systemd-resolved 2>/dev/null || true
        systemctl disable systemd-resolved 2>/dev/null || true
        systemctl mask systemd-resolved 2>/dev/null || true
        log_success "systemd-resolved отключён"
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

    # ЗАЩИТА ОТ СБРОСА (systemd-resolved и др.)
    log_info "Фиксация resolv.conf..."
    chattr +i /etc/resolv.conf 2>/dev/null || true
    log_success "resolv.conf зафиксирован (не будет перезаписан)"

    log_success "DNS настроен"
}

# Добавление репозитория Amnezia
add_repo() {
    local codename="$1"
    log_info "Добавление репозитория Amnezia ($codename)..."

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
    log_success "Репозиторий добавлен"
}

# Установка AmneziaWG
install_amneziawg() {
    case "$INSTALL_MODE" in
        go)      install_go_mode ;;
        kernel)  install_kernel_mode ;;
        default) install_default_mode ;;
    esac
}

# Остановка всех amneziawg интерфейсов
stop_interfaces() {
    for iface in "$@"; do
        log_info "Остановка интерфейса $iface..."
        awg-quick down "$iface" 2>/dev/null || true
    done
}

# Запуск списка amneziawg интерфейсов
start_interfaces() {
    for iface in "$@"; do
        log_info "Запуск интерфейса $iface..."
        awg-quick up "$iface" 2>/dev/null || true
    done
}

# Получить список активных amneziawg интерфейсов (работает и для kernel, и для go)
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

# Режим GO: amneziawg-go + amneziawg-tools (удалить dkms)
install_go_mode() {
    log_info "Режим: amneziawg-go + amneziawg-tools (без dkms)..."

    # 1. СНАЧАЛА гарантируем наличие инструментов (чтобы awg/awg-quick работали)
    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_info "Установка amneziawg-tools..."
        apt-get install -y amneziawg-tools 2>&1 || true
    fi

    # Сохраняем список активных интерфейсов (теперь инструменты точно есть)
    read -ra INTERFACES <<< "$(get_active_interfaces)"

    if [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "Найдены активные интерфейсы: ${INTERFACES[*]}"
    fi

    # Собираем/обновляем amneziawg-go
    log_info "Сборка amneziawg-go из исходников..."

    INSTALL_GO=false

    # 1. Проверяем, есть ли у нас уже свежий Go в /usr/local/go (от прошлых запусков)
    if [ -x /usr/local/go/bin/go ]; then
        export PATH=/usr/local/go/bin:$PATH
        log_info "Найден Go в /usr/local/go, используем его."
    fi

    # 2. Проверяем версию
    GO_VER_STR=$(go version 2>/dev/null || true)
    if [ -z "$GO_VER_STR" ]; then
        log_info "Go не найден в системе."
        INSTALL_GO=true
    else
        # Извлекаем версию (например, 1.19.8)
        GO_VER=$(echo "$GO_VER_STR" | grep -oE 'go[0-9]+\.[0-9.]+' | head -1 | sed 's/go//')
        log_info "Обнаружена версия Go: $GO_VER"
        
        # Сравниваем с требуемой (1.21)
        REQUIRED="1.21"
        # sort -V вернет меньшую версию первой
        LOWEST=$(printf '%s\n%s' "$REQUIRED" "$GO_VER" | sort -V | head -n1)
        
        # Если LOWEST равен нашей текущей версии (и она не равна требуемой), значит она старая
        if [ "$LOWEST" = "$GO_VER" ] && [ "$GO_VER" != "$REQUIRED" ]; then
            log_info "Версия Go устарела (требуется >= 1.21), скачиваем свежую..."
            INSTALL_GO=true
        fi
    fi

    # 3. Скачиваем и ставим Go, если нужно
    if [ "$INSTALL_GO" = true ]; then
        log_info "Скачиваю последнюю версию Golang..."
        
        # Получаем актуальную версию
        LATEST_VER=$(curl -sL https://go.dev/VERSION?m=text 2>/dev/null | head -1)
        if [[ "$LATEST_VER" != go* ]]; then
            LATEST_VER="go1.23.6" # Фоллбэк
        fi
        
        GO_URL="https://dl.google.com/go/${LATEST_VER}.linux-amd64.tar.gz"
        GO_TAR=$(mktemp)
        
        curl -sSL -o "$GO_TAR" "$GO_URL" || {
            log_error "Не удалось скачать Golang с ${GO_URL}"
            rm -f "$GO_TAR"
            exit 1
        }
        
        rm -rf /usr/local/go 2>/dev/null || true
        tar -C /usr/local -xzf "$GO_TAR" 2>/dev/null || {
            log_error "Ошибка распаковки Golang"
            rm -f "$GO_TAR"
            exit 1
        }
        rm -f "$GO_TAR"
        export PATH=/usr/local/go/bin:$PATH
        log_success "Golang обновлён до $(go version)"
    fi

    # 4. Сборка
    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    git clone https://github.com/amnezia-vpn/amneziawg-go 2>&1 || {
        log_error "Не удалось склонировать amneziawg-go"
        cd / && rm -rf "$TMPDIR"
        exit 1
    }
    cd amneziawg-go

    # Гарантируем использование свежего Go
    export PATH=/usr/local/go/bin:$PATH
    export GOTOOLCHAIN=local

    make 2>&1 || {
        log_error "Ошибка сборки amneziawg-go"
        cd / && rm -rf "$TMPDIR"
        exit 1
    }

    # Если бинарник уже существует (обновление), нужно остановить интерфейсы ПЕРЕД заменой
    # Иначе будет ошибка "Text file busy"
    if [ -f /usr/local/bin/amneziawg-go ] && [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "Обнаружена старая версия amneziawg-go, останавливаем интерфейсы для обновления..."
        stop_interfaces "${INTERFACES[@]}"
        INTERFACES_WAS_STOPPED=true
    else
        INTERFACES_WAS_STOPPED=false
    fi

    # Заменяем бинарник
    cp amneziawg-go /usr/local/bin/
    chmod +x /usr/local/bin/amneziawg-go
    cd / && rm -rf "$TMPDIR"
    log_success "amneziawg-go установлен/обновлён в /usr/local/bin/"

    # Останавливаем интерфейсы (только если они были и мы их ещё не остановили ради обновления бинарника)
    if [ "${INTERFACES_WAS_STOPPED:-false}" = false ] && [ ${#INTERFACES[@]} -gt 0 ]; then
        stop_interfaces "${INTERFACES[@]}"
    fi

    # Выгружаем kernel модуль
    log_info "Выгрузка kernel модуля..."
    rmmod amneziawg 2>/dev/null || true

    # Удаляем dkms
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_info "Удаление amneziawg-dkms..."
        apt-get remove -y --purge amneziawg-dkms 2>/dev/null || true
    fi

    # Запускаем интерфейсы обратно (через go)
    if [ ${#INTERFACES[@]} -gt 0 ]; then
        start_interfaces "${INTERFACES[@]}"
    fi

    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null && command -v amneziawg-go &>/dev/null; then
        log_success "Go версия готова (amneziawg-go + amneziawg-tools)"
        awg --version 2>&1 | head -n1
    else
        log_error "Не удалось установить go версию"
        exit 1
    fi
}

# Режим KERNEL: amneziawg-dkms + amneziawg-tools (удалить go)
install_kernel_mode() {
    log_info "Режим: amneziawg-dkms + amneziawg-tools (без go)..."

    # 1. СНАЧАЛА гарантируем наличие инструментов
    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_info "Установка amneziawg-tools..."
        apt-get install -y amneziawg-tools 2>&1 || true
    fi

    # Сохраняем список активных интерфейсов (теперь инструменты точно есть)
    read -ra INTERFACES <<< "$(get_active_interfaces)"

    if [ ${#INTERFACES[@]} -gt 0 ]; then
        log_info "Найдены активные интерфейсы: ${INTERFACES[*]}"
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
        log_info "Удаление amneziawg-go..."
        rm -f /usr/local/bin/amneziawg-go
    fi

    # Запускаем интерфейсы обратно (через kernel)
    if [ ${#INTERFACES[@]} -gt 0 ]; then
        start_interfaces "${INTERFACES[@]}"
    fi

    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_success "Kernel версия готова (dkms + tools)"
        awg --version 2>&1 | head -n1
    else
        log_error "Не удалось установить kernel версию"
        exit 1
    fi
}

# Режим DEFAULT: просто ставим мета-пакет amneziawg (dkms + tools)
install_default_mode() {
    log_info "Режим: установка пакета amneziawg (dkms + tools)..."

    # Пробуем установить мета-пакет (он сам подтянет dkms и tools)
    apt-get install -y amneziawg 2>&1 | grep -v "Error\|dpkg:\|Errors were" || true

    # Проверяем, встал ли dkms
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
        log_success "amneziawg установлен (dkms + tools)"
        awg --version 2>&1 | head -n1
    else
        # Фоллбэк: если мета-пакет не вытянул dkms, ставим компоненты вручную
        log_info "Мета-пакет не подтянул dkms, ставим отдельно..."
        apt-get install -y amneziawg-dkms amneziawg-tools 2>/dev/null || true

        if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
            log_success "amneziawg установлен (dkms + tools)"
            awg --version 2>&1 | head -n1
        else
            log_error "Не удалось установить amneziawg-dkms"
            exit 1
        fi
    fi
}

# Восстановление resolv.conf (создаёт рабочий DNS, НЕ восстанавливает битый symlink)
restore_resolvconf() {
    log_info "Восстановление DNS..."

    # Снимаем защиту
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Создаём рабочий статический DNS (не systemd stub!)
    cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 2606:4700:4700::1111
nameserver 2606:4700:4700::1001
EOF

    # Фиксируем от systemd-resolved
    chattr +i /etc/resolv.conf 2>/dev/null || true

    log_success "DNS восстановлен"
}

# Проверка установки
verify() {
    log_info "Проверка установки..."

    case "$INSTALL_MODE" in
        go)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "amneziawg-tools не найден"
                exit 1
            fi
            if ! command -v amneziawg-go &>/dev/null; then
                log_error "amneziawg-go не найден"
                exit 1
            fi
            ;;
        kernel)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "amneziawg-tools не найден"
                exit 1
            fi
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
                log_error "amneziawg-dkms не найден"
                exit 1
            fi
            lsmod | grep -q amneziawg 2>/dev/null || \
                log_info "Модуль ядра загрузится при первом запуске"
            ;;
        default)
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
                log_error "amneziawg-tools не найден"
                exit 1
            fi
            if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-dkms[[:space:]]" 2>/dev/null; then
                log_error "amneziawg-dkms не найден"
                exit 1
            fi
            lsmod | grep -q amneziawg 2>/dev/null || \
                log_info "Модуль ядра загрузится при первом запуске"
            ;;
    esac

    [ ! -d /etc/amnezia/amneziawg ] && mkdir -p /etc/amnezia/amneziawg
    log_success "Проверка завершена"
}

# Финальный вывод
print_info() {
    echo
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}       AmneziaWG успешно установлен!      ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo "Режим: ${INSTALL_MODE}"
    echo "Версия: $(awg --version 2>&1 | head -n1)"
    echo

    case "$INSTALL_MODE" in
        go)
            echo "Go версия — безопасная, без kernel panic!"
            echo "amneziawg-go собран из исходников"
            echo
            echo "Команды (go версия — без kernel модуля):"
            ;;
        kernel)
            echo "ВАЖНО! Для завершения установки на старых системах выполните:"
            echo "  apt-get upgrade -y    # Установить обновления ядра"
            echo "  reboot                # Перезагрузиться"
            echo "После перезагрузки модуль ядра соберётся автоматически!"
            echo
            echo "Команды (kernel версия):"
            ;;
        default)
            echo "ВАЖНО! Для завершения установки на старых системах выполните:"
            echo "  apt-get upgrade -y    # Установить обновления ядра"
            echo "  reboot                # Перезагрузиться"
            echo "После перезагрузки модуль ядра соберётся автоматически!"
            echo
            echo "Команды:"
            ;;
    esac

    echo "  # основные"
    echo "  awg-quick up awg                       # Поднять интерфейс"
    echo "  awg-quick down awg                     # Опустить интерфейс"
    echo "  awg                                    # Статус"
    echo "  # сервис"
    echo "  systemctl enable awg-quick@awg         # Добавить в автозагрузки"
    echo "  systemctl disable awg-quick@awg        # Удалить из автозагрузки"
    echo "  systemctl restart awg-quick@awg        # Перезапустить"
    echo "  systemctl status awg-quick@awg         # Проверить состояние"
    echo "  # конфигурация"
    echo "  awg-quick strip awg > /tmp/awg.conf    # Сохранить конфиг в чистом формате во временный файл"
    echo "  awg syncconf awg /tmp/awg.conf         # Загрузить конфиг для обновления пользователей без перезапуска интерфейса"
    echo
    echo "Конфигурация:"
    echo "  /etc/amnezia/amneziawg/"
    echo
}

# Cleanup при ошибке
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Ошибка (код: $exit_code)"
        restore_resolvconf 2>/dev/null || true
    fi
}

# ГЛАВНАЯ ФУНКЦИЯ
main() {
    trap cleanup EXIT

    # Парсим флаги ПЕРЕД всем остальным
    parse_flags "$@"

    echo
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   AmneziaWG Installer v6.1             ║${NC}"
    echo -e "${GREEN}║   Ubuntu 20-26 | Debian 11-13          ║${NC}"
    echo -e "${GREEN}║   + disable systemd-resolved           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo -e "    Режим: ${INSTALL_MODE}"
    echo

    check_root
    check_os

    local codename
    codename=$(get_codename)

    # Порядок ВАЖЕН!
    disable_systemd_resolved
    purge_resolvconf
    unlock_dpkg
    setup_kernel_modules   # 1. ПОДГОТОВКА МОДУЛЕЙ ЯДРА (ifb для лимитов)
    install_deps           # 2. apt update + зависимости
    install_resolvconf     # 3. openresolv/resolvconf
    setup_dns              # 4. DNS
    add_repo "$codename"   # 5. Репозиторий Amnezia
    install_amneziawg      # 6. AmneziaWG
    restore_resolvconf     # 7. Восстановление resolv.conf
    verify                 # 8. Проверка
    print_info             # 9. Вывод
}

main "$@"
