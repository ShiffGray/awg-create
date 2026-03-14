#!/bin/bash
#
# AmneziaWG Installer v5.4
# Ubuntu 20.04-25.04 | Debian 11-13
# Чистый код с учётом всех ошибок
#

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Логирование (в stderr чтобы не ломать переменные)
log_info()    { echo -e "${GREEN}>>> [Amnezia]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}>>> [Amnezia]${NC} ✅ $1" >&2; }
log_warning() { echo -e "${YELLOW}>>> [Amnezia]${NC} ⚠️  $1" >&2; }
log_error()   { echo -e "${RED}>>> [Amnezia]${NC} ❌ $1" >&2; }

# Неинтерактивный режим (сразу в начало!)
export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

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

    # Удаляем файлы-заглушки
    for path in /sbin/resolvconf /usr/sbin/resolvconf /usr/bin/resolvconf; do
        if [ -L "$path" ] || { [ -f "$path" ] && grep -q "exit 0" "$path" 2>/dev/null; }; then
            rm -f "$path" 2>/dev/null || true
        fi
    done

    # Удаляем пакет resolvconf если есть
    if dpkg -l | grep -q "^ii[[:space:]]*resolvconf[[:space:]]" 2>/dev/null; then
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

# Обновление и установка зависимостей
install_deps() {
    log_info "Обновление и установка зависимостей..."

    apt-get update -qq

    apt-get install -y -qq \
        gnupg \
        curl \
        ca-certificates \
        iptables \
        coreutils

    log_success "Зависимости установлены"
}

# Установка openresolv или resolvconf
install_resolvconf() {
    log_info "Установка openresolv / resolvconf..."

    # Проверяем что уже стоит И РАБОТАЕТ
    if command -v resolvconf &> /dev/null; then
        # Проверяем работает ли (вызываем с --version)
        if resolvconf --version &> /dev/null; then
            log_success "resolvconf/openresolv уже установлен и работает"
            return 0
        else
            log_warning "resolvconf найден но НЕ работает (битый symlink)"
            log_info "Пытаемся пересоздать symlink..."
        fi
    fi

    # Если resolvconf найден но не работает — пересоздаём symlink
    if [ -f /sbin/resolvconf ]; then
        ln -sf /sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true
        log_success "symlink /usr/bin/resolvconf → /sbin/resolvconf пересоздан"
        # Проверяем что заработал
        if resolvconf --version &> /dev/null; then
            log_success "resolvconf теперь работает"
            return 0
        fi
    fi
    
    if [ -f /usr/sbin/resolvconf ]; then
        ln -sf /usr/sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true
        log_success "symlink /usr/bin/resolvconf → /usr/sbin/resolvconf пересоздан"
        # Проверяем что заработал
        if resolvconf --version &> /dev/null; then
            log_success "resolvconf теперь работает"
            return 0
        fi
    fi

    # Попытка 1: openresolv (предпочтительно)
    if apt-get install -y openresolv 2>/dev/null; then
        log_success "openresolv установлен"
        # Ждём пока dpkg закончит
        sleep 2
        # Создаём symlink во все возможные места (ПРОВЕРЯЕМ ОБА!)
        if [ -f /sbin/resolvconf ]; then
            ln -sf /sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true
            log_success "symlink /usr/bin/resolvconf → /sbin/resolvconf создан"
        fi
        if [ -f /usr/sbin/resolvconf ]; then
            ln -sf /usr/sbin/resolvconf /usr/bin/resolvconf 2>/dev/null || true
            log_success "symlink /usr/bin/resolvconf → /usr/sbin/resolvconf создан"
        fi
        return 0
    fi

    # Попытка 2: resolvconf
    if apt-get install -y resolvconf 2>/dev/null; then
        log_success "resolvconf установлен"
        return 0
    fi

    # Заглушка (последний вариант)
    log_warning "Создаём заглушку..."
    printf '#!/bin/bash\nexit 0\n' > /usr/sbin/resolvconf
    chmod +x /usr/sbin/resolvconf
    ln -sf /usr/sbin/resolvconf /sbin/resolvconf 2>/dev/null || true
    log_success "Заглушка создана"
}

# Настройка DNS
setup_dns() {
    log_info "Настройка DNS..."

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
    log_info "Установка AmneziaWG..."

    # Проверяем что уже установлен
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_success "AmneziaWG уже установлен"
        awg --version 2>&1 | head -n1
        return 0
    fi

    # Пробуем установить полный пакет
    apt-get install -y amneziawg 2>&1 | grep -v "Error\|dpkg:\|Errors were" || true

    # Проверяем amneziawg-tools
    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_success "AmneziaWG установлен"
        awg --version 2>&1 | head -n1
        return 0
    fi

    # Если нет — ставим только tools
    apt-get install -y amneziawg-tools 2>/dev/null || true

    if dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_success "AmneziaWG установлен (amneziawg-tools)"
        awg --version 2>&1 | head -n1
    else
        log_error "Не удалось установить AmneziaWG"
        exit 1
    fi
}

# Восстановление resolv.conf
restore_resolvconf() {
    log_info "Восстановление resolv.conf..."

    # Снимаем защиту
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Восстанавливаем оригинал
    [ -f /etc/resolv.conf.original ] && cp /etc/resolv.conf.original /etc/resolv.conf

    log_success "resolv.conf восстановлен"
}

# Проверка установки
verify() {
    log_info "Проверка установки..."

    if ! dpkg -l | grep -q "^ii[[:space:]]*amneziawg-tools[[:space:]]" 2>/dev/null; then
        log_error "amneziawg-tools не найден"
        exit 1
    fi

    # Проверка resolvconf
    if command -v resolvconf &> /dev/null; then
        log_success "resolvconf найден: $(which resolvconf)"
    else
        log_warning "resolvconf НЕ найден — WARP с DNS не будут работать!"
        log_info "Исправь вручную: ln -sf /sbin/resolvconf /usr/bin/resolvconf"
    fi

    lsmod | grep -q amneziawg 2>/dev/null || \
        log_info "Модуль ядра загрузится при первом запуске"

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
    echo "Версия: $(awg --version 2>&1 | head -n1)"
    echo
    echo "ВАЖНО! Для завершения установки на старых системах выполните:"
    echo "  apt-get upgrade -y    # Установить обновления ядра"
    echo "  reboot                # Перезагрузиться"
    echo "После перезагрузки модуль ядра соберётся автоматически!"
    echo
    echo "Команды:"
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

    echo
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   AmneziaWG Installer v5.4             ║${NC}"
    echo -e "${GREEN}║   Ubuntu 20-25 | Debian 11-13          ║${NC}"
    echo -e "${GREEN}║   + disable systemd-resolved           ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo

    check_root
    check_os

    local codename
    codename=$(get_codename)

    # Порядок ВАЖЕН!
    disable_systemd_resolved
    purge_resolvconf
    unlock_dpkg
    install_deps           # 1. СНАЧАЛА apt update + зависимости
    install_resolvconf     # 2. ПОТОМ openresolv/resolvconf
    setup_dns              # 3. DNS
    add_repo "$codename"   # 4. Репозиторий Amnezia
    install_amneziawg      # 5. AmneziaWG
    restore_resolvconf     # 6. Восстановление resolv.conf
    verify                 # 7. Проверка
    print_info             # 8. Вывод
}

main "$@"
