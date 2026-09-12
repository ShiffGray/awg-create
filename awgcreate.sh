#!/bin/bash
#
# awgcreate Setup v7.0
# AmneziaWG + awgcreate: полный набор зависимостей
# (Go-сайдкары, Python-библиотеки, ipset, QR/PNG, aioquic)
#

set -e

export DEBIAN_FRONTEND=noninteractive
export DEBCONF_NONINTERACTIVE_SEEN=true

# ─── Проверка root ─────────────────────────────────
check_root() { if [ "$EUID" -ne 0 ]; then log_error "$MSG_ROOT_REQUIRED"; exit 1; fi; }

# ─── Установка AmneziaWG ───────────────────────────
install_amneziawg() {
    log_info "$MSG_INSTALL_AMNEZIAWG"
    bash <(curl -sSL https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/AmneziaWG.sh) -k
}

# ─── Установка Go (нужен для Go-сайдкаров на лету: awg-imitat, awg-probe) ──
# Паттерн как в AmneziaWG.sh: переиспользуем /usr/local/go, иначе скачиваем. Go НЕ удаляется.
install_go() {
    log_info "$MSG_INSTALL_GO"
    INSTALL_GO=false

    # 1. Проверяем, есть ли уже свежий Go в /usr/local/go (от прошлых запусков)
    if [ -x /usr/local/go/bin/go ]; then
        export PATH=/usr/local/go/bin:$PATH
        log_info "$MSG_GO_FOUND"
    fi

    # 2. Проверяем версию (uTLS v1.8.2 требует Go >= 1.24)
    GO_VER_STR=$(go version 2>/dev/null || true)
    if [ -z "$GO_VER_STR" ]; then
        log_info "$MSG_GO_NOT_FOUND"
        INSTALL_GO=true
    else
        # Извлекаем версию (например, 1.24.3)
        GO_VER=$(echo "$GO_VER_STR" | grep -oE 'go[0-9]+\.[0-9.]+' | head -1 | sed 's/go//')
        log_info "$MSG_GO_VER" "$GO_VER"

        # Сравниваем с требуемой (1.24)
        REQUIRED="1.24"
        # sort -V вернет меньшую версию первой
        LOWEST=$(printf '%s\n%s' "$REQUIRED" "$GO_VER" | sort -V | head -n1)

        # Если LOWEST равен нашей текущей версии (и она не равна требуемой), значит она старая
        if [ "$LOWEST" = "$GO_VER" ] && [ "$GO_VER" != "$REQUIRED" ]; then
            log_info "$MSG_GO_OLD"
            INSTALL_GO=true
        fi
    fi

    # 3. Скачиваем и ставим Go, если нужно (архив по архитектуре: amd64/arm64)
    if [ "$INSTALL_GO" = true ]; then
        log_info "$MSG_GO_DOWNLOAD"
        LATEST_VER=$(curl -sL https://go.dev/VERSION?m=text 2>/dev/null | head -1)
        if [[ "$LATEST_VER" != go* ]]; then
            LATEST_VER="go1.24.0" # Фоллбэк
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
        log_success "$MSG_GO_INSTALLED" "$(go version)"
    fi

    # Персистентный PATH для НОВЫХ сессий (фикс 16.09.2026): раньше export
    # жил только внутри процесса скрипта, и в свежем shell `go` был не виден
    # (awgcreate.py: "WARP-probe не собран: Go не найден" при работающем Go).
    if [ ! -f /etc/profile.d/zz-awgcreate-go.sh ]; then
        printf 'export PATH=/usr/local/go/bin:$PATH\n' > /etc/profile.d/zz-awgcreate-go.sh
    fi
}

# ─── Установка Python зависимостей (полный набор) ──
install_python_deps() {
    log_info "$MSG_INSTALL_PYDEPS"
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip ipset python3-qrcode python3-pil \
        python3-requests python3-cryptography python3-socks tor
    # tor — для --proxy tor (обход rate-limit Cloudflare через SOCKS);
    # смена выходного IP: systemctl restart tor@default. python3-socks —
    # обязателен для SOCKS-прокси в requests (без него — SOCKS support missing).

    # aioquic (уровень 2 QUIC: реальный TLS 1.3 стек) — опционально, через pip
    if command -v python3 >/dev/null 2>&1; then
        python3 -m pip install -q --break-system-packages aioquic 2>/dev/null \
            || python3 -m pip install -q aioquic 2>/dev/null \
            || log_warning "$MSG_AIOQUIC_WARN"
    fi
}

# ─── Загрузка awgcreate.py ─────────────────────────
fetch_awgcreate() {
    log_info "$MSG_FETCH_AWGCREATE"
    mkdir -p ~/awg && cd ~/awg

    curl -sSL -o awgcreate.py https://raw.githubusercontent.com/ShiffGray/awg-create/refs/heads/main/awgcreate.py

    # Проверка что файл не пустой
    if [ ! -s awgcreate.py ]; then
        log_error "$MSG_FETCH_FAIL"
        exit 1
    fi

    chmod +x awgcreate.py
    log_success "$MSG_FETCH_DONE"
}

# ─── Проверка ──────────────────────────────────────
verify() {
    log_info "$MSG_VERIFY"
    if command -v awg &>/dev/null && command -v ipset &>/dev/null && [ -f awgcreate.py ]; then
        log_success "$MSG_ALL_OK"
        echo
        printf "%s:\n" "$MSG_NEXT_STEPS"
        echo "  cd ~/awg"
        echo "  python3 awgcreate.py --make awg0 -i 10.1.0.1/24 -p 51820"
        echo "  awg-quick up awg0"
    else
        log_error "$MSG_SOMETHING_WRONG"
        exit 1
    fi
}

# ─── Главная ──────────────────────────────────────
main() {
    init_lang
    check_root

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║    AmneziaWG + awgcreate Setup v7.0    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""

    install_amneziawg
    install_go
    install_python_deps
    fetch_awgcreate
    verify
}

# ─── Оформление вывода ─────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()    { printf "${GREEN}>>> [AWG]${NC} $1\n" "${@:2}" >&2; }
log_success() { printf "${GREEN}>>> [AWG]${NC} ✅ $1\n" "${@:2}" >&2; }
log_warning() { printf "${YELLOW}>>> [AWG]${NC} ⚠️  $1\n" "${@:2}" >&2; }
log_error()   { printf "${RED}>>> [AWG]${NC} ❌ $1\n" "${@:2}" >&2; }

# ─── Локализация ───────────────────────────────────
init_lang() {
    if [[ "$LANG" == ru_RU* ]]; then
        MSG_ROOT_REQUIRED="Требуется root (sudo)"
        MSG_INSTALL_AMNEZIAWG="Установка AmneziaWG (kernel-режим)..."
        MSG_INSTALL_GO="Установка Go (для Go-сайдкаров)..."
        MSG_GO_FOUND="Найден Go в /usr/local/go, используем его."
        MSG_GO_NOT_FOUND="Go не найден в системе."
        MSG_GO_VER="Обнаружена версия Go: %s"
        MSG_GO_OLD="Версия Go устарела (требуется >= 1.24), скачиваем свежую..."
        MSG_GO_DOWNLOAD="Скачиваю последнюю версию Golang..."
        MSG_GO_DL_FAIL="Не удалось скачать Go с %s"
        MSG_GO_EXTRACT_FAIL="Ошибка распаковки Go"
        MSG_GO_INSTALLED="Go установлен: %s"
        MSG_INSTALL_PYDEPS="Установка Python зависимостей..."
        MSG_AIOQUIC_WARN="aioquic не установился — будет использован рукописный QUIC-фоллбэк"
        MSG_FETCH_AWGCREATE="Загрузка awgcreate.py..."
        MSG_FETCH_FAIL="Ошибка загрузки awgcreate.py!"
        MSG_FETCH_DONE="awgcreate.py загружен!"
        MSG_VERIFY="Проверка..."
        MSG_ALL_OK="Всё установлено!"
        MSG_NEXT_STEPS="Следующие шаги"
        MSG_SOMETHING_WRONG="Что-то пошло не так!"
    else
        MSG_ROOT_REQUIRED="Root required (sudo)"
        MSG_INSTALL_AMNEZIAWG="Installing AmneziaWG (kernel mode)..."
        MSG_INSTALL_GO="Installing Go (for Go sidecars)..."
        MSG_GO_FOUND="Go found in /usr/local/go, using it."
        MSG_GO_NOT_FOUND="Go not found in the system."
        MSG_GO_VER="Detected Go version: %s"
        MSG_GO_OLD="Go version is outdated (required >= 1.24), downloading fresh..."
        MSG_GO_DOWNLOAD="Downloading latest Golang..."
        MSG_GO_DL_FAIL="Failed to download Go from %s"
        MSG_GO_EXTRACT_FAIL="Failed to extract Go"
        MSG_GO_INSTALLED="Go installed: %s"
        MSG_INSTALL_PYDEPS="Installing Python dependencies..."
        MSG_AIOQUIC_WARN="aioquic failed to install — handcrafted QUIC fallback will be used"
        MSG_FETCH_AWGCREATE="Downloading awgcreate.py..."
        MSG_FETCH_FAIL="Failed to download awgcreate.py!"
        MSG_FETCH_DONE="awgcreate.py downloaded!"
        MSG_VERIFY="Verifying..."
        MSG_ALL_OK="Everything installed!"
        MSG_NEXT_STEPS="Next steps"
        MSG_SOMETHING_WRONG="Something went wrong!"
    fi
}

main "$@"
