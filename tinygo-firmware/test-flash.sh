#!/bin/bash
# Test script for TinyGo firmware flashing and testing

DAEMON_CMD="/home/d0mo/go/bin/skyhw daemon"
FIRMWARE="skyfirmware-tinygo.bin"
API_URL="http://127.0.0.1:9510/api/v1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/.daemon.pid"
LOG_FILE="$SCRIPT_DIR/.daemon.log"
cd "$SCRIPT_DIR"

# Build firmware
build() {
    echo "Building firmware..."
    rm -f skyfirmware-tinygo.bin skyfirmware-tinygo.elf temp.bin
    tinygo build -o skyfirmware-tinygo.elf -target=./stm32f205.json -opt=z -gc=leaking -scheduler=none . || exit 1
    arm-none-eabi-objcopy -O binary skyfirmware-tinygo.elf temp.bin
    # Sign (script handles padding internally)
    ../tiny-firmware/bootloader/firmware_sign.py -f temp.bin \
        -pk 03d7fe879bea92c657797881cc2437fea86337ed4dce19859f43d023c1772c81dd \
        02ce15278b4d1cf5c20a2a518b95438bc1d497b1d55bddf69dbb253b538c131625 \
        02bebd3856b3fdadc54714220819946980d413edc8bc49f679b88fd2bf99ae0e15 \
        02015aa7da6acb423266a50db8821b42493cd2d874911c309209a003a1051c5d74 \
        03579beeeb075dcd20c63cbd3851ff0c81b1448c4f28597ce28924344a3f4bdbd4 -a >/dev/null
    mv temp.bin skyfirmware-tinygo.bin
    echo "Build complete: $(ls -lh skyfirmware-tinygo.bin | awk '{print $5}')"
}

# Check if daemon is running via API
check_daemon_api() {
    curl -s "$API_URL/available" >/dev/null 2>&1
}

# Check if daemon PID is valid and running
check_daemon_pid() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Stop daemon by PID
stop_daemon() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping daemon (PID $pid)..."
            kill "$pid" 2>/dev/null
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                echo "Daemon still running, sending SIGKILL..."
                kill -9 "$pid" 2>/dev/null
                sleep 1
            fi
        fi
        rm -f "$PID_FILE"
    fi
    echo "Daemon stopped"
}

# Start daemon in background
start_daemon() {
    # Stop any existing daemon first
    if check_daemon_pid; then
        stop_daemon
    fi

    echo "Starting daemon..."
    # Truncate log file and write header with timestamp
    echo "=== Daemon started at $(date) ===" > "$LOG_FILE"

    # Start daemon and capture PID
    $DAEMON_CMD >> "$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"

    sleep 2
    if check_daemon_api; then
        echo "Daemon started (PID $pid)"
    else
        echo "Failed to start daemon (check $LOG_FILE)"
        exit 1
    fi
}

# Restart daemon
restart_daemon() {
    stop_daemon
    start_daemon
}

# Ensure daemon is running
ensure_daemon() {
    if ! check_daemon_api; then
        start_daemon
    fi
}

# Check device mode
check_mode() {
    timeout 5 skyhw cli features 2>&1 | grep -q '"bootloader_mode":true'
    if [ $? -eq 0 ]; then
        echo "bootloader"
    else
        echo "firmware"
    fi
}

# Flash firmware
flash() {
    ensure_daemon
    echo "Flashing $FIRMWARE..."
    curl -X PUT "$API_URL/firmware_update" -F "file=@$FIRMWARE" 2>&1
    sleep 3
}

# Generate mnemonic
gen_mnemonic() {
    ensure_daemon
    echo "Generating mnemonic..."
    skyhw cli generateMnemonic --wordCount=12 2>&1
}

# Test address generation
test_address() {
    ensure_daemon
    echo "Testing addressGen..."
    timeout 120 skyhw cli addressGen --addressN=1 2>&1
}

# Get device features
get_features() {
    ensure_daemon
    echo "Getting features..."
    timeout 10 skyhw cli features 2>&1
}

# Send ping message
ping() {
    ensure_daemon
    local msg="${2:-hello}"
    echo "Pinging with: $msg"
    timeout 10 skyhw cli ping "$msg" 2>&1
}

# Run crypto tests via ping
test_crypto() {
    ensure_daemon
    echo "Running crypto tests..."
    echo ""
    echo "=== SHA256 test ==="
    timeout 10 skyhw cli ping "TEST:SHA256" 2>&1
    echo ""
    echo "=== RIPEMD160 test ==="
    timeout 10 skyhw cli ping "TEST:RIPEMD" 2>&1
    echo ""
    echo "=== Base58 test ==="
    timeout 10 skyhw cli ping "TEST:B58" 2>&1
    echo ""
    echo "=== Square test ==="
    timeout 10 skyhw cli ping "TEST:SQR" 2>&1
    echo ""
    echo "=== Multiply test ==="
    timeout 10 skyhw cli ping "TEST:MUL" 2>&1
    echo ""
    echo "=== Generator point ==="
    timeout 10 skyhw cli ping "TEST:GPOINT" 2>&1
    echo ""
    echo "=== ECmult test ==="
    timeout 10 skyhw cli ping "TEST:ECMULT" 2>&1
    echo ""
    echo "=== Pubkey1 test ==="
    timeout 10 skyhw cli ping "TEST:PUBKEY1" 2>&1
    echo ""
    echo "=== Pubkey2 test ==="
    timeout 10 skyhw cli ping "TEST:PUBKEY2" 2>&1
    echo ""
    echo "=== Address test ==="
    timeout 120 skyhw cli ping "TEST:ADDR" 2>&1
}

# View daemon log
view_log() {
    if [ -f "$LOG_FILE" ]; then
        cat "$LOG_FILE"
    else
        echo "No log file found"
    fi
}

# Full test cycle
full_test() {
    MODE=$(check_mode)
    echo "Device mode: $MODE"

    if [ "$MODE" = "bootloader" ]; then
        flash
        sleep 2
    fi

    MODE=$(check_mode)
    if [ "$MODE" = "firmware" ]; then
        gen_mnemonic
        sleep 1
        test_address
    else
        echo "Device still in bootloader mode after flash"
    fi
}

# Build and test cycle
build_and_test() {
    build
    full_test
}

# Command dispatcher
case "${1:-full}" in
    build) build ;;
    daemon) ensure_daemon ;;
    stop) stop_daemon ;;
    restart) restart_daemon ;;
    mode) check_mode ;;
    flash) flash ;;
    mnemonic) gen_mnemonic ;;
    address) test_address ;;
    features) get_features ;;
    ping) ping "$@" ;;
    crypto) test_crypto ;;
    log) view_log ;;
    full) full_test ;;
    all) build_and_test ;;
    *) echo "Usage: $0 {build|daemon|stop|restart|mode|flash|mnemonic|address|features|ping|crypto|log|full|all}" ;;
esac
