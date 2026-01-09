#!/bin/bash
set -e

echo "========================================="
echo "Flashing TinyGo Skywallet Firmware v2"
echo "========================================="
echo ""
echo "Fixed: Stack pointer now at 0x20020000"
echo ""

if [ ! -f "skyfirmware-tinygo.bin" ]; then
    echo "Error: skyfirmware-tinygo.bin not found!"
    exit 1
fi

echo "Firmware size: $(ls -lh skyfirmware-tinygo.bin | awk '{print $5}')"
echo ""
echo "Flashing..."

curl -X PUT http://127.0.0.1:9510/api/v1/firmware_update -F "file=@skyfirmware-tinygo.bin"

echo ""
sleep 5

echo "Checking enumeration..."
if lsusb | grep -q "313a:0001"; then
    echo "✅ Device enumerated!"
    lsusb | grep "313a:0001"
else
    echo "❌ Device NOT enumerating"
    exit 1
fi

echo ""
echo "Testing communication..."
if timeout 5 skyhw cli features; then
    echo "✅✅✅ SUCCESS!"
else
    echo "❌ Enumerated but no response"
fi
