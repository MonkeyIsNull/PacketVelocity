#!/bin/bash

# PacketVelocity Capture Script with VFLisp Filtering
# Usage: sudo ./pcv.sh <interface> "<vflisp-expression>" [packet-count]
# Example: sudo ./pcv.sh en0 "(= src-ip6 ::1)" 20

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect if components are installed in /usr/local or running from source
if [[ -x "/usr/local/bin/packetvelocity" ]]; then
    # Installed system-wide
    PV_BINARY="/usr/local/bin/packetvelocity"
    VFLISP_COMPILER="/usr/local/bin/vflispc"
    VFM_DIS="/usr/local/bin/vfm-dis"
    echo "Using installed PacketVelocity from /usr/local"
elif [[ -x "$SCRIPT_DIR/packetvelocity" ]]; then
    # Running from source directory
    PV_BINARY="$SCRIPT_DIR/packetvelocity"
    VFM_DIR="$SCRIPT_DIR/../VelocityFilterMachine"
    VFLISP_COMPILER="$VFM_DIR/dsl/vflisp/vflispc"
    VFM_DIS="$VFM_DIR/tools/vfm-dis"
    echo "Using PacketVelocity from source directory"
else
    echo "Error: PacketVelocity not found in /usr/local/bin or current directory"
    echo "Please install PacketVelocity or run from source directory"
    exit 1
fi

# Default values
INTERFACE=""
EXPRESSION=""
PACKET_COUNT="10"

# Function to display usage
usage() {
    echo "PacketVelocity - High-Performance IPv4/IPv6 Packet Capture"
    echo ""
    echo "Usage: sudo $0 <interface> \"<vflisp-expression>\" [packet-count]"
    echo ""
    echo "Arguments:"
    echo "  interface         Network interface to capture from (e.g., en0, eth0)"
    echo "  vflisp-expression VFLisp filter expression in quotes"
    echo "  packet-count      Number of packets to capture (default: 10)"
    echo ""
    echo "IPv4 Examples:"
    echo "  sudo $0 en0 \"(= proto 6)\"                    # TCP traffic"
    echo "  sudo $0 en0 \"(= dst-port 443)\"               # HTTPS traffic"
    echo "  sudo $0 en0 \"(and (= proto 6) (= dst-port 80))\" # HTTP traffic"
    echo ""
    echo "IPv6 Examples:"
    echo "  sudo $0 en0 \"(= ip-version 6)\"               # All IPv6 traffic"
    echo "  sudo $0 en0 \"(= src-ip6 ::1)\"                # IPv6 loopback source"
    echo "  sudo $0 en0 \"(= dst-ip6 2001:db8::1)\"        # Specific IPv6 destination"
    echo "  sudo $0 en0 \"(and (= proto 6) (!= dst-ip6 ::))\" # IPv6 TCP non-null destination"
    echo ""
    echo "Mixed IPv4/IPv6 Examples:"
    echo "  sudo $0 en0 \"(or (= src-port 80) (= dst-port 80))\" # HTTP on either IP version"
    echo "  sudo $0 en0 \"(and (= ip-version 6) (= proto 17))\"   # IPv6 UDP traffic"
    echo ""
    echo "Field Reference:"
    echo "  IPv4 Fields:    src-ip4, dst-ip4, proto, src-port, dst-port"
    echo "  IPv6 Fields:    src-ip6, dst-ip6, proto, src-port, dst-port"
    echo "  Common Fields:  ip-version, ethertype"
    echo ""
    echo "Note: Requires root privileges for packet capture"
    exit 1
}

# Check for help
if [[ "$1" == "-h" || "$1" == "--help" || $# -lt 2 ]]; then
    usage
fi

# Parse arguments
INTERFACE="$1"
EXPRESSION="$2"
if [[ -n "$3" ]]; then
    PACKET_COUNT="$3"
fi

# Validate interface
if [[ -z "$INTERFACE" ]]; then
    echo "Error: Interface is required"
    usage
fi

# Validate expression
if [[ -z "$EXPRESSION" ]]; then
    echo "Error: VFLisp expression is required"
    usage
fi

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root for packet capture"
    echo "Usage: sudo $0 $INTERFACE \"$EXPRESSION\" $PACKET_COUNT"
    exit 1
fi

# Verify components exist
if [[ ! -x "$VFLISP_COMPILER" ]]; then
    echo "Error: VFLisp compiler not found at: $VFLISP_COMPILER"
    if [[ -n "$VFM_DIR" ]]; then
        echo "Please build VelocityFilterMachine first:"
        echo "  cd $VFM_DIR && make all"
    else
        echo "Please install VelocityFilterMachine:"
        echo "  cd VelocityFilterMachine && make install"
    fi
    exit 1
fi

if [[ ! -x "$PV_BINARY" ]]; then
    echo "Error: PacketVelocity binary not found at: $PV_BINARY"
    if [[ "$PV_BINARY" == *"/usr/local/"* ]]; then
        echo "Please install PacketVelocity:"
        echo "  cd PacketVelocity && make install"
    else
        echo "Please build PacketVelocity first:"
        echo "  cd $SCRIPT_DIR && make"
    fi
    exit 1
fi

# Create temporary filter file
TEMP_FILTER=$(mktemp /tmp/pv_filter.XXXXXX.bin)
trap "rm -f $TEMP_FILTER" EXIT

echo "PacketVelocity - Compiling VFLisp filter..."
echo "Interface: $INTERFACE"
echo "Expression: $EXPRESSION"
echo "Packet Count: $PACKET_COUNT"
echo ""

# Compile VFLisp expression to bytecode
echo "Compiling filter expression..."
if ! "$VFLISP_COMPILER" -e "$EXPRESSION" -o "$TEMP_FILTER" 2>/dev/null; then
    echo "Error: Failed to compile VFLisp expression: $EXPRESSION"
    echo ""
    echo "Common VFLisp syntax:"
    echo "  Comparisons: (= field value), (!= field value), (> field value), (< field value)"
    echo "  Logic:       (and expr1 expr2), (or expr1 expr2), (not expr)"
    echo "  Fields:      proto, src-port, dst-port, ip-version, src-ip6, dst-ip6"
    echo ""
    echo "Example: \"(and (= ip-version 6) (= proto 6))\""
    exit 1
fi

echo "Filter compiled successfully!"
echo ""

# Show compiled bytecode information
echo "Bytecode Information:"
BYTECODE_SIZE=$(wc -c < "$TEMP_FILTER")
echo "  Size: $BYTECODE_SIZE bytes"

# Optional: Show disassembly if available
if [[ -x "$VFM_DIS" ]]; then
    echo "  Disassembly:"
    "$VFM_DIS" "$TEMP_FILTER" 2>/dev/null | head -10 | sed 's/^/    /'
fi

echo ""
echo "Starting packet capture on $INTERFACE..."
echo "Filter: $EXPRESSION"
echo "Press Ctrl+C to stop capture early"
echo ""

# Run PacketVelocity with the compiled filter
"$PV_BINARY" -i "$INTERFACE" -f "$TEMP_FILTER" -c "$PACKET_COUNT" -v

echo ""
echo "Capture completed."