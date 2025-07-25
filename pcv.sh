#!/bin/bash

# PacketVelocity Capture Script with VFLisp Filtering
# Usage: sudo ./pcv.sh <interface> "<vflisp-expression>" [packet-count]
# Example: sudo ./pcv.sh en0 "(= src-ip6 ::1)" 20

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect if PacketVelocity is installed in /usr/local or running from source
if [[ -x "/usr/local/bin/packetvelocity" ]]; then
    # Installed system-wide
    PV_BINARY="/usr/local/bin/packetvelocity"
    echo "Using installed PacketVelocity from /usr/local"
elif [[ -x "$SCRIPT_DIR/packetvelocity" ]]; then
    # Running from source directory
    PV_BINARY="$SCRIPT_DIR/packetvelocity"
    echo "Using PacketVelocity from source directory"
else
    echo "Error: PacketVelocity not found in /usr/local/bin or current directory"
    echo "Please install PacketVelocity or run from source directory"
    exit 1
fi

# Default values
INTERFACE=""
EXPRESSION=""
PACKET_COUNT=""

# Function to display usage
usage() {
    echo "PacketVelocity - High-Performance IPv4/IPv6 Packet Capture"
    echo ""
    echo "Usage: sudo $0 <interface> \"<vflisp-expression>\" [packet-count|time-limit]"
    echo ""
    echo "Arguments:"
    echo "  interface         Network interface to capture from (e.g., en0, eth0)"
    echo "  vflisp-expression VFLisp filter expression in quotes"
    echo "  packet-count      Number of packets to capture (optional)"
    echo "  time-limit        Maximum time in seconds (optional, use 't:N' format)"
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
    echo "Limit Examples:"
    echo "  sudo $0 en0 \"(= proto 6)\" 50                 # Capture 50 TCP packets"
    echo "  sudo $0 en0 \"(= ip-version 6)\" t:30          # Capture IPv6 for 30 seconds"
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
LIMIT_ARG="$3"

# Parse limit argument (packet count or time limit)
PACKET_COUNT_ARG=""
TIME_LIMIT_ARG=""
if [[ -n "$LIMIT_ARG" ]]; then
    if [[ "$LIMIT_ARG" =~ ^t:([0-9]+)$ ]]; then
        # Time limit format: t:30 (30 seconds)
        TIME_LIMIT_ARG="${BASH_REMATCH[1]}"
    elif [[ "$LIMIT_ARG" =~ ^[0-9]+$ ]]; then
        # Packet count format: 10
        PACKET_COUNT_ARG="$LIMIT_ARG"
    else
        echo "Error: Invalid limit format. Use number for packet count or 't:N' for time limit"
        echo "Examples: 10 (capture 10 packets), t:30 (capture for 30 seconds)"
        exit 1
    fi
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
    echo "Usage: sudo $0 $INTERFACE \"$EXPRESSION\" [limit]"
    exit 1
fi

# Verify PacketVelocity binary exists

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

echo "PacketVelocity - Starting packet capture with VFLisp filter..."
echo "Interface: $INTERFACE"
echo "Expression: $EXPRESSION"
if [[ -n "$PACKET_COUNT_ARG" ]]; then
    echo "Packet Limit: $PACKET_COUNT_ARG"
elif [[ -n "$TIME_LIMIT_ARG" ]]; then
    echo "Time Limit: ${TIME_LIMIT_ARG}s"
else
    echo "Limit: None (run until Ctrl+C)"
fi
echo ""

echo "Starting packet capture on $INTERFACE..."
echo "Filter: $EXPRESSION"
echo "Press Ctrl+C to stop capture early"
echo ""

# Build PacketVelocity command with VFLisp expression directly
PV_ARGS=("-i" "$INTERFACE" "-l" "$EXPRESSION" "-v")

if [[ -n "$PACKET_COUNT_ARG" ]]; then
    PV_ARGS+=("--packet-num" "$PACKET_COUNT_ARG")
elif [[ -n "$TIME_LIMIT_ARG" ]]; then
    PV_ARGS+=("--seconds-num" "$TIME_LIMIT_ARG")
fi

# Run PacketVelocity with the compiled filter
"$PV_BINARY" "${PV_ARGS[@]}"

echo ""
echo "Capture completed."