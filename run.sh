#!/bin/bash

# PacketVelocity + VFLisp Runner Script with Directional Arrow Testing
# Tests the new directional arrow functionality (< and >) for packet flow direction
#
# Usage: sudo ./run.sh [interface] [lisp_expression] [duration]
# Example: sudo ./run.sh en0 "(and (= proto 6) (or (= dst-port 80) (= dst-port 443)))" 10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}PacketVelocity + VFLisp Interface Runner with Directional Arrows${NC}"
echo -e "${BLUE}===============================================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script requires root privileges for packet capture${NC}"
    echo "Usage: sudo $0 [interface] [lisp_expression] [duration]"
    echo "Example: sudo $0 en0 \"(and (= proto 6) (or (= dst-port 80) (= dst-port 443)))\" 10"
    exit 1
fi

# Check if PacketVelocity binary exists
PV_BINARY="./packetvelocity"
if [ ! -f "$PV_BINARY" ]; then
    echo -e "${RED}ERROR: PacketVelocity binary not found at $PV_BINARY${NC}"
    echo "Please build PacketVelocity first:"
    echo "  make"
    exit 1
fi

# Parse arguments
INTERFACE=${1:-""}
LISP_EXPR=${2:-""}
DURATION=${3:-""}

# Default interface detection
if [ -z "$INTERFACE" ]; then
    echo -e "${YELLOW}Auto-detecting network interface...${NC}"
    
    # Detect default interface
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - find active Wi-Fi interface
        INTERFACE=$(route get default | grep interface | awk '{print $2}')
        if [ -z "$INTERFACE" ]; then
            INTERFACE="en0"  # fallback
        fi
    else
        # Linux - find active interface
        INTERFACE=$(ip route | grep '^default' | grep -o 'dev [^ ]*' | head -1 | cut -d' ' -f2)
        if [ -z "$INTERFACE" ]; then
            INTERFACE="eth0"  # fallback
        fi
    fi
    
    echo -e "${GREEN}Detected interface: $INTERFACE${NC}"
else
    echo -e "${GREEN}Using specified interface: $INTERFACE${NC}"
fi

# VFLisp expression is required
if [ -z "$LISP_EXPR" ]; then
    echo -e "${RED}ERROR: VFLisp expression is required${NC}"
    echo ""
    echo "Usage: sudo $0 [interface] [lisp_expression] [duration]"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  sudo $0 en0 \"1\" 5                                                      # Accept all for 5 seconds"
    echo "  sudo $0 en0 \"(= proto 6)\" 10                                          # TCP for 10 seconds"
    echo "  sudo $0 en0 \"(= proto 1)\"                                             # ICMP (indefinite)"
    echo "  sudo $0 en0 \"(and (= proto 17) (= dst-port 53))\" 15                  # DNS for 15 seconds"
    echo "  sudo $0 en0 \"(and (= proto 6) (or (= dst-port 80) (= dst-port 443)))\" # HTTP/HTTPS"
    echo ""
    echo -e "${CYAN}Supported VFLisp expressions:${NC}"
    echo "  Accept all:    1"
    echo "  TCP traffic:   (= proto 6)"
    echo "  UDP traffic:   (= proto 17)"
    echo "  ICMP traffic:  (= proto 1)"
    echo "  HTTP traffic:  (and (= proto 6) (or (= dst-port 80) (= dst-port 443)))"
    echo "  DNS queries:   (and (= proto 17) (= dst-port 53))"
    echo "  SSH traffic:   (and (= proto 6) (= dst-port 22))"
    echo ""
    echo -e "${YELLOW}Directional Arrow Display:${NC}"
    echo "  Look for these patterns in the output:"
    echo -e "    ${GREEN}OUT IP${NC} source.ip > dest.ip   (Outgoing from local machine)"
    echo -e "    ${GREEN}IN  IP${NC} source.ip < dest.ip   (Incoming to local machine)"
    echo ""
    echo -e "${BLUE}See VFLISP_PACKET_MATCHING.md for comprehensive examples${NC}"
    exit 1
fi

# Validate interface exists
if ! ifconfig "$INTERFACE" &>/dev/null; then
    echo -e "${RED}ERROR: Network interface '$INTERFACE' not found${NC}"
    echo "Available interfaces:"
    ifconfig -l
    exit 1
fi

echo -e "${GREEN}Using VFLisp expression: ${YELLOW}$LISP_EXPR${NC}"
echo -e "${GREEN}Platform: ${YELLOW}$(uname -s)${NC}"
if [ -n "$DURATION" ]; then
    echo -e "${GREEN}Duration: ${YELLOW}${DURATION}s${NC}"
else
    echo -e "${GREEN}Duration: ${YELLOW}Indefinite (Ctrl+C to stop)${NC}"
fi
echo ""

echo -e "${BLUE}=========================================="
echo -e "DIRECTIONAL ARROW TESTING"
echo -e "==========================================${NC}"
echo -e "${CYAN}This version of PacketVelocity includes directional arrows:${NC}"
echo ""
echo -e "  ${GREEN}OUT IP${NC} x.x.x.x ${YELLOW}>${NC} y.y.y.y  - Outgoing packets (from your machine)"
echo -e "  ${GREEN}IN  IP${NC} x.x.x.x ${YELLOW}<${NC} y.y.y.y  - Incoming packets (to your machine)"
echo ""
echo -e "${CYAN}The direction is determined by comparing source/destination IPs${NC}"
echo -e "${CYAN}with your local machine's IP address on interface $INTERFACE${NC}"
echo ""

# Get local IP for reference
LOCAL_IP=$(ifconfig "$INTERFACE" | grep 'inet ' | awk '{print $2}')
if [ -n "$LOCAL_IP" ]; then
    echo -e "${GREEN}Local IP on $INTERFACE: ${YELLOW}$LOCAL_IP${NC}"
    echo ""
fi

echo -e "${BLUE}Starting packet capture with VFLisp dynamic compilation...${NC}"
echo -e "${BLUE}==========================================${NC}"
echo -e "${CYAN}Command: $PV_BINARY -i $INTERFACE -l \"$LISP_EXPR\" -v${NC}"
echo ""
echo -e "${YELLOW}VFLisp Expression: $LISP_EXPR${NC}"
echo ""
echo -e "${CYAN}This will:${NC}"
echo "  * Capture packets from interface: $INTERFACE"
echo "  * Dynamically compile VFLisp expression to VFM bytecode"
echo "  * Apply compiled filter for packet matching"
echo "  * Display packet metadata with directional arrows"
echo "  * Use VFLisp compiler with fixed verification"
if [ -n "$DURATION" ]; then
    echo "  * Run for $DURATION seconds"
else
    echo "  * Continuously run until Ctrl+C"
fi
echo ""
echo -e "${GREEN}Press Ctrl+C to stop capture${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""

# Build command
CMD_ARGS=("-i" "$INTERFACE" "-l" "$LISP_EXPR" "-v")

# Run PacketVelocity with optional timeout
if [ -n "$DURATION" ]; then
    echo -e "${GREEN}Running with $DURATION second timeout...${NC}"
    echo ""
    timeout "$DURATION" "$PV_BINARY" "${CMD_ARGS[@]}" || {
        exit_code=$?
        echo ""
        if [ $exit_code -eq 124 ]; then
            echo -e "${GREEN}Capture completed after ${DURATION}s${NC}"
        else
            echo -e "${RED}Capture ended with exit code: $exit_code${NC}"
        fi
    }
else
    echo -e "${GREEN}Running indefinitely (Ctrl+C to stop)...${NC}"
    echo ""
    "$PV_BINARY" "${CMD_ARGS[@]}"
fi

echo ""
echo -e "${GREEN}VFM packet capture completed.${NC}"