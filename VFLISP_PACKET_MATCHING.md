# PacketVelocity VFLisp Packet Matching Analysis

This document provides a comprehensive guide to using VFLisp expressions in PacketVelocity for matching network packets in both incoming and outgoing directions.

## Available Packet Fields

VFLisp can access the following packet fields for filtering:

- `proto` - IP protocol (TCP=6, UDP=17, ICMP=1)
- `src-ip` - Source IPv4 address (32-bit integer)
- `dst-ip` - Destination IPv4 address (32-bit integer)  
- `src-port` - Source port (16-bit)
- `dst-port` - Destination port (16-bit)
- `ethertype` - Ethernet type
- `ip-len` - IP packet length
- `tcp-flags` - TCP flags byte

## VFLisp Operators

### Arithmetic Operators
- `+`, `-`, `*`, `/`, `%` (modulo)

### Comparison Operators
- `=`, `!=`, `>`, `>=`, `<`, `<=`

### Logical Operators
- `and`, `or`, `not`

### Bitwise Operators
- `&`, `|`, `^`, `<<`, `>>`

### Control Flow
- `if` - `(if condition then-expr else-expr)`

## VFLisp Expression Examples for Matching All Traffic

### 1. Accept All Packets (Simplest)
```lisp
1
```
This always returns true (1), accepting every packet regardless of direction.

### 2. Accept All IP Traffic
```lisp
(= ethertype 2048)
```
Matches all IPv4 packets (ethertype 0x0800 = 2048).

### 3. Accept All TCP Traffic (Bidirectional)
```lisp
(= proto 6)
```
Matches all TCP packets regardless of ports or direction.

### 4. Accept All UDP Traffic (Bidirectional)
```lisp
(= proto 17)
```
Matches all UDP packets regardless of ports or direction.

### 5. Accept Web Traffic (HTTP/HTTPS) - Bidirectional
```lisp
(and (= proto 6) 
     (or (= dst-port 80) (= src-port 80)
         (= dst-port 443) (= src-port 443)))
```
This matches HTTP/HTTPS traffic in both directions by checking both source and destination ports.

### 6. Accept SSH Traffic - Bidirectional
```lisp
(and (= proto 6)
     (or (= dst-port 22) (= src-port 22)))
```
Matches SSH connections in both directions.

### 7. Accept DNS Traffic - Bidirectional
```lisp
(and (= proto 17)
     (or (= dst-port 53) (= src-port 53)))
```
Matches DNS queries and responses.

### 8. Accept All TCP Traffic with Common Ports
```lisp
(and (= proto 6)
     (or (or (= dst-port 80) (= src-port 80))
         (or (= dst-port 443) (= src-port 443))
         (or (= dst-port 22) (= src-port 22))
         (or (= dst-port 25) (= src-port 25))
         (or (= dst-port 21) (= src-port 21))))
```

### 9. Accept Traffic on High Ports (Ephemeral)
```lisp
(or (> dst-port 1024) (> src-port 1024))
```
Matches traffic involving ephemeral ports (typically client connections).

### 10. Accept All Traffic from/to Specific Network
```lisp
; 192.168.1.0/24 network (3232235776 to 3232236031)
(or (and (>= src-ip 3232235776) (<= src-ip 3232236031))
    (and (>= dst-ip 3232235776) (<= dst-ip 3232236031)))
```

## Common Protocol Values

- **TCP**: `proto = 6`
- **UDP**: `proto = 17`
- **ICMP**: `proto = 1`
- **IPv4**: `ethertype = 2048`

## Common Port Numbers

- **HTTP**: 80
- **HTTPS**: 443
- **SSH**: 22
- **DNS**: 53
- **SMTP**: 25
- **FTP**: 21
- **Telnet**: 23
- **POP3**: 110
- **IMAP**: 143

## TCP Flags

TCP flags can be checked using bitwise operations:

```lisp
(= (& tcp-flags 2) 2)    ; SYN flag
(= (& tcp-flags 16) 16)  ; ACK flag
(= (& tcp-flags 1) 1)    ; FIN flag
(= (& tcp-flags 4) 4)    ; RST flag
(= (& tcp-flags 8) 8)    ; PSH flag
(= (& tcp-flags 32) 32)  ; URG flag
```

## IP Address Conversion

IP addresses in VFLisp are represented as 32-bit integers. To convert:

- 192.168.1.1 = (192 << 24) + (168 << 16) + (1 << 8) + 1 = 3232235777
- 10.0.0.1 = (10 << 24) + (0 << 16) + (0 << 8) + 1 = 167772161

Common private network ranges:
- 192.168.1.0/24: 3232235776 to 3232236031
- 10.0.0.0/8: 167772160 to 184549375
- 172.16.0.0/12: 2886729728 to 2887778303

## Key Points for Bidirectional Matching

1. **Direction Independence**: To capture traffic in both directions, you need to check both `src-port`/`dst-port` and `src-ip`/`dst-ip` fields.

2. **Protocol Awareness**: Different protocols use different fields (TCP/UDP use ports, ICMP doesn't).

3. **The Directional Arrows**: PacketVelocity's directional arrow feature (< and >) works at the display level by comparing packet IPs with the local machine's IP, regardless of the VFLisp filter used.

## Example Test Commands

```bash
# Accept all packets
sudo ./run.sh en0 "1" 10

# Accept all TCP traffic (bidirectional)
sudo ./run.sh en0 "(= proto 6)" 15

# Accept web traffic (HTTP/HTTPS) in both directions
sudo ./run.sh en0 "(and (= proto 6) (or (= dst-port 80) (= src-port 80) (= dst-port 443) (= src-port 443)))" 10

# Accept all traffic involving common ports
sudo ./run.sh en0 "(or (or (= dst-port 80) (= src-port 80)) (or (= dst-port 443) (= src-port 443)) (or (= dst-port 22) (= src-port 22)))" 20

# Accept DNS traffic (queries and responses)
sudo ./run.sh en0 "(and (= proto 17) (or (= dst-port 53) (= src-port 53)))" 30
```

## Advanced Examples

### Complex Conditional Logic
```lisp
(if (= proto 6)
    (or (and (= dst-port 22)
             (or (and (>= src-ip 3232235776)
                      (<= src-ip 3232236031))
                 (and (>= src-ip 167772160)
                      (<= src-ip 184549375))))
        (= dst-port 443))
    0)
```
This accepts SSH traffic from trusted networks or any HTTPS traffic.

### Port Range Filtering
```lisp
(and (= proto 6)
     (or (and (>= dst-port 1000) (<= dst-port 2000))
         (and (>= src-port 1000) (<= src-port 2000))))
```
Accepts TCP traffic on ports 1000-2000 in either direction.

### Multiple Protocol Support
```lisp
(or (= proto 6)   ; TCP
    (= proto 17)  ; UDP
    (= proto 1))  ; ICMP
```
Accepts TCP, UDP, or ICMP traffic.

The directional arrows (< and >) in PacketVelocity's output will show you the actual direction of the matched packets relative to your local machine, making it easy to distinguish incoming from outgoing traffic even when using bidirectional filters.