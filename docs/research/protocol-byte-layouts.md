# Technical report: EtherNet/IP + CIP at the byte level

## Note on endianness (confirmed)

All of EtherNet/IP and CIP is **little-endian** ("low byte first"). The 1756-PM020 manual confirms this explicitly in every table ("Multi-byte data values are transmitted low-byte first"), and the Wireshark dissectors read all fields with `GetUintFromMessage`/`GetUdintFromMessage` in LE. **The only exception** is the embedded `sockaddr_in` structures: in the CPF Sockaddr Info items (0x8000/0x8001) and in the ListIdentity Identity item, the `sin_family`, `sin_port`, and `sin_addr` fields are in **big-endian (network byte order)**. In OpENer this is visible because the port is encoded with `htons()` and the IP in network order, while the rest of the packet is LE. This is the number-one implementation pitfall.

---

## 1. ENCAPSULATION LAYER

### Ports
- **TCP 44818**: explicit messaging (session-based). Also UDP 44818 for ListIdentity/ListServices/ListInterfaces (including broadcast).
- **UDP 2222**: implicit I/O messaging (class 0/1).
- The `START_DTLS` command (0x00C8) exists for secure EtherNet/IP, out of scope here.

### Encapsulation header (24 bytes, fixed)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | Command | UINT LE (see command table) |
| 2 | 2 | Length | UINT LE = number of data bytes following the header (0 if none) |
| 4 | 4 | Session Handle | UDINT LE. 0 in the RegisterSession request; assigned by the target |
| 8 | 4 | Status | UDINT LE (0 = success). The originator always sends 0 |
| 12 | 8 | Sender Context | 8 opaque bytes; the target returns them unchanged (for correlation) |
| 20 | 4 | Options | UDINT LE, normally 0 |

Structure verified in OpENer's `encap.c` (`GenerateEncapsulationHeader`) and in `packet-enip.c`.

### Encapsulation commands (from `packet-enip.c`)

```
NOP                0x0000
LIST_SERVICES      0x0004
LIST_IDENTITY      0x0063
LIST_INTERFACES    0x0064
REGISTER_SESSION   0x0065
UNREGISTER_SESSION 0x0066
SEND_RR_DATA       0x006F
SEND_UNIT_DATA     0x0070
```

### Encapsulation status codes

```
0x0000 Success
0x0001 Invalid/Unsupported Command
0x0002 Insufficient Memory (No Memory Resources)
0x0003 Incorrect Data (malformed CPF)
0x0064 Invalid Session Handle
0x0065 Invalid Length
0x0069 Unsupported Protocol Revision
```

### Format of each command

**NOP (0x00)**: header + optional padding data. No response. The receiver discards it. Serves as a TCP keep-alive.

**RegisterSession (0x65)**: data = Protocol Version (UINT LE = 1) + Options Flags (UINT LE = 0). The request carries Session Handle = 0 in the header; the **response** repeats the same 4 data bytes and places the assigned session handle in the header field at offset 4. OpENer validates `0 < version <= 1` and flags == 0.

**UnRegisterSession (0x66)**: header with the session handle to close, length = 0, no data. No mandatory response; the target closes the session and typically the TCP socket.

**ListServices (0x04)**: response = Item Count (UINT) + an item of type `0x0100` (List Services Response) containing: Version (UINT), Capability Flags (UINT; bit 5 = supports CIP encapsulation over TCP, bit 8 = supports class 0/1 UDP), and a 16-byte Name String ("Communications\0\0").

**ListInterfaces (0x64)**: response = Item Count + items describing non-CIP interfaces (usually Item Count = 0).

**ListIdentity (0x63)**: discovery. Response = Item Count (UINT, =1) + one **Identity item of type 0x000C**. Item layout (after Type ID 2B + Length 2B), verified in OpENer's `EncodeListIdentityCipIdentityItem`:

| Field | Size | Notes |
|---|---|---|
| Encapsulation Protocol Version | 2 (UINT LE) | =1 |
| sin_family | 2 | **big-endian**, =2 (AF_INET) |
| sin_port | 2 | **big-endian**, =44818 (htons) |
| sin_addr | 4 | **big-endian**, device IP |
| sin_zero | 8 | zeros |
| Vendor ID | 2 (UINT LE) | |
| Device Type | 2 (UINT LE) | |
| Product Code | 2 (UINT LE) | |
| Revision | 2 | Major (1B) + Minor (1B) |
| Status | 2 (WORD LE) | Identity object status word |
| Serial Number | 4 (UDINT LE) | |
| Product Name | 1 + N | SHORT_STRING: length byte + N ASCII chars |
| State | 1 (USINT) | device state |

**SendRRData (0x6F)** — unconnected explicit message (request/response). Data after the header:
- Interface Handle (UDINT LE) = 0 (CIP)
- Timeout (UINT LE) in seconds
- **CPF** (see below). For unconnected: Null Address item (0x0000) + Unconnected Data item (0x00B2) wrapping the CIP message (Message Router request).

OpENer subtracts `data_length -= 6` (4+2) before parsing the CPF.

**SendUnitData (0x70)** — connected explicit message (class 3) or data transport over an established connection. Same 6 bytes (Interface Handle + Timeout, normally 0) + CPF with a Connected Address item (0x00A1, containing the connection ID) + a Connected Data item (0x00B1, which starts with a 16-bit sequence count).

### Common Packet Format (CPF)
```
Item Count : UINT LE
For each item: Type ID (UINT LE) + Length (UINT LE) + Data[Length]
```
Item types (from `packet-enip.c`):
```
0x0000 Null Address        (Length=0; null addressing, used in unconnected)
0x00A1 Connected Address    (Length=4; 32-bit connection ID)
0x8002 Sequenced Address    (Length=8; 32b connection ID + 32b sequence number) → I/O UDP
0x00B1 Connected Data       (connection data; starts with a 16b seq count in class 1/3)
0x00B2 Unconnected Data     (unconnected CIP message)
0x8000 Sockaddr Info O→T    (16 bytes sockaddr_in, big-endian)
0x8001 Sockaddr Info T→O    (16 bytes sockaddr_in, big-endian)
0x0100 List Services Response
0x000C List Identity Response (Identity item)
```

---

## 2. CIP CORE (Message Router)

### Request
```
Service          : 1 byte (service code, MSB=0 in a request)
Request Path Size: 1 byte (number of 16-bit WORDS in the EPATH)
Request Path     : EPATH (Request Path Size * 2 bytes)
Request Data     : service-specific bytes (optional)
```

### Response
```
Reply Service        : 1 byte = Service | 0x80  (MSB set)
Reserved             : 1 byte = 0x00
General Status       : 1 byte (0x00 = success)
Additional Status Sz : 1 byte (number of 16-bit WORDS of additional status; 0 if success)
Additional Status    : Sz * 2 bytes (extended status, present only if Sz>0)
Reply Data           : response bytes (optional)
```
E.g.: Read Tag request = 0x4C → reply = 0xCC; Write Tag 0x4D → 0xCD; Multiple Service 0x0A → 0x8A.

### EPATH (segment encoding, confirmed in 1756-PM020 pp. 13-14)

**Logical segments** (type/format byte + value):

| Segment | 8-bit | 16-bit | 32-bit |
|---|---|---|---|
| Class | 0x20 v | 0x21 00 lo hi | — |
| Instance | 0x24 v | 0x25 00 lo hi | — |
| Attribute | 0x30 v | 0x31 00 lo hi | — |
| Member | 0x28 v | 0x29 00 lo hi | 0x2A 00 lolo lo hi hihi |
| Connection Point | 0x2C v | 0x2D 00 lo hi | 0x2E ... |

The 16/32-bit formats **insert a 0x00 pad byte** after the type byte to align the value (e.g.: `21 00 <lo> <hi>`). The low format byte: 0x00=8-bit, 0x01=16-bit, 0x02=32-bit; the high nibble encodes the logical type (class=0x20, instance=0x24, member=0x28, conn point=0x2C, attribute=0x30).

**ANSI Extended symbolic segment (0x91)**:
```
0x91  <Length=number of chars>  <char 0> ... <char N-1>  [pad 0x00 if N is odd]
```
Verified against the real example in the manual: reading `TotalCount` (10 chars) = `91 0A 54 6F 74 61 6C 43 6F 75 6E 74` (even, no pad). If the name has an odd length (e.g. "rate", 4 chars, even; "ports", 5 chars, odd) a trailing 0x00 is added so the segment occupies a whole number of words.

**Port segment (routing to the backplane)**: byte 0x00 (port segment) with the port number in the low bits + link address. For the ControlLogix backplane: `01 <slot>` (port 1 = backplane, followed by the slot address). E.g. slot 0 = `01 00`. Format used in the route path of Unconnected Send / connection path of Forward Open.

### Common CIP services
```
0x01 Get_Attributes_All
0x02 Set_Attributes_All
0x03 Get_Attribute_List
0x04 Set_Attribute_List
0x05 Reset
0x0A Multiple_Service_Packet
0x0E Get_Attribute_Single
0x10 Set_Attribute_Single
0x4E Forward_Close       (Connection Manager)
0x52 Unconnected_Send    (Connection Manager)
0x54 Forward_Open        (Connection Manager)
0x5B Large_Forward_Open  (Connection Manager)
```

### CIP General Status codes (complete relevant list)
```
0x00 Success
0x01 Connection failure (use Extended Status for the real detail)
0x02 Resource unavailable
0x03 Invalid parameter value (deprecated; use 0x20)
0x04 Path segment error (bad EPATH syntax)
0x05 Path destination unknown (nonexistent class/instance/attribute)
0x06 Partial transfer (more data available → fragmentation)
0x07 Connection lost
0x08 Service not supported
0x09 Invalid attribute value
0x0A Attribute list error
0x0B Already in requested mode/state
0x0C Object state conflict
0x0D Object already exists
0x0E Attribute not settable
0x0F Privilege violation
0x10 Device state conflict
0x11 Reply data too large
0x13 Not enough data
0x14 Attribute not supported
0x15 Too much data
0x16 Object does not exist
0x1E Embedded service error
0x1F Vendor specific error (see Additional Code)
0x20 Invalid parameter
0x26 Path size invalid (Request Path Size larger/smaller than expected)
0x2C Attribute not gettable
0xFF (Logix) General Error, see extended (0x2104/0x2105/0x2107...)
```

### Elementary CIP data types (from pycomm3 `data_types.py`, extended to 16 bits in Logix)
```
BOOL 0xC1   SINT 0xC2   INT 0xC3   DINT 0xC4   LINT 0xC5
USINT 0xC6  UINT 0xC7   UDINT 0xC8 ULINT 0xC9
REAL 0xCA   LREAL 0xCB
STIME 0xCC  DATE 0xCD   TIME_OF_DAY 0xCE   DATE_AND_TIME 0xCF   DT 0xC0
STRING 0xD0 BYTE 0xD1   WORD 0xD2  DWORD 0xD3  LWORD 0xD4
STRING2 0xD5 FTIME 0xD6 LTIME 0xD7 ITIME 0xD8  STRINGN 0xD9
SHORT_STRING 0xDA  TIME 0xDB  EPATH 0xDC  ENGUNIT 0xDD  STRINGI 0xDE
```
Structured / derived:
```
0xA0 ABBREV_STRUCT (abbreviated structure; in Logix = 0x02A0 + 2B Structure Handle)
0xA1 ABBREV_ARRAY
0xA2 STRUCT
0xA3 ARRAY
```
The **tag type of a Logix structure** is a 4-byte sequence: `A0 02 <handle_lo> <handle_hi>` (confirmed in 1756-PM020 p. 12). The Structure Handle = Template attribute 1. An array of an atomic type reports the element's 2-byte tag type; an array of structures reports the 4-byte one.

---

## 3. CONNECTION MANAGER (class 0x06, instance 1)

### Unconnected Send (0x52)
Addressed to the Connection Manager. Request data:
```
Priority/Time_tick : 1 byte  (bits: tick time; bit4 typically)
Timeout Ticks      : 1 byte  (timeout = time_tick_ms * ticks; practical minimum ~10 s)
Message Request Size: 2 bytes (UINT LE = size in bytes of the embedded message)
Embedded Message    : N bytes (a complete Message Router request)
Pad                 : 1 byte 0x00 ONLY if N is odd
Route Path Size     : 1 byte (WORDS)
Reserved            : 1 byte 0x00
Route Path          : EPATH (port+link, e.g. 01 00 to slot 0)
```

### Forward Open (0x54) and Large Forward Open (0x5B)
Request data (verified in OpENer `cipconnectionmanager.c` and `LargeForwardOpen.scala`):

| Field | FO (0x54) | LFO (0x5B) |
|---|---|---|
| Priority/Time_tick | 1 | 1 |
| Timeout Ticks | 1 | 1 |
| O→T Network Connection ID | 4 | 4 |
| T→O Network Connection ID | 4 | 4 |
| Connection Serial Number | 2 | 2 |
| Originator Vendor ID | 2 | 2 |
| Originator Serial Number | 4 | 4 |
| Connection Timeout Multiplier | 1 | 1 |
| Reserved | 3 | 3 |
| O→T RPI (µs) | 4 | 4 |
| O→T Network Connection Params | **2** | **4** |
| T→O RPI (µs) | 4 | 4 |
| T→O Network Connection Params | **2** | **4** |
| Transport Type/Trigger | 1 | 1 |
| Connection Path Size (words) | 1 | 1 |
| Connection Path | var | var |

In the request, the originator proposes the Connection IDs (one per direction; for point-to-point connections the target may accept them, for multicast the producer assigns its own in the response). The **Connection Triad** that uniquely identifies the connection = (Connection Serial Number, Originator Vendor ID, Originator Serial Number).

**Network Connection Parameters — 16-bit format (FO)** (from EIPScanner `NetworkConnectionParams.h`):
```
bit 15    : Redundant Owner (0 = exclusive, 1 = redundant)
bits 14-13: Connection Type  (0=Null, 1=Multicast (1<<13), 2=Point-to-Point (2<<13))
bit 12    : reserved
bits 11-10: Priority (0=Low, 1=High, 2=Scheduled, 3=Urgent)
bit 9     : Size type (0=Fixed, 1=Variable)
bits 8-0  : Connection Size in bytes (max 511)
```

**32-bit format (LFO)** (from `LargeForwardOpen.scala`):
```
bit 31    : Redundant Owner
bits 30-29: Connection Type
bits 27-26: Priority
bit 25    : Size type (Fixed/Variable)
bits 15-0 : Connection Size in bytes (max 65535)
```
This is the key difference: LFO shifts the high bits and widens the size field from 9 to 16 bits, which is why it is used for large arrays (>~500 bytes).

**Transport Class/Trigger (1 byte)**:
```
bit 7    : Direction (0 = client, 1 = server/producer)
bits 6-4 : Production Trigger (0=Cyclic, 1=Change of State, 2=Application object)
bits 3-0 : Transport Class (0,1,2,3)
```

**Connection Path**: EPATH with the connection points. For a typical I/O adapter: `[optional port segment routing] + Config assembly (0x20 04 24 <cfg>) + O→T conn point (0x2C <out>) + T→O conn point (0x2C <in>)`. For explicit class 3 connections the path points to the Message Router (`20 02 24 01`).

**Forward Open response (success)**:
```
Reply Service (0xD4) | 00 | General Status (00) | Ext Status Size (00)
O→T Network Connection ID : 4
T→O Network Connection ID : 4   (for multicast, this is where the producer's real CID arrives)
Connection Serial Number  : 2
Originator Vendor ID       : 2
Originator Serial Number   : 4
O→T API (Actual Packet Interval, µs) : 4
T→O API (µs)                          : 4
Application Reply Size (words) : 1
Reserved                       : 1
Application Reply              : var
```

**Forward Open response (error)**: General Status = 0x01 (or 0x08) + Additional Status with the **extended status** (2 bytes, or more). Important codes (from OpENer `cipconnectionmanager.h`):
```
0x0100 Connection in use / Duplicate Forward Open
0x0106 Ownership conflict
0x0110 Target for connection not configured
0x0111 RPI not supported
0x0113 Out of connections (no more connections available)
0x0123 Invalid O→T connection type
0x0124 Invalid T→O connection type
0x0127 Invalid O→T connection size
0x0128 Invalid T→O connection size
0x0315 Invalid segment type in connection path
```
On a size error, the target may return the suggested correct size in the additional status.

### Forward Close (0x4E)
```
Priority/Time_tick : 1
Timeout Ticks      : 1
Connection Serial Number : 2
Originator Vendor ID      : 2
Originator Serial Number  : 4
Connection Path Size (words): 1
Reserved                    : 1 (pad)
Connection Path            : var (same path as in the open)
```
The target locates the connection by the triad and closes it.

### Timeouts
- **Connection (inactivity/watchdog) timeout = RPI × 2^(Connection Timeout Multiplier)**. Multiplier 0→×4 per the CIP mapping (0=×4, 1=×8, 2=×16, 3=×32, 4=×64...). OpENer resets the watchdog upon receiving a packet with a valid sequence number and closes when it reaches zero.
- **Unconnected timeout** (Priority/Timeout Ticks) has a recommended minimum of **10 seconds**.

---

## 4. IMPLICIT MESSAGING (Class 0/1, UDP 2222)

### I/O packet
Over UDP 2222, with no session encapsulation header in the cyclic flow: a CPF is sent directly with:
```
Item Count = 2
Item 1: Sequenced Address (0x8002), Length=8:
        Connection ID   : UDINT LE (4)
        Sequence Number : UDINT LE (4)  ← must NEVER decrement
Item 2: Connected Data (0x00B1), Length=N:
        [Sequence Count 16 bits]  ← only in Transport Class 1
        [Run/Idle header 32 bits] ← if applicable (see below)
        Application data...
```

### Sequence count and Run/Idle
- **Transport Class 1**: connected data starts with a **16-bit sequence count** (LE). Class 0 has none.
- **Run/Idle header (32 bits)**: bit 0 = 1 (Run) / 0 (Idle); the rest reserved. Confirmed in OpENer `cipioconnection.c`: it is asymmetric and configurable per direction (`OPENER_CONSUMED_DATA_HAS_RUN_IDLE_HEADER` for O→T, `OPENER_PRODUCED_DATA_HAS_RUN_IDLE_HEADER` for T→O). In Rockwell scanner practice, **O→T (scanner→adapter) almost always carries run/idle**; **T→O (adapter→scanner) often does not**. The consumer must subtract 4 bytes from the assembly size if run/idle is present, and 2 bytes for the class 1 sequence count. The order in the payload is: sequence count (16b) → run/idle (32b) → data.
- A data_size of 0 with "heartbeat" (listen-only/input-only connection) carries neither run/idle nor data.

### Multicast
- By default **O→T is point-to-point (unicast)** and **T→O can be multicast** (multiple scanners listening to the same producer).
- **Multicast IP allocation** (from OpENer `CipTcpIpCalculateMulticastIp`), exact formula:
  ```
  base = 0xEFC00100                       // 239.192.1.0
  host_id = ntohl(ip) & ~ntohl(netmask)   // host portion of the IP
  host_id = host_id - 1
  host_id = host_id & 0x3FF               // 10 bits
  mcast_start = htonl( base + (host_id << 5) )   // <<5 = ×32
  ```
  In other words, each device reserves **32 consecutive multicast addresses** starting at 239.192.1.0. The number of addresses and the allocation mode are controlled by attribute 9 (Mcast Config) of the TCP/IP object.
- Multicast **TTL** = attribute 8 of the TCP/IP object (0xF5), range 1-255, **default 1** (does not cross routers by default).
- UDP source and destination port = **2222** in both directions.

### Watchdog on the consumer
Timeout = RPI × multiplier (see §3). If a new packet does not arrive within that time, the consumer marks the connection as timed-out and acts (faults the connection / sets data to idle). Production is cyclic every RPI.

---

## 5. CONNECTED EXPLICIT MESSAGING (Class 3)

Transported over **SendUnitData (0x70)** on TCP after a class 3 Forward Open (path to the Message Router `20 02 24 01`, transport class 3, application trigger). CPF:
```
Item 1: Connected Address (0x00A1), Length=4 → Connection ID (the T→O from the open, LE)
Item 2: Connected Data (0x00B1) →
        Sequence Count : 2 bytes (UINT LE)  ← increments on each request
        CIP Message Router request/response...
```
**Difference from class 1**: class 3 goes over TCP with a Connected Address item (0x00A1) + a **16-bit** sequence count and carries complete explicit messages (with EPATH and data); class 1 goes over UDP 2222 with a Sequenced Address item (0x8002, which additionally carries a 32-bit sequence number) + raw I/O data (no EPATH, just the assembly). Both use a 16-bit sequence count at the start of the Connected Data, but class 1 adds a 32-bit sequence number on top at the network addressing level.

---

## 6. STANDARD CIP OBJECTS (minimal adapter)

Class IDs: **Identity 0x01, Message Router 0x02, Assembly 0x04, Connection Manager 0x06, TCP/IP Interface 0xF5, Ethernet Link 0xF6**.

**Identity (0x01)** — instance 1 attributes:
```
1 Vendor ID        UINT
2 Device Type      UINT
3 Product Code     UINT
4 Revision         USINT major + USINT minor
5 Status           WORD (bitmap: owned, configured, faults...)
6 Serial Number    UDINT
7 Product Name     SHORT_STRING (1B len + chars)
```
Supports Get_Attributes_All (0x01), Get_Attribute_Single (0x0E), and **Reset (0x05)** (type 0 = reset, type 1 = factory reset).

**Message Router (0x02)**: instance 1 is the destination of explicit messages; it exposes the list of supported objects.

**Assembly (0x04)**: input/output/config instances (the numbers are vendor-specific). Attribute **3 = Data** (the assembly's bytes), attribute **4 = Size** (UINT, size in bytes). The config assembly is referenced in the Forward Open connection path.

**Connection Manager (0x06)**: processes Forward_Open/Close/Unconnected_Send (§3).

**TCP/IP Interface (0xF5)** — attributes (from OpENer/TI):
```
1  Status                       DWORD (bits: interface config status; 1 = valid config)
2  Configuration Capability     DWORD (bits: BOOTP, DNS, DHCP, config settable, ACD...)
3  Configuration Control        DWORD (bits 0-3: 0=static,1=BOOTP,2=DHCP; bit4=DNS enable)
4  Physical Link Object          STRUCT: path size (UINT) + EPATH to the Ethernet Link (20 F6 24 01)
5  Interface Configuration       STRUCT: IP(UDINT) + NetMask(UDINT) + Gateway(UDINT)
                                  + NameServer1(UDINT) + NameServer2(UDINT) + DomainName(STRING)
6  Host Name                     STRING (max 64)
8  Mcast TTL Value               USINT (default 1)
9  Mcast Config                  STRUCT: alloc control(USINT)+reserved+num_mcast(UINT)+start_addr(UDINT)
10 SelectACD                     BOOL
11 LastConflictDetected          STRUCT
13 Encapsulation Inactivity TO   UINT (seconds, default 120)
```

**Ethernet Link (0xF6)** — attributes:
```
1 Interface Speed   UDINT (Mbps: 10/100/1000)
2 Interface Flags   DWORD (bit0=Link up, bit1=Full duplex, bits2-4=neg status, ...)
3 Physical Address  ARRAY[6] of USINT (MAC)
6 Interface Control STRUCT: Control Bits(WORD, auto-neg/duplex) + Forced Speed(WORD)
(optional: 4 Interface Counters, 5 Media Counters, 7 Interface Type, 8 Interface State,
 9 Admin State, 10 Interface Label)
```

**Device Type** (Identity attr 2) for a generic adapter: **Communications Adapter = 0x0C**; **Generic Device (keyable) = 0x2B**; Managed Ethernet Switch = 0x2C. Public range 0x00-0x63 and 0x100-0x2FF; vendor-specific 0x64-0xC7 and 0x300-0x4FF. The Vendor ID is assigned by ODVA.

---

## 7. LOGIX SERVICES (1756-PM020, verified at the byte level)

The services operate on the controller with two addressing methods: **Symbolic Segment** (ANSI name) or **Symbol Instance** (Class 0x6B + Instance ID, v21+).

**Read Tag (0x4C)**. Request = service + path + **element count (UINT LE)**. Real example (tag `TotalCount`, DINT=534):
```
Req: 4C 06 | 91 0A 54 6F 74 61 6C 43 6F 75 6E 74 | 01 00
Rep: CC 00 00 00 | C4 00 | 16 02 00 00      (type=DINT 0x00C4, value 0x00000216=534)
```
With Symbol Instance: `4C 03 | 20 6B 25 00 8F F6 | 01 00` (Class 0x6B, Instance 0xF68F). Errors: 0x04 (path syntax), 0x05 (destination unknown / nonexistent instance), **0x06 (Insufficient Packet Space → more data available, use fragmented)**, 0x13 (not enough data), 0x26 (path size), 0xFF/0x2105 (access beyond the end of the tag).

**Read Tag Fragmented (0x52)**: identical but **adds a Byte Offset (DINT, 4 bytes LE)** at the end of the request data. The offset is in **bytes** (not elements). The controller returns General Status 0x06 while more data remains and 0x00 on the last fragment; the client increments the offset by the bytes received. The type code (2B) comes at the start of the reply data of each fragment. Reply service = 0xD2.

**Write Tag (0x4D)**: request data = **Tag Type (UINT LE)** + **element count (UINT LE)** + data. E.g. writing 14 to DINT `CartonSize`:
```
4D 06 | 91 0A 43 61 72 74 6F 6E 53 69 7A 65 | C4 00 | 01 00 | 0E 00 00 00
Rep: CD 00 00 00
```
Errors: 0xFF/0x2107 = "tag type used in request does not match target tag's data type" (strict type validation).

**Write Tag Fragmented (0x53)**: request data = Tag Type (UINT) + Total element count (UINT) + **Byte Offset (DINT)** + fragment data. Reply service = 0xD3.

**Read-Modify-Write (0x4E)**: request data = **Size of Masks (UINT, only 1/2/4/8/12 valid)** + **OR mask** (bits to set to 1) + **AND mask** (bits to keep/set to 0), each mask being "Size" bytes. E.g. setting bit2 and resetting bit5 of a DINT `ControlWord`:
```
4E 07 | 91 0B ...ControlWord... 00 | 04 00 | 04 00 00 00 | DF FF FF FF
Rep: CE 00 00 00
```
The mask size must match the size of the data type for integrity.

**Multiple Service Packet (0x0A)**: path to the Message Router `20 02 24 01`. Request data:
```
Number of Services : UINT LE
Offset array       : UINT LE × N (offset in bytes from the start of the Request Data to each sub-request)
Sub-request 1      : complete Message Router request
...
```
Reply (0x8A) is symmetric: Number of Replies + offset array + each complete reply. Real example in the manual reading `ports` and `ControlWord` in a single frame.

**Tag listing — Symbol Object (Class 0x6B)** with **Get_Instance_Attribute_List (0x55)**, attributes 1 (Symbol Name) and 2 (Symbol Type):
```
Req: 55 03 | 20 6B 25 00 <inst_lo> <inst_hi> | 02 00 | 01 00 | 02 00
Rep (0xD5): status 0x06 (more data) or 0x00, followed by repeated:
     Instance ID (UDINT 4B) | Name Length (UINT 2B) + chars | Symbol Type (WORD 2B)
```
Iteration: start at instance 0, and on each response with status 0x06 take the last Instance ID returned, add 1, and request again; stop on status 0x00. Instance IDs have gaps (they are not consecutive).

**Symbol Type decoding (16 bits)** (1756-PM020 p. 50):
```
bit 15    : 0 = atomic tag, 1 = structure
bit 12    : 1 = system tag (reserved, do NOT access)
bits 14-13: array dimensions (00=0, 01=1 dim, 10=2 dims, 11=3 dims)
If bit15=0 (atomic): bits 7-0 = tag type reporting param (0xC1, 0xC3, 0xC4, 0xCA...);
                      if it is a BOOL (0xC1), bits 10-8 = bit position (0-7)
If bit15=1 (struct): bits 11-0 = Instance ID of the Template object defining the structure
```
Rules to isolate user tags: discard bit12=1 (system), names with a leading double underscore (`__`) or containing a colon (`:`, Module-Defined), and validate ranges (atomics 0x001-0x0FF, structs 0x100-0xEFF).

**Template Object (Class 0x6C)** — `Get_Attribute_List (0x03)` for the header:
```
Attr 1: Structure Handle (UINT)   → tag type of the structure (with 0xA0 0x02)
Attr 2: Template Member Count (UINT)
Attr 4: Template Object Definition Size (UDINT, in 32-bit WORDS)
Attr 5: Template Structure Size (UDINT, bytes on the wire when reading the whole struct)
```
Example: `03 03 | 20 6C 25 00 E9 02 | 04 00 | 04 00 05 00 02 00 01 00`. The response (0x83) returns, for each attribute: attr id (UINT) + status (UINT) + value.

**Read Template (0x4C on Class 0x6C)**: request data = **Offset (DINT 4B)** + **number of bytes to read (UINT 2B)**. The number of bytes = **(Attr4 × 4) − 23** (the 23 header bytes are not transmitted). If it does not fit, status 0x06 and continue with offset = bytes received + 1.

Format of the member definition returned (per member, verified against the `STRUCT_B` example):
```
Member i (8 bytes):
   INFO (UINT, lower 16b): 0 if atomic | size if array | bit position if BOOL
   Data Type (UINT, upper 16b): CIP code (0xC1, 0xC3, 0xCA... or 0x8xxx if nested struct)
   Offset (UDINT, 4B): member's offset within the struct's stream
```
After all members: **Template Name** (null-terminated, format `Name;n...`) followed by the **names of each member** (null-terminated). Real example: BOOL `pilot_on`, INT[12] `hourlyCount`, REAL `rate` → members with offsets 0, 4, 0x1C; BOOLs are mapped to a hidden host SINT (name with `ZZZZZZZZZZ` prefix), with 3 bytes of pad for alignment.

**Routing**: for ControlLogix the connection path (or the Unconnected Send route path) points to the controller's slot: port segment `01 <slot>` (backplane) + Message Router `20 02 24 01`. Micro800 and single-port controllers **do not require routing** (direct path to the Message Router).

**Change detection**: periodically read attributes 1,2,3,4,10 of the **Controller Object (Class 0xAC)** with Get_Attribute_List; if they change, refresh the symbol/template list. General Status 0x05 when reading them = project download in progress.

---

## 8. DISCOVERY

**ListIdentity via UDP broadcast on 44818**: send an encapsulation header with Command=0x0063, Length=0, Session Handle=0 to `255.255.255.255:44818` (or the subnet broadcast). Each EtherNet/IP device responds with its Identity item (0x000C, §1). No session required. This is the basis of the RSLinx/EIPScanner "browse". ListServices (0x0004) via broadcast also works for discovering capabilities.

---

## KNOWN IMPLEMENTATION PITFALLS

1. **Big-endian sockaddr**: in items 0x8000/0x8001 and in ListIdentity, `sin_family`/`sin_port`/`sin_addr` are in network byte order even though everything else is LE. Classic mistake: reading them as LE and getting reversed ports/IPs.
2. **Odd EPATH pad**: the ANSI symbolic segment (0x91 + len + chars) needs a 0x00 padding byte if the number of chars is odd, so that the Request Path Size (in words) is a whole number. Forgetting it produces status 0x04/0x26. Same with Unconnected Send: pad after the embedded message if its size is odd.
3. **Logix STRING**: the predefined Logix STRING type is NOT a standard CIP STRING; it is a structure with `DINT LEN` (4 bytes) + `SINT DATA[82]` (82 fixed bytes), 88 bytes total. It must be read as a struct, not as STRING 0xD0.
4. **Tag type match on Write**: the controller rejects (0xFF/0x2107) if the Tag Type sent does not exactly match the tag's; for structures you must send `A0 02 <handle>` with the correct template handle.
5. **Alignment in templates**: structures start and end on a 32-bit boundary; SINT on 8b, INT on 16b, DINT/REAL/arrays on 32b. There are pad bytes (visible on the wire, not in Data Monitor) — you must respect the template's offsets, not assume compact packing.
6. **BOOLs in UDTs**: they are grouped into a hidden host SINT (`ZZZZZZZZZZ` prefix); up to 8 contiguous BOOLs share a SINT. BOOL arrays are multiples of BOOL[32] (a DWORD array). The visible BOOL member shares its offset with its host SINT.
7. **Asymmetric Run/Idle**: O→T normally carries a 4-byte run/idle header, T→O often does not. Subtracting those 4 bytes incorrectly (or the 2 bytes of the class 1 sequence count) throws off the assembly size and the Forward Open fails with 0x0127/0x0128 (invalid connection size).
8. **Monotonic sequence numbers**: the 32-bit sequence number of the Sequenced Address Item (I/O) and the 16-bit count must never decrement; the consumer discards old/duplicate packets based on this value. Resetting it to a lower value breaks the connection.
9. **Connection ID generation**: the originator generates unique IDs (usually random/incremental) for O→T and T→O; the connection serial number + vendor id + originator serial number must be unique per open connection or the target responds 0x0100 (duplicate/in use). Reusing the triad after an unclean close causes 0x0100 until the target's watchdog expires.
10. **Session handle 0**: RegisterSession is sent with handle 0 in the header; use the returned handle in ALL subsequent messages. Sending SendRRData with handle 0 or an invalid handle returns encapsulation status 0x0064.
11. **RPI in microseconds**: the Forward Open RPIs are in µs (an RPI of 10 ms = 10000). Confusing ms/µs makes the target reject with 0x0111 (RPI not supported).
12. **Fragmentation in bytes vs elements**: the Byte Offset of Read/Write Tag Fragmented is always in bytes, not in number of elements; they only coincide when the type is SINT (1 byte). Examples in the manual show offsets like 490, 980, 1470 for SINTs but they would be ×2/×4 for INT/DINT.
13. **Encapsulation Inactivity Timeout**: the TCP/IP object closes the TCP session after 120 s of inactivity by default (attribute 13). Sending periodic NOPs or traffic keeps the session alive.
14. **Multiple Service Packet not for verification writes**: the manual warns against bundling the Controller Object attribute check with a Write Tag in the same Multiple Service, because the write would execute before knowing whether the tag definition needs to be re-read.

---

## URLs consulted

- Wireshark EtherNet/IP dissector: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-enip.c
- Wireshark CIP dissector (header): https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-cip.h
- OpENer encapsulation: https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/encap.c
- OpENer Connection Manager: https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/cipconnectionmanager.c
- OpENer Connection Manager (header, extended status): https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/cipconnectionmanager.h
- OpENer TCP/IP Interface (multicast): https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/ciptcpipinterface.c
- OpENer I/O connection (run/idle): https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/cipioconnection.c
- OpENer ciptypes.h: https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/ciptypes.h
- EIPScanner NetworkConnectionParams.h: https://github.com/nimbuscontrols/EIPScanner/blob/master/src/cip/connectionManager/NetworkConnectionParams.h
- pycomm3 data_types.py: https://github.com/ottowayi/pycomm3/blob/master/pycomm3/cip/data_types.py
- pycomm3 services.py: https://github.com/ottowayi/pycomm3/blob/master/pycomm3/cip/services.py
- scala-ethernet-ip LargeForwardOpen.scala: https://github.com/kevinherron/scala-ethernet-ip/blob/master/enip-core/src/main/scala/com/digitalpetri/ethernetip/cip/services/LargeForwardOpen.scala
- Rockwell 1756-PM020 Logix 5000 Data Access: https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf
- ODVA PUB00213 Quick Start for Vendors: https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf
- ODVA PUB00123 CIP and Family of CIP Networks: https://www.odva.org/wp-content/uploads/2020/06/PUB00123R1_Common-Industrial_Protocol_and_Family_of_CIP_Networks.pdf
- ODVA PUB00070 Recommended Functionality for EtherNet/IP Devices: https://www.odva.org/wp-content/uploads/2020/05/PUB00070_Recommended-Functionality-for-EIP-Devices-v10.pdf
- TI TCP/IP Interface Object (0xF5): https://software-dl.ti.com/mcu-plus-sdk/esd/AM64X/08_01_00_07/exports/docs/industrial_protocol_docs/am64x/ethernetip_adapter/group___e_i___a_p_i___a_d_p___t_c_p.html
- TI Ethernet Link Object (0xF6): https://software-dl.ti.com/mcu-plus-sdk/esd/AM64X/08_02_00_31/exports/docs/industrial_protocol_docs/am64x/ethernetip_adapter/group___e_i___a_p_i___a_d_p___e_t_h_e_r_n_e_t.html
- SCADA Protocols — CIP General Status Codes: https://scadaprotocols.com/cip-general-status-codes-reference/
- SCADA Protocols — CIP Device Profiles: https://scadaprotocols.com/cip-device-profiles-guide/
- CIP Vol 2 (infrastructure/multicast reference): http://read.pudn.com/downloads648/doc/comm/2625669/CIP_Vol2_1.4.pdf

---

**Coverage summary**: the report covers the 8 requested sections with exact byte layouts verified against real source code (Wireshark, OpENer, EIPScanner, pycomm3, scala-ethernet-ip) and against the 1756-PM020 manual read page by page. The most solid data (with real wire byte examples) are the Logix services, the Symbol/Template object, and the encapsulation header. The multicast formula and the run/idle handling come directly from the OpENer code. The only things I could not extract verbatim from the closed ODVA spec (PUB00138/CIP Vol 1-2) are a few minor bit tables, which I reconstructed from the matching OSS implementations.
