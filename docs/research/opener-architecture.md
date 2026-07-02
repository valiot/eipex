# Technical report: OpENer architecture as a reference for an EtherNet/IP adapter in Elixir/OTP

## 1. Module structure

OpENer (C, CMake, `master` branch) is organized into three layers under `source/src/`:

- **`enet_encap/`** — EtherNet/IP encapsulation layer: `encap.c` (encapsulation commands), `cpf.c` (Common Packet Format), endianness conversion.
- **`cip/`** — CIP core: `cipmessagerouter.c`, `cipidentity.c`, `cipassembly.c`, `cipconnectionmanager.c`, `cipconnectionobject.c/.h`, `cipioconnection.c`, `ciptcpipinterface.c`, `cipethernetlink.c`, `cipepath.c`, `cipqos.c`, plus `ciptypes.h` with the base structures.
- **`ports/`** — platform code (POSIX, WIN32, MINGW, STM32) and `generic_networkhandler.c`, the shared socket event loop. The user application (e.g. `ports/POSIX/sample_application/sampleapplication.c`) implements mandatory callbacks: `ApplicationInitialization`, `HandleApplication`, `CheckIoConnectionEvent`, `AfterAssemblyDataReceived`, `BeforeAssemblyDataSend`, `ResetDevice`, `ResetDeviceToInitialConfiguration`, `RunIdleChanged`.

`encap.c` handles the 8 commands: NOP, ListServices, ListIdentity, ListInterfaces, RegisterSession, UnRegisterSession, SendRRData, and SendUnitData. TCP sessions live in a global array `g_registered_sessions[OPENER_NUMBER_OF_SUPPORTED_SESSIONS]` (20 by default) that maps session handle → socket. The encapsulation header is a fixed 24 bytes + 4 (command, length, session handle, status, 8-byte sender context, options). SendRRData/SendUnitData extract the interface handle and timeout, and pass the rest to CPF: `NotifyCommonPacketFormat()` (UCMM → Message Router) or `NotifyConnectedCommonPacketFormat()` (class 3 → Connection Manager). Interesting detail: UDP responses to ListIdentity are deferred with a random delay (`DelayedEncapsulationMessage`, `DetermineDelayTime()`) to avoid broadcast storms — in Elixir this is a trivial `Process.send_after/3`.

**Suggested OTP mapping:** one `Registry`/GenServer per TCP session under a `DynamicSupervisor` (here Elixir beats C's static array), with `ranch` or `gen_tcp` in active mode.

## 2. CIP object model and Message Router dispatch

The data model (in `ciptypes.h`) is a class → instances → attributes hierarchy:

- **`CipClass`**: `class_code`, `revision`, linked list of `instances`, array of `services`, access bitmasks (`get_single_bit_mask`, `set_bit_mask`, `get_all_bit_mask`) and `PreGet/PostGet/PreSet/PostSet` callbacks.
- **`CipInstance`**: `instance_number`, array of `CipAttributeStruct`, pointer to its class.
- **`CipAttributeStruct`**: number, CIP type, flags (`kGetableSingle`, `kSetable`, `kPreGetFunc`, `kPostSetFunc`, `kNvDataFunc`…), its own **encode/decode** functions and a pointer to the data. The attribute is "self-describing": there is no generic reflection-based getter/setter but rather a pair of serialization functions per attribute.
- **`CipServiceStruct`**: service code, `CipServiceFunction` pointer (receives instance, request, response, originator address and session) and name.

The construction API is `CreateCipClass()` → `AddCipInstance(s)()` → `InsertAttribute()` / `InsertService()` / `InsertGetSetCallback()`. The Message Router maintains a linked list `CipMessageRouterObject` (anchored at `g_first_object`); `RegisterCipClass()` adds classes. Dispatch in `NotifyMessageRouter()`: it parses service + EPATH with `DecodePaddedEPath()` (error → 0x04 Path Segment Error), looks up the class with `GetRegisteredObject()` (not found → 0x05 Path Destination Unknown), and `NotifyClass()` locates the instance and service in the table (not supported → 0x08). The response carries `reply_service = 0x80 | service`.

**OTP mapping:** the class registry is a `%{class_code => module}` map where each CIP class is a module implementing a behaviour (`handle_service/4`, `encode_attribute/2`, `decode_attribute/3`); instances can be structs in ETS or the state of a per-class GenServer. The per-attribute encode/decode pattern translates naturally to pattern matching on binaries.

## 3. Lifecycle of a Class 1 connection

**States** (`cipconnectionobject.h`, per CIP Vol 1 chapter 3-4): `NonExistent`, `Configuring`, `WaitingForConnectionID`, `Established`, `TimedOut`, `DeferredDelete`, `Closing`, `Invalid`. Instance types: `ExplicitMessaging`, `IO`, `IOExclusiveOwner`, `IOInputOnly`, `IOListenOnly`, `CipBridged`. Watchdog actions: `TransitionToTimedOut`, `AutoDelete`, `AutoReset`, `DeferredDelete`.

**Incoming Forward Open** (`cipconnectionmanager.c`): `ForwardOpen()`/`LargeForwardOpen()` → `ForwardOpenRoutine()`: (1) `ConnectionObjectInitializeFromMessage()` parses the request into a temporary object (`g_dummy_connection_object`); (2) the O→T/T→O connection type is validated and, if T→O is multicast, that the originator is on the same subnet; (3) `CheckForExistingConnection()` searches for duplicates by the **triad** (connection serial number, originator vendor id, originator serial number) → "connection in use or duplicate FO" error; (4) `ParseConnectionPath()` decodes the electronic key (vendor/type/product code/revision, with `CheckElectronicKeyData()`) and the consumed/produced assembly paths; (5) it dispatches to the `OpenConnectionFunction` registered per class via `g_connection_management_list` (`AddConnectableObject()`): `EstablishClass3Connection()` or `EstablishIoConnection()`. Errors return precise extended codes (`...ErrorInvalidOToTConnectionSize` with the correct size included, `...ErrorRpiValuesNotAcceptable`, `...OwnershipConflict`…). On success, `AddNewActiveConnection()` inserts into `connection_list` (doubly linked list) and the state transitions to `Established`. The Connection ID is generated with 16 bits of "incarnation ID" (unique per boot, seeded in `CipStackInit`) + counter/random.

**T→O production:** in `ManageConnections()` the `transmission_trigger_timer` is decremented; on expiry `SendConnectedData()` is called: it increments `eip_level_sequence_count_producing`, invokes `BeforeAssemblyDataSend()` (if it returns true it also increments the class 1 application sequence count), builds the CPF (Sequenced Address Item + Connected Data Item, optional 4-byte run/idle header) and sends over UDP port 2222. The timer is reloaded with the RPI.

**O→T consumption:** the network handler delivers datagrams to `HandleReceivedConnectedData()` → `GetConnectedObject()` by connection ID; it validates the originator's IP (anti-hijacking) and the sequence number with `SEQ_GT32()`; if it is new it resets the watchdog (`ConnectionObjectResetInactivityWatchdogTimerValue()`) and calls `HandleReceivedIoConnectionData()`: it consumes the 16-bit sequence count (class 1, discards duplicates with `SEQ_LEQ16`), the 32-bit run/idle header (bit 0 = Run, triggers `RunIdleChanged()`), and passes the payload to `NotifyAssemblyConnectedDataReceived()`.

**Timeout/Forward Close:** if `inactivity_watchdog_timer` (RPI × timeout multiplier) expires → `HandleIoConnectionTimeOut()` → `TimedOut` state and cascading closes (see §4). `ForwardClose()` searches by triad in the `Established`/`TimedOut` states, verifies that the closer is the same originator (`WrongCloser`) and invokes `connection_close_function()` → `CloseIoConnection()` → `CheckIoConnectionEvent(..., kIoConnectionEventClosed)` notification, socket closure and `NonExistent` state.

**OTP mapping:** each connection is an ideal candidate for `gen_statem` with the literal CIP states; watchdog and production are state timeouts (`state_timeout` / `{:timeout, :production}`), and the cascading close is coordinated via Registry + monitors.

## 4. Exclusive owner vs input-only vs listen-only

The application declares "connection points" with `ConfigureExclusiveOwnerConnectionPoint(num, output_assembly, input_assembly, config_assembly)` and Input-Only/Listen-Only analogues (quantities fixed by macros: 1 exclusive owner, 1 input-only with 3 connections per path, 1 listen-only with 3 per path in the example config). `EstablishIoConnection()` classifies the Forward Open according to which connection point matches the requested paths: **exclusive owner** consumes O→T and produces T→O (only one may exist per output assembly — conflict → ownership conflict); **input-only** consumes only heartbeat (assembly with no data) and produces; **listen-only** requires that a non-listen-only connection already exists producing on that assembly (multicast) and "listens" to that production. On exclusive owner timeout, `CloseAllConnectionsForInputWithSameType()` also tears down the dependent input-only and listen-only connections; in multicast there is a "master" handover: `transfer_master_connection()`/`GetNextNonControlMasterConnection()` transfers the producing socket to another active connection before closing the listen-only ones.

## 5. Multicast vs point-to-point

`OpenCommunicationChannels()` branches by type in each direction: `OpenConsumingPointToPointConnection`, `OpenProducingPointToPointConnection`, `OpenMulticastConnection`, `OpenProducingMulticastConnection`. The multicast address comes from the TCP/IP Interface object (attribute 9, `g_tcpip.mcast_config.starting_multicast_address`), computed by `CipTcpIpCalculateMulticastIp()` following the spec's algorithm: base 239.192.1.0 + ((host_id − 1 masked to 10 bits) << 5). The TTL is attribute 8 (`mcast_ttl_value`, default 1). Default port `kOpenerEipIoUdpPort` = 2222, with QoS/DSCP via `SetQos()`. The adapter communicates the multicast address to the scanner in the Sockaddr Info Item of the Forward Open response.

## 6. Tick/timer API

The timing heart: `NetworkHandlerProcessCyclic()` runs `select()` with a timeout adjusted to wake up every `kOpenerTimerTickInMilliSeconds` (10 ms). It accumulates the actual elapsed time (`GetMilliSeconds()`, `g_actual_time − g_last_time`) and when it exceeds the tick it calls `ManageConnections(elapsed_time)` — which decrements watchdogs and production triggers of all connections — plus `ManageEncapsulationMessages()` and the `RegisterTimeoutChecker()` hooks. Everything is **single-threaded**: network, timers and application (`HandleApplication()` is invoked at the start of each cycle). In Elixir replicating the global tick is not advisable: each connection (`gen_statem`) can carry its own timers with millisecond precision, eliminating the jitter of a centralized scheduler; a tick is only worth keeping for aggregates (e.g. delayed ListIdentity).

## 7. Exposing assemblies to the application

`CreateAssemblyObject(instance_number, buffer, length)` creates an instance of class 0x04 whose **attribute 3** wraps the user's buffer in a `CipByteArray` (no copy; attribute 4 = size). Services: Get/SetAttributeSingle. Incoming data (implicit or explicit Set on config) → exact length validation, `memcpy` into the buffer and `AfterAssemblyDataReceived(instance)` callback (the app validates, especially config; it may reject). Before producing, `BeforeAssemblyDataSend(instance)` lets the app refresh the buffer. The demo uses instances 100 (input), 150 (output), 151 (config), 152/153 (input-only/listen-only heartbeats), 154 (explicit). In Elixir mutable shared buffers do not exist: the equivalent is an ETS/`:atomics`/GenServer "AssemblyStore" with binary `get/put`, or callbacks to an application behaviour with the binary as the value.

## 8. Identity configuration

The identity (class 0x01, attributes 1–7) takes defaults from macros `OPENER_DEVICE_VENDOR_ID`, `OPENER_DEVICE_TYPE`, `OPENER_DEVICE_PRODUCT_CODE`, `OPENER_DEVICE_MAJOR/MINOR_REVISION`, `OPENER_DEVICE_NAME`, generated by CMake from `source/src/ports/devicedata.h.in` (placeholders `@OpENer_Device_Config_*@`). The serial number is set at runtime (`SetDeviceSerialNumber()`), and there are dynamic setters (`SetDeviceStatus`, `SetDeviceProductCode`, etc.). Stack limits in `opener_user_conf.h` (sessions, explicit connections = 6, tick, etc.). The Reset service (type 0 → `ResetDevice`, type 1 → `ResetDeviceToInitialConfiguration`) delegates to the app. In Elixir: identity config as a keyword list in `Application.get_env` or a struct passed to `start_link`, plus the EDS file as a data artifact (OpENer includes it in `data/`).

## 9. Lessons and limitations

- **Single-threaded by design** (comments assume "one CPF at a time", massive global state: `g_tcpip`, `g_dummy_connection_object`, global lists). Porting it as-is to concurrent processes requires redesigning data ownership; OTP solves this with per-process ownership.
- **Static memory and buffer arithmetic in C**: the currently open issues (#567–#582) are almost all overflows/OOB in EPATH, CPF and ForwardOpen parsing (e.g. `ParseConnectionPath()` with unbounded segments). Key lesson: binary parsing is the attack surface; binary pattern matching in Elixir eliminates this entire class of bugs, but lengths must be validated explicitly to respond with the correct CIP error codes instead of crashing.
- Compile-time limits (number of sessions/connections) and build-time-fixed identity — in Elixir everything can be dynamic.
- Multicast handling with master handover and cascading listen-only closure is the part with the most implicit shared state: modeling it explicitly (one "ProducerGroup" process per produced assembly) will avoid the historical bugs in that area.

## EIPScanner (originator side, C++)

- **`SessionInfo`**: opens TCP, sends RegisterSession (`EncapsPacketFactory().createRegisterSessionPacket()`), stores `_sessionHandle`; `sendAndReceive()` reads the header (24 B), extracts the length, validates status and session handle; the destructor sends UnRegisterSession. Maps 1:1 to a session GenServer.
- **`MessageRouter::sendRequest(si, service, epath, data)`**: builds a `MessageRouterRequest`, wraps it in CPF (Null Address Item + Unconnected Data Item), sends it as SendRRData and expands the `MessageRouterResponse` (general status + additional status). It is the originator's UCMM primitive.
- **`ConnectionManager::forwardOpen(si, params)`**: increments the serial, generates `t2oNetworkConnectionId` (P2P) or `o2tNetworkConnectionId` (multicast, `_incarnationId << 16` + counter), sends service 0x54/0x5B to the EPath (6,1), parses the `ForwardOpenResponse` (O2T/T2O IDs and APIs), creates the `IOConnection`, indexes it in `_connectionMap` by T2O connection ID, and prepares the UDP 2222 socket using the response's Sockaddr Info Item if present.
- **`IOConnection`**: stores RPIs in µs, sizes, `_o2tRealTimeFormat`/`_t2oRealTimeFormat` flags (32-bit run/idle header), sequence numbers and handlers (`setReceiveDataListener`, `setSendDataListener`, `setCloseListener`, `setDataToSend`). `notifyReceiveData()` strips run/idle and the sequence count, validates the size and resets the timeout counter; `notifyTick()` (called from `ConnectionManager::handleConnections`, a loop with `select()`) accumulates time, produces every `_o2tAPI` µs (increments the sequence, builds the CPF with run/idle = 1 RUN) and closes the connection if `_connectionTimeoutCount` exceeds `multiplier × _t2oAPI`. It is the exact mirror of the adapter side and validates the same per-connection `gen_statem` + timers model for a future Elixir originator.

## Consulted URLs

- https://github.com/EIPStackGroup/OpENer
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/opener_api.h
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/enet_encap/encap.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipmessagerouter.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/ciptypes.h
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipconnectionobject.h
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipconnectionmanager.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipioconnection.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipassembly.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipidentity.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/ciptcpipinterface.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/cip/cipethernetlink.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/ports/generic_networkhandler.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/ports/POSIX/main.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/ports/POSIX/sample_application/sampleapplication.c
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/ports/POSIX/sample_application/opener_user_conf.h
- https://raw.githubusercontent.com/EIPStackGroup/OpENer/master/source/src/ports/devicedata.h.in
- https://github.com/EIPStackGroup/OpENer/tree/master/source/src/ports
- https://github.com/EIPStackGroup/OpENer/issues
- https://github.com/nimbuscontrols/EIPScanner
- https://raw.githubusercontent.com/nimbuscontrols/EIPScanner/master/src/SessionInfo.cpp
- https://raw.githubusercontent.com/nimbuscontrols/EIPScanner/master/src/MessageRouter.cpp
- https://raw.githubusercontent.com/nimbuscontrols/EIPScanner/master/src/ConnectionManager.cpp
- https://raw.githubusercontent.com/nimbuscontrols/EIPScanner/master/src/IOConnection.cpp
