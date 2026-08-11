# ImShark User Guide

ImShark is an offline packet analyzer with a Wireshark-like layout: a packet list on top, the protocol tree and a
hex/ASCII view below, a display-filter bar and a main menu. This guide describes what the application does today; every
menu and shortcut named here is in the code (`src/ui/`). What is and is not decoded per protocol is in
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) and [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

On macOS the Command key takes the place of Ctrl in every shortcut below (Dear ImGui swaps the two on macOS).

> Screenshots: **TODO.** They could not be captured non-interactively on the machine this guide was written on
> (`screencapture` produced a black image because Screen Recording is not permitted for the terminal). The planned set,
> to be saved as small PNGs under `docs/images/`: `main-window.png` (packet list, tree, hex view on
> `tests/data/sample.pcap`), `filter-help.png` (Display Filter Reference), `follow-stream.png`, `statistics.png`,
> `decode-as.png`, `preferences-tls.png`.

## Contents

[Opening files](#opening-files) - [The main window](#the-main-window) - [Display filters](#display-filters) -
[Finding packets](#finding-packets) - [Coloring](#coloring) - [Statistics](#statistics) - [Follow stream](#follow-stream) -
[Export](#export) - [Capture file properties](#capture-file-properties) - [Live capture](#live-capture) -
[TLS key log](#tls-key-log) - [Decode As](#decode-as) - [Settings](#settings) - [Keyboard shortcuts](#keyboard-shortcuts)

## Opening files

- **File > Open...** (Ctrl+O) opens a file chooser; **File > Open Recent** lists the last 10 files (**Clear Recent** empties
  it); dropping a file on the window opens it; `imshark capture.pcap` on the command line opens it at start.
- Readable formats: classic **pcap** (both byte orders, microsecond and nanosecond timestamps), **pcapng**, **Sun snoop**,
  **Microsoft Network Monitor 2.x** (`.cap`), **Endace ERF** and **AIX iptrace 2.0**, and pcap or pcapng compressed with
  **gzip** (`.gz`). The format is recognised by its magic number, not the extension (ERF has none: it is recognised by a
  plausible first record). Frames of a medium ImShark cannot decode (Token Ring, FDDI, ATM, ...) are listed as
  "Unsupported link type" and their bytes are shown as data; the status bar says how many frames were affected.
- Loading runs in the background with a progress bar and a Cancel button; the list fills when it is done. Damaged or
  truncated files load as far as they are readable, and problems are shown in the status bar.
- **File > Close File** (Ctrl+W) closes the capture.

## The main window

- **Packet list** columns: No., Time, Source, Destination, Protocol, Length, Info. Click a header to sort; select with
  the mouse or with Up/Down, PgUp/PgDn, Home/End; right-click a row for Follow TCP/UDP Stream and Copy Row / Source /
  Destination / Info. The splitter between list and details is draggable and remembered.
- **Packet details**: the protocol tree of the selected packet. Selecting a field highlights its bytes; right-click for
  Copy, Copy Value and Copy Bytes as Hex / ASCII.
- **Bytes** pane: hex and ASCII. Clicking a byte selects the most specific field containing it; the selection can be copied
  (Ctrl+C while hovering, or right-click: Copy Selection as Hex / ASCII, Copy All as Hex Dump).
- The Time column format is set in **View > Time Display Format**: seconds since beginning of capture, since previous
  packet, UTC date and time, or seconds since epoch. **View > Dark Theme / Light Theme** switches the theme.

## Display filters

Type an expression in the filter bar (Ctrl+L focuses it) and press Enter or **Apply**. The bar turns red with the error
text and position while the expression is invalid and green while a filter is applied; **X** clears it; the arrow button
shows the last 15 filters used; **?** opens the *Display Filter Reference* window, a searchable list of every field with
click-to-insert and ready-made examples.

Syntax:

- Combine tests with `&&` `||` `!` (or `and` `or` `not`) and parentheses.
- Comparisons: `==` `!=` `<` `>` `<=` `>=` (or `eq ne lt gt le ge`), `contains` (substring), `matches` (regular expression;
  prefix `(?i)` to ignore case) and sets: `tcp.port in {80 443 8000..8100}`. `!=` is the exact negation of `==`.
- Text values are quoted: `info contains "GET"`. IP addresses may be networks: `ip.addr == 10.0.0.0/8`,
  `ipv6.src == 2001:db8::/32`.
- A bare protocol or flag name is true when it is present: `dns or arp`, `tcp.flags.syn && !tcp.flags.ack`, `malformed`.
- Filters read what the packet **summary** holds, never the details tree. Not every protocol has fields yet (SIP, RTP, Modbus,
  DNP3 and CAN have none; see KNOWN_ISSUES).

Examples:

```
tcp.port in {80 443} && !tcp.flags.rst
ip.addr == 10.0.0.0/8 && !arp
frame.len > 1000
frame.time_delta > 1.0
tcp.analysis.retransmission
tls.handshake.extensions_server_name contains "example"
```

**The complete list of fields, with type and description, is [FILTER_FIELDS.md](FILTER_FIELDS.md).** It is generated from
the field modules in `core/src/dissect/*_fields.cpp`, and a test fails when the two differ, so it is always the list this build
accepts. Field names are lower case.

Filters from statistics windows and from **Follow Stream > Filter Out This Stream** go through the same bar.

## Finding packets

**Ctrl+F** opens the find bar; F3 / Shift+F3 repeat the search forward / backward (even with the bar closed); Esc closes it.
Modes: *Text in summary* (source, destination, protocol, info), *Display filter* (next packet matching a filter),
*Hex bytes* (e.g. `47 45 54 20`) and *Text in bytes* (inside the packet bytes). The search runs in the background.

## Coloring

Rows are colored by the first enabled rule whose display filter matches. **View > Colorize Packet List** turns it on or
off; **View > Coloring Rules...** edits the rules: enable, name, filter, background and text color, reorder (Up / Dn),
remove (X), **New**, **Reset to Defaults**, **Apply**. A rule with an invalid filter is reported and skipped. The
built-in rules color malformed packets, TCP resets, TCP analysis problems, SYN/FIN, ICMP, ARP, UDP and TCP. Your rules are
stored in the settings file.

## Statistics

The **Statistics** menu opens four windows; each has **Limit to displayed packets**:

- **Expert Information**: findings by severity (chat, note, warning, error) with a summary line each, for example TCP
  analysis, bad checksums, malformed packets. Double-click a line to apply its filter.
- **Protocol Hierarchy**: the protocol tree (including encapsulations such as VLAN, MPLS, GRE, IP-in-IP and TLS carrying
  HTTP) with packet and byte counts.
- **Conversations** and **Endpoints**: tabs per address kind (IPv4, IPv6, TCP, UDP, SCTP, Ethernet, WLAN, Bluetooth, USB) with packet and
  byte counts per direction. Double-click a row to filter on it; right-click for **Apply as Filter** / **Copy Filter**.

## Follow stream

**Analyze > Follow TCP Stream** / **Follow UDP Stream** (also in the packet list's right-click menu; enabled when the
selected packet is TCP or UDP over IP) reassembles the conversation. The window shows the byte counts per direction, two
colors for the two directions, and lets you choose the direction (entire conversation or one side) and the view (**ASCII**
or **Hex Dump**). A TCP stream offers **TLS (decrypted)** when keys are available (see below). **Copy**, **Save As...** (raw
bytes) and **Filter Out This Stream** are at the top. Bytes missing from the capture and streams cut at the size limit are
reported in the header line.

## Export

**File > Export Packets...** writes **All packets**, **Displayed packets** (those passing the filter, in list order) or the
**Selected packet** as **pcapng**, classic **pcap** (original frames and timestamps; microsecond resolution), **CSV** or
**JSON** (the packet list columns). Export runs in the background with Cancel; a cancelled export leaves no partial file.
Follow Stream's **Save As...** writes the raw bytes of the stream.

## Capture file properties

**File > Capture File Properties...** shows file name, size (compressed and decompressed for gzip), format, per-interface
link type, snap length, packet counts and drop counters, packet comments, name-resolution records, and a note about
embedded TLS secrets.

## Live capture

The **Capture** menu needs a build with libpcap (Npcap on Windows); without it the menu is disabled and the tooltip says
why. Capturing needs privileges: `/dev/bpf*` access on macOS, `CAP_NET_RAW` on Linux.

- **Capture > Interfaces...** (Ctrl+K): choose the interface (name, description, addresses, flags), a BPF capture filter
  (validated while you type), the snap length and promiscuous mode. The last choices are saved.
- **Start** / **Stop** (Ctrl+E), **Restart** (Ctrl+R), **Auto-scroll During Capture**.
- While capturing, the list grows as packets arrive, the display filter and coloring apply to new packets, and the status
  bar shows "Capturing on <interface> - N packets, D dropped". A stopped capture behaves like an opened file (export,
  statistics, Follow Stream). Closing or quitting with an unsaved capture asks whether to export it or discard it.

## TLS key log

**Edit > Preferences...** has **Protocols > TLS**: the path of a (Pre)-Master-Secret log (the file `SSLKEYLOGFILE` points
to; **Browse...**, **Apply**/**Reload**, **Clear**). Captures are decrypted while loading, so changing the file loads the
open capture again; the status line reports how many secrets were read and whether the file is unreadable. Secrets stored
in a pcapng file (Decryption Secrets Blocks) are used automatically; the file you set takes precedence. Decrypted
application data appears in the details tree as "Decrypted TLS", HTTP/1.x and HTTP/2 are dissected inside it, and Follow
Stream's **TLS (decrypted)** shows it. Decryption needs an OpenSSL 3 build ("not available in this build" otherwise);
supported suites and limits (no 0-RTT, no renegotiation tracking) are in KNOWN_ISSUES. DTLS 1.2 AES-GCM is decrypted with the
same key log.

## Decode As

**Analyze > Decode As...** makes a port carry a protocol you choose, for traffic the automatic recognition does not catch.
**Add rule**, pick TCP or UDP, the port and the protocol, then **Apply** (the capture is loaded again; **Revert** discards
edits). Protocols offered (a name appears for the transports it supports):
`BGP`, `DCERPC`, `DHCP`, `DNP3`, `DNS`, `DTLS`, `FTP`, `FTP-DATA`, `HTTP`, `HTTP2`, `Kerberos`, `LDAP`, `MDNS`, `Modbus`,
`MySQL`, `NFS`, `NTP`, `PGSQL`, `Portmap`, `RTCP`, `RTP`, `RTSP`, `SCTP`, `SIP`, `SMB2`, `SMTP`, `SNMP`, `SSH`, `TDS`, `Telnet`,
`TFTP`, `TLS`. RTP and RTCP are reachable only this way. A test checks that this list equals the registry's.

## Settings

Settings are saved automatically in `settings.ini` in the per-user configuration folder: `~/Library/Application
Support/imshark/` on macOS, `$XDG_CONFIG_HOME/imshark/` (or `~/.config/imshark/`) on Linux, `%APPDATA%\imshark\` on Windows.
They hold the recent files and filter history, theme, time format, colorize switch, coloring rules, the list height, the TLS
key log path and the last live capture choices. A missing or damaged file gives the defaults; delete it to reset.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| Ctrl+O | Open a capture file |
| Ctrl+W | Close the file |
| Ctrl+L | Focus the display filter bar |
| Enter (in the filter bar) | Apply the filter |
| Ctrl+F | Open the find bar |
| F3 / Shift+F3 | Find next / previous |
| Esc | Close the find bar |
| Up / Down, PgUp / PgDn, Home / End | Move the selection in the packet list |
| Ctrl+C (hover the bytes pane) | Copy the selected bytes |
| Ctrl+K | Capture interfaces |
| Ctrl+E | Start / stop capture |
| Ctrl+R | Restart capture |
