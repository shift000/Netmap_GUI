"""
Protocol reference documentation for netmap wiki.
Each protocol entry contains:
  description, ports, flags, header_fields, nc_example, reference
"""

PROTOCOLS = {

    "HELP": {
        "_section": "Help",
        "description": (
            "Netmap filter and control reference. Press H in the main view for keyboard shortcuts."
        ),
        "ports": [],
        "flags": {},
        "header_fields": [],
        "nc_example": "",
        "notes": "",
    },

    "FILTER_F": {
        "_section": "Help",
        "description": (
            "Text filter (F key) — searches packet metadata for a substring. "
            "Searches across: source IP, destination IP, protocol, source port, destination port, info text. "
            "Case-insensitive. Use * as wildcard."
        ),
        "ports": [],
        "flags": {},
        "header_fields": [
            ("Examples", "", ""),
            ("  *10.10.*", "wildcard", "Match any packet mentioning 10.10. (e.g. 10.10.0.1, 10.10.255.250)"),
            ("  dns,dhcp", "multi-term", "Match if any term appears (OR logic)"),
            ("  192.168.1.100", "ip-address", "Match packets to/from specific host"),
            ("  google.com", "domain", "Match DNS queries to google.com"),
            ("  SYN", "protocol-flag", "Match TCP packets with SYN flag in info"),
            ("  GET /api", "http", "Match HTTP requests with /api in the path"),
            ("  *.local", "zeroconf", "Match mDNS/Bonjour queries for .local domains"),
            ("  '' (empty)", "reset", "Clear the filter and show all traffic"),
        ],
        "nc_example": (
            "# Enter via F key, type filter, press ENTER to apply.\n"
            "# BACKSPACE to delete characters, ESC to cancel.\n"
            "# Examples to try:\n"
            "#   *192.168.*\n"
            "#   dns,http\n"
            "#   TCP and SYN"
        ),
        "notes": (
            "The filter matches against the raw packet string. "
            "Using wildcards like *10.10.* captures any packet mentioning 10.10 — "
            "useful to isolate subnets or specific hosts. "
            "Multiple comma-separated terms use OR logic: 'dns,dhcp' shows both DNS and DHCP packets."
        ),
        "reference": "Press F in netmap to open the filter dialog.",
    },

    "FILTER_P": {
        "_section": "Help",
        "description": (
            "Protocol filter (P key) — shows only packets of the specified protocol type. "
            "Unlike the text filter, this is an exact match on the protocol field. "
            "Multiple protocols can be specified as a comma-separated list."
        ),
        "ports": [],
        "flags": {},
        "header_fields": [
            ("Examples", "", ""),
            ("  TCP", "single", "Show only TCP packets"),
            ("  UDP,DNS", "multi", "Show only UDP and DNS packets"),
            ("  ARP,ICMP", "multi", "Show ARP and ICMP (useful for network diagnostics)"),
            ("  TLS_CLIENT_HELLO", "specific", "Show only TLS ClientHello messages"),
            ("  HTTP,TLS", "web", "Show HTTP and HTTPS traffic"),
            ("  '' (empty)", "reset", "Clear protocol filter and show all"),
        ],
        "nc_example": (
            "# Enter via P key, type protocol name, press ENTER.\n"
            "# Examples:\n"
            "#   TCP\n"
            "#   DNS,DHCP\n"
            "#   ARP,ICMP\n"
            "# Press ENTER with empty input to clear the filter."
        ),
        "notes": (
            "Protocol names are case-insensitive. "
            "Use the Wiki (W key) to see all available protocol names and their purposes. "
            "TShark internally names protocols in capital letters: TCP, UDP, DNS, HTTP, TLS, ARP, ICMP, IGMPV3, DHCP, mDNS, SSDP, NBNS, LLMNR."
        ),
        "reference": "Press P in netmap to open the protocol filter dialog.",
    },

    "FILTER_O": {
        "_section": "Help",
        "description": (
            "Port filter (O key) — shows only packets where source or destination port contains the entered substring. "
            "Partial match: entering '443' matches both source and destination port 443."
        ),
        "ports": [],
        "flags": {},
        "header_fields": [
            ("Examples", "", ""),
            ("  443", "https", "Show HTTPS traffic on port 443"),
            ("  53", "dns", "Show DNS queries and responses"),
            ("  67", "dhcp-server", "Show DHCP server messages"),
            ("  5353", "mdns", "Show mDNS multicast traffic"),
            ("  22", "ssh", "Show SSH connections"),
            ("  80,443", "note", "Port filter only accepts one substring — use text filter (F) for multiple ports"),
            ("  '' (empty)", "reset", "Clear port filter"),
        ],
        "nc_example": (
            "# Enter via O key, type port number, press ENTER.\n"
            "# Examples:\n"
            "#   53\n"
            "#   443\n"
            "#   5353\n"
            "# Note: only a single substring is supported, not '80,443'."
        ),
        "notes": (
            "Port filter does a substring match on both source and destination port fields. "
            "Entering '53' matches port 53, 5353, 15353, etc. "
            "For multiple ports simultaneously, use the text filter (F): '*53*' matches 53, 5353, etc. "
            "For protocol-specific ports, use the protocol filter (P) instead."
        ),
        "reference": "Press O in netmap to open the port filter dialog.",
    },

    "TCP": {
        "description": (
            "Transmission Control Protocol — connection-oriented, reliable, ordered byte stream. "
            "Data arrives intact and in sequence via acknowledgments, retransmissions, and flow control. "
            "The 3-way handshake establishes a connection: SYN → SYN-ACK → ACK."
        ),
        "ports": [20, 21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443],
        "flags": {
            "URG": "Urgent Pointer field is significant",
            "ACK": "Acknowledgment field is significant",
            "PSH": "Push — data passed to application immediately",
            "RST": "Reset the connection (abort)",
            "SYN": "Synchronize sequence numbers (connection establishment)",
            "FIN": "No more data from sender (connection termination)",
        },
        "header_fields": [
            ("Source Port", "16 bits", "Sender's port number"),
            ("Destination Port", "16 bits", "Receiver's port number"),
            ("Sequence Number", "32 bits", "Byte position in the data stream, SYN packet sets initial seq"),
            ("Acknowledgment Number", "32 bits", "Next expected byte (ACK must be set)"),
            ("Data Offset + Reserved", "4 + 6 bits", "Header length in 32-bit words + reserved (must be 0)"),
            ("TCP Flags", "6 bits", "CWR | ECE | URG | ACK | PSH | RST | SYN | FIN (8 bits with NS)"),
            ("Window Size", "16 bits", "Receive buffer size for flow control"),
            ("Checksum", "16 bits", "Header + data integrity check"),
            ("Urgent Pointer", "16 bits", "Points to last byte of urgent data (only if URG set)"),
            ("Options", "0-320 bits", "Optional: MSS, Window Scale, SACK, Timestamp (variable, padded to 32-bit)"),
        ],
        "nc_example": (
            "# Raw HTTP GET request:\n"
            "echo -ne 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n' | nc example.com 80\n\n"
            "# Raw HTTP POST:\n"
            "echo -ne 'POST /api HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Length: 27\\r\\n\\r\\n{\\\"key\\\":\\\"val\\\"}' | nc example.com 80\n\n"
            "# TCP connect and interact:\n"
            "nc -nv 192.168.1.1 22  # SSH handshake"
        ),
        "notes": (
            "TCP 3-way handshake: SYN (client) → SYN-ACK (server) → ACK (client). "
            "Connection termination: FIN → ACK → FIN → ACK (both sides). "
            "Use 'ss -tulnp' or 'netstat -tulnp' to see active TCP sockets. "
            "Raw TCP requires CAP_NET_RAW or sudo."
        ),
        "reference": "RFC 793",
    },

    "UDP": {
        "description": (
            "User Datagram Protocol — connectionless, unreliable, no ordering guarantees. "
            "Simpler than TCP: no handshake, no acknowledgments, no retransmission. "
            "Used where speed matters more than reliability: DNS, DHCP, VoIP, streaming, gaming."
        ),
        "ports": [53, 67, 68, 69, 123, 161, 162, 5353, 1194],
        "flags": {},
        "header_fields": [
            ("Source Port", "16 bits", "Sender's port (0 if unused, e.g., DNS queries)"),
            ("Destination Port", "16 bits", "Receiver's port"),
            ("Length", "16 bits", "Header + payload length in bytes"),
            ("Checksum", "16 bits", "Header + pseudo-header + payload integrity check"),
        ],
        "nc_example": (
            "# DNS query for 'example.com' (A record) — raw UDP:\n"
            "echo -ne '\\xaa\\xbb\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65\\x03\\x63\\x6f\\x6d\\x00\\x00\\x01\\x00\\x01' | nc -u 8.8.8.8 53\n\n"
            "# With socat:\n"
            "socat - UDP-DATAGRAM:8.8.8.8:53,crlf"
        ),
        "notes": (
            "UDP is stateless — no SYN/ACK. "
            "A response comes from the server's source port (53) back to our source port. "
            "Source port should be >= 1024 for client queries (unprivileged). "
            "Use 'ss -ulnp' or 'netstat -ulnp' for open UDP sockets."
        ),
        "reference": "RFC 768",
    },

    "ICMP": {
        "description": (
            "Internet Control Message Protocol — used for error reporting and network diagnostics. "
            "ICMP is the protocol behind 'ping' and 'traceroute'. "
            "Operates at network layer (IP protocol number 1) — no ports. "
            "Type and Code fields together identify the specific message."
        ),
        "ports": [],  # Layer 3 — no ports, IP protocol number 1
        "flags": {},
        "header_fields": [
            ("Type", "8 bits", "Message class: 0=Echo Reply, 3=Dest Unreachable, 8=Echo Request, 11=Time Exceeded"),
            ("Code", "8 bits", "Subtype within the type: e.g., Type 3 Code 1=Host Unreachable"),
            ("Checksum", "16 bits", "ICMP header + data integrity check"),
            ("Rest of Header", "32 bits", "Content varies by Type/Code: for Echo: ID (16) + Sequence (16)"),
        ],
        "nc_example": (
            "# Ping (ICMP Echo Request type 8, code 0):\n"
            "ping -c 3 192.168.1.1\n\n"
            "# With hping3:\n"
            "sudo hping3 -1 -c 1 192.168.1.1\n\n"
            "# Raw ICMP with scapy:\n"
            "python3 -c \"from scapy.all import *; send(IP(dst='192.168.1.1')/ICMP(type=8,code=0)/'test')\""
        ),
        "notes": (
            "Common types: 0=Echo Reply, 3=Destination Unreachable, 8=Echo Request, 11=Time Exceeded. "
            "Ping uses Type 8 (Echo Request), destination replies with Type 0 (Echo Reply). "
            "ICMP is rate-limited by most kernels. "
            "Traceroute uses Type 11 (Time Exceeded) with increasing TTL. "
            "Requires CAP_NET_RAW or sudo for raw ICMP."
        ),
        "reference": "RFC 792",
    },

    "DNS": {
        "description": (
            "Domain Name System — hierarchical distributed naming system that maps domain names "
            "to IP addresses. Operates on port 53 (both TCP and UDP). "
            "DNS queries are typically UDP; TCP is used for zone transfers, DNS over TCP, and responses >512 bytes."
        ),
        "ports": [53],
        "flags": {
            "QR=0": "Query (client → server)",
            "QR=1": "Response (server → client)",
            "OPCODE=0": "Standard query (QUERY)",
            "OPCODE=1": "Inverse query (IQUERY)",
            "OPCODE=2": "Server status request (STATUS)",
            "AA": "Authoritative Answer (valid in responses)",
            "TC": "Truncated — response too large for UDP, retry over TCP",
            "RD": "Recursion Desired (client asks server to resolve recursively)",
            "RA": "Recursion Available (server indicates it supports recursive queries)",
            "RCODE=0": "No error (response only)",
            "RCODE=1": "Format error in query",
            "RCODE=2": "Server failure",
            "RCODE=3": "NXDOMAIN — domain does not exist",
            "RCODE=5": "Query refused",
        },
        "header_fields": [
            ("Transaction ID", "16 bits", "Randomized by client, echoed in response — prevents spoofing"),
            ("Flags + Opcode + AA + TC + RD + RA + Z + RCODE", "16 bits", "Combined: QR|OPCODE|AA|TC|RD|RA|Z|RCODE"),
            ("Question Count (QDCOUNT)", "16 bits", "Number of questions in the query section"),
            ("Answer Record Count (ANCOUNT)", "16 bits", "Number of resource records in the answer section"),
            ("Authority Record Count (NSCOUNT)", "16 bits", "Number of NS records in the authority section"),
            ("Additional Record Count (ARCOUNT)", "16 bits", "Number of additional records (e.g., EDNS)"),
            ("Question Section", "variable", "Format: QNAME + QTYPE + QCLASS (variable length, terminated by 0x00)"),
            ("Answer / Authority / Additional Sections", "variable", "Resource Records: NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA"),
        ],
        "nc_example": (
            "# DNS A record query with raw hex:\n"
            "echo -ne '\\xaa\\xbb\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x65\\x78\\x61\\x6d\\x70\\x6c\\x65\\x03\\x63\\x6f\\x6d\\x00\\x00\\x01\\x00\\x01' | nc -u 8.8.8.8 53\n\n"
            "# Same with dig:\n"
            "dig @8.8.8.8 example.com A +noedns\n\n"
            "# With host:\n"
            "host -t A example.com 8.8.8.8\n\n"
            "# Reverse DNS (PTR):\n"
            "dig @8.8.8.8 -x 1.2.3.4 +short"
        ),
        "notes": (
            "Transaction ID and source port are randomized to prevent DNS spoofing. "
            "Common record types: A (IPv4), AAAA (IPv6), CNAME, MX (mail), TXT, NS, SOA, PTR, SRV. "
            "TShark filter: 'dns' shows all DNS traffic. "
            "DNS over TCP uses the same format but with a 2-byte length prefix."
        ),
        "reference": "RFC 1035",
    },

    "BROWSER": {
        "description": (
            "Microsoft Windows Browser Protocol — maintains lists of servers and domains "
            "on a Windows network segment. Operates on UDP port 138 (Datagram) and TCP port 139 (Session). "
            "The Browser service collects and distributes information about: "
            "domains, domain controllers, backup domain controllers, file servers, printer servers, and other network resources. "
            "Master Browser elections decide which server manages the browse list for a workgroup."
        ),
        "ports": [137, 138, 139],
        "flags": {
            "Browser Election": "Election packets determine the Master Browser for a workgroup",
            "Domain announcement": "A server announces itself as primary domain controller",
            "Workstation announcement": "A client announces itself as a network workstation",
            "Server announcement": "A server announces available shares and services",
        },
        "header_fields": [
            ("Browser Packet Header", "", ""),
            ("Opcode", "16 bits", "1=Election, 2=Announcement, 5=Master Announcement, 8=Refresh Server"),
            ("Flags / Result", "16 bits", "Holds election priority and election version"),
            ("Update Count", "16 bits", "Number of updates to the browse list"),
            ("Browser Name", "variable", "NetBIOS name of the browser server (16 bytes, padded)"),
            ("", "", ""),
            ("Datagram Payload (UDP 138):", "", ""),
            ("Request Count", "16 bits", "Number of browse requests"),
            ("Server Name(s)", "variable", "List of server NetBIOS names being queried"),
            ("", "", ""),
            ("Session Service (TCP 139):", "", ""),
            ("Called Name", "variable", "NetBIOS name being queried (the browser server)"),
            ("Session Type", "8 bits", "0x03 = Messenger service, 0x1F = Browser service"),
        ],
        "nc_example": (
            "# Monitor Browser protocol:\n"
            "sudo tcpdump -i eth0 port 138 or port 139 -v -A\n\n"
            "# View Windows browse list:\n"
            "net view  # on Windows CMD\n\n"
            "# Force browser election with nbtstat:\n"
            "nbtstat -r\n\n"
            "# List_nbstat cache:\n"
            "nbtstat -c  # on Windows\n\n"
            "# Linux: query SMB browsers with nbtscan:\n"
            "nbtscan 192.168.1.0/24"
        ),
        "notes": (
            "Browser elections use a priority value embedded in the election packet — highest wins. "
            "The Master Browser maintains the browse list for a workgroup/domain. "
            "Backup Browsers poll the Master every 12-15 minutes. "
            "Browser traffic is broadcast-heavy and can be significant on legacy Windows networks. "
            "TShark filter: 'browser or nbns or nbss' captures related traffic. "
            "Modern networks use Active Directory DNS instead of Browser lists."
        ),
        "reference": "Microsoft MS-BRWS Protocol Specification",
    },

    "ARP": {
        "description": (
            "Address Resolution Protocol — maps IP addresses to MAC addresses on a local network. "
            "ARP operates at layer 2 (Ethernet frame, EtherType 0x0806) — no IP header. "
            "Before sending an IP packet, a host broadcasts an ARP request: 'who has IP X?'. "
            "The owner replies with an ARP response containing its MAC address."
        ),
        "ports": [],  # Layer 2 — no ports, EtherType 0x0806
        "flags": {},
        "header_fields": [
            ("Hardware Type (HTYPE)", "16 bits", "Layer 1 protocol: 0x0001 = Ethernet"),
            ("Protocol Type (PTYPE)", "16 bits", "Layer 3 protocol: 0x0800 = IPv4, 0x86DD = IPv6"),
            ("Hardware Address Length (HLEN)", "8 bits", "MAC address length: 6 for Ethernet"),
            ("Protocol Address Length (PLEN)", "8 bits", "IP address length: 4 for IPv4, 16 for IPv6"),
            ("Opcode", "16 bits", "1=ARP Request, 2=ARP Reply, 3=RARP Request, 4=RARP Reply"),
            ("Sender Hardware Address (SHA)", "48 bits", "MAC address of the sender"),
            ("Sender Protocol Address (SPA)", "32 bits", "IP address of the sender"),
            ("Target Hardware Address (THA)", "48 bits", "MAC address of the target (empty in Request)"),
            ("Target Protocol Address (TPA)", "32 bits", "IP address of the target"),
        ],
        "nc_example": (
            "# ARP is handled by the kernel — monitor with tcpdump:\n"
            "sudo tcpdump -i eth0 arp -v\n\n"
            "# View ARP cache:\n"
            "arp -a\n\n"
            "# Static ARP entry:\n"
            "sudo arp -s 192.168.1.1 00:11:22:33:44:55\n\n"
            "# ARP scan with arp-scan:\n"
            "sudo arp-scan --localnet\n\n"
            "# With hping3:\n"
            "sudo hping3 --arp 192.168.1.1 -c 1"
        ),
        "notes": (
            "ARP is link-local — never routed beyond the broadcast domain. "
            "Gratuitous ARP: a host announces its MAC for its own IP (updates caches on other hosts). "
            "ARP cache poisoning is a common MITM attack vector — use static ARP entries or VLANs to mitigate. "
            "TShark filter: 'arp'"
        ),
        "reference": "RFC 826",
    },

    "DHCP": {
        "description": (
            "Dynamic Host Configuration Protocol — dynamically assigns IP addresses and network "
            "parameters (subnet mask, gateway, DNS, lease time) to devices on a network. "
            "DHCP uses UDP ports 67 (server) and 68 (client). "
            "Exchange: DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK."
        ),
        "ports": [67, 68],
        "flags": {
            "BOOTREQUEST (opcode 1)": "Client to server message",
            "BOOTREPLY (opcode 2)": "Server to client message",
        },
        "header_fields": [
            ("Opcode", "8 bits", "1=BOOTREQUEST, 2=BOOTREPLY"),
            ("Hardware Type (htype)", "8 bits", "1=Ethernet, 15=IEEE 802, etc."),
            ("Hardware Address Length (hlen)", "8 bits", "6 for Ethernet MAC"),
            ("Hops", "8 bits", "Relay agent counter (initially 0)"),
            ("Transaction ID (xid)", "32 bits", "Random ID chosen by client, echoed in server response"),
            ("Seconds Elapsed", "16 bits", "Seconds since client began lease acquisition"),
            ("Flags", "16 bits", "Broadcast (0x8000) or Unicast (0x0000) flag"),
            ("ciaddr (Client IP)", "32 bits", "Client's current IP if already configured (0.0.0.0 normally)"),
            ("yiaddr ('Your' IP)", "32 bits", "IP address assigned by server to client"),
            ("siaddr (Next Server IP)", "32 bits", "IP of next bootstrap server (e.g., TFTP)"),
            ("giaddr (Relay Agent IP)", "32 bits", "IP of relay agent if involved"),
            ("Client Hardware Address (chaddr)", "128 bits", "MAC address of client (Ethernet = 48 bits used)"),
            ("Server Host Name (sname)", "512 bits", "Optional server host name (often empty)"),
            ("Boot File Name", "1024 bits", "Boot file name (e.g., pxelinux.0 for PXE)"),
            ("DHCP Options", "variable", "TLV format: Option code + length + value. Required: 53=Message Type, 255=End"),
        ],
        "nc_example": (
            "# Release and renew DHCP lease:\n"
            "sudo dhclient -r && sudo dhclient\n\n"
            "# Monitor DHCP with tcpdump:\n"
            "sudo tcpdump -i eth0 port 67 or port 68 -v\n\n"
            "# DHCP with scapy (Python):\n"
            "python3 -c \\\n"
            "  \"from scapy.all import *; \\\n"
            "   send(Ether(src='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67)/\\ \n"
            "   BOOTP(chaddr='001122334455')/DHCP(options=[('message-type','discover'), 'end']))\""
        ),
        "notes": (
            "DHCP Option 53 = Message Type: 1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK, 6=NACK. "
            "Key options: 1=subnet mask, 3=router, 6=DNS servers, 15=domain name, 51=lease time, 58=renewal time. "
            "TShark filter: 'dhcp' or 'bootp'. "
            "Requires sudo to capture DHCP (non-root cannot bind ports 67/68)."
        ),
        "reference": "RFC 2131",
    },

    "HTTP": {
        "description": (
            "Hypertext Transfer Protocol — text-based, stateless, application-layer protocol for "
            "distributed hypermedia. HTTP runs over TCP (typically port 80 for HTTP, 8443 for HTTP-alt). "
            "HTTPS wraps HTTP in TLS; this entry covers raw HTTP only."
        ),
        "ports": [80, 8080, 8443],
        "flags": {},
        "header_fields": [
            ("Request Line", "text", "METHOD SP Request-URI SP HTTP-Version CRLF"),
            ("Response Line", "text", "HTTP-Version SP Status-Code SP Reason-Phrase CRLF"),
            ("Header Fields", "text", "Field-Name ':' SP Value CRLF (one per line)"),
            ("Empty Line", "CRLF", "Separates headers from body"),
            ("Message Body", "binary", "Payload (POST data, JSON, HTML, etc.)"),
        ],
        "nc_example": (
            "# Raw HTTP GET:\n"
            "echo -ne 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n' | nc example.com 80\n\n"
            "# HTTP POST with JSON body:\n"
            "echo -ne 'POST /api/login HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/json\\r\\nContent-Length: 27\\r\\n\\r\\n{\\\"user\\\":\\\"admin\\\"}' | nc example.com 80\n\n"
            "# Check HTTP headers:\n"
            "echo -ne 'HEAD / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n' | nc -i 1 example.com 80\n\n"
            "# HTTP/1.1 requires Host header. HTTP/1.0 does not."
        ),
        "notes": (
            "HTTP/1.1 supports persistent connections (Connection: keep-alive). "
            "HTTP/1.0 closes connection after response unless Keep-Alive is set. "
            "HTTP/2 uses binary framing (not text-based). "
            "TShark filter: 'http' captures HTTP; 'http.request.method == \"GET\"' filters GET requests."
        ),
        "reference": "RFC 9112 (HTTP/1.1)",
    },

    "TLS": {
        "description": (
            "Transport Layer Security — cryptographic protocol providing privacy and integrity "
            "between communicating peers. TLS succeeds SSL and encrypts HTTP (HTTPS), SMTP, IMAP, etc. "
            "TLS runs on top of TCP (for UDP, see DTLS). "
            "Handshake: ClientHello → ServerHello → Certificates → Key Exchange → Finished."
        ),
        "ports": [443, 993, 995, 587],
        "flags": {},
        "header_fields": [
            ("TLS Record Layer", "", ""),
            ("Content Type", "8 bits", "20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application Data"),
            ("Protocol Version", "16 bits", "0x0301=TLS 1.0, 0x0302=TLS 1.1, 0x0303=TLS 1.2, 0x0304=TLS 1.3"),
            ("Length", "16 bits", "Bytes of encrypted data following this field"),
            ("", "", ""),
            ("TLS Handshake (after decryption)", "", ""),
            ("Handshake Type", "8 bits", "1=ClientHello, 2=ServerHello, 11=Certificate, 12=ServerKeyExchange, 14=ServerHelloDone, 16=ClientKeyExchange, 20=Finished"),
            ("Client Random", "32 bytes", "4-byte timestamp + 28 random bytes (used for key derivation)"),
            ("Session ID", "variable", "Session identifier (empty for new session)"),
            ("Cipher Suites Length", "16 bits", "Total length of the cipher suites list"),
            ("Cipher Suites", "variable", "List of 2-byte cipher suite IDs (e.g., 0x002F=TLS_RSA_WITH_AES_128_CBC_SHA)"),
            ("Compression Methods", "variable", "List of 1-byte methods: 0x00=null (no compression)"),
            ("Extensions Length", "16 bits", "Length of extensions (TLS 1.2+)"),
            ("Extensions", "variable", "Key-value pairs: SNI, ALPN, supported_versions, supported_curves, etc."),
        ],
        "nc_example": (
            "# TLS handshake with openssl:\n"
            "openssl s_client -connect example.com:443\n\n"
            "# Specific TLS version and cipher:\n"
            "openssl s_client -tls1_2 -cipher 'AES256-SHA' -connect example.com:443\n\n"
            "# Show certificate chain:\n"
            "openssl s_client -connect example.com:443 -showcerts 2>/dev/null | openssl x509 -text -noout\n\n"
            "# Check TLS version and cipher of a server:\n"
            "openssl s_client -connect example.com:443 </dev/null 2>&1 | grep -E 'Protocol|Cipher'"
        ),
        "notes": (
            "TLS 1.3 simplifies handshake to 1-RTT (or 0-RTT with PSK). "
            "TLS 1.2 and earlier use RSA key exchange or Diffie-Hellman. "
            "TShark can decrypt TLS if you have the server's private key or a pre-master-secret log: "
            "'Edit → Preferences → Protocols → TLS → RSA keys or Pre-Master-Secret log filename'. "
            "TShark filter: 'tls'. "
            "SNI (Server Name Indication) in ClientHello reveals the hostname being accessed before TLS is established."
        ),
        "reference": "RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2)",
    },

    "IGMPV3": {
        "description": (
            "Internet Group Management Protocol version 3 — manages multicast group membership "
            "on a local network segment. Hosts send IGMP reports to join/leave multicast groups. "
            "Routers send IGMP queries to discover which groups have members. "
            "IGMPv3 adds source-specific multicast (SSM) — hosts can specify which sources to receive from."
        ),
        "ports": [],  # Layer 3 — IP protocol number 2
        "flags": {
            "MODE_IS_INCLUDE": "Host wants to receive from specific sources only",
            "MODE_IS_EXCLUDE": "Host wants to receive from all sources except specific ones",
            "CHANGE_TO_INCLUDE": "Host is changing its include list",
            "CHANGE_TO_EXCLUDE": "Host is changing its exclude list",
            "ALLOW_NEW_SOURCES": "Add sources to include list",
            "BLOCK_OLD_SOURCES": "Remove sources from exclude list",
        },
        "header_fields": [
            ("Type", "8 bits", "0x22=IGMPv3 Membership Report, 0x11=General Query, 0x17=Leave Group"),
            ("Reserved", "8 bits", "Must be 0"),
            ("Checksum", "16 bits", "IP-like checksum over entire IGMP message"),
            ("Reserved", "32 bits", "Must be 0"),
            ("Group Record(s)", "variable", "One or more group records (see below)"),
            ("", "", ""),
            ("Group Record:", "", ""),
            ("Record Type", "8 bits", "128=MODE_IS_EXCLUDE, 129=MODE_IS_INCLUDE, 130=CHANGE_TO_EXCLUDE, 131=CHANGE_TO_INCLUDE, 132=ALLOW_NEW_SOURCES, 133=BLOCK_OLD_SOURCES"),
            ("Aux Data Len", "8 bits", "Length of auxiliary data in 32-bit words (usually 0)"),
            ("Number of Sources (N)", "16 bits", "How many source addresses follow"),
            ("Multicast Address", "32 bits", "IPv4 group address (e.g., 239.255.255.250)"),
            ("Source Address(s)", "32 bits × N", "One IPv4 address per source"),
        ],
        "nc_example": (
            "# IGMP is typically handled by the kernel. Monitor:\n"
            "sudo tcpdump -i eth0 'ip[9] == 2' -v\n\n"
            "# Join multicast group with iproute2:\n"
            "ip maddr add 239.255.255.250 dev eth0\n\n"
            "# View multicast memberships:\n"
            "ip maddr show dev eth0\n\n"
            "# IGMP query from router (type 0x11) with scapy:\n"
            "python3 -c \"from scapy.all import *; send(IP(src='192.168.1.1', dst='224.0.0.1')/ICMP()/Raw(load='\\x11\\x00\\xf7\\xff'))\""
        ),
        "notes": (
            "IGMPv3 adds source-specific multicast (SSM) — hosts can specify which sources to receive from. "
            "IGMP is link-local — only operates on the local broadcast domain, never routed. "
            "Common multicast addresses: 224.0.0.1 (all hosts), 224.0.0.251 (mDNS), 239.255.255.250 (SSDP). "
            "TShark filter: 'igmp'"
        ),
        "reference": "RFC 3376 (IGMPv3)",
    },

    "TLS_CLIENT_HELLO": {
        "description": (
            "TLS ClientHello is the first message in a TLS handshake, sent by the client "
            "to initiate a secure connection. It contains the TLS version, random bytes, "
            "session ID, cipher suites, compression methods, and extensions (SNI, ALPN, etc.)."
        ),
        "ports": [443, 8443],
        "flags": {},
        "header_fields": [
            ("TLS Record Layer", "", ""),
            ("Content Type", "8 bits", "0x16 = Handshake"),
            ("Version", "16 bits", "0x0301=TLS 1.0 ... 0x0304=TLS 1.3 (client declares max version)"),
            ("Length", "16 bits", "Bytes in this TLS record after the length field"),
            ("", "", ""),
            ("Handshake Header", "", ""),
            ("Handshake Type", "8 bits", "0x01 = ClientHello"),
            ("Length", "24 bits", "Bytes in ClientHello body (3-byte big-endian)"),
            ("", "", ""),
            ("ClientHello Body", "", ""),
            ("Client Random", "32 bytes", "4-byte Unix timestamp + 28 random bytes (for key derivation)"),
            ("Session ID Length", "8 bits", "Length of session ID (0 for new session)"),
            ("Session ID", "variable", "Session identifier (empty or up to 32 bytes)"),
            ("Cipher Suites Length", "16 bits", "Total length of cipher suites list"),
            ("Cipher Suites", "variable", "List of 2-byte cipher suite IDs (e.g., 0x002F=TLS_RSA_WITH_AES_128_CBC_SHA)"),
            ("Compression Methods Length", "8 bits", "Length of compression methods list"),
            ("Compression Methods", "variable", "List of 1-byte methods: 0x00=null (no compression)"),
            ("Extensions Length", "16 bits", "Length of all extensions (TLS 1.2+)"),
            ("Extensions", "variable", "Key-value list (see below)"),
            ("", "", ""),
            ("Key Extensions:", "", ""),
            ("server_name (SNI)", "TLV", "Type 0x0000: hostname in ASCII the client is connecting to"),
            ("supported_versions", "TLV", "Type 0x002b: list of TLS versions client supports"),
            ("supported_groups", "TLV", "Type 0x000a: elliptic curves (e.g., x25519, secp256r1)"),
            ("signature_algorithms", "TLV", "Type 0x000d: supported signature algorithms"),
            ("psk_key_exchange_modes", "TLV", "Type 0x002d: PSK modes (TLS 1.3)"),
            ("key_share", "TLV", "Type 0x0033: client Diffie-Hellman public key (TLS 1.3)"),
        ],
        "nc_example": (
            "# Extract ClientHello SNI from pcap:\n"
            "tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions.server_name\n\n"
            "# Parse ClientHello with openssl:\n"
            "echo | openssl s_client -tls1_2 -connect example.com:443 2>&1 | grep -A 50 'Client Hello'\n\n"
            "# Parse with scapy:\n"
            "python3 -c \"from scapy.all import *; pkt = rdpcap('capture.pcap')[0]; print(pkt[TCP].payload.show())\""
        ),
        "notes": (
            "SNI (Server Name Indication) in ClientHello reveals the hostname being accessed even before TLS is established — "
            "useful for filtering and censorship. "
            "TLS 1.3 ClientHello has additional extensions (supported_versions, key_share, psk_key_exchange_modes). "
            "TShark: 'tls.handshake.type == 1' filters ClientHello; "
            "'tls.handshake.extensions.server_name' extracts SNI."
        ),
        "reference": "RFC 8446, RFC 5246",
    },

    "mDNS": {
        "description": (
            "Multicast DNS — zeroconf service discovery protocol. mDNS runs on UDP port 5353 "
            "and uses the link-local multicast address 224.0.0.251 (IPv4) or ff02::fb (IPv6). "
            "It allows devices to discover each other on a local network without a central DNS server — "
            "devices announce their presence and query for services by broadcasting."
        ),
        "ports": [5353],
        "flags": {
            "QR=0": "Query (who has _service._proto.local?)",
            "QR=1": "Response (I have it!)",
            "AA (Authoritative)": "Set by the responding mDNS device",
            "TC": "Truncated (response too large)",
        },
        "header_fields": [
            ("Transaction ID", "16 bits", "Randomized ID to match queries with responses"),
            ("Flags + Opcode + AA + TC + RD + RA + Z + RCODE", "16 bits", "Combined header flags"),
            ("Question Count (QDCOUNT)", "16 bits", "Number of questions (usually 1 for mDNS)"),
            ("Answer Record Count (ANCOUNT)", "16 bits", "Number of answers (resource records)"),
            ("Authority Record Count (NSCOUNT)", "16 bits", "Authority records (usually 0 in mDNS)"),
            ("Additional Record Count (ARCOUNT)", "16 bits", "Additional records (e.g., service info)"),
            ("Question Section", "variable", "QNAME + QTYPE + QCLASS: e.g., '_http._tcp.local' + PTR + IN"),
            ("Answer Section", "variable", "PTR / SRV / TXT / A / AAAA records"),
        ],
        "nc_example": (
            "# Monitor mDNS with tcpdump:\n"
            "sudo tcpdump -i eth0 port 5353 -v\n\n"
            "# Query for a service with dig (multicast):\n"
            "dig @224.0.0.251 -p 5353 _http._tcp.local PTR\n\n"
            "# With systemd-resolve:\n"
            "systemd-resolve --interface=eth0 _printer._tcp.local\n\n"
            "# Raw mDNS query with socat:\n"
            "echo -ne '\\x00\\x00\\x84\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x09\\x5f\\x68\\x74\\x74\\x70\\x05\\x5f\\x74\\x63\\x70\\x05\\x6c\\x6f\\x63\\x61\\x6c\\x00\\x00\\x0c\\x00\\x01' | nc -u 224.0.0.251 5353"
        ),
        "notes": (
            "mDNS uses link-local multicast — 224.0.0.251:5353 (IPv4) or [ff02::fb]:5353 (IPv6). "
            "Common service types: _http._tcp, _printer._tcp, _ssh._tcp, _airplay._tcp, _homekit._tcp. "
            "Devices pick a random mDNS source port (usually UDP 5353 or random >1023) and stick with it. "
            "TShark filter: 'mdns' captures all mDNS traffic."
        ),
        "reference": "RFC 6762",
    },

    "SSDP": {
        "description": (
            "Simple Service Discovery Protocol — part of UPnP, used to discover network services "
            "on a local segment. SSDP uses HTTP-like NOTIFY and M-SEARCH messages over UDP port 1900 "
            "and the multicast address 239.255.255.250. "
            "Devices advertise their presence with NOTIFY messages; clients search with M-SEARCH."
        ),
        "ports": [1900],
        "flags": {},
        "header_fields": [
            ("HTTP-like Request Line", "text", "NOTIFY * HTTP/1.1 or M-SEARCH * HTTP/1.1"),
            ("HOST", "header", "239.255.255.250:1900"),
            ("ST (Search Target)", "header", "What to search for: ssdp:all, upnp:rootdevice, urn:schemas-..., etc."),
            ("MX", "header", "Maximum wait time in seconds (for M-SEARCH)"),
            ("NT (Notification Type)", "header", "Type of service being advertised (for NOTIFY)"),
            ("NTS (Notification Sub-Type)", "header", "ssdp:alive, ssdp:byebye, ssdp:update"),
            ("LOCATION", "header", "URL of the device's UPnP description document"),
            ("SERVER", "header", "OS/version, UPnP/1.0, product/version"),
            ("USN (Unique Service Name)", "header", "UUID-based unique identifier for this device"),
            ("CACHE-CONTROL", "header", "max-age in seconds until advertisement expires"),
        ],
        "nc_example": (
            "# Monitor SSDP with tcpdump:\n"
            "sudo tcpdump -i eth0 port 1900 -v -A\n\n"
            "# M-SEARCH discovery with raw HTTP:\n"
            "echo -ne 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \\\"ssdp:discover\\\"\\r\\nMX: 3\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -u 239.255.255.250 1900\n\n"
            "# With curl (HTTP-style over UDP — will fail but shows the point):\n"
            "# curl -H 'MAN: ssdp:discover' --max-time 3 'http://239.255.255.250:1900' 2>/dev/null\n\n"
            "# SSDP NOTIFY is broadcast by devices automatically on network join"
        ),
        "notes": (
            "SSDP uses HTTP-over-UDP with multicast. "
            "Common ST values: 'ssdp:all' (all devices), 'upnp:rootdevice', 'urn:schemas-upnp-org:device:...' "
            "Devices send NOTIFY every ~10 minutes and on network join. "
            "TShark filter: 'ssdp'"
        ),
        "reference": "UPnP Device Architecture 2.0 (UPnP-DA)",
    },

    "NBNS": {
        "description": (
            "NetBIOS Name Service — name registration and resolution protocol used by SMB/CIFS "
            "networks (Windows file sharing) on older networks. NBNS provides hostname-to-IP "
            "resolution in the absence of DNS. Operates on UDP port 137 (and TCP 137 for node status). "
            "Broadcast-based: names are registered and queried on the local broadcast domain."
        ),
        "ports": [137],
        "flags": {
            "BROADCAST FLAG (B)": "1 = broadcast query/response, 0 = direct unicast",
            "NODE TYPE B": "B-node: broadcast only (no WINS)",
            "NODE TYPE P": "P-node: point-to-point WINS only",
            "NODE TYPE M": "M-node: mixed (broadcast first, then WINS)",
            "NODE TYPE H": "H-node: hybrid (WINS first, then broadcast)",
        },
        "header_fields": [
            ("Transaction ID", "16 bits", "Unique ID to match queries with responses"),
            ("Flags + RCODE", "16 bits", "Broadcast flag, opcode, NMFLAGS, and response code"),
            ("Question Count (QDCOUNT)", "16 bits", "Number of questions (usually 1)"),
            ("Answer Count (ANCOUNT)", "16 bits", "Number of name entries in response"),
            ("Authority Count (NSCOUNT)", "16 bits", "Authority record count"),
            ("Additional Count (ARCOUNT)", "16 bits", "Additional record count"),
            ("Question Name", "variable", "NetBIOS name (16 bytes, padded with spaces, encoded as length-prefixed labels)"),
            ("Question Type", "16 bits", "0x0020=NB, 0x0021=NBSTAT"),
            ("Question Class", "16 bits", "0x0001=IN (Internet class)"),
        ],
        "nc_example": (
            "# Monitor NBNS with tcpdump:\n"
            "sudo tcpdump -i eth0 port 137 -v -A\n\n"
            "# Query NBNS name with nbtname (part of nmb-tools):\n"
            "nmblookup -U 192.168.1.1 -R 'WORKGROUP\\x00'\n\n"
            "# Windows-style name query:\n"
            "nbtstat -A 192.168.1.1\n\n"
            "# NBNS broadcast query with raw hex:\n"
            "echo -ne '\\x00\\x0d\\x01\\x0e\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x20\\x43\\x4b\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x45\\x00\\x00\\x20\\x00\\x01' | nc -u 192.168.1.255 137"
        ),
        "notes": (
            "NetBIOS names are 15 characters + 1 byte suffix (0x00 = workstation, 0x1b = master browser). "
            "Names are encoded in a quirky format: each label is length-prefixed, padded to 15 chars with spaces. "
            "Windows networks use NetBIOS for SMB file sharing (ports 445/139). "
            "TShark filter: 'nbns'"
        ),
        "reference": "RFC 1002 (NBNS/NetBIOS), Microsoft MS-NBNS specification",
    },

    "LLMNR": {
        "description": (
            "Link-Local Multicast Name Resolution — Microsoft's alternative to mDNS/DNS. "
            "LLMNR resolves hostnames to IP addresses on a local network without a DNS server. "
            "Uses UDP port 5355 and multicast addresses 224.0.0.252 (IPv4) or ff02::1:3 (IPv6). "
            "Similar to mDNS but uses a different multicast address and simpler DNS-like format."
        ),
        "ports": [5355],
        "flags": {
            "QR=0": "Query (client → servers)",
            "QR=1": "Response (server → client)",
            "C (Conflict)": "Set if the name is already known to the responder",
            "TC (Truncated)": "Response too large for UDP",
        },
        "header_fields": [
            ("Transaction ID", "16 bits", "Randomized ID to match queries with responses"),
            ("Flags", "16 bits", "QR|OPC|AA|TC|RD|RA|Z|AD|CD| RCODE"),
            ("Question Count (QDCOUNT)", "16 bits", "Number of questions"),
            ("Answer Count (ANCOUNT)", "16 bits", "Number of resource records in answer"),
            ("Authority Count (NSCOUNT)", "16 bits", "Number of authority records"),
            ("Additional Count (ARCOUNT)", "16 bits", "Number of additional records"),
            ("Question Name", "variable", "Hostname being queried (DNS-style name encoding)"),
            ("Question Type", "16 bits", "0x0001=A (IPv4), 0x001C=AAAA (IPv6), 0x0028=ANY"),
            ("Question Class", "16 bits", "0x0001=IN (Internet class)"),
        ],
        "nc_example": (
            "# Monitor LLMNR with tcpdump:\n"
            "sudo tcpdump -i eth0 port 5355 -v -A\n\n"
            "# Windows: query LLMNR:\n"
            "nslookup hostname.local  # tries LLMNR on Vista+\n\n"
            "# LLMNR query with socat:\n"
            "echo -ne '\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01\\x08\\x74\\x65\\x73\\x74\\x68\\x6f\\x73\\x74\\x05\\x6c\\x6f\\x63\\x61\\x6c\\x00\\x00\\x01\\x00\\x01' | nc -u 224.0.0.252 5355\n\n"
            "# With dig (if your dig supports LLMNR):\n"
            "dig @224.0.0.252 -p 5355 hostname.local LLMNR"
        ),
        "notes": (
            "LLMNR is Windows Vista+ only — Linux clients use systemd-resolved which can also send LLMNR. "
            "Multicast address: 224.0.0.252:5355 (IPv4) or [ff02::1:3]:5355 (IPv6). "
            "Unlike mDNS, LLMNR uses standard DNS name encoding (not DNS-SD service types). "
            "TShark filter: 'llmnr'"
        ),
        "reference": "RFC 4795 (LLMNR)",
    },

    "TLSv1.2": {
        "description": (
            "TLS 1.2 is TLS version 1.2 (defined in RFC 5246). It is the most widely deployed "
            "TLS version. The handshake uses RSA or Diffie-Hellman key exchange to establish "
            "a shared master secret, then encrypts all traffic with symmetric ciphers (AES, ChaCha20). "
            "TLS 1.2 ClientHello can be distinguished from TLS 1.3 by the supported_versions extension."
        ),
        "ports": [443, 8443, 993, 995, 587],
        "flags": {},
        "header_fields": [
            ("TLS Record Layer", "", ""),
            ("Content Type", "8 bits", "0x16=Handshake, 0x17=Application Data, 0x15=Alert"),
            ("Version", "16 bits", "0x0303 = TLS 1.2"),
            ("Length", "16 bits", "Bytes following this field"),
            ("", "", ""),
            ("Handshake Header", "", ""),
            ("Handshake Type", "8 bits", "0x01=ClientHello, 0x02=ServerHello, 0x0b=Certificate, etc."),
            ("Length", "24 bits", "Handshake message length (3 bytes)"),
            ("", "", ""),
            ("ClientHello Body", "", ""),
            ("Client Version", "16 bits", "0x0303 = TLS 1.2 (max version client supports)"),
            ("Client Random", "32 bytes", "Unix timestamp (4 bytes) + 28 random bytes"),
            ("Session ID Length", "8 bits", "0-32 bytes"),
            ("Session ID", "variable", ""),
            ("Cipher Suites Length", "16 bits", "Total bytes of cipher suites list"),
            ("Cipher Suites", "variable", "Each 2 bytes: e.g., 0x002F=TLS_RSA_WITH_AES_128_CBC_SHA"),
            ("Compression Methods", "8 bits", "List length + methods: 0x01 + 0x00"),
            ("Extensions Length", "16 bits", "Length of extensions"),
            ("Extensions", "variable", "SNI, ALPN, renegotiation_info, etc."),
        ],
        "nc_example": (
            "# TLS 1.2 handshake:\n"
            "openssl s_client -tls1_2 -connect example.com:443\n\n"
            "# Force specific cipher:\n"
            "openssl s_client -tls1_2 -cipher 'ECDHE-RSA-AES256-SHA' -connect example.com:443\n\n"
            "# View TLS 1.2 ClientHello:\n"
            "openssl s_client -tls1_2 -connect example.com:443 </dev/null 2>&1 | grep -A 30 'Client Hello'\n\n"
            "# Extract handshake bytes from pcap:\n"
            "tshark -r capture.pcap -Y 'tls.handshake.type == 1 && tls.handshake.version == 0x0303' -T fields -e frame.number"
        ),
        "notes": (
            "TLS 1.2 vs TLS 1.3: TLS 1.3 ClientHello has supported_versions extension (0x002b) listing 0x0304. "
            "TLS 1.2 does NOT have supported_versions — it uses the legacy Version field for negotiation. "
            "Common TLS 1.2 ciphers: AES128-SHA, AES256-SHA, ECDHE-RSA-AES128-GCM-SHA256. "
            "TShark: 'tls.record.version == 0x0303' filters TLS 1.2."
        ),
        "reference": "RFC 5246",
    },

    "UDP/XML": {
        "description": (
            "Many protocols use UDP as a transport for XML-encoded messages. Common examples: "
            "SSDP (HTTP-over-UDP), WBXML (Wireless Binary XML), custom industrial/SCADA protocols. "
            "Since UDP has no inherent message framing, XML-over-UDP protocols define their own "
            "delimiters (e.g., null byte, newline, or length prefix)."
        ),
        "ports": [1900, 4840, 789],  # common UDP/XML ports
        "flags": {},
        "header_fields": [
            ("Transport", "UDP", "No protocol-specific header — XML is the payload of a UDP datagram"),
            ("Message Framing", "variable", "Most UDP/XML protocols use a length prefix or delimiter"),
            ("XML Declaration", "text", "<?xml version='1.0' encoding='UTF-8'?> at the start of the document"),
            ("Root Element", "text", "Protocol-specific XML root element name and namespace"),
        ],
        "nc_example": (
            "# SSDP M-SEARCH (HTTP-over-UDP) example:\n"
            "echo -ne 'M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\nMAN: \\\"ssdp:discover\\\"\\r\\nMX: 3\\r\\nST: ssdp:all\\r\\n\\r\\n' | nc -u 239.255.255.250 1900\n\n"
            "# Custom UDP/XML to a SCADA/ICS device on port 4840:\n"
            "echo -ne '<?xml version=\"1.0\"?><EnrollRequest><DeviceID>12345</DeviceID></EnrollRequest>\\n' | nc -u 192.168.1.100 4840\n\n"
            "# WBXML (binary XML) — monitor with tcpdump:\n"
            "sudo tcpdump -i eth0 port 4840 -X -v\n\n"
            "# Note: UDP/XML has no inherent framing. The receiver must know message boundaries."
        ),
        "notes": (
            "UDP is message-oriented — each send() call produces one datagram. "
            "However, some UDP/XML parsers treat the stream as continuous and need explicit length headers. "
            "Common UDP/XML ports: 1900 (SSDP), 4840 (OPC-UA), 789 (Tridium Niagra AX), 787 (Nortel). "
            "TShark: 'data.len > 0' combined with port filter shows raw UDP payloads that may be XML."
        ),
        "reference": "Various protocol specifications (OPC-UA, WBXML, proprietary SCADA protocols)",
    },
}
