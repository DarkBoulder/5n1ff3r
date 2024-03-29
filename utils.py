def get_key(dic: dict, val):
    for key, value in dic.items():
        if val == value:
            return key
    return 'unknown value'


tcp_udp_ports = {
    1: 'tcpmux',
    5: 'rje',
    7: 'echo',
    9: 'discard',
    11: 'systat',
    13: 'daytime',
    17: 'qotd',
    18: 'msp',
    19: 'chargen',
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    37: 'time',
    39: 'rlp',
    42: 'nameserver',
    43: 'nicname',
    49: 'tacacs',
    50: 're-mail-ck',
    53: 'domain',
    63: 'whois++',
    67: 'dhcp',
    68: 'dhcp',
    69: 'tftp',
    70: 'gopher',
    71: 'netrjs-1',
    72: 'netrjs-2',
    73: 'netrjs-3',
    79: 'finger',
    80: 'http',
    88: 'kerberos',
    95: 'supdup',
    101: 'hostname',
    102: 'iso-tsap',
    105: 'csnet-ns',
    107: 'rtelnet',
    109: 'pop2',
    110: 'pop3',
    111: 'sunrpc',
    113: 'auth',
    115: 'sftp',
    117: 'uucp-path',
    119: 'nntp',
    123: 'ntp',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    143: 'imap',
    161: 'snmp',
    162: 'snmptrap',
    163: 'cmip-man',
    164: 'cmip-agent',
    174: 'mailq',
    177: 'xdmcp',
    178: 'nextstep',
    179: 'bgp',
    191: 'prospero',
    194: 'irc',
    199: 'smux',
    201: 'at-rtmp',
    202: 'at-nbp',
    204: 'at-echo',
    206: 'at-zis',
    209: 'qmtp',
    210: 'z39.50',
    213: 'ipx',
    220: 'imap3',
    245: 'link',
    347: 'fatserv',
    363: 'rsvp_tunnel',
    369: 'rpc2portmap',
    370: 'codaauth2',
    372: 'ulistproc',
    389: 'ldap',
    427: 'svrloc',
    434: 'mobileip-agent',
    435: 'mobilip-mn',
    443: 'https',
    444: 'snpp',
    445: 'microsoft-ds',
    464: 'kpasswd',
    468: 'photuris',
    487: 'saft',
    488: 'gss-http',
    496: 'pim-rp-disc',
    500: 'isakmp',
    535: 'iiop',
    538: 'gdomap',
    546: 'dhcpv6-client',
    547: 'dhcpv6-server',
    554: 'rtsp',
    563: 'nntps',
    565: 'whoami',
    587: 'submission',
    610: 'npmp-local',
    611: 'npmp-gui',
    612: 'hmmp-ind',
    631: 'ipp',
    636: 'ldaps',
    674: 'acap',
    694: 'ha-cluster',
    749: 'kerberos-adm',
    750: 'kerberos-iv',
    765: 'webster',
    767: 'phonebook',
    873: 'rsync',
    992: 'telnets',
    993: 'imaps',
    994: 'ircs',
    995: 'pop3s',
    1900: 'ssdp',
    5353: 'mdns'
}

ieee_802_numbers = {
    '0200': 'XEROX PUP (see 0A00)',
    '0201': 'PUP Addr Trans (see 0A01)',
    '0400': 'Nixdorf',
    '0600': 'XEROX NS IDP',
    '0660': 'DLOG',
    '0661': 'DLOG',
    '0800': 'Internet Protocol version 4 (IPv4)',
    '0801': 'X.75 Internet',
    '0802': 'NBS Internet',
    '0803': 'ECMA Internet',
    '0804': 'Chaosnet',
    '0805': 'X.25 Level 3',
    '0806': 'Address Resolution Protocol (ARP)',
    '0807': 'XNS Compatability',
    '0808': 'Frame Relay ARP',
    '081C': 'Symbolics Private',
    '0900': 'Ungermann-Bass net debugr',
    '0A00': 'Xerox IEEE802.3 PUP',
    '0A01': 'PUP Addr Trans',
    '0BAD': 'Banyan VINES',
    '0BAE': 'VINES Loopback',
    '0BAF': 'VINES Echo',
    '1000': 'Berkeley Trailer nego',
    '1600': 'Valid Systems',
    '22F3': 'TRILL',
    '22F4': 'L2-IS-IS',
    '4242': 'PCS Basic Block Protocol',
    '5208': 'BBN Simnet',
    '6000': 'DEC Unassigned (Exp.)',
    '6001': 'DEC MOP Dump/Load',
    '6002': 'DEC MOP Remote Console',
    '6003': 'DEC DECNET Phase IV Route',
    '6004': 'DEC LAT',
    '6005': 'DEC Diagnostic Protocol',
    '6006': 'DEC Customer Protocol',
    '6007': '"DEC LAVC',
    '6558': 'Trans Ether Bridging',
    '6559': 'Raw Frame Relay',
    '7000': 'Ungermann-Bass download',
    '7002': 'Ungermann-Bass dia/loop',
    '7030': 'Proteon',
    '7034': 'Cabletron',
    '8003': 'Cronus VLN',
    '8004': 'Cronus Direct',
    '8005': 'HP Probe',
    '8006': 'Nestar',
    '8008': 'AT&T',
    '8010': 'Excelan',
    '8013': 'SGI diagnostics',
    '8014': 'SGI network games',
    '8015': 'SGI reserved',
    '8016': 'SGI bounce server',
    '8019': 'Apollo Domain',
    '802E': 'Tymshare',
    '802F': '"Tigan',
    '8035': 'Reverse Address Resolution Protocol (RARP)',
    '8036': 'Aeonic Systems',
    '8038': 'DEC LANBridge',
    '803D': 'DEC Ethernet Encryption',
    '803E': 'DEC Unassigned',
    '803F': 'DEC LAN Traffic Monitor',
    '8044': 'Planning Research Corp.',
    '8046': 'AT&T',
    '8047': 'AT&T',
    '8049': 'ExperData',
    '805B': 'Stanford V Kernel exp.',
    '805C': 'Stanford V Kernel prod.',
    '805D': 'Evans & Sutherland',
    '8060': 'Little Machines',
    '8062': 'Counterpoint Computers',
    '8065': 'Univ. of Mass. @ Amherst',
    '8066': 'Univ. of Mass. @ Amherst',
    '8067': 'Veeco Integrated Auto.',
    '8068': 'General Dynamics',
    '8069': 'AT&T',
    '806A': 'Autophon',
    '806C': 'ComDesign',
    '806D': 'Computgraphic Corp.',
    '807A': 'Matra',
    '807B': 'Dansk Data Elektronik',
    '807C': 'Merit Internodal',
    '8080': 'Vitalink TransLAN III',
    '809B': 'Appletalk',
    '809F': 'Spider Systems Ltd.',
    '80A3': 'Nixdorf Computers',
    '80C4': 'Banyan Systems',
    '80C5': 'Banyan Systems',
    '80C6': 'Pacer Software',
    '80C7': 'Applitek Corporation',
    '80D5': 'IBM SNA Service on Ether',
    '80DD': 'Varian Associates',
    '80F2': 'Retix',
    '80F3': 'AppleTalk AARP (Kinetics)',
    '80F7': 'Apollo Computer',
    '80FF': 'Wellfleet Communications',
    '8100': '"Customer VLAN Tag Type (C-Tag',
    '8130': 'Hayes Microcomputers',
    '8131': 'VG Laboratory Systems',
    '8148': 'Logicraft',
    '8149': 'Network Computing Devices',
    '814A': 'Alpha Micro',
    '814C': 'SNMP',
    '814D': 'BIIN',
    '814E': 'BIIN',
    '814F': 'Technically Elite Concept',
    '8150': 'Rational Corp',
    '817D': 'XTP',
    '817E': 'SGI/Time Warner prop.',
    '8180': 'HIPPI-FP encapsulation',
    '8181': '"STP',
    '8182': 'Reserved for HIPPI-6400',
    '8183': 'Reserved for HIPPI-6400',
    '818D': 'Motorola Computer',
    '81A4': 'ARAI Bunkichi',
    '86DB': 'SECTRA',
    '86DE': 'Delta Controls',
    '86DD': 'Internet Protocol version 6 (IPv6)',
    '86DF': 'ATOMIC',
    '876B': 'TCP/IP Compression',
    '876C': 'IP Autonomous Systems',
    '876D': 'Secure Data',
    '8808': 'IEEE Std 802.3 - Ethernet Passive Optical Network (EPON)',
    '8809': '"Slow Protocols (Link Aggregation',
    '880B': 'Point-to-Point Protocol (PPP)',
    '880C': 'General Switch Management Protocol (GSMP)',
    '8822': 'Ethernet NIC hardware and software testing',
    '8847': 'MPLS',
    '8848': 'MPLS with upstream-assigned label',
    '8861': 'Multicast Channel Allocation Protocol (MCAP)',
    '8863': 'PPP over Ethernet (PPPoE) Discovery Stage',
    '8864': 'PPP over Ethernet (PPPoE) Session Stage',
    '888E': 'IEEE Std 802.1X - Port-based network access control',
    '88A8': 'IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)',
    '88B5': 'IEEE Std 802 - Local Experimental Ethertype',
    '88B6': 'IEEE Std 802 - Local Experimental Ethertype',
    '88B7': 'IEEE Std 802 - OUI Extended Ethertype',
    '88C7': 'IEEE Std 802.11 - Pre-Authentication (802.11i)',
    '88CC': 'IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP)',
    '88E5': 'IEEE Std 802.1AE - Media Access Control Security',
    '88E7': 'Provider Backbone Bridging Instance tag',
    '88F5': 'IEEE Std 802.1Q  - Multiple VLAN Registration Protocol (MVRP)',
    '88F6': 'IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP)',
    '890D': 'IEEE Std 802.11 - Fast Roaming Remote Request (802.11r)',
    '8917': 'IEEE Std 802.21 - Media Independent Handover Protocol',
    '8929': 'IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol',
    '893B': 'TRILL Fine Grained Labeling (FGL)',
    '8940': 'IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR)',
    '8946': 'TRILL RBridge Channel',
    '8947': 'GeoNetworking as defined in ETSI EN 302 636-4-1',
    '894F': 'NSH (Network Service Header)',
    '9000': 'Loopback',
    '9001': '3Com(Bridge) XNS Sys Mgmt',
    '9002': '3Com(Bridge) TCP-IP Sys',
    '9003': '3Com(Bridge) loop detect',
    '9A22': 'Multi-Topology',
    'A0ED': 'LoWPAN encapsulation',
    'B7EA': '"The Ethertype will be used to identify a ""Channel"" in which control messages are encapsulated as payload of GRE packets. When a GRE packet tagged with the Ethertype is received',
    'FF00': 'BBN VITAL-LanBridge cache',
    'FFFF': 'Reserved'
}

protocol_numbers = {
    0: 'HOPOPT',
    1: 'ICMP',
    2: 'IGMP',
    3: 'GGP',
    4: 'IPv4',
    5: 'ST',
    6: 'TCP',
    7: 'CBT',
    8: 'EGP',
    9: 'IGP',
    10: 'BBN-RCC-MON',
    11: 'NVP-II',
    12: 'PUP',
    13: 'ARGUS (deprecated)',
    14: 'EMCON',
    15: 'XNET',
    16: 'CHAOS',
    17: 'UDP',
    18: 'MUX',
    19: 'DCN-MEAS',
    20: 'HMP',
    21: 'PRM',
    22: 'XNS-IDP',
    23: 'TRUNK-1',
    24: 'TRUNK-2',
    25: 'LEAF-1',
    26: 'LEAF-2',
    27: 'RDP',
    28: 'IRTP',
    29: 'ISO-TP4',
    30: 'NETBLT',
    31: 'MFE-NSP',
    32: 'MERIT-INP',
    33: 'DCCP',
    34: '3PC',
    35: 'IDPR',
    36: 'XTP',
    37: 'DDP',
    38: 'IDPR-CMTP',
    39: 'TP++',
    40: 'IL',
    41: 'IPv6',
    42: 'SDRP',
    43: 'IPv6-Route',
    44: 'IPv6-Frag',
    45: 'IDRP',
    46: 'RSVP',
    47: 'GRE',
    48: 'DSR',
    49: 'BNA',
    50: 'ESP',
    51: 'AH',
    52: 'I-NLSP',
    53: 'SWIPE (deprecated)',
    54: 'NARP',
    55: 'MOBILE',
    56: 'TLSP',
    57: 'SKIP',
    58: 'IPv6-ICMP',
    59: 'IPv6-NoNxt',
    60: 'IPv6-Opts',
    61: 'any host internal protocol',
    62: 'CFTP',
    63: 'any local network',
    64: 'SAT-EXPAK',
    65: 'KRYPTOLAN',
    66: 'RVD',
    67: 'IPPC',
    68: 'any distributed file system',
    69: 'SAT-MON',
    70: 'VISA',
    71: 'IPCV',
    72: 'CPNX',
    73: 'CPHB',
    74: 'WSN',
    75: 'PVP',
    76: 'BR-SAT-MON',
    77: 'SUN-ND',
    78: 'WB-MON',
    79: 'WB-EXPAK',
    80: 'ISO-IP',
    81: 'VMTP',
    82: 'SECURE-VMTP',
    83: 'VINES',
    84: 'TTP',
    85: 'NSFNET-IGP',
    86: 'DGP',
    87: 'TCF',
    88: 'EIGRP',
    89: 'OSPFIGP',
    90: 'Sprite-RPC',
    91: 'LARP',
    92: 'MTP',
    93: 'AX.25',
    94: 'IPIP',
    95: 'MICP (deprecated)',
    96: 'SCC-SP',
    97: 'ETHERIP',
    98: 'ENCAP',
    99: 'any private encryption scheme',
    100: 'GMTP',
    101: 'IFMP',
    102: 'PNNI',
    103: 'PIM',
    104: 'ARIS',
    105: 'SCPS',
    106: 'QNX',
    107: 'A/N',
    108: 'IPComp',
    109: 'SNP',
    110: 'Compaq-Peer',
    111: 'IPX-in-IP',
    112: 'VRRP',
    113: 'PGM',
    114: 'any 0-hop protocol',
    115: 'L2TP',
    116: 'DDX',
    117: 'IATP',
    118: 'STP',
    119: 'SRP',
    120: 'UTI',
    121: 'SMP',
    122: 'SM (deprecated)',
    123: 'PTP',
    124: 'ISIS over IPv4',
    125: 'FIRE',
    126: 'CRTP',
    127: 'CRUDP',
    128: 'SSCOPMCE',
    129: 'IPLT',
    130: 'SPS',
    131: 'PIPE',
    132: 'SCTP',
    133: 'FC',
    134: 'RSVP-E2E-IGNORE',
    135: 'Mobility Header',
    136: 'UDPLite',
    137: 'MPLS-in-IP',
    138: 'manet',
    139: 'HIP',
    140: 'Shim6',
    141: 'WESP',
    142: 'ROHC',
    143: 'Ethernet',
    144: 'AGGFRAG',
    253: 'Use for experimentation and testing',
    254: 'Use for experimentation and testing',
    255: 'Reserved',
}  # 145-252		Unassigned

http_request_methods = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT',
                        'OPTIONS', 'TRACE', 'PATCH', 'MOVE', 'COPY', 'LINK',
                        'UNLINK', 'WRAPPED', 'Extension-method'}
