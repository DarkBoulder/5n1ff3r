import binascii
import struct
import socket
from utils import *
from hexdump import hexdump


def parse_flag(flag, flag_dict):
    flag_nums = len(flag_dict)
    res = []
    bin_flag = bin(flag)
    for i in range(len(bin_flag)):
        ub = len(bin_flag) - i - 1
        if bin_flag[ub] == '1':
            res.append(flag_dict[flag_nums - i - 1])
        elif bin_flag[ub] == 'b':
            break
    return res


def bytestream_to_hardwareaddr(stream):
    raw = str(bytes.hex(stream))
    return '{}:{}:{}:{}:{}:{}'.format(raw[0:2], raw[2:4], raw[4:6], raw[6:8], raw[8:10], raw[10:12])


def bytestream_to_ipv6addr(stream):
    raw = str(bytes.hex(stream))
    addr_seg = [raw[0:4], raw[4:8], raw[8:12], raw[12:16],
                raw[16:20], raw[20:24], raw[24:28], raw[28:32]]
    addr = ''
    all_zero_used_flag = 0  # 0: not used, 1: using, 2: used
    for ele in addr_seg:
        if not ele.startswith('0'):
            addr += ele
        elif ele.startswith('0000'):
            if all_zero_used_flag == 0:
                addr += ':'
                all_zero_used_flag += 1
                continue
            elif all_zero_used_flag == 1:
                continue
            else:
                addr += '0'
        else:
            if all_zero_used_flag == 1:
                all_zero_used_flag += 1
            addr += ele[ele.rfind('0') + 1:]
        addr += ':'
    return addr[:-1]


class PacketDemo:
    def __init__(self, data_src, cnt, now_time, st_time, pheader):
        """
        struct pcap_pkthdr
        {
          struct timeval ts;    /* time stamp */
          bpf_u_int32 caplen;   /* length of portion present */
          bpf_u_int32 len;      /* length this packet (off wire) */
        };
        """
        self.cnt = cnt  # frame cnt
        self.time_stamp = now_time
        self.time_span = format(now_time - st_time, '.6f')
        self.len = pheader.len
        self.caplen = pheader.caplen
        self.raw_packet = None
        if str(type(data_src)) == '<class \'str\'>':  # path of testcases
            with open(data_src, 'r') as f:
                a = f.readline()
                self.raw_packet = binascii.unhexlify(a)
        else:
            self.raw_packet = data_src
        self.hex_packet = hexdump(self.raw_packet, 'return')
        # EthernetII
        self.layer1 = {'name': None, 'dst': None, 'src': None, 'type': None}
        # ipv4 ipv6 arp
        self.layer2 = {
            'name': None, 'src': None, 'dst': None, 'version': None, 'ihl': None,
            'tos': None, 'len': None, 'id': None, 'flag': None, 'ttl': None, 'protocol': None,
            'chksum': None, 'tc': None, 'fl': None, 'pl': None, 'nh': None,
            'opt': None, 'htype': None, 'ptype': None, 'hlen': None, 'plen': None,
            'op': None, 'info': None, 'sha': None, 'spa': None, 'tha': None, 'tpa': None
        }
        # tcp udp icmp igmp
        self.layer3 = {
            'name': None, 'src': None, 'dst': None, 'seq': None, 'ack': None, 'op': None,
            'hl': None, 'reserved': None, 'flag': None, 'len': None, 'chksum': None, 'up': None,
            'type': None, 'code': None, 'id': None, 'info': None, 'window': None, 'tcptrace': None,
            'tcpSdTrace': None, 'tcpRcTrace': None
        }
        self.layer4 = {
            'name': None, 'info': None, 'rqm': None, 'rqu': None, 'rqv': None, 'rpv': None, 'sc': None, 'rpp': None,
            'tid': None, 'flag': None, 'ques': None, 'ansrr': None, 'authrr': None, 'addrr': None
        }
        self.general_info = {
            'src': None, 'dst': None, 'proto': None, 'info': None
        }
        self.parse_packet()

    def set_general_info(self, src=None, dst=None, proto=None, info=None):
        if src:
            self.general_info['src'] = src
        if dst:
            self.general_info['dst'] = dst
        if proto:
            self.general_info['proto'] = proto
        if info:
            self.general_info['info'] = info

    def parse_layer1(self):
        # TODO: 802.3 and other protocols
        try:
            layer1_info = struct.unpack('<6s6s2s', self.raw_packet[0:14])
            self.layer1['name'] = 'EthernetII'
            self.layer1['dst'] = bytestream_to_hardwareaddr(layer1_info[0])
            self.layer1['src'] = bytestream_to_hardwareaddr(layer1_info[1])
            self.layer1['type'] = ieee_802_numbers.get(str(bytes.hex(layer1_info[2])).upper(), 'UNK')
            self.set_general_info(self.layer1['src'], self.layer1['dst'], self.layer1['name'], '')
            self.parse_layer2(14)
        except:
            self.set_general_info('', '', 'UNK', 'unknown protocol')

    def parse_layer2(self, st):
        if self.layer1['type'] == 'Internet Protocol version 4 (IPv4)':
            ipv4_info = struct.unpack('>BBHHHBBH4s4s', self.raw_packet[st:st + 20])
            self.layer2['name'] = self.layer1['type']
            self.layer2['src'] = socket.inet_ntoa(ipv4_info[-2])
            self.layer2['dst'] = socket.inet_ntoa(ipv4_info[-1])
            self.layer2['version'] = ipv4_info[0] >> 4
            self.layer2['ihl'] = ipv4_info[0] & 15  # internet header length, represents 4B for each
            self.layer2['tos'] = ipv4_info[1]  # type of service
            self.layer2['len'] = ipv4_info[2]  # total length, 1B for each
            self.layer2['id'] = ipv4_info[3]
            self.layer2['flag'] = ipv4_info[4]  # TODO: parse 3 flags, 13 fragment offset
            self.layer2['ttl'] = ipv4_info[5]
            self.layer2['protocol'] = protocol_numbers.get(ipv4_info[6], 'Unassigned')
            self.layer2['chksum'] = ipv4_info[7]
            self.set_general_info(self.layer2['src'], self.layer2['dst'], 'IPv4', '')
            op_extra = 0  # option segment
            if self.layer2['ihl'] > 5:
                op_extra = 4 * (self.layer2['ihl'] - 5)
                self.layer2['op'] = struct.unpack('>{}s'.format(op_extra), self.raw_packet[st + 20:st + 20 + op_extra])
            self.parse_layer3(st + 20 + op_extra)

        elif self.layer1['type'] == 'Internet Protocol version 6 (IPv6)':
            ipv6_info = struct.unpack('>IHBB16s16s', self.raw_packet[st:st + 40])
            self.layer2['name'] = self.layer1['type']
            self.layer2['src'] = bytestream_to_ipv6addr(ipv6_info[4])
            self.layer2['dst'] = bytestream_to_ipv6addr(ipv6_info[5])
            self.layer2['version'] = ipv6_info[0] >> 28
            self.layer2['tc'] = hex((ipv6_info[0] & 0xfffffff) >> 20)  # traffic_class TODO: need to parse
            self.layer2['fl'] = hex(ipv6_info[0] & 0xfffff)  # flow_label
            self.layer2['pl'] = ipv6_info[1]  # payload_length
            self.layer2['nh'] = protocol_numbers.get(ipv6_info[2], 'Unassigned')  # next_header
            self.layer2['hl'] = ipv6_info[3]  # hop_limit
            self.set_general_info(self.layer2['src'], self.layer2['dst'], 'IPv6', '')
            self.parse_layer3(st + 40)

        elif self.layer1['type'] == 'Address Resolution Protocol (ARP)':
            arp_info = struct.unpack('>H2sBBH6s4s6s4s', self.raw_packet[st:st + 28])
            self.layer2['name'] = self.layer1['type']
            self.layer2['htype'] = arp_info[0]  # hardware type TODO: parse type
            self.layer2['ptype'] = str(bytes.hex(arp_info[1]))  # protocol type
            self.layer2['hlen'] = arp_info[2]  # Hardware address length
            self.layer2['plen'] = arp_info[3]  # Protocol address length
            self.layer2['op'] = 'request' if arp_info[4] == 1 else 'reply'  # operation
            self.layer2['sha'] = bytestream_to_hardwareaddr(arp_info[5])  # Sender hardware address
            self.layer2['spa'] = socket.inet_ntoa(arp_info[6])  # Sender protocol address
            self.layer2['tha'] = bytestream_to_hardwareaddr(arp_info[7])  # target hardware address
            self.layer2['tpa'] = socket.inet_ntoa(arp_info[8])  # target protocol address
            self.layer2['info'] = 'Who has {}? Tell {}'.format(self.layer2['tpa'], self.layer2['spa']) \
                if self.layer2['op'] == 'request' else '{} is at {}'.format(self.layer2['spa'], self.layer2['sha'])
            self.set_general_info(self.layer2['sha'], self.layer2['tha'], 'ARP', self.layer2['info'])
        else:
            pass

    def parse_layer3(self, st):
        if self.layer2['protocol'] == 'TCP' or self.layer2['nh'] == 'TCP':
            tcp_info = struct.unpack('>HHIIHHHH', self.raw_packet[st:st + 20])
            self.layer3['name'] = 'TCP'
            self.layer3['src'] = tcp_info[0]  # source port num
            self.layer3['dst'] = tcp_info[1]  # destination port num
            self.layer3['seq'] = tcp_info[2]
            self.layer3['ack'] = tcp_info[3]
            self.layer3['hl'] = tcp_info[4] >> 12  # header length
            self.layer3['reserved'] = (tcp_info[4] & 0xfff) >> 6  # should be 0
            self.layer3['flag'] = tcp_info[4] & 0x3f  # TODO: need to parse
            flag_dic = parse_flag(self.layer3['flag'], ['CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'])
            flag_info = ''
            for ele in flag_dic:
                flag_info += (ele + ', ')
            flag_info = flag_info[:-2]
            self.layer3['window'] = tcp_info[5]
            self.layer3['chksum'] = tcp_info[6]
            self.layer3['up'] = tcp_info[7]  # urgent pointer
            op_extra = 0
            if self.layer3['hl'] > 5:
                op_extra = 4 * (self.layer3['hl'] - 5)
                self.layer3['op'] = struct.unpack('>{}s'.format(op_extra), self.raw_packet[st + 20:st + 20 + op_extra])
            # self.print_layer()
            if self.layer2['protocol'] == 'TCP':
                self.set_general_info(proto='TCP', info='{} -> {} [{}]'
                                      .format(self.layer3['src'], self.layer3['dst'], flag_info))
            else:
                self.set_general_info(proto='TCPv6', info='{} -> {} [{}]'
                                      .format(self.layer3['src'], self.layer3['dst'], flag_info))
            if len(self.raw_packet) > st + 20 + op_extra:  # padding to 64 (with FCS)
                # print(len(self.raw_packet), st+20+op_extra)
                self.parse_layer4(st + 20 + op_extra)

        elif self.layer2['protocol'] == 'UDP' or self.layer2['nh'] == 'UDP':
            udp_info = struct.unpack('>HHHH', self.raw_packet[st:st + 8])
            self.layer3['name'] = 'UDP'
            self.layer3['src'] = udp_info[0]  # source port num
            self.layer3['dst'] = udp_info[1]  # destination port num
            self.layer3['length'] = udp_info[2]  # header(8) + data
            self.layer3['chksum'] = udp_info[3]
            if self.layer2['protocol'] == 'UDP':
                self.set_general_info(proto='UDP', info='')
            else:
                self.set_general_info(proto='UDPv6', info='')
            if len(self.raw_packet) >= st + 8:
                self.parse_layer4(st + 8)

        elif self.layer2['protocol'] == 'ICMP':
            icmp_info = struct.unpack('>BBHHH', self.raw_packet[st:st + 8])
            self.layer3['name'] = 'ICMP'
            self.layer3['type'] = icmp_info[0]
            self.layer3['code'] = icmp_info[1]
            self.layer3['chksum'] = icmp_info[2]
            self.layer3['id'] = icmp_info[3]
            self.layer3['seq'] = icmp_info[4]
            self.layer3['info'] = 'Echo (ping) request id={}, seq={}'.format(self.layer3['id'], self.layer3['seq']) \
                if self.layer3['type'] == 8 else 'Echo (ping) reply id={}, seq={}'.format(self.layer3['id'],
                                                                                          self.layer3['seq']) \
                if self.layer3['type'] == 0 else 'id={}, seq={}'.format(self.layer3['id'], self.layer3['seq'])
            self.set_general_info(proto='ICMP', info=self.layer3['info'])

    def parse_layer4(self, st):
        if self.layer3['name'] == 'TCP' and (self.layer3['src'] == 80 or self.layer3['dst'] == 80):  # http
            try:
                http_info = bytes.decode(self.raw_packet[st:], 'utf8').split('\r\n')
            except:
                self.layer4['name'] = 'UNK'
                return
            self.layer4['name'] = 'HTTP'
            is_request = False
            for ele in http_request_methods:
                if ele in set(http_info[0]):
                    is_request = True
                    break
            if is_request:
                request = http_info[0].split(' ')
                self.layer4['rqm'] = request[0]  # request_method
                self.layer4['rqu'] = request[1]  # request_uri
                self.layer4['rqv'] = request[2]  # request_version
            elif http_info[0].find('HTTP') != -1:
                response = http_info[0].split(' ')
                self.layer4['rpv'] = response[0]  # response version
                self.layer4['sc'] = response[1]  # status code
                self.layer4['rpp'] = ' '.join(response[2:])  # response phrase
            self.layer4['info'] = http_info[0]
            self.set_general_info(proto='HTTP', info='')
        elif self.layer3['name'] == 'TCP' and (self.layer3['src'] == 443 or self.layer3['dst'] == 443):  # https
            self.layer4['name'] = 'HTTPS'
            self.layer4['info'] = ''
            self.set_general_info(proto='HTTPS', info='')
        elif self.layer3['name'] == 'UDP' and (self.layer3['src'] == 53 or self.layer3['dst'] == 53):  # DNS
            dns_info = struct.unpack('>HHHHHH', self.raw_packet[st:st + 12])
            self.layer4['name'] = 'DNS'
            self.layer4['tid'] = hex(dns_info[0])
            self.layer4['flag'] = dns_info[1]
            response = self.layer4['flag'] >> 15  # query or response
            opcode = (self.layer4['flag'] & 0x7800) >> 11  # 0: standard query 1: inverse query 2: server status request
            auth = (self.layer4['flag'] & 0x400) >> 10  # server is (not) an authority of domain
            trun = (self.layer4['flag'] & 0x200) >> 9  # 1: truncated
            rec_des = (self.layer4['flag'] & 0x100) >> 8  # recursion desired, 1: do query recursively
            rec_ava = (self.layer4['flag'] & 0x80) >> 7  # server can do recursive queries
            reply_code = (self.layer4[
                              'flag'] & 0xf)  # 0: no error, 1: format error, 2: server fail, 3: Nonexistent domain
            self.layer4['ques'] = dns_info[2]
            self.layer4['ansrr'] = dns_info[3]
            self.layer4['authrr'] = dns_info[4]
            self.layer4['addrr'] = dns_info[5]

            info = ''
            if opcode == 0:
                info += 'Standard query'
            if opcode == 1:
                info += 'Inverse query'
            if opcode == 2:
                info += 'Server status request'
            if response:
                info += ' response'
            info += str(self.layer4['tid'])

            self.set_general_info(proto='DNS', info=info)

    def parse_packet(self):
        self.parse_layer1()

    def print_layer(self, layer_num=0):
        if layer_num == 1 or layer_num == 0:
            print('----------layer1-----------')
            print(self.layer1)
        if layer_num == 2 or layer_num == 0:
            print('----------layer2-----------')
            for a, b in self.layer2.items():
                if b is not None:
                    print('{}: {}'.format(a, b))
        if layer_num == 3 or layer_num == 0:
            print('----------layer3-----------')
            for a, b in self.layer3.items():
                if b is not None:
                    print('{}: {}'.format(a, b))
        if layer_num == 4 or layer_num == 0:
            print('----------layer4-----------')
            for a, b in self.layer4.items():
                if b is not None:
                    print('{}: {}'.format(a, b))


if __name__ == '__main__':
    # with open('/mnt/hgfs/share/protocol-numbers-1.csv', 'r') as f, open('./utils.py', 'w') as f1:
    #     for line in f.readlines():
    #         line_li = line.strip().split(',')
    #         if line_li and line_li[0].isdigit():
    #             f1.write('{}: \'{}\',\n'.format(line_li[0], line_li[1]))

    myPacket = PacketDemo('./packet_testcase/http.txt')
    myPacket.print_layer(4)
