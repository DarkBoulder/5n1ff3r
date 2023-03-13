import binascii
import ctypes
import struct
import socket
from utils import *


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
    def __init__(self, data_src):
        self.raw_packet = None
        if str(type(data_src)) == '<class \'libpcap._bpf.LP_c_ubyte\'>':
            # data_src: ct.pointer(packet.contents)
            self.raw_packet = bytes(data_src[0:])
            # print(self.raw_packet)
        else:  # path of testcases
            with open(data_src, 'r') as f:
                a = f.readline()
                self.raw_packet = binascii.unhexlify(a)
        self.layer1 = {'name': None, 'dst': None, 'src': None, 'type': None}
        self.layer2 = {
            'name': None, 'src': None, 'dst': None, 'version': None, 'ihl': None,
            'tos': None, 'len': None, 'id': None, 'flag': None, 'ttl': None, 'protocol': None,
            'chksum': None, 'tc': None, 'fl': None, 'pl': None, 'nh': None,
            'opt': None, 'htype': None, 'ptype': None, 'hlen': None, 'plen': None,
            'op': None, 'info': None, 'sha': None, 'spa': None, 'tha': None, 'tpa': None
            }
        self.parse_packet()

    def parse_layer1(self):
        # TODO: 802.3 and other protocols
        layer1_info = struct.unpack('<6s6s2s', self.raw_packet[0:14])
        self.layer1['name'] = 'EthernetII'
        self.layer1['dst'] = bytestream_to_hardwareaddr(layer1_info[0])
        self.layer1['src'] = bytestream_to_hardwareaddr(layer1_info[1])
        self.layer1['type'] = ieee_802_numbers.get(str(bytes.hex(layer1_info[2])).upper(), 'UNK')

    def parse_layer2(self):
        if self.layer1['type'] == 'Internet Protocol version 4 (IPv4)':
            ipv4_info = struct.unpack('>BBHHHBBH4s4s', self.raw_packet[14:34])
            self.layer2['name'] = self.layer1['type']
            self.layer2['src'] = socket.inet_ntoa(ipv4_info[-2])
            self.layer2['dst'] = socket.inet_ntoa(ipv4_info[-1])
            self.layer2['version'] = ipv4_info[0] >> 4
            self.layer2['ihl'] = ipv4_info[0] & 15  # internet header length, represents 4B for each
            self.layer2['tos'] = ipv4_info[1]  # type of service
            self.layer2['len'] = ipv4_info[2]  # total length, 1B for each
            self.layer2['id'] = ipv4_info[3]
            self.layer2['flag'] = ipv4_info[4]  # 3 flags, 13 fragment offset
            self.layer2['ttl'] = ipv4_info[5]
            self.layer2['protocol'] = protocol_numbers.get(ipv4_info[6], 'Unassigned')
            self.layer2['chksum'] = ipv4_info[7]

        elif self.layer1['type'] == 'Internet Protocol version 6 (IPv6)':
            ipv6_info = struct.unpack('>IHBB16s16s', self.raw_packet[14:54])
            self.layer2['name'] = self.layer1['type']
            self.layer2['src'] = bytestream_to_ipv6addr(ipv6_info[4])
            self.layer2['dst'] = bytestream_to_ipv6addr(ipv6_info[5])
            self.layer2['version'] = ipv6_info[0] >> 28
            self.layer2['tc'] = hex((ipv6_info[0] & 0xfffffff) >> 20)  # traffic_class
            self.layer2['fl'] = hex(ipv6_info[0] & 0xfffff)  # flow_label
            self.layer2['pl'] = ipv6_info[1]  # payload_length
            self.layer2['nh'] = protocol_numbers.get(ipv6_info[2], 'Unassigned')  # next_header
            self.layer2['hl'] = ipv6_info[3]  # hop_limit

        elif self.layer1['type'] == 'Address Resolution Protocol (ARP)':
            arp_info = struct.unpack('>H2sBBH6s4s6s4s', self.raw_packet[14:42])
            self.layer2['name'] = self.layer1['type']
            self.layer2['htype'] = arp_info[0]  # hardware type
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

        else:
            pass

    def parse_packet(self):
        self.parse_layer1()
        self.parse_layer2()

    def print_layer(self, layer_num=0):
        if layer_num == 1 or layer_num == 0:
            print('----------layer1-----------')
            print(self.layer1)
        if layer_num == 2 or layer_num == 0:
            print('----------layer2-----------')
            for a, b in self.layer2.items():
                if b is not None:
                    print('{}: {}'.format(a, b))


if __name__ == '__main__':
    # IPV6 testcase
    # with open('packet_testcase/icmpv6.txt', 'r') as f:
    #     a = f.readline()
    #     b = binascii.unhexlify(a)
    #     ipv6_info = struct.unpack('>IHBB16s16s', b[14:54])
    #     print(ipv6_info)
    #     src = bytestream_to_ipv6addr(ipv6_info[4])
    #     dst = bytestream_to_ipv6addr(ipv6_info[5])
    #     ver = ipv6_info[0] >> 28
    #     traffic_class = hex((ipv6_info[0] & 0xfffffff) >> 20)
    #     flow_label = hex(ipv6_info[0] & 0xfffff)
    #     payload_length = ipv6_info[1]
    #     next_header = ipv6_info[2]
    #     hop_limit = ipv6_info[3]
    #     print('src:{}\ndst:{}\nver:{}\ntf_cl:{}\n{}'.format(src, dst, ver, traffic_class, flow_label))

    # with open('/mnt/hgfs/share/protocol-numbers-1.csv', 'r') as f, open('./utils.py', 'w') as f1:
    #     for line in f.readlines():
    #         line_li = line.strip().split(',')
    #         if line_li and line_li[0].isdigit():
    #             f1.write('{}: \'{}\',\n'.format(line_li[0], line_li[1]))

    # with open('/mnt/hgfs/share/ieee-802-numbers-1.csv', 'r') as f, open('./utils1.py', 'w') as f1:
    #     for line in f.readlines():
    #         line_li = line.strip().split(',')
    #         print(line_li)
    #         if len(line_li) >= 5 and line_li[1].find('-') == -1:
    #             f1.write('\'{}\': \'{}\',\n'.format(line_li[1], line_li[4]))
    myPacket = PacketDemo('./packet_testcase/arp_reply.txt')
    myPacket.print_layer()
