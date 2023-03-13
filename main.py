import struct
import socket
import ctypes as ct
import libpcap as pcap
from packetAnalyzer import *


def show_all_devs(alldevs):
    """
    pcap_if._fields_ = [
    ("next",        ct.POINTER(pcap_if)),
    ("name",        ct.c_char_p),  # name to hand to "pcap.open_live()"
    ("description", ct.c_char_p),  # textual description of interface, or NULL
    ("addresses",   ct.POINTER(pcap_addr)),
    ("flags",       bpf_u_int32),  # PCAP_IF_ interface flags
    :param alldevs:
    :return:
    """
    pt = alldevs[0]
    while pt:
        print(pt.name)
        if pt.next:
            pt = pt.next[0]
        else:
            break


if __name__ == "__main__":
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    alldevs = ct.POINTER(pcap.pcap_if_t)()
    pcap.findalldevs(ct.byref(alldevs), errbuf)
    device = alldevs[0].name
    handle = pcap.open_live(device, 4096, 1, 1000, errbuf)
    if errbuf.value:
        print("handle error :", errbuf.value)
        exit()

    fname = b"realtime1.cap"
    fPcap = pcap.dump_open(handle, fname)
    fPcapUbyte = ct.cast(fPcap, ct.POINTER(ct.c_ubyte))

    pheader = pcap.pkthdr()
    """
    struct pcap_pkthdr
    {
      struct timeval ts;    /* time stamp */
      bpf_u_int32 caplen;   /* length of portion present */
      bpf_u_int32 len;      /* length this packet (off wire) */
    };
    """
    cnt = 0
    print('live cap start')
    while True:
        packet = pcap.next(handle, pheader)
        # print(type(packet))
        if not packet:
            continue
        print(cnt, pheader.ts.tv_sec, pheader.len, pheader.caplen)
        my_packet = PacketDemo(ct.string_at(packet, pheader.len))
        # my_packet.print_layer1()
        my_packet.print_layer()
        # ipInfo = struct.unpack('<BBHHHBBH4s4s', bytes(p[14:34]))
        # # print(ipInfo)
        # srcIp = socket.inet_ntoa(ipInfo[-2])
        # dstIp = socket.inet_ntoa(ipInfo[-1])
        #
        # print(srcIp, "=>", dstIp)
        # pcap.dump(fPcapUbyte, pheader, packet)
        #
        cnt += 1

    print('cnt = {}'.format(cnt))
    print('live cap end')
    pcap.close(handle)
    pcap.freealldevs(alldevs)
    pcap.dump_flush(fPcap)
    pcap.dump_close(fPcap)

