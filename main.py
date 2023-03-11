import struct
import socket
import ctypes as ct
import libpcap as pcap

if __name__ == "__main__":
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    device = pcap.lookupdev(errbuf)
    handle = pcap.open_live(device, 4096, 1, 1000, errbuf)
    """
    device为网络接口的名字,
    snaplen是捕获数据包的长度，不能大于65535,
    promise用于标记是否开启混杂模式，1代表混杂模式，其它值代表非混杂模式
    to_ms代表需要等待的毫秒数，超过这个时间后，获得数据包的函数会立即返回，0表示一直等待直到有数据包到来
    errbuf为c语言字符串类型，用于获取错误信息。
    """
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
        if not packet:
            continue
        print(cnt, pheader.ts.tv_sec, pheader.len, pheader.caplen)
        p = ct.pointer(packet.contents)
        ipInfo = struct.unpack('<BBHHHBBH4s4s', bytes(p[14:34]))
        # print(ipInfo)
        srcIp = socket.inet_ntoa(ipInfo[-2])
        dstIp = socket.inet_ntoa(ipInfo[-1])

        print(srcIp, "=>", dstIp)
        pcap.dump(fPcapUbyte, pheader, packet)

        cnt += 1
        if cnt >= 10:
            break

    print('cnt = {}'.format(cnt))
    print('live cap end')
    pcap.close(handle)
    pcap.dump_flush(fPcap)
    pcap.dump_close(fPcap)

