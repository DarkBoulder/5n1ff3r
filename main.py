import ctypes as ct
import libpcap as pcap

if __name__ == "__main__":
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    device = pcap.lookupdev(errbuf)
    handle = pcap.open_live(device, 4096, 1, 1000, errbuf)
    if errbuf.value:
        print("handle error :", errbuf.value)


