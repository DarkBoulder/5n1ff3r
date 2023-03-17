import struct
import socket
from PyQt5.Qt import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QSplitter
import ctypes as ct
import time
import sys

import libpcap as pcap
from packetAnalyzer import *


def get_devs_name(alldevs):
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
    res = []
    pt = alldevs[0]
    while pt:
        res.append(pt.name)
        if pt.next:
            pt = pt.next[0]
        else:
            break
    return res


class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

    def setupDevice(self):
        _translate = QtCore.QCoreApplication.translate
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        alldevs = ct.POINTER(pcap.pcap_if_t)()
        pcap.findalldevs(ct.byref(alldevs), errbuf)
        devs_name = get_devs_name(alldevs)

        for i in range(len(devs_name)):
            row = self.ui.tableWidget.rowCount()
            self.ui.tableWidget.insertRow(row)
            item = QtWidgets.QTableWidgetItem(bytes.decode(devs_name[i], 'utf8'))
            item.setFlags(
                QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            self.ui.tableWidget.setItem(row, 0, item)

    def setConnection(self):
        pass

    def setMainUI(self):
        splitter1 = QSplitter(Qt.Horizontal)
        splitter1.addWidget(self.ui.tableWidget_2)
        splitter1.addWidget(self.ui.tableWidget_3)

        splitter2 = QSplitter(Qt.Vertical)
        splitter2.addWidget(self.ui.tableWidget)
        splitter2.addWidget(splitter1)

        self.ui.verticalLayout.addWidget(splitter2)

    def m(self):
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        alldevs = ct.POINTER(pcap.pcap_if_t)()
        pcap.findalldevs(ct.byref(alldevs), errbuf)
        get_devs_name(alldevs)
        device = alldevs[0].name
        handle = pcap.open_live(device, 4096, 1, 1000, errbuf)
        if errbuf.value:
            print("handle error :", errbuf.value)
            exit()

        fname = b"realtime1.cap"
        fPcap = pcap.dump_open(handle, fname)
        fPcapUbyte = ct.cast(fPcap, ct.POINTER(ct.c_ubyte))

        pheader = pcap.pkthdr()
        cnt = 1
        print('live cap start')
        st_time = time.time()
        while True:
            packet = pcap.next(handle, pheader)
            if not packet:
                continue
            now_time = pheader.ts.tv_sec + pheader.ts.tv_usec / 1000000
            my_packet = PacketDemo(ct.string_at(packet, pheader.len), cnt, now_time, st_time, pheader)
            cnt += 1

        print('cnt = {}'.format(cnt))
        print('live cap end')
        pcap.close(handle)
        pcap.freealldevs(alldevs)
        pcap.dump_flush(fPcap)
        pcap.dump_close(fPcap)

