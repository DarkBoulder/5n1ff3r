import struct
import socket
from PyQt5.Qt import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QSplitter
import ctypes as ct
import time
from Sniffer import *
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
        self.sniffer = Sniffer()
        self.setConnection()
        self.setMainUI()
        self._translate = QtCore.QCoreApplication.translate
        self.errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.alldevs = ct.POINTER(pcap.pcap_if_t)()
        self.setupDevice()
        self.packets = []

    def setupDevice(self):
        pcap.findalldevs(ct.byref(self.alldevs), self.errbuf)
        devs_name = get_devs_name(self.alldevs)

        for i in range(len(devs_name)):
            row = self.ui.tableWidget.rowCount()
            self.ui.tableWidget.insertRow(row)
            item = QtWidgets.QTableWidgetItem(bytes.decode(devs_name[i], 'utf8'))
            item.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.ui.tableWidget.setItem(row, 0, item)

    def selectDevice(self, row, col):
        # 打印被选中的单元格
        res = self.ui.tableWidget.item(row, col)
        # print(row, col, self.ui.tableWidget.item(row, col))
        device = res.text()
        handle = pcap.open_live(bytes(device, 'utf8'), 4096, 1, 1000, self.errbuf)
        if self.errbuf.value:
            print("handle error :", self.errbuf.value)
            exit()

        self.sniffer.getHandle(handle)
        fname = b"realtime1.cap"
        fPcap = pcap.dump_open(handle, fname)
        fPcapUbyte = ct.cast(fPcap, ct.POINTER(ct.c_ubyte))

        res = self.ui.tableWidget.rowCount()
        for i in range(res):
            self.ui.tableWidget.removeRow(0)

        self.ui.tableWidget.cellDoubleClicked.disconnect(self.selectDevice)
        self.ui.tableWidget.cellClicked.connect(self.showDetailInfo)

        col_header = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        self.ui.tableWidget.setColumnCount(len(col_header))
        for i in range(len(col_header) - 1):
            item = QtWidgets.QTableWidgetItem()
            self.ui.tableWidget.setHorizontalHeaderItem(i + 1, item)
            item = self.ui.tableWidget.horizontalHeaderItem(i + 1)
            item.setText(self._translate("MainWindow", col_header[i + 1]))

        self.ui.tableWidget.horizontalHeader().setVisible(True)

        self.sniffer.start()

        # print('cnt = {}'.format(cnt))
        # print('live cap end')
        # pcap.close(handle)
        # pcap.freealldevs(self.alldevs)
        # pcap.dump_flush(fPcap)
        # pcap.dump_close(fPcap)

    def setConnection(self):
        # print(self.ui.tableWidget.__dict__)
        self.ui.tableWidget.cellDoubleClicked.connect(self.selectDevice)
        self.sniffer.HandleSignal.connect(self.CallBack)

    def setMainUI(self):
        splitter1 = QSplitter(Qt.Horizontal)
        splitter1.addWidget(self.ui.tableWidget_2)
        splitter1.addWidget(self.ui.plainTextEdit)

        splitter2 = QSplitter(Qt.Vertical)
        splitter2.addWidget(self.ui.tableWidget)
        splitter2.addWidget(splitter1)

        self.ui.verticalLayout.addWidget(splitter2)

    def CallBack(self, my_packet: PacketDemo):
        # assert type(packet) == 'PacketDemo'
        self.packets.append(my_packet)
        number = my_packet.cnt
        time = my_packet.time_span
        src = my_packet.general_info['src']
        dst = my_packet.general_info['dst']
        proto = my_packet.general_info['proto']
        length = my_packet.len
        info = my_packet.general_info['info']
        general_info = [number, time, src, dst, proto, length, info]
        # print(general_info)

        # add to widget
        self.ui.tableWidget.setSelectionBehavior(self.ui.tableWidget.SelectRows)
        row = self.ui.tableWidget.rowCount()
        self.ui.tableWidget.insertRow(row)
        for i in range(len(general_info)):
            item = QtWidgets.QTableWidgetItem(str(general_info[i]))
            item.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.ui.tableWidget.setItem(row, i, item)
            if number == 1:
                self.ui.tableWidget.resizeColumnToContents(i)
        # print(my_packet.print_layer())

    def showDetailInfo(self, row, col):
        pkt = self.packets[row]
        self.ui.plainTextEdit.setPlainText(str(pkt.hex_packet))
