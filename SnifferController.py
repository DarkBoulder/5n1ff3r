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
        print(row, col, self.ui.tableWidget.item(row, col))
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

        self.ui.tableWidget.setColumnCount(6)
        item = QtWidgets.QTableWidgetItem()
        self.ui.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.ui.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.ui.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.ui.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.ui.tableWidget.setHorizontalHeaderItem(5, item)
        item = self.ui.tableWidget.horizontalHeaderItem(1)
        item.setText(self._translate("MainWindow", "Time"))
        item = self.ui.tableWidget.horizontalHeaderItem(2)
        item.setText(self._translate("MainWindow", "Source"))
        item = self.ui.tableWidget.horizontalHeaderItem(3)
        item.setText(self._translate("MainWindow", "Destination"))
        item = self.ui.tableWidget.horizontalHeaderItem(4)
        item.setText(self._translate("MainWindow", "Protocol"))
        item = self.ui.tableWidget.horizontalHeaderItem(5)
        item.setText(self._translate("MainWindow", "Info"))

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

    def setMainUI(self):
        splitter1 = QSplitter(Qt.Horizontal)
        splitter1.addWidget(self.ui.tableWidget_2)
        splitter1.addWidget(self.ui.tableWidget_3)

        splitter2 = QSplitter(Qt.Vertical)
        splitter2.addWidget(self.ui.tableWidget)
        splitter2.addWidget(splitter1)

        self.ui.verticalLayout.addWidget(splitter2)
