# -*- coding: utf-8 -*-
"""
Editor : GH

This is a temporary script file.
"""

import ctypes as ct
import time
from PyQt5 import QtCore

import libpcap as pcap
from packetAnalyzer import *


class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(PacketDemo)
    FinishSignal = QtCore.pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        self.handle = None
        self.brk = False

    def run(self):
        pheader = pcap.pkthdr()
        cnt = 1
        print('live cap start')
        st_time = time.time()
        while True:
            if self.brk:
                break
            packet = pcap.next(self.handle, pheader)
            if not packet:
                continue
            now_time = pheader.ts.tv_sec + pheader.ts.tv_usec / 1000000
            my_packet = PacketDemo(ct.string_at(packet, pheader.len), cnt, now_time, st_time, pheader)
            self.HandleSignal.emit(my_packet)
            cnt += 1
        pcap.close(self.handle)
        print('thread finished')
        self.FinishSignal.emit(0)

    def getHandle(self, handle):
        self.handle = handle

    def play(self):
        self.brk = False
        self.start()

    def stop(self):
        self.brk = True
