# -*- coding: utf-8 -*-
"""
Editor : GH

This is a temporary script file.
"""

from socket import timeout
from scapy.all import *
import ctypes as ct
import os
import time
import multiprocessing
from scapy.layers import http
import numpy as np
import matplotlib.pyplot as plt
import binascii
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import libpcap as pcap
from packetAnalyzer import *


class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(PacketDemo)

    def __init__(self) -> None:
        super().__init__()
        # self.filter = None
        # self.iface = None
        # self.conditionFlag = False
        self.mutex_1 = QMutex()
        # self.cond = QWaitCondition()
        self.conditionFlag = False
        self.cond = QWaitCondition()
        self.handle = None

    def run(self):
        pheader = pcap.pkthdr()
        cnt = 1
        print('live cap start')
        st_time = time.time()
        while True:
            self.mutex_1.lock()
            if self.conditionFlag:
                self.cond.wait(self.mutex_1)
            packet = pcap.next(self.handle, pheader)
            if not packet:
                continue
            now_time = pheader.ts.tv_sec + pheader.ts.tv_usec / 1000000
            my_packet = PacketDemo(ct.string_at(packet, pheader.len), cnt, now_time, st_time, pheader)
            self.HandleSignal.emit(my_packet)
            cnt += 1
            self.mutex_1.unlock()

    def getHandle(self, handle):
        self.handle = handle

    def play(self):
        self.conditionFlag = False
        self.cond.wakeAll()

    def restart(self):
        self.conditionFlag = True

    def stop(self):
        self.conditionFlag = True

    # def pause(self):
    #     self.conditionFlag = True
    #
    # def resume(self):
    #     self.conditionFlag = False
    #     self.cond.wakeAll()

