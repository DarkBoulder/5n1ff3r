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
    FinishSignal = QtCore.pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        # self.filter = None
        # self.iface = None
        # self.mutex_1 = QMutex()
        # self.conditionFlag = False
        # self.cond = QWaitCondition()
        self.handle = None
        self.brk = False

    def run(self):
        pheader = pcap.pkthdr()
        cnt = 1
        print('live cap start')
        st_time = time.time()
        while True:
            # self.mutex_1.lock()
            if self.brk:
                break
            # if self.conditionFlag:
            #     self.cond.wait(self.mutex_1)
            packet = pcap.next(self.handle, pheader)
            if not packet:
                continue
            now_time = pheader.ts.tv_sec + pheader.ts.tv_usec / 1000000
            my_packet = PacketDemo(ct.string_at(packet, pheader.len), cnt, now_time, st_time, pheader)
            self.HandleSignal.emit(my_packet)
            cnt += 1
            # self.mutex_1.unlock()
        pcap.close(self.handle)
        print('thread finished')
        self.FinishSignal.emit(0)

    def getHandle(self, handle):
        self.handle = handle

    def play(self):
        # self.conditionFlag = False
        # self.cond.wakeAll()
        self.brk = False
        self.start()

    # def restart(self):
    #     pass
        # self.stop()
        # self.msleep(200)
        # self.play()

    def stop(self):
        self.brk = True
        # self.conditionFlag = True

    # def pause(self):
    #     self.conditionFlag = True
    #
    # def resume(self):
    #     self.conditionFlag = False
    #     self.cond.wakeAll()

