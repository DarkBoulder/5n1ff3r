import struct
import socket
from PyQt5.Qt import *
from PyQt5 import QtCore
import ctypes as ct
import time
import sys
import SnifferUI
import SnifferController

import libpcap as pcap
from packetAnalyzer import *


if __name__ == "__main__":
    app = QApplication(sys.argv)  # 创建QApplication类的实例
    window = QMainWindow()  # 创建一个窗口
    ui = SnifferUI.Ui_MainWindow()
    ui.setupUi(window)
    # window.setWindowIcon(QIcon('web.png'))#增加icon图标
    sc = SnifferController.SnifferController(ui)  # C
    window.show()
    sys.exit(app.exec_())  # 进入程序的主循环，并通过exit函数确保主循环安全结束

