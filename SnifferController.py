import struct
import socket
from PyQt5.Qt import *
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QSplitter
import ctypes as ct
import time
from Sniffer import *
import sys
import time

import libpcap as pcap
from packetAnalyzer import *
from utils import *


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
        self.setMainUI()
        self.setConnection()
        self._translate = QtCore.QCoreApplication.translate
        self.errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.alldevs = ct.POINTER(pcap.pcap_if_t)()
        self.setupDevice()
        self.packets = []
        self.packets_mutex = QMutex()
        self.device_name = ''
        self.filter_policy = ''
        self.legal_proto = {'eth', 'ip', 'ipv6', 'arp', 'tcp', 'udp', 'icmp', 'http', 'https', 'dns'}
        self.legal_oprd1 = {'ip.src', 'ip.dst', 'ip.addr', 'tcp.port', 'tcp.srcport', 'tcp.dstport',
                            'udp.port', 'udp.srcport', 'udp.dstport', 'eth.src', 'eth.dst', 'eth.addr'}
        self.legal_words = {'ip.src', 'ip.dst', 'ip.addr', 'tcp.port', 'tcp.srcport', 'tcp.dstport',
                            'udp.port', 'udp.srcport', 'udp.dstport', 'eth.src', 'eth.dst', 'eth.addr',
                            'eth', 'ipv6', 'ip', 'arp', 'tcp', 'udp', 'icmp', 'https', 'http', 'dns'}
        self.seg = []
        self.ind = []

    def setupDevice(self):
        # show available devices
        pcap.findalldevs(ct.byref(self.alldevs), self.errbuf)
        devs_name = get_devs_name(self.alldevs)

        for i in range(len(devs_name)):
            row = self.ui.tableWidget.rowCount()
            self.ui.tableWidget.insertRow(row)
            item = QtWidgets.QTableWidgetItem(bytes.decode(devs_name[i], 'utf8'))
            item.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.ui.tableWidget.setItem(row, 0, item)

    def get_device_name(self, row, col):
        res = self.ui.tableWidget.item(row, col)
        # print(row, col, self.ui.tableWidget.item(row, col))
        self.device_name = res.text()
        handle = pcap.open_live(bytes(self.device_name, 'utf8'), 4096, 1, 100, self.errbuf)
        if self.errbuf.value:
            print("handle error :", self.errbuf.value)
            exit()

        self.sniffer.getHandle(handle)
        # fname = b"realtime1.cap"
        # fPcap = pcap.dump_open(handle, fname)
        # fPcapUbyte = ct.cast(fPcap, ct.POINTER(ct.c_ubyte))

        # clear device_name list
        res = self.ui.tableWidget.rowCount()
        for i in range(res):
            self.ui.tableWidget.removeRow(0)

        self.ui.tableWidget.cellDoubleClicked.disconnect(self.get_device_name)
        self.ui.tableWidget.cellClicked.connect(self.showHexInfo)
        self.ui.tableWidget.cellClicked.connect(self.showTreeInfo)

        self.ui.tableWidget.setSelectionBehavior(self.ui.tableWidget.SelectRows)

        # self.ui.buttonRestart.setEnabled(True)
        self.ui.buttonStop.setEnabled(True)

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
        # pcap.freealldevs(self.alldevs)
        # pcap.dump_flush(fPcap)
        # pcap.dump_close(fPcap)

    def setConnection(self):
        # print(self.ui.tableWidget.__dict__)
        self.ui.tableWidget.cellDoubleClicked.connect(self.get_device_name)
        self.sniffer.HandleSignal.connect(self.CallBack)
        self.sniffer.FinishSignal.connect(self.FinishCallBack)

        self.ui.buttonPlay.clicked.connect(lambda: self.play_status())
        # self.ui.buttonRestart.clicked.connect(lambda: self.restart_status())
        self.ui.buttonStop.clicked.connect(lambda: self.stop_status())

        self.ui.buttonPlay.clicked.connect(lambda: self.sniffer.play())
        # self.ui.buttonRestart.clicked.connect(lambda: self.sniffer.restart())
        self.ui.buttonStop.clicked.connect(lambda: self.sniffer.stop())

        self.ui.buttonPlay.setEnabled(False)
        # self.ui.buttonRestart.setEnabled(False)
        self.ui.buttonStop.setEnabled(False)

        self.ui.lineEdit.returnPressed.connect(lambda: self.apply_filter_policy())

    def setMainUI(self):
        splitter1 = QSplitter(Qt.Horizontal)
        splitter1.addWidget(self.ui.treeWidget)
        splitter1.addWidget(self.ui.plainTextEdit)

        splitter2 = QSplitter(Qt.Vertical)
        splitter2.addWidget(self.ui.tableWidget)
        splitter2.addWidget(splitter1)

        self.ui.verticalLayout.addWidget(splitter2)

        self.ui.buttonPlay = QtWidgets.QPushButton()
        self.ui.buttonPlay.setIcon(QIcon("./icons/play.jpg"))
        self.ui.buttonPlay.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.ui.buttonPlay.setToolTip("开始捕获")
        self.ui.toolBar.addWidget(self.ui.buttonPlay)
        self.ui.toolBar.addSeparator()

        self.ui.buttonStop = QtWidgets.QPushButton()
        self.ui.buttonStop.setIcon(QIcon("./icons/stop.jpg"))
        self.ui.buttonStop.setStyleSheet("background:rgba(0,0,0,0);border:1px solid rgba(0,0,0,0);border-radius:5px;")
        self.ui.buttonStop.setToolTip("停止捕获")
        self.ui.toolBar.addWidget(self.ui.buttonStop)
        self.ui.toolBar.addSeparator()

    def FinishCallBack(self, res):
        self.ui.buttonPlay.setEnabled(True)

    def add_packet_to_tableWidget(self, pkt):
        number = pkt.cnt
        time = pkt.time_span
        src = pkt.general_info['src']
        dst = pkt.general_info['dst']
        proto = pkt.general_info['proto']
        length = pkt.len
        info = pkt.general_info['info']
        general_info = [number, time, src, dst, proto, length, info]

        # add to widget
        row = self.ui.tableWidget.rowCount()
        self.ui.tableWidget.insertRow(row)
        for i in range(len(general_info)):
            item = QtWidgets.QTableWidgetItem(str(general_info[i]))
            item.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            self.ui.tableWidget.setItem(row, i, item)
            if number == 1:
                self.ui.tableWidget.resizeColumnToContents(i)

    def CallBack(self, pkt: PacketDemo):  # call back after parsing a packet, deal with new packets
        self.packets_mutex.lock()
        self.packets.append(pkt)
        self.packets_mutex.unlock()
        if len(self.seg) and not self.isFiltered(pkt, self.seg, self.ind):
            return

        self.add_packet_to_tableWidget(pkt)
        # print(pkt.print_layer())

    def showHexInfo(self, row, col):
        pkt = self.packets[row]
        self.ui.plainTextEdit.setPlainText(str(pkt.hex_packet))

    def showTreeInfo(self, row, col):
        self.ui.treeWidget.clear()

        pkt = self.packets[row]

        # packet info
        frame = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
        frame.setText(0, 'Frame {}: {} bytes on wire, {} bytes captured'.format(pkt.cnt, pkt.len, pkt.caplen))
        frameproto = QtWidgets.QTreeWidgetItem(frame)
        frameproto.setText(0, 'Encapsulation Type: {}'.format(pkt.layer1['name']))
        frameIface = QtWidgets.QTreeWidgetItem(frame)
        frameIface.setText(0, 'Device: {}'.format(self.device_name))
        frameTimestamp = QtWidgets.QTreeWidgetItem(frame)
        frameTimestamp.setText(0,
                               'Localtime: {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pkt.time_stamp))))
        framenum = QtWidgets.QTreeWidgetItem(frame)
        framenum.setText(0, 'Frame Number: {}'.format(pkt.cnt))
        framelength = QtWidgets.QTreeWidgetItem(frame)
        framelength.setText(0, 'Frame Length: {} bytes ({} bits)'.format(pkt.len, pkt.len * 8))
        framecapturelen = QtWidgets.QTreeWidgetItem(frame)
        framecapturelen.setText(0, 'Capture Length: {} bytes ({} bits)'.format(pkt.caplen, pkt.caplen * 8))

        # layer1 info
        if pkt.layer1['name']:
            layer1 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer1.setText(0, '{}, Src: {}, Dst: {}'.format(pkt.layer1['name'], pkt.layer1['src'], pkt.layer1['dst']))
            layer1_dst = QtWidgets.QTreeWidgetItem(layer1)
            layer1_dst.setText(0, 'Destination: {}'.format(pkt.layer1['dst']))
            layer1_src = QtWidgets.QTreeWidgetItem(layer1)
            layer1_src.setText(0, 'Source: {}'.format(pkt.layer1['src']))
            layer1_type = QtWidgets.QTreeWidgetItem(layer1)
            layer1_type.setText(0, 'Type: {} ({})'.format(pkt.layer1['type'],
                                                          '0x' + get_key(ieee_802_numbers, pkt.layer1['type'])))
        else:
            return

        # layer2 info
        if pkt.layer2['name'] == 'Internet Protocol version 4 (IPv4)':
            layer2 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer2.setText(0, '{}, Src: {}, Dst: {}'.format('Internet Protocol version 4', pkt.layer2['src'],
                                                            pkt.layer2['dst']))
            layer2_version = QtWidgets.QTreeWidgetItem(layer2)
            layer2_version.setText(0, '0100 .... = Version 4')
            layer2_ihl = QtWidgets.QTreeWidgetItem(layer2)
            layer2_ihl.setText(0, '.... {} = Header Length: {} bytes ({})'.format(bin(pkt.layer2['ihl'])[2:],
                                                                                  pkt.layer2['ihl'] * 4,
                                                                                  pkt.layer2['ihl']))
            layer2_tos = QtWidgets.QTreeWidgetItem(layer2)
            layer2_tos.setText(0, 'Differentiated Services Field: 0x{}'.format(str(pkt.layer2['tos']).zfill(2)))
            layer2_len = QtWidgets.QTreeWidgetItem(layer2)
            layer2_len.setText(0, 'Total Length: {}'.format(str(pkt.layer2['len'])))
            layer2_id = QtWidgets.QTreeWidgetItem(layer2)
            layer2_id.setText(0, 'Identification: {}'.format(str(hex(pkt.layer2['id']))))
            layer2_flag = QtWidgets.QTreeWidgetItem(layer2)
            layer2_flag.setText(0, 'Flags: {}'.format(str(hex(pkt.layer2['flag']))))
            layer2_ttl = QtWidgets.QTreeWidgetItem(layer2)
            layer2_ttl.setText(0, 'Time to Live: {}'.format(str(pkt.layer2['ttl'])))
            layer2_proto = QtWidgets.QTreeWidgetItem(layer2)
            layer2_proto.setText(0, 'Protocol: {} ({})'.format(str(pkt.layer2['protocol']),
                                                               get_key(protocol_numbers, pkt.layer2['protocol'])))
            layer2_chksum = QtWidgets.QTreeWidgetItem(layer2)
            layer2_chksum.setText(0, 'Header Checksum: {}'.format(str(hex(pkt.layer2['chksum']))))
            layer2_src = QtWidgets.QTreeWidgetItem(layer2)
            layer2_src.setText(0, 'Source Address: {}'.format(pkt.layer2['src']))
            layer2_dst = QtWidgets.QTreeWidgetItem(layer2)
            layer2_dst.setText(0, 'Destination Address: {}'.format(pkt.layer2['dst']))
        elif pkt.layer2['name'] == 'Internet Protocol version 6 (IPv6)':
            layer2 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer2.setText(0, '{}, Src: {}, Dst: {}'.format('Internet Protocol version 6', pkt.layer2['src'],
                                                            pkt.layer2['dst']))
            layer2_version = QtWidgets.QTreeWidgetItem(layer2)
            layer2_version.setText(0, '0110 .... = Version 6')
            layer2_tc = QtWidgets.QTreeWidgetItem(layer2)
            layer2_tc.setText(0, 'Traffic Class: {}'.format(str(pkt.layer2['tc'])))
            layer2_fl = QtWidgets.QTreeWidgetItem(layer2)
            layer2_fl.setText(0, 'Flow Lable: {}'.format(str(pkt.layer2['fl'])))
            layer2_pl = QtWidgets.QTreeWidgetItem(layer2)
            layer2_pl.setText(0, 'Payload Length: {}'.format(pkt.layer2['pl']))
            layer2_nh = QtWidgets.QTreeWidgetItem(layer2)
            layer2_nh.setText(0, 'Next Header: {} ({})'.format(pkt.layer2['nh'],
                                                               get_key(protocol_numbers, pkt.layer2['nh'])))
            layer2_hl = QtWidgets.QTreeWidgetItem(layer2)
            layer2_hl.setText(0, 'Hop Limit: {}'.format(str(pkt.layer2['hl'])))
            layer2_src = QtWidgets.QTreeWidgetItem(layer2)
            layer2_src.setText(0, 'Source Address: {}'.format(pkt.layer2['src']))
            layer2_dst = QtWidgets.QTreeWidgetItem(layer2)
            layer2_dst.setText(0, 'Destination Address: {}'.format(pkt.layer2['dst']))
        elif pkt.layer2['name'] == 'Address Resolution Protocol (ARP)':
            layer2 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer2.setText(0, 'Address Resolution Protocol ({})'.format(pkt.layer2['op']))
            layer2_htype = QtWidgets.QTreeWidgetItem(layer2)
            layer2_htype.setText(0, 'Hardware Type: {}'.format(str(pkt.layer2['htype'])))
            layer2_ptype = QtWidgets.QTreeWidgetItem(layer2)
            layer2_ptype.setText(0, 'Protocol Type: {} ({})'.format(ieee_802_numbers.get(pkt.layer2['ptype'][2:]),
                                                                    pkt.layer2['ptype']))
            layer2_hlen = QtWidgets.QTreeWidgetItem(layer2)
            layer2_hlen.setText(0, 'Hardware Size: {}'.format(str(pkt.layer2['hlen'])))
            layer2_plen = QtWidgets.QTreeWidgetItem(layer2)
            layer2_plen.setText(0, 'Protocol Size: {}'.format(str(pkt.layer2['plen'])))
            layer2_op = QtWidgets.QTreeWidgetItem(layer2)
            layer2_op.setText(0,
                              'Opcode: {} ({})'.format(pkt.layer2['op'], '1' if pkt.layer2['op'] == 'request' else '2'))
            layer2_sha = QtWidgets.QTreeWidgetItem(layer2)
            layer2_sha.setText(0, 'Sender Hardware Address: {}'.format(pkt.layer2['sha']))
            layer2_spa = QtWidgets.QTreeWidgetItem(layer2)
            layer2_spa.setText(0, 'Sender IP Address: {}'.format(pkt.layer2['spa']))
            layer2_tha = QtWidgets.QTreeWidgetItem(layer2)
            layer2_tha.setText(0, 'Target Hardware Address: {}'.format(pkt.layer2['tha']))
            layer2_tpa = QtWidgets.QTreeWidgetItem(layer2)
            layer2_tpa.setText(0, 'Target IP Address: {}'.format(pkt.layer2['tpa']))
        else:
            return

        # layer3 info
        if pkt.layer3['name'] == 'TCP':
            layer3 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer3.setText(0, 'Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Len: {}'.format(
                str(pkt.layer3['src']), str(pkt.layer3['dst']), str(pkt.layer3['seq']), str(pkt.layer3['payload_len'])))
            layer3_src = QtWidgets.QTreeWidgetItem(layer3)
            layer3_src.setText(0, 'Source Port: {}'.format(str(pkt.layer3['src'])))
            layer3_dst = QtWidgets.QTreeWidgetItem(layer3)
            layer3_dst.setText(0, 'Destination Port: {}'.format(str(pkt.layer3['dst'])))
            layer3_seq = QtWidgets.QTreeWidgetItem(layer3)
            layer3_seq.setText(0, 'Sequence Number: {}'.format(str(pkt.layer3['seq'])))
            layer3_ack = QtWidgets.QTreeWidgetItem(layer3)
            layer3_ack.setText(0, 'Acknowledgement Number: {}'.format(str(pkt.layer3['ack'])))
            layer3_hl = QtWidgets.QTreeWidgetItem(layer3)
            layer3_hl.setText(0, 'Header Length: {}'.format(str(pkt.layer3['hl'])))
            layer3_dst = QtWidgets.QTreeWidgetItem(layer3)
            layer3_dst.setText(0, 'Destination Port: {}'.format(str(pkt.layer3['dst'])))

            flag_info = ''
            for ele in pkt.layer3['flag_dic']:
                flag_info += (ele + ', ')
            flag_info = flag_info[:-2]
            layer3_flag = QtWidgets.QTreeWidgetItem(layer3)
            layer3_flag.setText(0, 'Flags: {} ({})'.format('0x%03x' % pkt.layer3['flag'], flag_info))
            layer3_window = QtWidgets.QTreeWidgetItem(layer3)
            layer3_window.setText(0, 'Window: {}'.format(str(pkt.layer3['window'])))
            layer3_chksum = QtWidgets.QTreeWidgetItem(layer3)
            layer3_chksum.setText(0, 'Checksum: {}'.format(str(hex(pkt.layer3['chksum']))))
            layer3_up = QtWidgets.QTreeWidgetItem(layer3)
            layer3_up.setText(0, 'Urgent Pointer: {}'.format(str(hex(pkt.layer3['up']))))
            layer3_payload = QtWidgets.QTreeWidgetItem(layer3)
            layer3_payload.setText(0, 'TCP Payload: {}'.format(str(hex(pkt.layer3['payload_len']))))
        elif pkt.layer3['name'] == 'UDP':
            layer3 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer3.setText(0, 'User Datagram Protocol, Src Port: {}, Dst Port: {}'.format(
                str(pkt.layer3['src']), str(pkt.layer3['dst'])))
            layer3_src = QtWidgets.QTreeWidgetItem(layer3)
            layer3_src.setText(0, 'Source Port: {}'.format(str(pkt.layer3['src'])))
            layer3_dst = QtWidgets.QTreeWidgetItem(layer3)
            layer3_dst.setText(0, 'Destination Port: {}'.format(str(pkt.layer3['dst'])))
            layer3_len = QtWidgets.QTreeWidgetItem(layer3)
            layer3_len.setText(0, 'Length: {}'.format(str(pkt.layer3['length'])))
            layer3_chksum = QtWidgets.QTreeWidgetItem(layer3)
            layer3_chksum.setText(0, 'Checksum: {}'.format(str(hex(pkt.layer3['chksum']))))
            layer3_payload = QtWidgets.QTreeWidgetItem(layer3)
            layer3_payload.setText(0, 'UDP Payload ({} bytes)'.format(str(pkt.layer3['length'] - 8)))
        elif pkt.layer3['name'] == 'ICMP':
            layer3 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer3.setText(0, 'Internet Control Message Protocol')
            layer3_type = QtWidgets.QTreeWidgetItem(layer3)
            type_option = 'request' if pkt.layer3['type'] == 8 else 'reply' if pkt.layer3['type'] == 0 else ''
            layer3_type.setText(0, 'Type: {} (Echo (ping) {})'.format(str(pkt.layer3['type']), type_option))
            layer3_code = QtWidgets.QTreeWidgetItem(layer3)
            layer3_code.setText(0, 'Code: {}'.format(str(pkt.layer3['code']), type_option))
            layer3_chksum = QtWidgets.QTreeWidgetItem(layer3)
            layer3_chksum.setText(0, 'Checksum: {}'.format(str(hex(pkt.layer3['chksum']))))
            layer3_id = QtWidgets.QTreeWidgetItem(layer3)
            layer3_id.setText(0, 'Identifier: {}'.format(str(hex(pkt.layer3['id']))))
            layer3_seq = QtWidgets.QTreeWidgetItem(layer3)
            layer3_seq.setText(0, 'Sequence Number: {}'.format(str(hex(pkt.layer3['seq']))))
            layer3_data = QtWidgets.QTreeWidgetItem(layer3)
            layer3_data.setText(0, 'Data ({} bytes)'.format(str(pkt.layer2['len'] - pkt.layer2['ihl'] * 4 - 8)))
        else:
            return

        # layer4 info
        if pkt.layer4['name'] == 'HTTP':
            layer4 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer4.setText(0, 'Hypertext Transfer Protocol')
            layer4_httpinfo = []
            if pkt.layer4['httpinfo'] and pkt.layer4['httpinfo'][0] and pkt.layer4['httpinfo'][0][0] == '\x00':
                return
            for ele in pkt.layer4['httpinfo']:
                layer4_httpinfo.append(QtWidgets.QTreeWidgetItem(layer4))
                layer4_httpinfo[-1].setText(0, ele)
        elif pkt.layer4['name'] == 'HTTPS':
            layer4 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer4.setText(0, 'Hypertext Transfer Protocol Secure')
        elif pkt.layer4['name'] == 'DNS':
            opration = ''
            if pkt.layer4['flag_dict']['opcode'] <= 1:
                operation = 'query'
            elif pkt.layer4['flag_dict']['opcode'] == 2:
                operation = 'request'
            layer4 = QtWidgets.QTreeWidgetItem(self.ui.treeWidget)
            layer4.setText(0, 'Domain Name System ({})'.format(opration))
            layer4_tid = QtWidgets.QTreeWidgetItem(layer4)
            layer4_tid.setText(0, 'Transaction ID: {}'.format(str(pkt.layer4['tid'])))
            flag_info = 'Standard query' if pkt.layer4['flag_dict']['opcode'] == 0 else \
                'Inverse query' if pkt.layer4['flag_dict']['opcode'] == 1 else \
                    'Server status request' if pkt.layer4['flag_dict']['opcode'] == 2 else \
                        ''
            layer4_flag = QtWidgets.QTreeWidgetItem(layer4)
            layer4_flag.setText(0, 'Flags: {} {}'.format('0x%04x' % pkt.layer4['flag'], flag_info))
            # TODO: put flag details in
            layer4_ques = QtWidgets.QTreeWidgetItem(layer4)
            layer4_ques.setText(0, 'Questions: {}'.format(str(pkt.layer4['ques'])))
            layer4_ansrr = QtWidgets.QTreeWidgetItem(layer4)
            layer4_ansrr.setText(0, 'Answer RRs: {}'.format(str(pkt.layer4['ansrr'])))
            layer4_authrr = QtWidgets.QTreeWidgetItem(layer4)
            layer4_authrr.setText(0, 'Authority RRs: {}'.format(str(pkt.layer4['authrr'])))
            layer4_addrr = QtWidgets.QTreeWidgetItem(layer4)
            layer4_addrr.setText(0, 'Additional RRs: {}'.format(str(pkt.layer4['addrr'])))
            layer4_query = QtWidgets.QTreeWidgetItem(layer4)
            layer4_query.setText(0, 'Queries')
        else:
            return

    def play_status(self):
        self.clear_tableWidget()
        handle = pcap.open_live(bytes(self.device_name, 'utf8'), 4096, 1, 1000, self.errbuf)
        if self.errbuf.value:
            print("handle error :", self.errbuf.value)
            exit()

        self.sniffer.getHandle(handle)
        self.packets.clear()

        self.ui.buttonPlay.setEnabled(False)
        # self.ui.buttonRestart.setEnabled(True)
        self.ui.buttonStop.setEnabled(True)

    def stop_status(self):
        self.ui.buttonPlay.setEnabled(False)
        # self.ui.buttonRestart.setEnabled(False)
        self.ui.buttonStop.setEnabled(False)

    def clear_tableWidget(self):
        row = self.ui.tableWidget.rowCount()
        for i in range(row):
            self.ui.tableWidget.removeRow(0)

    def apply_filter_policy(self):  # triggered when pressed enter in lineEdit, deal with existing packets
        self.filter_policy = self.ui.lineEdit.text().strip().lower()
        self.clear_tableWidget()
        self.seg, self.ind = self.policy_slice()
        print('****** new policy applied ******\nseg: {}, ind: {}'.format(self.seg, self.ind))
        for ele in self.packets:
            if self.isFiltered(ele, self.seg, self.ind):
                self.add_packet_to_tableWidget(ele)

    def isFiltered(self, pkt, seg, ind) -> bool:  # True -> show pkt
        def triplizer(expr: str):
            if expr in self.legal_proto:
                return expr, '==', None
            else:
                op_st = expr.find('=')
                if expr[op_st - 1] == '!':
                    op_st -= 1
                return expr[:op_st].strip(), expr[op_st:op_st + 2], expr[op_st + 2:].strip()

        seg_cpy = seg.copy()
        print("-----pkt info: {}-----".format(pkt.layer2['name']))
        for ele in ind:
            print("------checking segs------\nseg[ele]: {}".format(seg_cpy[ele]))
            opd1, opr, opd2 = triplizer(seg_cpy[ele])
            print("expression after seg: {}, {}, {}".format(opd1, opr, opd2))
            seg_cpy[ele] = 'True' if self.isSentenceFiltered(pkt, opd1, opr, opd2) else 'False'

        val = None
        expr = ' '.join(seg_cpy)
        try:
            val = eval(expr)
            # print('expr: ' + expr + ' val: {}'.format(val))
        except:
            print('expr error: ' + expr)
        # print('val{}'.format(val))
        return val

    def policy_slice(self) -> (dict, dict):
        # "A and B" -> ["A", "and", "B"]
        raw_str = self.filter_policy
        res1 = []  # sliced string
        res2 = []  # index of sentence in res1
        st = 0
        while st < len(raw_str):
            word_find = False
            for word in self.legal_words:  # TODO: wrong usage
                find_res = raw_str.find(word, st)
                if find_res != -1:
                    word_find = True
                    if word in self.legal_proto:
                        if raw_str[st:find_res] != '':
                            res1.append(raw_str[st:find_res])
                        res1.append(raw_str[find_res:find_res + len(word)])
                        res2.append(len(res1) - 1)
                        st = find_res + len(word)
                    else:  # legal_oprd1
                        def find_whole_sentence():  # return last ind + 1 if found else -1
                            st0 = find_res + len(word)
                            while st0 < len(raw_str) and raw_str[st0] == ' ':
                                st0 += 1
                            if st0 == len(raw_str):
                                return -1
                            if st0 + 1 < len(raw_str) and (
                                    raw_str[st0:st0 + 2] == '==' or raw_str[st0:st0 + 2] == '!='):
                                st0 += 2
                            else:
                                return -1
                            while st0 < len(raw_str) and raw_str[st0] == ' ':
                                st0 += 1
                            if st0 == len(raw_str):
                                return -1

                            while st0 < len(raw_str) and raw_str[st0] != ' ':
                                st0 += 1
                            return st0

                        ed = find_whole_sentence()
                        if ed == -1:  # TODO: illegal expression, deal later, now escape
                            res1.append(raw_str[st:])
                            st = len(raw_str)
                        else:
                            if raw_str[st:find_res] != '':
                                res1.append(raw_str[st:find_res])
                            res1.append(raw_str[find_res:ed])
                            res2.append(len(res1) - 1)
                            st = ed
                    break
            if not word_find:
                if raw_str[st:] != '':
                    res1.append(raw_str[st:])
                break

        return res1, res2

    def isSentenceFiltered(self, pkt: PacketDemo, opd1: str, opr: str = None, opd2: str = None):  # True == show pkt
        # ip filter, ip.src/dst/addr == x.x.x.x
        if opd1 in ['ip.src', 'ip.dst', 'ip.addr']:
            if pkt.layer2['name'] != 'Internet Protocol version 4 (IPv4)':  # pkt is not a valid object
                return True
            if not self.isValidIP(opd2):
                print('illegal ip opd2')
                return False
            if opr not in ['==', '!=']:
                print('illegal ip opr')
                return False
            if opd1 == 'ip.src':
                return pkt.layer2['src'] == opd2 if opr == '==' else pkt.layer2['src'] != opd2
            elif opd1 == 'ip.dst':
                return pkt.layer2['dst'] == opd2 if opr == '==' else pkt.layer2['dst'] != opd2
            else:
                return (pkt.layer2['src'] == opd2 or pkt.layer2['dst'] == opd2) if opr == '==' else \
                    (pkt.layer2['src'] != opd2 or pkt.layer2['dst'] != opd2)

        # tcp/udp.port/srcport/dstport == 80
        elif opd1 in ['tcp.port', 'tcp.srcport', 'tcp.dstport', 'udp.port', 'udp.srcport', 'udp.dstport']:
            if opd1 in ['tcp.port', 'tcp.srcport', 'tcp.dstport']:
                if pkt.layer3['name'] != 'TCP':
                    return True
                if not self.isValidPort(opd2):
                    print('illegal tcp opd2')
                    return False
                if opr not in ['==', '!=']:
                    print('illegal tcp opr')
                    return False

                opd2 = int(opd2)
                if opd1 == 'tcp.srcport':
                    return pkt.layer3['src'] == opd2 if opr == '==' else pkt.layer3['src'] != opd2
                elif opd1 == 'tcp.dstport':
                    return pkt.layer3['dst'] == opd2 if opr == '==' else pkt.layer3['dst'] != opd2
                else:
                    return (pkt.layer3['src'] == opd2 or pkt.layer3['dst'] == opd2) if opr == '==' else \
                        (pkt.layer3['src'] != opd2 or pkt.layer3['dst'] != opd2)

            if opd1 in ['udp.port', 'udp.srcport', 'udp.dstport']:
                if pkt.layer3['name'] != 'UDP':
                    return True
                if not self.isValidPort(opd2):
                    print('illegal udp opd2')
                    return False
                if opr not in ['==', '!=']:
                    print('illegal udp opr')
                    return False

                opd2 = int(opd2)
                if opd1 == 'tcp.srcport':
                    return pkt.layer3['src'] == opd2 if opr == '==' else pkt.layer3['src'] != opd2
                elif opd1 == 'tcp.dstport':
                    return pkt.layer3['dst'] == opd2 if opr == '==' else pkt.layer3['dst'] != opd2
                else:
                    return (pkt.layer3['src'] == opd2 or pkt.layer3['dst'] == opd2) if opr == '==' else \
                        (pkt.layer3['src'] != opd2 or pkt.layer3['dst'] != opd2)

        # http/tcp/ip/ipv6...
        elif opd1 in ['eth', 'ip', 'ipv6', 'arp', 'tcp', 'udp', 'icmp', 'http', 'https', 'dns']:
            if opr not in ['==', '!=']:
                print('illegal protocol opr')
                return False
            if opd1 == 'eth':
                return pkt.layer1['name'] == 'EthernetII' if opr == '==' else pkt.layer1['name'] != 'EthernetII'
            elif opd1 in ['ip', 'ipv6', 'arp']:
                token = 'Internet Protocol version 4 (IPv4)' if opd1 == 'ip' else \
                    'Internet Protocol version 6 (IPv6)' if opd1 == 'ipv6' else \
                        'Address Resolution Protocol (ARP)'
                return pkt.layer2['name'] == token if opr == '==' else pkt.layer2['name'] != token
            elif opd1 in ['tcp', 'udp', 'icmp']:
                token = opd1.upper()
                return pkt.layer3['name'] == token if opr == '==' else pkt.layer3['name'] != token
            elif opd1 in ['http', 'https', 'dns']:
                token = opd1.upper()
                return pkt.layer4['name'] == token if opr == '==' else pkt.layer4['name'] != token
            else:
                print('illegal protocol type')
                return False
        # eth.src/dst/addr == xxx
        elif opd1 in ['eth.src', 'eth.dst', 'eth.addr']:
            if pkt.layer1['name'] != 'EthernetII':  # pkt is not a valid object
                return True
            if opr not in ['==', '!=']:
                print('illegal eth opr')
                return False
            if opd1 == 'eth.src':
                return pkt.layer1['src'] == opd2 if opr == '==' else pkt.layer1['src'] != opd2
            elif opd1 == 'eth.dst':
                return pkt.layer1['dst'] == opd2 if opr == '==' else pkt.layer1['dst'] != opd2
            else:
                return (pkt.layer1['src'] == opd2 or pkt.layer1['dst'] == opd2) if opr == '==' else \
                    (pkt.layer1['src'] != opd2 or pkt.layer1['dst'] != opd2)
        else:  # illegal sentence, do filter
            print('illegal sentence')
            return False

    def isValidIP(self, ip: str):
        segs = ip.split('.')
        if len(segs) != 4:
            return False
        for ele in segs:
            if not ele.isdigit() or int(ele) < 0 or int(ele) > 255:
                return False
        return True

    def isValidPort(self, port: str):
        if not port.isdigit() or int(port) < 1 or int(port) > 65535:
            return False
        return True
