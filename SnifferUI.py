# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SnifferUI.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("5n1ff3r")
        MainWindow.setEnabled(True)
        MainWindow.resize(945, 620)
        font = QtGui.QFont()
        font.setFamily("Sans Serif")
        font.setPointSize(9)
        font.setItalic(False)
        font.setKerning(False)
        MainWindow.setFont(font)
        MainWindow.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setObjectName("lineEdit")
        self.verticalLayout.addWidget(self.lineEdit)
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget.setEnabled(True)
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(QtCore.Qt.NoPen)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(1)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        self.tableWidget.horizontalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.verticalHeader().setVisible(False)
        self.verticalLayout.addWidget(self.tableWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.header().setVisible(False)
        self.horizontalLayout.addWidget(self.treeWidget)
        self.plainTextEdit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit.setUndoRedoEnabled(False)
        self.plainTextEdit.setPlainText("")
        self.plainTextEdit.setTextInteractionFlags(QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.horizontalLayout.addWidget(self.plainTextEdit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setMovable(True)
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("5n1ff3r", "5n1ff3r"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("5n1ff3r", "No."))
        self.treeWidget.headerItem().setText(0, _translate("5n1ff3r", "1"))
        self.toolBar.setWindowTitle(_translate("5n1ff3r", "toolBar"))
