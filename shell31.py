# Form implementation generated from reading ui file 'shell3.ui'
#
# Created by: PyQt6 UI code generator 6.2.3
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from fileinput import filename
from tkinter import filedialog
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QFileDialog
import hashlib
import requests

filename = ''

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(889, 571)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:1, x2:1, y2:0, stop:0 rgba(142, 200, 195, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(32, 41, 64);")
        self.centralwidget.setObjectName("centralwidget")
        self.QuickScanB = QtWidgets.QPushButton(self.centralwidget,clicked = lambda:self.quickscan())
        self.QuickScanB.setGeometry(QtCore.QRect(50, 270, 191, 101))
        self.QuickScanB.setStyleSheet("background-color: qconicalgradient(cx:0.5, cy:0.5, angle:0, stop:0 rgba(0, 85, 0, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(101, 51, 172);\n"
"\n"
"\n"
"border-radius : 15;")
        self.QuickScanB.setObjectName("QuickScanB")
        self.DeepScanB = QtWidgets.QPushButton(self.centralwidget, clicked = lambda:self.deepscan())
        self.DeepScanB.setGeometry(QtCore.QRect(320, 270, 181, 101))
        self.DeepScanB.setStyleSheet("background-color: rgb(131, 154, 255);\n"
"background-color: rgb(101, 51, 172);\n"
"border-radius : 15;")
        self.DeepScanB.setFlat(False)
        self.DeepScanB.setObjectName("DeepScanB")
        self.ViewLogsB = QtWidgets.QPushButton(self.centralwidget)
        self.ViewLogsB.setGeometry(QtCore.QRect(570, 270, 181, 101))
        self.ViewLogsB.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(120, 159, 200, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(101, 51, 172);\n"
"border-radius : 15;")
        self.ViewLogsB.setObjectName("ViewLogsB")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(50, 30, 791, 61))
        self.pushButton.setStyleSheet("background-color:rgb(85, 255, 255)")
        self.pushButton.setObjectName("pushButton")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(60, 170, 781, 51))
        self.lineEdit.setObjectName("lineEdit")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 889, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)


        self.pushButton.clicked.connect(self.clicker)



        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


 
    def clicker(self):
            fname = filedialog.askopenfilename()
            if fname:
                    print(str(fname))
                    #print(type(fname))   # fname is a string by default , somewhat good thing is that it accepts only files not folders!
            
            global filename 
            filename = fname

    def quickscan(self):
            #print('Quickscan pressed!')
            global filename
            if filename == '':
                    
        

               












    def deepscan(self):
            print('DeepScan pressed!')



    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.QuickScanB.setText(_translate("MainWindow", "Quick Scan"))
        self.DeepScanB.setText(_translate("MainWindow", "Deep Scan"))
        self.ViewLogsB.setText(_translate("MainWindow", "View Logs"))
        self.pushButton.setText(_translate("MainWindow", "CLICK TO SELECT FILE(S)"))
        self.lineEdit.setText(_translate("MainWindow", "ENTER FILE LOCATION HERE"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())



