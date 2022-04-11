

from PyQt6 import QtCore, QtGui, QtWidgets
from tkinter import filedialog
from PyQt6.QtWidgets import QFileDialog
import hashlib
import requests
import time
import json
import os

filenm = ''

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(884, 499)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:1, x2:1, y2:0, stop:0 rgba(142, 200, 195, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(32, 41, 64);")
        self.centralwidget.setObjectName("centralwidget")
        self.QuickScanB = QtWidgets.QPushButton(self.centralwidget,clicked = lambda:self.quickscan())
        self.QuickScanB.setGeometry(QtCore.QRect(50, 270, 191, 101))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.QuickScanB.setFont(font)
        self.QuickScanB.setStyleSheet("background-color: qconicalgradient(cx:0.5, cy:0.5, angle:0, stop:0 rgba(0, 85, 0, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(101, 51, 172);\n"
"\n"
"\n"
"border-radius : 15;")
        self.QuickScanB.setObjectName("QuickScanB")
        self.DeepScanB = QtWidgets.QPushButton(self.centralwidget,clicked = lambda:self.deepscan()  )
        self.DeepScanB.setGeometry(QtCore.QRect(340, 270, 191, 101))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.DeepScanB.setFont(font)
        self.DeepScanB.setStyleSheet("background-color: rgb(131, 154, 255);\n"
"background-color: rgb(101, 51, 172);\n"
"border-radius : 15;")
        self.DeepScanB.setFlat(False)
        self.DeepScanB.setObjectName("DeepScanB")
        self.ViewLogsB = QtWidgets.QPushButton(self.centralwidget,clicked = lambda:self.viewlogs())
        self.ViewLogsB.setGeometry(QtCore.QRect(620, 270, 191, 101))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.ViewLogsB.setFont(font)
        self.ViewLogsB.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(120, 159, 200, 255), stop:1 rgba(255, 255, 255, 255));\n"
"background-color: rgb(101, 51, 172);\n"
"border-radius : 15;")
        self.ViewLogsB.setObjectName("ViewLogsB")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(50, 30, 761, 71))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.pushButton.setFont(font)
        self.pushButton.setStyleSheet("background-color:rgb(85, 255, 255)")
        self.pushButton.setObjectName("pushButton")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(50, 160, 761, 71))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setStyleSheet("background-color: rgb(158, 255, 161);")
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label.setObjectName("label")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 884, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)



        self.pushButton.clicked.connect(self.clicker)

    def clicker(self):
        global filenm
        fname = filedialog.askopenfilename()  # askopenfilenames also an option to handle multiple files
        filenm = fname




    def viewlogs(self):
        os.startfile('C:/Users/Siddharth/Desktop/AV/LOGS.txt')




    def MalwareDestroyer(self):
            global filenm

            #normally one would delete the suspicious file first, but for demonstrative purposes, no file deletion is being done
            f = open(filenm,'rb')
            data = f.read()
            f.close()

            bytes = len(data)
            inc = int((bytes+2)/2)
            fileNames = []

            for i in range(0,bytes+1,inc):
                    fn1 = "file%s"%i
                    fileNames.append(fn1)
                    f = open(fn1,'wb')
                    f.write(data[i:i+inc])
                    f.close()
  



    def Logger(self,line,MalYesorNo,scantype):
            global filenm
            if scantype == 'qs' :
                with open("C:/Users/Siddharth/Desktop/AV/LOGS.txt",'a+') as f:
                        f.write("QuickScan ran at : "+ time.strftime("%a, %d %b %Y %H:%M:%S" + " . \n"))
                        if MalYesorNo == True:
                                f.write("The file "+filenm+ " is suspected to be a malware! :( \n For a comprehensive check use the DeepScan \n ")
                                f.write("Malware details : " + line + " \n \n")
                                        
                        else :
                                f.write("The file "+filenm+ "is not suspected to be a malware! :) \n For a comprehensive check use DeepScan! \n \n \n")

            elif scantype == 'ds':
                    with open("C:/Users/Siddharth/Desktop/AV/LOGS.txt",'a+') as f:
                            f.write("DeepScan ran at : " + time.strftime("%a, %d %b %Y %H:%M:%S" + " . \n"))
                            if MalYesorNo == True:
                                    f.write("The file "+filenm+" is highly likely to be malware! :( \n")
                            else :
                                    f.write("The file "+filenm+" is safe! :) \n \n \n")





    def deepscan(self):
            connection = True
            url = 'https://www.google.com'
            timeout = 5
            try :
                request = requests.get(url = url,timeout = timeout)
            except (requests.ConnectionError, requests.Timeout) as exception:
                self.label.setText("OOPS, looks like you dont have an active internet connection! \n Try connecting to the internet, or try a quickscan!")
                connection = False


            if connection == True:
                global filenm
                key = 'a7c08c6918d3b21e88d037d82bff5f4d033b3cae0b425aa5d62342cf158c67ca' # or any other private key
                result = None
                if filenm == '':
                        self.label.setText("Oops! You have to select a file first and then scan!\nSelect a file using the above button and then click on any of the scans!")
                else:
                    filenm = filenm.strip()        
                
                    params = dict(apikey = key)
                    api_url = "https://www.virustotal.com/vtapi/v2/file/scan"
                    with open(filenm,'rb') as file:
                            files = dict(file=(filenm,file))
                            response = requests.post(api_url,files = files,params = params)   # HTTPS POST request being made to submit the file to VirusTotal so that it can be parsed in their servers

                    if response.status_code == 200:
                          result = response.json() # will contain just some info that parsing has been successfull
                        

                    result2 = None
                    api_url2 = 'https://www.virustotal.com/vtapi/v2/file/report'
                    params2 = dict(apikey = key, resource = result['scan_id'])
                    response2 = requests.get(api_url2,params = params2)         # HTTPS GET request to get the analysis of file which has been most recently parsed!

                    avlist = []
                    if response2.status_code == 200:
                            result2 = response2.json()
                            #for keys in result2['scans']:
                            #        avlist.append(keys)

                            try:
                                if result2['positives'] > 0 :
                                        self.MalwareDestroyer()
                                        self.label.setText("YIKES! The file is most likely malware! \n DONT worry it's been nullified! \n For more information, read the LOGS")
                                        self.label.setStyleSheet("background-color: rgb(255, 172, 164);")
                                        self.Logger('',True,'ds')
                                else :
                                        self.label.setText("The file is SAFE! YAY!")
                                        self.label.setStyleSheet("background-color: rgb(158, 255, 161);")
                                        self.Logger('',False,'ds')
                            except KeyError:
                                self.label.setText("Oops! Looks like something went wrong with the deep scan! \n CLick on the deepscan button to try again!")







    def quickscan(self):
            global filenm
            
            if filenm == '':
                    self.label.setText("Oops! You have to select a file first and then scan!\nSelect a file using the above button and then click on any of the scans!")
            else:
                    h = hashlib.md5()
                    with open(filenm,'rb') as file:
                            while True:
                                    chunk = file.read(h.block_size)
                                    if not chunk:
                                            break
                                    h.update(chunk)
                    md5hash = h.hexdigest()

                    full = None
                    #lineno = 0
                    with open("C:/Users/Siddharth/Desktop/AV/HashLists/main.hdb") as f:
                            #full = f.read()
                            for lineno,line in enumerate(f):
                                    if md5hash in line :
                                            self.MalwareDestroyer()
                                            self.label.setText("MALWARE DETECTED! Do not worry, the file has been neutralised! \n Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(255, 172, 164);")
                                            self.Logger(line,True,'qs')
                                    else :
                                            self.label.setText("YAAY! No malware detected! Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(158, 255, 161);")
                                            self.Logger('',False,'qs')
                
                # open all the remaining files here for scans, all using md5 hash presumably
                    with open("C:/Users/Siddharth/Desktop/AV/HashLists/main.mdb") as f:
                            for lineno,line in enumerate(f):
                                    if md5hash in line :
                                            self.MalwareDestroyer()
                                            self.label.setText("MALWARE DETECTED! Do not worry, the file has been neutralised! \n Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(255, 172, 164);")
                                            self.Logger(line,True,'qs')
                                    else :
                                            self.label.setText("YAAY! No malware detected! Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(158, 255, 161);")
                                            self.Logger('',False,'qs')
                    
                    with open("C:/Users/Siddharth/Desktop/AV/HashLists/main.hsb") as f:
                            for lineno,line in enumerate(f):
                                    if md5hash in line :
                                            self.MalwareDestroyer()
                                            self.label.setText("MALWARE DETECTED! Do not worry, the file has been neutralised! \n Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(255, 172, 164);")
                                            self.Logger(line,True,'qs')
                                    else :
                                            self.label.setText("YAAY! No malware detected! Read LOGS for more details!")
                                            self.label.setStyleSheet("background-color: rgb(158, 255, 161);")
                                            self.Logger('',False,'qs')





    def retranslateUi(self, MainWindow):                # generates the UI
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Garuda AV"))
        self.QuickScanB.setText(_translate("MainWindow", "Quick Scan"))
        self.DeepScanB.setText(_translate("MainWindow", "Deep Scan"))
        self.ViewLogsB.setText(_translate("MainWindow", "View Logs"))
        self.pushButton.setText(_translate("MainWindow", "CLICK TO SELECT FILE(S)"))
        self.label.setText(_translate("MainWindow", "Select the file you want to scan by using the button above, and run a scan on it!"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
