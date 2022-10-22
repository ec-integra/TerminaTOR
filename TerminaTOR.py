#Импорт библиотек для работы программы
from py import _std
from py import __metainfo
from py import _builtin
from py import _error
from py import _xmlgen
from py import _code
from py import _io
from py import _log
from py import _path
from py import _process
from py import _path
from py._vendored_packages import iniconfig
from py._path import local
from pyshark import config
import pyshark
import psutil
import threading
import sys
import time
import encodings
import codecs
import socket
import scapy
from scapy.all import send
from scapy.all import *
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QWidget, QPushButton, QApplication, QHBoxLayout, QVBoxLayout, QDesktopWidget, QLabel
from PyQt5.QtGui import QPixmap
from PyQt5 import Qt
from PyQt5.QtCore import QFile, QIODevice, QUrl
from PyQt5.QtGui import QDesktopServices, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QTreeView
from PyQt5.QtXml import QDomDocument
from netifaces import *
import netifaces as ni
import paramiko
from paramiko.ssh_exception import (
    SSHException,
    BadHostKeyException,
    NoValidConnectionsError,
)
from tkinter import *
from tkinter.messagebox import showerror
#Класс описывающий граффический интерфейс программы 
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")#Присвоение имени
        MainWindow.setFixedSize(621, 396)#Установка размера
        self.gui=MainWindow#Указатель на обЪект
        #Инициализация виджетов всех виджетов
        #QtWidgets.QWidget - центральный виджет, на котором расположены все кнопки, линии, надписи и т.д.
        #QtWidgets.QComboBox - виджет выбора интерфейса
        #QtWidgets.QPushButton - виджет кнопок
        #QtWidgets.QLabel - виджет всех надписей
        #QtWidgets.QTextBrowser - виджет вывода сообщений (текста)
        #QtWidgets.QLineEdit - виджет ввода строковых данных
        #QtWidgets.QCheckBox - виджет выбора True или False (галочка)
        #Для всех виджетов указываются размеры и все виджеты привязываются к главному (центральному) виджету
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(10, 291, 301, 41))
        self.comboBox.setObjectName("comboBox")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(320, 290, 93, 41))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(320, 290, 0, 0))
        self.pushButton_4.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(420, 290, 93, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(520, 290, 93, 41))
        self.pushButton_3.setObjectName("pushButton_3")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 270, 301, 16))
        self.label.setObjectName("label")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(10, 10, 601, 251))
        self.textBrowser.setObjectName("textBrowser")
        self.patch = QtWidgets.QFileDialog(self.centralwidget)
        #________________________________________________________________
        self.pushButton5 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton5.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.pushButton5.setObjectName("pushButton")
        self.pushButton6 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton6.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.pushButton6.setObjectName("pushButton_2")
        self.spinBox = QtWidgets.QLineEdit(self.centralwidget)
        self.spinBox.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.spinBox.setObjectName("spinBox")
        self.spinBox_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.spinBox_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.spinBox_2.setObjectName("spinBox_2")
        self.label_1 = QtWidgets.QLabel(self.centralwidget)
        self.label_1.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_1.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_5.setObjectName("label_5")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_8.setObjectName("label_8")
        self.spinBox_3 = QtWidgets.QLineEdit(self.centralwidget)
        self.spinBox_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.spinBox_3.setObjectName("spinBox_3")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_6.setObjectName("label_6")
        self.spinBox_5 = QtWidgets.QLineEdit(self.centralwidget)
        self.spinBox_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.spinBox_5.setObjectName("spinBox_5")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_7.setObjectName("label_7")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit.setObjectName("lineEdit")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_10.setObjectName("label_10")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_12 = QtWidgets.QLabel(self.centralwidget)
        self.label_12.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_12.setObjectName("label_12")
        self.label_13 = QtWidgets.QLabel(self.centralwidget)
        self.label_13.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_13.setObjectName("label_13")
        self.lineEdit_time = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_time.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_time.setObjectName("lineEdit_time")
        self.label_14 = QtWidgets.QLabel(self.centralwidget)
        self.label_14.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_14.setObjectName("label_14")
        self.label_11 = QtWidgets.QLabel(self.centralwidget)
        self.label_11.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_11.setObjectName("label_11")
        self.CheckBox=QtWidgets.QCheckBox(self.centralwidget)
        self.CheckBox.setGeometry(QtCore.QRect(0,0,0,0))
        self.CheckBox.setObjectName("CheckBox")
        self.CheckBox2=QtWidgets.QCheckBox(self.centralwidget)
        self.CheckBox2.setGeometry(QtCore.QRect(0,0,0,0))
        self.CheckBox2.setObjectName("CheckBox")
        #________________________________________________________________
        self.label_host = QtWidgets.QLabel(self.centralwidget)
        self.label_host.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_host.setObjectName("label_host")
        self.label_title = QtWidgets.QLabel(self.centralwidget)
        self.label_title.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_title.setObjectName("label_title")
        self.lineEdit_host = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_host.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_host.setObjectName("lineEdit_host")
        self.label_user = QtWidgets.QLabel(self.centralwidget)
        self.label_user.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_user.setObjectName("label_user")
        self.lineEdit_user = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_user.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_user.setObjectName("lineEdit_user")
        self.label_password = QtWidgets.QLabel(self.centralwidget)
        self.label_password.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_password.setObjectName("label_password")
        self.lineEdit_password = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_password.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_password.setObjectName("lineEdit_password")
        self.label_port = QtWidgets.QLabel(self.centralwidget)
        self.label_port.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_port.setObjectName("label_port")
        self.lineEdit_port = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_port.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_port.setObjectName("lineEdit_port")
        self.label_command = QtWidgets.QLabel(self.centralwidget)
        self.label_command.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.label_command.setObjectName("label_command")
        self.lineEdit_command = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_command.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.lineEdit_command.setObjectName("lineEdit_command")
        self.pushButton_setSSHOption = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_setSSHOption.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.pushButton_setSSHOption.setObjectName("setSSHOption")
        self.pushButton_NotsetSSHOption = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_NotsetSSHOption.setGeometry(QtCore.QRect(0, 0, 0, 0))
        self.pushButton_NotsetSSHOption.setObjectName("NotsetSSHOption")
        #________________________________________________________________
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 621, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        #Добавление текста во все виджеты
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "TerminaTOR"))
        self.pushButton.setText(_translate("MainWindow", "Поиск в сети"))
        self.pushButton_4.setText(_translate("MainWindow", "Остановить\nпоиск"))
        self.pushButton_2.setText(_translate("MainWindow", "Поиск\n"
"по дампу"))
        self.pushButton_3.setText(_translate("MainWindow", "Настройки\n"
"поиска"))
        self.pushButton_setSSHOption.setText(_translate("MainWindow", "Применить"))
        self.pushButton_NotsetSSHOption.setText(_translate("MainWindow", "Назад"))
        self.label.setText(_translate("MainWindow", "Выберите интерфейс для поиска"))
        self.pushButton5.setText(_translate("MainWindow", "Применить"))
        self.pushButton6.setText(_translate("MainWindow", "Настройки\n"
"по умолчанию"))
        self.label_1.setText(_translate("MainWindow", "от"))
        self.label_2.setText(_translate("MainWindow", "Длина сертификата TLS1.2"))
        self.label_3.setText(_translate("MainWindow", "до"))
        self.label_4.setText(_translate("MainWindow", "Настройки поиска"))
        self.label_5.setText(_translate("MainWindow", "Длина фрейма рукопожатия"))
        self.label_8.setText(_translate("MainWindow", "до"))
        self.label_6.setText(_translate("MainWindow", "от"))
        self.label_7.setText(_translate("MainWindow", "до"))
        self.label_9.setText(_translate("MainWindow", "TLS1.3"))
        self.label_10.setText(_translate("MainWindow", "Расширение имени\n"
" сервера содержит"))
        self.label_12.setText(_translate("MainWindow", "Значение 1"))
        self.label_13.setText(_translate("MainWindow", "Значение 2"))
        self.label_14.setText(_translate("MainWindow", "Время одной сессии\n    поиска пакетов"))
        self.label_11.setText(_translate("MainWindow", "Расширение имени\n"
" сервера содержит"))
        self.CheckBox.setText(_translate("MainWindow","Заблокировать соединение"))
        self.CheckBox2.setText(_translate("MainWindow","Добавить в сетевой экран "))
        self.label_host.setText(_translate("MainWindow", "Адрес"))
        self.label_user.setText(_translate("MainWindow", "Логин"))
        self.label_password.setText(_translate("MainWindow", "Пароль"))
        self.label_port.setText(_translate("MainWindow", "Порт"))
        self.label_command.setText(_translate("MainWindow", "           Введите команду для роутера.\nВместо блокируемого IP укажите {address}"))
        self.label_title.setText(_translate("MainWindow","Настройки подключения по SSH"))
#Модуль преобразования адреса узла в адрес сети
def Network(address):
    Address=address.split('.')
    return Address[0]+'.'+Address[1]+'.'+Address[2]+'.'+'0'
#Модуль для запуска функции в другом потоке
def thread(my_func):
    def wrapper(*args, **kwargs):
        global my_thread
        my_thread = threading.Thread(target=my_func, args=args, kwargs=kwargs)
        my_thread.setDaemon(True)
        my_thread.start()
    return wrapper
#Модуль для запуска функции в другом потоке
def thread2(my_func2):
    def wrapper2(*args, **kwargs):
        my_thread2 = threading.Thread(target=my_func2, args=args, kwargs=kwargs)
        my_thread2.setDaemon(True)
        my_thread2.start()
    return wrapper2
#Модуль разрыва соединения
def sendRST(tls,interfase,dstip,srcip,dport,sport,seq,windowsize,ack):
    if tls is True:#определение типа пакетов
     #Сборка пакета
     x=IP(dst=dstip,src=srcip,len=0)/TCP(dport=int(dport),sport=int(sport),flags='RA',seq=int(seq),ack=int(ack),window=0)#+int(windowsize))
     if int(seq)>0:
         #Отправление пакета в сеть
         send(x)
    #Аналогичные действия для другого типа пакетов
    if tls is False:
     y=IP(dst=dstip,src=srcip,len=0)/TCP(dport=int(dport),sport=int(sport),flags='R',seq=int(seq),window=0)#+int(windowsize))
     if int(seq)>0:
         send(y)
def command(str,addr):
 #Модуль преобразования шаблона к команде, пригодной к отправлению по SSH
 #Команда разбивается на модули разделителем выступает пробел
 #Первая часть команды - весь шаблон до модуля {address}
 #Вторая часть команды - полученный адрес тора
 #Третья часть команды - весь шаблон после модуля {address}
 command=str.split(' ')
 index=0
 sendcommand=[]
 strsendcommand=''
 for i in range(len(command)):
    if command[i]=='{address}':
        index=i        
 for m in range(0,index):
    sendcommand.append(command[m])
 for i in range(len(sendcommand)):
    strsendcommand=strsendcommand+' '+sendcommand[i]
 strsendcommand=strsendcommand+addr
 sendcommand=[]
 for m in range(index+1,len(command)):
    sendcommand.append(command[m])
 for i in range(len(sendcommand)):
    strsendcommand=strsendcommand+sendcommand[i]+' '
 strsendcommand=strsendcommand+'\n'
 return strsendcommand
def AddFireWall(signal,address,host,user,password,port,timesleep,commandSSH):
    #Модуль добавления адреса тора в сетевой экран по SSH
    global IPaddFireWall
    try:
     client = paramiko.SSHClient() #Инициализация клиента SSH
     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())#Применение политики
     client.connect(hostname=host, username=user, password=password, port=port)#Соединение с устройством
     client.exec_command(command(commandSSH,address))#Отправление команды    
     client.close()#Закртыие соединения
     time.sleep(timesleep)#остановка скрипта на время timesleep
     IPaddFireWall.append(address)#Запоминание адресов, уже добавленных в сетевой экран
     #Запись запомненых адресов в файл
     file3=open('IPaddFireWall.txt','a')
     file3.write(address+'\n')
     file3.close()
     #Обработка ошибок соединения
    except NoValidConnectionsError as Error:
     signal.emit('Ошибка подключения к устройству по SSH!\n'+str(Error))#Ошибка политик
    except BadHostKeyException as Error:
     signal.emit('Ошибка подключения к устройству по SSH!\n'+str(Error))#Ошибка ключей
    except SSHException as Error:
     signal.emit('Ошибка подключения к устройству по SSH!\n'+str(Error))#Ошибка соединения
    except TimeoutError as Error:
     signal.emit('Ошибка подключения к устройству по SSH!\n'+str(Error))#Время установления соединения истекло
#Модуль отслеживания TLS пакетов
def SniffTCP(interface,ip,addr):
    global Stop
    while Stop is False:
     Packet = pyshark.LiveCapture(interface=interface,display_filter=f'tls and ip.addr=={ip} and tcp.flags.res==0')#Инициализация захвата пакетов с установлением фильтра
     Packet.sniff(timeout=2)#Запуск захвата с параметром времени ожидания пакетов
     pkts = [pkt for pkt in Packet._packets]#Запись полученных пакетов в переменную
     Packet=Packet#Обновление переменной
     #Обработка полученных пакетов
     if len(Packet)>0:
         for i in Packet:
             #Условия работают по принципу:
             #Если полученный пакет в качестве адреса назначения имеет адрес сети хоста - то выполняется действие внутри модуля if
             #Если полученный пакет в качестве адреса назначения имеет адрес сети тор - то выполняется действие внутри модуля else
             if Network(str(i.ip.dst))==addr:
                 try:
                     #Запуск модуля разрыва соединения в отдельном потоке с передачей необходимых значений
                     rstpotok=threading.Thread(target=sendRST,kwargs={'tls':True,'interfase':interface,'dstip':i.ip.src,'srcip':i.ip.dst,'dport':i.tcp.srcport,'sport':i.tcp.dstport,'ack':i.tcp.nxtseq,'windowsize':i.tcp.window_size,'seq':str(int(i.tcp.ack)+int(i.tcp.len)+1)})
                     rstpotok.setDaemon(True)
                     rstpotok.start()
                 except:pass
             else:
                 try:
                     #Запуск модуля разрыва соединения в отдельном потоке с передачей необходимых значений
                     rstpotok=threading.Thread(target=sendRST,kwargs={'tls':True,'interfase':interface,'dstip':i.ip.dst,'srcip':i.ip.src,'dport':i.tcp.dstport,'sport':i.tcp.srcport,'ack':i.tcp.nxtseq,'windowsize':i.tcp.window_size,'seq':str(int(i.tcp.ack)+int(i.tcp.len)+1)})
                     rstpotok.setDaemon(True)
                     rstpotok.start()
                     pass
                 except:pass
         Packet.clear()#Очистка буфера захвата
    Packet.close()#Закрытие захвата
#Модуль отслеживания TCP пакетов
def SniffTCP2(interface,ip,addr):
   global Stop
   while Stop is False:
    Packet2=pyshark.LiveCapture(interface=interface,display_filter=f'tcp and ip.addr=={ip} and tcp.flags.res==0')#Инициализация захвата пакетов с установлением фильтра
    Packet2.sniff(timeout=2)#Запуск захвата с параметром времени ожидания пакетов
    pkts = [pkt for pkt in Packet2._packets]#Запись полученных пакетов в переменную
    Packet2=Packet2#Обновление переменной
    #Обработка полученных пакетов
    if len(Packet2)>0:
         for i in Packet2:
             #Условия работают по принципу:
             #Если полученный пакет в качестве адреса назначения имеет адрес сети хоста - то выполняется действие внутри модуля if
             #Если полученный пакет в качестве адреса назначения имеет адрес сети тор - то выполняется действие внутри модуля else
             if str(i.ip.dst)==addr:
                 try:
                     #Запуск модуля разрыва соединения в отдельном потоке с передачей необходимых значений
                     rstpotok=threading.Thread(target=sendRST,kwargs={'tls':False,'interfase':interface,'dstip':i.ip.src,'srcip':i.ip.dst,'dport':i.tcp.srcport,'sport':i.tcp.dstport,'seq':i.tcp.ack,'windowsize':i.tcp.window_size,'ack':i.tcp.seq})
                     rstpotok.setDaemon(True)
                     rstpotok.start()
                 except:pass
             else:
                 try:
                     #Запуск модуля разрыва соединения в отдельном потоке с передачей необходимых значений
                     rstpotok=threading.Thread(target=sendRST,kwargs={'tls':False,'interfase':interface,'dstip':i.ip.dst,'srcip':i.ip.src,'dport':i.tcp.dstport,'sport':i.tcp.srcport,'seq':i.tcp.ack,'windowsize':i.tcp.window_size,'ack':i.tcp.seq})
                     rstpotok.setDaemon(True)
                     rstpotok.start()
                     pass
                 except:pass
         Packet2.clear()#Очистка буфера захвата
    Packet2.close()#Закрытие захвата
#Модуль отслеживания трафика сети тор в реальном времени
@thread
def Sniff(signal,Interfa,filter,timerange,ver,check,check2,host,user,password,port,commandSSH):
 global Findip
 global Stop
 global IPaddFireWall
 Stop=False
 Interfa=Interfa.split('::')#Получение имени интерфейса из комбобокса
 Interf=Interfa[0]#Присвоение имения интерфейса переменной
 addr=Network(Interfa[1])#Получение адреса этого интерфейса
 if ver!='':signal.emit(f'Запущен поиск TLS{ver} пакетов на интерфейсе {Interf} : {addr} ')#Строковый сигнал в графический интерфейс
 else:pass
 while Stop is False:
  capture = pyshark.LiveCapture(interface=Interf,display_filter=filter)#Инициализация захвата с установленным фильтром
  capture.sniff(timeout=timerange)#Запуск захвата с параметром времени ожидания пакетов
  pkts = [pkt for pkt in capture._packets]#Запись полученных пакетов в переменную
  capture=capture#Обновление переменной
  if len(capture)>0:
      for i in capture:
       signal.emit(str(i.tls.record))
       #Условия работают по принципу:
       #Если полученный пакет в качестве адреса источника имеет адрес сети хоста - то выполняется действие внутри модуля if ==
       #Если полученный пакет в качестве адреса источника имеет адрес сети тор - то выполняется действие внутри модуля if !=
       if Network(i.ip.src)==addr:
          if str(i.ip.dst) not in Findip:#Проверка условия, был ли этот адрес найден ранее
           signal.emit(str(i.ip.dst)+'  новый IP адрес TOR')#Строковый сигнал в графический интерфейс
           if check is True:#Проверка условия из чекбокса №1
            #Запуск модуля поиска TLS пакетов в отдельном потоке с передачей определенных параметров
            sniftcp=threading.Thread(target=SniffTCP,kwargs={'interface':Interf,'ip':i.ip.dst,'addr':addr})
            sniftcp.setDaemon(True)
            sniftcp.start()
            #Запуск модуля поиска TCP пакетов в отдельном потоке с передачей определенных параметров
            sniftcp2=threading.Thread(target=SniffTCP2,kwargs={'interface':Interf,'ip':i.ip.dst,'addr':addr})
            sniftcp2.setDaemon(True)
            sniftcp2.start()
           if check2 is True:#Проверка условия из чекбокса №2
            if str(i.ip.dst) not in IPaddFireWall:#Проверка условия были ли адрес ранее добавлен в сетевой экран
             #Запуск модуля добавления адреса Тора в сетевой экран
             addfirewall=threading.Thread(target=AddFireWall,kwargs={'signal':signal,'address':i.ip.dst,'host':host,'user':user,'password':password,'port':port,'timesleep':timerange,'commandSSH':commandSSH})
             addfirewall.setDaemon(True)
             addfirewall.start()
          else:
           signal.emit(str(i.ip.dst)+' уже известный IP TOR')#Строковый сигнал в графический интерфейс
           if check is True:
            sniftcp=threading.Thread(target=SniffTCP,kwargs={'interface':Interf,'ip':i.ip.dst,'addr':addr})
            sniftcp.setDaemon(True)
            sniftcp.start()
            sniftcp2=threading.Thread(target=SniffTCP2,kwargs={'interface':Interf,'ip':i.ip.dst,'addr':addr})
            sniftcp2.setDaemon(True)
            sniftcp2.start()
           if check2 is True:
            if str(i.ip.dst) not in IPaddFireWall:
             addfirewall=threading.Thread(target=AddFireWall,kwargs={'signal':signal,'address':i.ip.dst,'host':host,'user':user,'password':password,'port':port,'timesleep':timerange,'commandSSH':commandSSH})
             addfirewall.setDaemon(True)
             addfirewall.start()
       if Network(i.ip.src)!=addr:
          if str(i.ip.src) not in Findip: 
           signal.emit(str(i.ip.src)+'  новый IP адрес TOR')
           if check is True:
            sniftcp=threading.Thread(target=SniffTCP,kwargs={'interface':Interf,'ip':i.ip.src,'addr':addr})
            sniftcp.setDaemon(True)
            sniftcp.start()
            sniftcp2=threading.Thread(target=SniffTCP2,kwargs={'interface':Interf,'ip':i.ip.src,'addr':addr})
            sniftcp2.setDaemon(True)
            sniftcp2.start()
           if check2 is True:
            if str(i.ip.src) not in IPaddFireWall:
             addfirewall=threading.Thread(target=AddFireWall,kwargs={'signal':signal,'address':i.ip.src,'host':host,'user':user,'password':password,'port':port,'timesleep':timerange+4,'commandSSH':commandSSH})
             addfirewall.setDaemon(True)
             addfirewall.start()
          else:
           signal.emit(str(i.ip.src)+' уже известный IP TOR')
           if check is True:
            sniftcp=threading.Thread(target=SniffTCP,kwargs={'interface':Interf,'ip':i.ip.src,'addr':addr})
            sniftcp.setDaemon(True)
            sniftcp.start()
            sniftcp2=threading.Thread(target=SniffTCP2,kwargs={'interface':Interf,'ip':i.ip.src,'addr':addr})
            sniftcp2.setDaemon(True)
            sniftcp2.start()
           if check2 is True:
            if str(i.ip.src) not in IPaddFireWall:
             addfirewall=threading.Thread(target=AddFireWall,kwargs={'signal':signal,'address':i.ip.src,'host':host,'user':user,'password':password,'port':port,'timesleep':timerange+4,'commandSSH':commandSSH})
             addfirewall.setDaemon(True)
             addfirewall.start()
      capture.clear()#Очистка буфера захвата
  capture.close()#Закрытие захвата
#Модуль поиска пакетов по файлам дампов
@thread2
def SniffforDUMP(signal,PATH,filter,ver):
    global Findip
    signal.emit(f'Запущен поиск TLS{ver} пакетов по файлу дампа: {PATH}')#Строковый сигнал в графический интерфейс
    try:
     capture=pyshark.FileCapture(PATH,display_filter=filter)#Запуско поиска по файлу с заданным фильтром
     for i in capture:
      signal.emit(str(i.tls.record))#Строковый сигнал в графический интерфейс
      if i.tls.record[-12:]=='Client Hello':#Если info в пакете содержит Client Hello
          signal.emit(str(i.ip.dst)+'  это IP адрес TOR')#Строковый сигнал в графический интерфейс
      if i.tls.record[-12:]=='Server Hello':#Если info в пакете содержbn Server Hello
          signal.emit(str(i.ip.src)+'  это IP адрес TOR')#Строковый сигнал в графический интерфейс
     signal.emit('END')#Строковый сигнал в графический интерфейс
    except FileNotFoundError as Error:#Обработка ошибки неверного указания файлов
        signal.emit('[Ошибка 2] Неверно выбран файл в директории: '+PATH)
        signal.emit('END')
#Класс инициализирующий графический интерфейс    
class AVT(QtWidgets.QMainWindow):
     my_signal = QtCore.pyqtSignal(str, name='my_signal')#Инициализация сигнала №1
     my_signal2 = QtCore.pyqtSignal(str, name='my_signal2')#Инициализация сигнала №2
     def __init__(self):
         super(AVT,self).__init__()
         self.ui=Ui_MainWindow()#Привязка к классу описания графического интерфейса
         self.ui.setupUi(self)#Инициализация
         addrs = psutil.net_if_addrs()#Получение интерфейсов текущего хоста
         global Stop#Объявление глобальной переменной
         #Запись интерфейсов и их адресов в виджет комбобокс
         for key,value in addrs.items():
            try:
             self.ui.comboBox.addItem(str(key)+'::'+str(value[1][1]))
            except:pass
         self.interfase=None#Сетевой интерфейс
         global FinSert
         global StartSert
         global StartlenTLS2
         global FinlenTLS2
         global StartlenTLS3
         global FinlenTLS3
         global Check
         global Check2
         global IPaddFireWall
         global Findip
         global timeSniff
         Findip=[]
         Check=False
         Check2=False
         #Считывание логов программы с предыдущих запусков
         try: 
             f=open("IPaddFireWall.txt",'r')
             f.close()
         except: 
             startfile1=open('IPaddFireWall.txt','w')
             startfile1.close()
         try: 
             f=open("TOR ip.txt",'r')
             f.close()
         except: 
             startfile1=open('TOR ip.txt','w')
             startfile1.close()
         #Присваивание значений поумолчанию при первом запуске программы
         self.ui.lineEdit.setText('com')
         self.ui.lineEdit_2.setText('www')
         self.ui.spinBox.setText('400')
         self.ui.spinBox_2.setText('600')
         self.ui.spinBox_3.setText('399')
         self.ui.spinBox_5.setText('369')
         self.ui.lineEdit_time.setText('30')
         #Присваивание значений переменным
         FinSert=self.ui.lineEdit.text()
         StartSert=self.ui.lineEdit_2.text()
         StartlenTLS2=self.ui.spinBox.text()
         FinlenTLS2=self.ui.spinBox_2.text()
         StartlenTLS3=self.ui.spinBox_5.text()
         FinlenTLS3=self.ui.spinBox_3.text()
         timeSniff=self.ui.lineEdit_time.text()
         #Обработчики событий виджетов. Событие - клик
         self.ui.pushButton.clicked.connect(self.btn)
         self.ui.pushButton_4.clicked.connect(self.btn4)
         self.ui.pushButton_2.clicked.connect(self.btn2)
         self.ui.pushButton_3.clicked.connect(self.btn3)
         self.ui.pushButton5.clicked.connect(self.btn5)
         self.ui.pushButton6.clicked.connect(self.btn6)
         self.ui.CheckBox2.clicked.connect(self.SSHOption)
         self.ui.pushButton_setSSHOption.clicked.connect(self.SaveOptionSSH)
         self.ui.pushButton_NotsetSSHOption.clicked.connect(self.NotSave)
         #Смена режима для одной из линий ввода на режим ввода паролей
         self.ui.lineEdit_password.setEchoMode(QtWidgets.QLineEdit.Password)
         #Обработчик выбора одной из позиций в виджите комбобокс
         self.ui.comboBox.activated[str].connect(self.ActivatedBox)
         #Обработчики сигналов
         self.my_signal.connect(self.mySignalHandler, QtCore.Qt.QueuedConnection)
         self.my_signal2.connect(self.mySignalHandler2, QtCore.Qt.QueuedConnection)
         #Шаблоны фильтров
         self.tls1=f'(tls.handshake.certificate_length<={FinlenTLS2} && tls.handshake.certificate_length>={StartlenTLS2})'
         self.tls2=f'(tls&&frame.len<={FinlenTLS3}&&frame.len>={StartlenTLS3}&&tls.handshake.extensions_server_name contains {FinSert}&&tls.handshake.extensions_server_name contains {StartSert})'
     #Функция открытия окна настройки SSH подключения
     def SSHOption(self):
         global Host
         global User
         global Password
         global Port
         global commandSSH
         if self.ui.CheckBox2.isChecked() is True:#Проверка значения чекбокса №2
             self.WindowOptionSSH()#Вызов функции открытия окна настройки SSH подключения
         else:
          #Удаление значений при отключении модуля добавления адреса в сетевой экран
          self.ui.lineEdit_host.setText("")
          self.ui.lineEdit_user.setText("")
          self.ui.lineEdit_password.setText("")
          self.ui.lineEdit_port.setText("")
          self.ui.lineEdit_command.setText("")
     #Функция проверки подлинности адреса
     def validate_ip(self,ipcheck):    
      a = ipcheck.split('.')#Полученная строка делится на 4 квартета. В роли разделителя выступает точка
      if len(a) != 4:#Если количество квартетов больше или меньше 4 - адрес неверный
        return False
      for x in a:#Проверка каждого из 4-х квартетов
        if not x.isdigit():#Если квартеты - не числа => адрес неверный
            return False
        i = int(x)#Смена типа переменной(из строки в число)
        if i < 0 or i > 255:#Каждое число из каждого квартета должно лежать в диапазоне от 0 до 255, иначе - адрес неверный
            return False
        return True
     # Функция сохранения новых параметров подключения по SSH
     def SaveOptionSSH(self):
         global Host
         global User
         global Password
         global Port
         global commandSSH
         if self.validate_ip(self.ui.lineEdit_host.text()) is True:#Вызов функции проверки подлинности адреса
          Host=self.ui.lineEdit_host.text()
         else:
             #Обработка ошибки - неверный адрес
             Tk().withdraw()
             showerror(title='Ошибка ввода параметров SSH!',message="Поле 'Адрес' должно содержать ip адрес устройства")
             Tk().destroy()
         #Присвоение переменных Логин, пароль, шаблон команды
         User=self.ui.lineEdit_user.text()
         Password=self.ui.lineEdit_password.text()
         commandSSH=self.ui.lineEdit_command.text()
         if self.ui.lineEdit_port.text().isdigit() is True:#Если значение Порта не число - значение задано неверно
          Port=self.ui.lineEdit_port.text()
         else:
             #Обработка ошибки - неверный порт
             Tk().withdraw()
             showerror(title='Ошибка ввода параметров SSH!',message="Поле 'Порт' может содержать только числа")
             Tk().destroy()
         global IPaddFireWall
         #После успешного изменения параметров подключения по SSH просиходит подгрузка адресов,
         #которые были добавлены в сетевой экран в течении других сессий работы программы
         if self.validate_ip(self.ui.lineEdit_host.text()) is True:
          if self.ui.lineEdit_port.text().isdigit() is True:
           IPaddFireWall=[]
           file2=open('IPaddFireWall.txt','r')
           for line in file2.readlines():
             if line[len(line)-1]=='\n':IPaddFireWall.append(line[:-1])
             else:IPaddFireWall.append(line)
           file2.close()
           #Вызов окна настроек поиска
           self.WindowOptions()
     #Отмена изменения настроек подключения по SSH
     def NotSave(self):
         self.ui.CheckBox2.setChecked(False)
         self.WindowOptions()
     #Функция вызова окна настроек подключения по SSH
     def WindowOptionSSH(self):
         #Происходит изменения геометрии виджетов для отображения определенных окон
         #Изменение геометрии виджетов окна настроек поиска
         self.ui.pushButton5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton6.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_1.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_4.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_8.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_6.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_7.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_9.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_10.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_time.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_12.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_13.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_14.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_11.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.CheckBox.setGeometry(QtCore.QRect(0,0,0,0))
         self.ui.CheckBox2.setGeometry(QtCore.QRect(0,0,0,0))
         #Изменение геометрии виджетов окна настроек подключения по SSH
         self.ui.label_title.setGeometry(QtCore.QRect(100,10,200,20))
         self.ui.label_host.setGeometry(QtCore.QRect(140,40,100,20))
         self.ui.lineEdit_host.setGeometry(QtCore.QRect(140,60,100,20))
         self.ui.label_user.setGeometry(QtCore.QRect(140,80,100,20))
         self.ui.lineEdit_user.setGeometry(QtCore.QRect(140,100,100,20))
         self.ui.label_password.setGeometry(QtCore.QRect(140,120,100,20))
         self.ui.lineEdit_password.setGeometry(QtCore.QRect(140,140,100,20))
         self.ui.label_port.setGeometry(QtCore.QRect(140,160,100,20))
         self.ui.lineEdit_port.setGeometry(QtCore.QRect(140,180,100,20))
         self.ui.label_command.setGeometry(QtCore.QRect(65,200,260,40))
         self.ui.lineEdit_command.setGeometry(QtCore.QRect(40,240,310,20))
         self.ui.pushButton_setSSHOption.setGeometry(QtCore.QRect(144,270,92, 25))
         self.ui.pushButton_NotsetSSHOption.setGeometry(QtCore.QRect(144,300,92, 25))
         #Изменение размеров окна программы
         self.ui.gui.setFixedSize(388, 359)
     #Функция обработки нажатия на кнопку "поиск в сети"
     def btn(self):
         #Объявление глобальных переменных
         global Findip
         global Check
         global Check2
         global Host
         global User
         global Password
         global Port
         global commandSSH
         global timeSniff
         #Подгрузка адресов Тора, найденных в предыдущих сессиях работы программы
         #И запись этих адресов в массив
         Findip=[]
         file1=open('TOR ip.txt','r')
         for line in file1.readlines():
             if line[len(line)-1]=='\n':Findip.append(line[:-1])
             else:Findip.append(line)
         file1.close()
         #Присвоение значений переменным
         Host=self.ui.lineEdit_host.text()
         User=self.ui.lineEdit_user.text()
         Password=self.ui.lineEdit_password.text()
         Port=self.ui.lineEdit_port.text()
         commandSSH=self.ui.lineEdit_command.text()
         #Запуск функций поиска
         #Запуск поиска TLS 1.2
         #Передаются: сигнал, интерфейс, фильтр, время поиска, версия TLS, значения виджетов чекбокс, параметры подключения по SSH
         Sniff(self.my_signal,self.interfase,self.tls1,int(timeSniff),'1.2',Check,Check2,Host,User,Password,Port,commandSSH)
         #Запуск поиска TLS 1.3
         #Передаются: сигнал, интерфейс, фильтр, время поиска, версия TLS, значения виджетов чекбокс, параметры подключения по SSH
         Sniff(self.my_signal,self.interfase,self.tls2,int(timeSniff),'1.3',Check,Check2,Host,User,Password,Port,commandSSH)
         #Изменение геометрии некоторых виджетов
         self.ui.pushButton.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_4.setGeometry(QtCore.QRect(320, 290, 93, 41))
         self.ui.pushButton_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         #Запрет взаимодействия с виджетом комбобокс
         self.ui.comboBox.setDisabled(True)
     #Функция обработки нажатия кнопки "поиск по дампу"
     def btn2(self):
         #Получение пути к файлу дампа
         PATH=self.ui.patch.getOpenFileName(filter = "(*.pcap)")[0]
         #Запуск поиска TLS 1.2 по дампу.
         #Передаются: сигнал, путь к файлу, фильтр, версия TLS
         SniffforDUMP(self.my_signal2,PATH,self.tls1,'1.2')
         #Запуск поиска TLS 1.3 по дампу
         #Передаются: сигнал, путь к файлу, фильтр, версия TLS
         SniffforDUMP(self.my_signal2,PATH,self.tls2,'1.3')
         #Запрет взаимодействия с виджетом комбобокс
         self.ui.comboBox.setDisabled(True)
         #Изменение геометрии некоторых виджетов окна
         self.ui.pushButton.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.comboBox.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label.setGeometry(QtCore.QRect(0, 0, 0, 0))
     #Функция обработки нажатия на кнопку "Настройки поиска"
     def btn3(self):
         #Вызов функции вызова окна настроек
         self.WindowOptions()
     #Функция обработки нажатия на кнопку "Остановить поиск"
     def btn4(self):
         #Переменная, отслеживаемая всеми модулями программы
         global Stop
         Stop=True
         #Изменение геометрии некоторых виджетов окна
         self.ui.pushButton.setGeometry(QtCore.QRect(320, 290, 93, 41))
         self.ui.pushButton_4.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_2.setGeometry(QtCore.QRect(420, 290, 93, 41))
         self.ui.pushButton_3.setGeometry(QtCore.QRect(520, 290, 93, 41))
         #Разрешение взаимодействия с виджетом комбобокс
         self.ui.comboBox.setDisabled(False)
         #Вывод уведомления для пользователя
         self.ui.textBrowser.append('Поиск остановлен')
     #Функция обработки нажатия на кнопку "Применить" в окне настроек поиска
     def btn5(self):

         #Объявление глобальных переменных
         global FinSert
         global StartSert
         global StartlenTLS2
         global FinlenTLS2
         global StartlenTLS3
         global FinlenTLS3
         global Check
         global Check2
         global timeSniff
         #Присвоение значений переменным
         FinSert=self.ui.lineEdit.text()
         StartSert=self.ui.lineEdit_2.text()
         StartlenTLS2=self.ui.spinBox.text()
         FinlenTLS2=self.ui.spinBox_2.text()
         StartlenTLS3=self.ui.spinBox_5.text()
         FinlenTLS3=self.ui.spinBox_3.text()
         Check=self.ui.CheckBox.isChecked()
         Check2=self.ui.CheckBox2.isChecked()
         #Проверка на содержание поля 
         if self.ui.lineEdit_time.text().isdigit() is True:
            timeSniff=self.ui.lineEdit_time.text()
            #Вызов функции вызова основого окна
            self.WindowSniff()
         else:
            Tk().withdraw()
            showerror(title='Ошибка ввода параметра времени',message="Поле может содержать только числа")
            Tk().destroy()
     #Функция обработки нажатий на кнопку "Настройки по умолчанию"
     def btn6(self):
         #Присвоение значений некоторым виджетам окна
         self.ui.lineEdit.setText('com')
         self.ui.lineEdit_2.setText('www')
         self.ui.spinBox.setText('400')
         self.ui.spinBox_2.setText('600')
         self.ui.spinBox_3.setText('399')
         self.ui.spinBox_5.setText('369')
         self.ui.lineEdit_time.setText('30')
     #Функция обработки выбора интерфейса в виджете комбобокс
     def ActivatedBox(self,text):self.interfase=text#присвоение значения переменной
     #Обработчик сигнала №1
     def mySignalHandler(self,text):
         global Findip
         self.ui.textBrowser.append(text)#Вывод сообщения пользователю
         #Запись в файл найденного адреса (только новые)
         file=open('TOR ip.txt','a')
         if text[0].isdigit() is True:
             ip=text.split(' ')[0]
             if ip not in Findip:
              Findip.append(ip)
              file.write(ip+'\n')
         file.close()
     #Обработчик сигнала №2
     def mySignalHandler2(self,text):
         global Findip
         if text!='END':
          self.ui.textBrowser.append(text)#Вывод сообщения пользователю
          #Запись в файл найденного адреса (только новые)
          file=open('TOR ip.txt','a')
          if text[0].isdigit() is True:
             ip=text.split(' ')[0]
             if ip not in Findip:
                 Findip.append(ip)
                 file.write(ip+'\n')
          file.close()
         if text=='END':
             #Разрешение взаимодействия с виджетом комбобокс
             self.ui.comboBox.setDisabled(False)
             #Изменение геометрии некоторых виджетов окна
             self.ui.label.setGeometry(QtCore.QRect(10, 270, 301, 16))
             self.ui.comboBox.setGeometry(QtCore.QRect(10, 291, 301, 41))
             self.ui.pushButton.setGeometry(QtCore.QRect(320, 290, 93, 41))
             self.ui.pushButton_2.setGeometry(QtCore.QRect(420, 290, 93, 41))
             self.ui.pushButton_3.setGeometry(QtCore.QRect(520, 290, 93, 41))
     #Функция вызова основого окна
     def WindowSniff(self):
         #Изменение геометрии виджетов побочных окон
         self.ui.pushButton5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton6.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_1.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_4.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_8.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_6.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.spinBox_5.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_7.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_9.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_10.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_12.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_13.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_14.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_11.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_time.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.CheckBox.setGeometry(QtCore.QRect(0,0,0,0))
         self.ui.CheckBox2.setGeometry(QtCore.QRect(0,0,0,0))
         #________________________________________________________
         #Изменение геометрии виджетов основного окна
         self.ui.comboBox.setGeometry(QtCore.QRect(10, 291, 301, 41))
         self.ui.pushButton.setGeometry(QtCore.QRect(320, 290, 93, 41))
         self.ui.pushButton_4.setGeometry(QtCore.QRect(320, 290, 0, 0))
         self.ui.pushButton_2.setGeometry(QtCore.QRect(420, 290, 93, 41))
         self.ui.pushButton_3.setGeometry(QtCore.QRect(520, 290, 93, 41))
         self.ui.label.setGeometry(QtCore.QRect(10, 270, 301, 16))
         self.ui.textBrowser.setGeometry(QtCore.QRect(10, 10, 601, 251))
         #Изменение размеров окна программы
         self.ui.gui.setFixedSize(621, 396)
     #Функция вызова окна настроек поиск
     def WindowOptions(self):
         #Изменение геометрии виджетов окна настроек поиска
         self.ui.pushButton5.setGeometry(QtCore.QRect(10, 190, 93, 41))
         self.ui.pushButton6.setGeometry(QtCore.QRect(10, 140, 93, 41))
         self.ui.spinBox.setGeometry(QtCore.QRect(30, 60, 51, 22))
         self.ui.spinBox_2.setGeometry(QtCore.QRect(130, 60, 51, 22))
         self.ui.label_1.setGeometry(QtCore.QRect(10, 60, 21, 21))
         self.ui.label_2.setGeometry(QtCore.QRect(10, 30, 171, 16))
         self.ui.label_3.setGeometry(QtCore.QRect(110, 60, 21, 21))
         self.ui.label_4.setGeometry(QtCore.QRect(0, 0, 201, 16))
         self.ui.label_5.setGeometry(QtCore.QRect(206, 30, 171, 20))
         self.ui.label_8.setGeometry(QtCore.QRect(480, 100, 21, 21))
         self.ui.spinBox_3.setGeometry(QtCore.QRect(316, 60, 51, 22))
         self.ui.label_6.setGeometry(QtCore.QRect(196, 60, 21, 21))
         self.ui.spinBox_5.setGeometry(QtCore.QRect(216, 60, 51, 22))
         self.ui.label_7.setGeometry(QtCore.QRect(296, 60, 21, 21))
         self.ui.lineEdit.setGeometry(QtCore.QRect(256, 140, 113, 22))
         self.ui.label_9.setGeometry(QtCore.QRect(266, 10, 55, 16))
         self.ui.label_10.setGeometry(QtCore.QRect(250, 100, 121, 31))
         self.ui.lineEdit_2.setGeometry(QtCore.QRect(256, 210, 113, 22))
         self.ui.label_12.setGeometry(QtCore.QRect(180, 140, 71, 20))
         self.ui.label_13.setGeometry(QtCore.QRect(180, 210, 71, 20))
         self.ui.label_14.setGeometry(QtCore.QRect(180,240,140,40))
         self.ui.lineEdit_time.setGeometry(QtCore.QRect(337, 240, 30, 20))
         self.ui.label_11.setGeometry(QtCore.QRect(250, 170, 121, 31))
         self.ui.CheckBox.setGeometry(QtCore.QRect(10,90,200,16))
         self.ui.CheckBox2.setGeometry(QtCore.QRect(10,116,200,16))
         #Изменение геометрии виджетов окна настроек подключения по SSH
         self.ui.lineEdit_host.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_user.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_password.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_port.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_title.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_host.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_user.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_password.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_port.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_setSSHOption.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_NotsetSSHOption.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label_command.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.lineEdit_command.setGeometry(QtCore.QRect(0, 0, 0, 0))
         #Изменение размеров окна программы
         self.ui.gui.setFixedSize(388, 309)
         #______________________________________________________________
         #Изменение геометрии виджетов основного окна
         self.ui.comboBox.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_4.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_2.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.pushButton_3.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.label.setGeometry(QtCore.QRect(0, 0, 0, 0))
         self.ui.textBrowser.setGeometry(QtCore.QRect(0,0,0,0))
#Модуль устранения ошибок связанных с ОС
def suppress_qt_warnings():
    from os import environ
    environ["QT_DEVICE_PIXEL_RATIO"] = "0"
    environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    environ["QT_SCREEN_SCALE_FACTORS"] = "1"
    environ["QT_SCALE_FACTOR"] = "1"
#Основной поток программы
if __name__ == '__main__':
 suppress_qt_warnings()
 app=QtWidgets.QApplication(sys.argv)#ОбЪявление объекта - графического интерфейса
 w=AVT()#Объявление объекта - экземпляр класса
 w.show()#Показать графический интерфейс
 app.exec_()#действие после закрытия графического окна - завершение работы программы