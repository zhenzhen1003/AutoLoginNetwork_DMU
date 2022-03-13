# -*- coding:utf-8 -*-

import sys#导入系统
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton,QDesktopWidget,QFileDialog
from PyQt5 import uic
import qtmodern.styles
import qtmodern.windows

from PyQt5.QtCore import Qt,QTimer

import os
import requests
import re
from pyDes import des, PAD_PKCS5, ECB
import binascii
import time




class MainUi(QMainWindow):#第一个窗口类
    def __init__(self,parent=None):
        super(MainUi,self).__init__(parent)
        self.ui=uic.loadUi("login.ui")
        self.ui.setWindowTitle("自动登录")
        self.modern_window=qtmodern.windows.ModernWindow(self.ui)
        self.move2center()
        self.Timer=QTimer()#设置定时器
        self.Timer.timeout.connect(self.TimerOutFun)#每当定时器计时结束一次就触发一次timeroutfun
        self.ui.start.clicked.connect(self.TimerStart)
        self.num = 0


    def move2center(self):
        screen = QDesktopWidget().screenGeometry()#屏幕的坐标
        size = self.modern_window.geometry()#对象的坐标、
        self.modern_window.move((screen.width() - size.width()) / 2,  
        (screen.height() - size.height()) / 2)#将对象坐标移动到屏幕中央


    def TimerOutFun(self):
         RESULT = self.ping()
         if RESULT != 0:
             #不连通
             self.login(self.ui.username.text(), self.ui.password.text())
         
        
    def ping(self):
        result = os.system(u"ping www.baidu.com -n 3")

        return result

    def TimerStart(self):
        self.num = self.num + 1
        if self.num % 2 == 0:
            self.Timer.stop()
            self.ui.start.setText("开始监测网络")
        else:
            self.Timer.start(10 * 60 * 1000)   #10分钟
            self.ui.start.setText("停止监测网络")

    def des_encrypt(self, s, key):
        """
        DES 加密
        :param key: 秘钥
        :param s: 原始字符串
        :return: 加密后字符串，16进制
        """
        secret_key = key
        k = des(secret_key, mode=ECB, pad=None, padmode=PAD_PKCS5)
        en = k.encrypt(s, padmode=PAD_PKCS5)
        return en  # 得到加密后的16位进制密码 <class 'bytes'>
 
 
    def encrypt(self, pd='12345', key='aM51f8FuE/s='):
        """
        密码加密过程：
        1 从认证页面中可获得base64格式的秘钥
        2 将秘钥解码成bytes格式
        3 输入明文密码
        4 通过des加密明文密码
        5 返回base64编码格式的加密后密码
        :param pd: 明文密码
        :param key: 秘钥
        :return: 加密后的密码（base64格式）
        """
        key = binascii.a2b_base64(key.encode('utf-8'))  # 先解码 <class 'bytes'>
        pd_bytes = self.des_encrypt(pd, key)  # 得到加密后的16位进制密码 <class 'bytes'>
        pd_base64 = binascii.b2a_base64(pd_bytes, newline=False).decode('utf-8')
        return pd_base64
 
 
    def login(self, username, password):
        start_time = time.process_time()
        session = requests.session()
        headers = {
            'Connection': 'keep-alive',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3;q=0.9',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/95.0.4638.69 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        session.headers = headers
 
        # 访问任意网址，返回包含认证页面链接的内容（自动跳转）
        url = 'http://bilibili.com/'
        resp = session.get(url, verify=False)
 
        # 提取认证链接并访问，经历一次重定向得到认证页面，且会返回一个cookie值：session
        url = re.search(r"href='(.*?)'</script>", resp.text).group(1)
        resp = session.get(url)
 
        # '''从认证页面正则得到 croypto（密钥 base64格式） 与 execution（post参数）的值 '''
        croypto = re.search(r'"login-croypto">(.*?)<', resp.text, re.S).group(1)
        execution = re.search(r'"login-page-flowkey">(.*?)<', resp.text, re.S).group(1)
        # 构建post数据 填入自己的学号 密码
        data = {
            'username': username,  # 学号
            'type': 'UsernamePassword',
            '_eventId': 'submit',
            'geolocation': '',
            'execution': execution,
            'captcha_code': '',
            'croypto': croypto,  # 密钥 base64格式
            'password': self.encrypt(password, croypto)  # 密码 经过des加密 base64格式
        }
 
        # 添加cookie值
        session.cookies.update({'isPortal': 'false'})
 
        # 提交数据，进行登录，这里禁止重定向，因为会有cookie限制
        url = 'https://id.dlmu.edu.cn/login'
        resp = session.post(url, data=data, allow_redirects=False)
 
        # 得到上一步返回的重定向网址，继续访问（需要清空cookie值）
        # 这里实际经过了三次重定向
        url = resp.headers['Location']
        session.cookies.clear()
        resp = session.get(url)
 
        end_time = time.process_time()
        print(end_time - start_time)
        if resp.status_code == 200:
            self.ui.status.setText("监测中    登录成功")
        else:
            self.ui.status.setText("监测中    登录失败")

        
def main():
    app = QApplication(sys.argv)
    w = MainUi()#将第一和窗口换个名字
    app.aboutToQuit.connect(app.deleteLater)
    qtmodern.styles.dark(app)
    w.modern_window.show()#将第一和窗口换个名字显示出来
    sys.exit(app.exec_())#app.exet_()是指程序一直循环运行直到主窗口被关闭终止进程（如果没有这句话，程序运行时会一闪而过）
    
if __name__ == '__main__':#只有在本py文件中才能用，被调用就不执行
    main()