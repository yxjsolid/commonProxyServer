__author__ = 'xyang'


import threading
import time, socket




class HTTP_PROXY(threading.Thread):
    def __init__(self,threadname):
        threading.Thread.__init__(self, name=threadname)

    def proxyInit(self, proxyIp, proxyPort, serverDict, serverPort):
        self.proxyIp = proxyIp
        self.proxyPort = proxyPort
        self.serverDict = serverDict
        self.serverSessionIp = None
        self.serverPort = serverPort

        self.proxyDataLog = None
        #self.proxyInit()
        self.proxy_sock = None
        self.client_sock = None

        self.proxyServerInit()
        self.proxyClientInit()

    def setProxyDataLog(self, logger):
        self.proxyDataLog = logger

    def proxyServerInit(self):
        self.proxy_sock = socket.socket()
        self.proxy_sock.bind((self.proxyIp, self.proxyPort))
        self.proxy_sock.listen(5)

    def proxyClientInit(self):
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def getServerFromReq(self, req):
        start = req.find("Host:")
        end = req.find(":80", start)
        hostName =  req[start:end].split()[1]

        self.serverSessionIp, enable = self.serverDict[hostName]

        print "find server:%s ip: %s, enable: %d" %(hostName, self.serverSessionIp, enable)
        return hostName, self.serverSessionIp, enable

    def proxyDataToServer(self, data):

        if len(data) == 0:
            return None

        name, ip, enable = self.getServerFromReq(data)
        data = self.proxySendToServer(ip, data)

        return data

    def proxyReceiveFromServer(self):
        data = ""
        while True:
            try:
                recv = self.client_sock.recv(65536)
                #data += self.client_sock.recv(65536)
                #print "receve from server ", [recv]
                data += recv
            except Exception, e:
                print "proxyReceiveFromServer error:", e
                return data

        return data

    def proxySendToServer(self, ip, data):

        try:
            self.client_sock.getpeername()
            isconnected = 1
        except Exception:
            isconnected = 0

        try:
            self.client_sock.settimeout(2)
            if not isconnected:
                self.client_sock.connect((ip, self.serverPort))

            self.client_sock.send(data)
            #self.client_sock.settimeout(1)
        except Exception, e:
            print "proxySendToServer error:", e


        data = self.proxyReceiveFromServer()
        return data


    def doDataLog(self, info, data):
        if self.proxyDataLog:
            self.proxyDataLog.doLog(info, data)

    def sendResponseToClient(self, data):
        try:
            self.sessionSock.send(data)
        except Exception, e:
            print e

    def receiveFromClient(self):

        self.sessionSock, addr = self.proxy_sock.accept()
        self.sessionSock.settimeout(2)
        # self.sessionSock.setblocking(False)
        data = ""
        while True:
            try:
                recv = self.sessionSock.recv(1024)
                data += recv
                #print "recv:", recv
                if len(recv) == 0:
                    return data
            except Exception, e:
                print "receiveFromClient error:", e
                return data

        return data

    def proxyRun(self):

        while True:

            print "waiting for client data"
            data = self.receiveFromClient()
            print "client data received"
            print [data]


            self.doDataLog("Receive data from client", data)
            print "send data to server"
            data = self.proxyDataToServer(data)

            print "server response recieved"
            print [data]

            self.doDataLog("Data Send to server, get response", data)
            self.sendResponseToClient(data)
            print "sendserver response back to client"
            print "proxy done \r\n"

    def run(self):
        self.proxyRun()

        print self.getName()

if __name__ == "__main__":

    ServerList = [
        ["tbquery.alltobid.com",    "222.73.114.4",     1],
        ["tbquery2.alltobid.com",   "222.73.114.19",    1],
        #["tbquery.alltobid.com",    "180.76.3.151",     1],
        #["tbquery2.alltobid.com",   "180.76.3.151",    1],
        ["www.baidu.com",           "180.76.3.151",     1]
        ]



    ServerListTest = [
        ["tbquery.alltobid.com",    "127.0.0.1",        1],
        ["tbquery2.alltobid.com",   "127.0.0.1",        1],
        ]
#checkServerCfg(ServerList)

    serverDict = {}
    serverDictTest = {}

    for i in ServerList:
        serverDict[i[0]] = [i[1], i[2]]

    for i in ServerListTest:
        serverDictTest[i[0]] = [i[1], i[2]]


    proxyIp = "127.0.0.1"
    proxyPort = 80
    serverPort = 80


    proxy = HTTP_PROXY("ttttt")
    proxy.proxyInit(proxyIp, proxyPort, serverDict, serverPort)

    dataLog = MyUtil.MYLOGGER("log\http_log.txt")
    proxy.setProxyDataLog(dataLog)

    proxy.start()