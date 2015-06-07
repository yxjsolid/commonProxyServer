__author__ = 'xyang'

import sslUtil as myssl
import sys, time, datetime, DNS
import MyHttpProxy
import threading


class MY_BID_PROXY():
    def __init__(self, proxyIp, proxyPort, proxySrvCert, proxyKeyf, serverDict, serverPort):
        self.proxyIp = proxyIp
        self.proxyPort = proxyPort
        self.proxySrvCert = proxySrvCert
        self.proxyKeyf = proxyKeyf
        self.serverDict = serverDict
        self.serverSessionIp = None
        self.serverPort = serverPort
        self.sslServer = None
        self.sslClient = None
        self.proxyDataLog = None
        self.proxyInit()
        self.keepAlive = 0


        pass

    def proxyInit(self):
        self.sslServer = myssl.MY_SSL_SERVER(self.proxyIp, self.proxyPort, self.proxySrvCert, self.proxyKeyf)
        #self.sslClient = myssl.MY_SSL_CLIENT(self.serverIp, self.serverPort)

    def setProxyDataLog(self, logger):
        self.proxyDataLog = logger

    def doDataLog(self, info, data):
        if self.proxyDataLog:
            self.proxyDataLog.doLog(info, data)

    def receiveFromClient(self):
        self.sslServer.accept()




        data = self.sslServer.readData()


        print self.sslServer.getPeerName()
        return data

    def responseToClient(self, data):
        self.sslServer.sendData(data)

    def shutdownClient(self):
        self.sslServer.shutdown()

    def getServerFromReq(self, req):
        start = req.find("Host:")
        end = req.find(":443", start)
        hostName =  req[start:end].split()[1]

        self.serverSessionIp, enable = self.serverDict[hostName]

        if enable:
            self.sslClient = myssl.MY_SSL_CLIENT(hostName, self.serverSessionIp, self.serverPort)
        else:
            self.sslClient = None


        print "find server:%s ip: %s, enable: %d" %(hostName, self.serverSessionIp, enable)

        return enable



    def proxyToServer(self, data):

        #if len(data) == 0:
        #    return None

        if not self.getServerFromReq(data):
            return None


        if self.sslClient.clientConnect():
            self.sslClient.sendData(data)
            data = self.sslClient.receiveData()
            self.sslClient.clientClose()

            return data

    def proxyRun(self):
        while True:
            data = self.receiveFromClient()
            print "send data:", data
            self.doDataLog("Get Data From Client", data)

            if len(data) > 0:
                data = self.proxyToServer(data)
                if not self.sslClient:
                    print "force switch server"
                    self.doDataLog("Force switch server", "")
                    self.sslServer.shutdown()
                else:
                    pass

                self.doDataLog("Data Send to server, get response", data)

                print "send response", data
                self.responseToClient(data)
            print "\r\nproxy done"



def checkServerCfg(serverDict):

    for key in serverDict:
        r = DNS.DnsRequest(key[0], qtype="A", server=['4.2.2.2'], timeout=300)
        res = r.req()
        record = map(lambda x: x['data'], res.answers)

        if record[1] != key[1]:
            print "error:", key, record

        print record



def launchhttpProxy(serverDict):
    proxyIp = "127.0.0.1"
    proxyPort = 80
    serverPort = 80

    proxy = MyHttpProxy.HTTP_PROXY("ttttt")
    proxy.proxyInit(proxyIp, proxyPort, serverDict, serverPort)

    dataLog = MyUtil.MYLOGGER("log\http_log.txt")
    proxy.setProxyDataLog(dataLog)
    proxy.start()


class PROXY_SSL_SERVER(myssl.MY_SSL_SERVER):
    def __init__(self, host, port, Certf, keyf):
        myssl.MY_SSL_SERVER.__init__(self, host, port, Certf, keyf)
        pass


    def getConnection(self):
        # conn = self.connCtrl.getImageConn()
        # isFromConnCtrl = 1
        # if not conn:
        #     conn = self.getBidServerConn()

        pass

    def __runTask(self, func, arg):
        tsk = threading.Thread(target=func, args=arg)
        tsk.start()

    def proxyRun(self):
        dataHandler = BidDataHandler.BID_DATA_HANDLER()

        while True:
            if self.accept():
                sessionSock = self.sessionSock
                sslSock = self.ssl_sock
                addr = self.addr
                self.__runTask(self.handleConnection, (sessionSock, addr, sslSock, dataHandler))

    def receiveFromClient(self, sslSock):
        data = self.sslReceiveHttpResponse(sslSock)
        return data

    def responseToClient(self, sslSock, rsp):
        sslSock.send(rsp)

    def proxyToServerAndRead(self, data):
        conn = self.getConnection()
        conn.sendData(data)
        resp = conn.connReadData()

        return resp

    def handleProxyConnection(self, sessionSock, addr, sslSock, dataHandler):
        while True:
            data = self.receiveFromClient(sslSock)
            if data and len(data):
                resp = self.proxyToServerAndRead(data)

                if not resp or len(resp) == 0:
                    #self.gui.writeLog("received response is None")
                    return None
                self.responseToClient(sslSock, resp)
            else:
                print "peer sock closed, return"
                sslSock.close()
                sessionSock.close()
                return



if __name__ == "__main__":

# tbudp.alltobid.com"
# http://tbquery.alltobid.com/carnetbidinfo.html"
# https://tbresult.alltobid.com/car/gui/querybid.aspx?"
# https://tblogin.alltobid.com/car/gui/login.aspx?"
# https://toubiao.alltobid.com/car/gui/imagecode.aspx?"
# https://toubiao.alltobid.com/car/gui/bid.aspx?"

    ServerList = [
        ["tbudp.alltobid.com",      "222.73.114.4",        1],
        ["tbquery.alltobid.com",    "222.73.114.4",        1],
        ["tblogin.alltobid.com",    "222.73.114.3",        1],
        ["toubiao.alltobid.com",    "222.73.114.3",        1],
        ["tbresult.alltobid.com",   "222.73.114.3",        1],



        ["tbudp2.alltobid.com",      "222.73.114.19",        1],
        ["tbquery2.alltobid.com",    "222.73.114.19",        1],
        ["tblogin2.alltobid.com",    "222.73.114.22",        1],
        ["toubiao2.alltobid.com",    "222.73.114.22",        1],
        ["tbresult2.alltobid.com",   "222.73.114.22",        1],

    ]



    ServerListTest = [
        ["tbudp.alltobid.com",      "127.0.0.1",        1],
        ["tbquery.alltobid.com",    "127.0.0.1",        1],
        ["tblogin.alltobid.com",    "127.0.0.1",        1],
        ["toubiao.alltobid.com",    "127.0.0.1",        1],
        ["tbresult.alltobid.com",   "127.0.0.1",        1],



        ["tbudp2.alltobid.com",      "127.0.0.1",        1],
        ["tbquery2.alltobid.com",    "127.0.0.1",        1],
        ["tblogin2.alltobid.com",    "127.0.0.1",        1],
        ["toubiao2.alltobid.com",    "127.0.0.1",        1],
        ["tbresult2.alltobid.com",   "127.0.0.1",        1],
        ]
    #checkServerCfg(ServerList)

    serverDict = {}
    serverDictTest = {}

    for i in ServerList:
        serverDict[i[0]] = [i[1], i[2]]

    for i in ServerListTest:
        serverDictTest[i[0]] = [i[1], i[2]]


    proxyIp = "0.0.0.0"
    proxyPort = 443
    proxySrvCert="cacert.pem"
    proxyKeyf="cakey.pem"
    serverPort = 443

    #104.36.192.237
    #launchhttpProxy(serverDict)


    proxy =  MY_BID_PROXY(proxyIp, proxyPort, proxySrvCert, proxyKeyf, serverDict, serverPort)


    proxy.setProxyDataLog(None)

    print "proxy Run"
    proxy.proxyRun()
