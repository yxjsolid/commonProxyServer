__author__ = 'xyang'
import socket, ssl, os


import datetime
import time
import httplib
import threading
# response.begin()
# resp = response.read()

MY_SSL_PORT = 443
MY_SSL_PROTOCOL = ssl.PROTOCOL_SSLv3

class MY_HTTP_READER():
    def __init__(self):

        pass

    def getHttpHeader(self, data):
        index = data.find("\r\n\r\n")
        return index + 4

    def getResponseLength(self, data):
        headerIndex = self.getHttpHeader(data)

        if headerIndex > 0:
            startIndex = data.find("Content-Length:")
            endIndex = data.find("\r\n", startIndex)
            if endIndex > 0:
                contLen = int(data[startIndex:endIndex].split()[1])

                return headerIndex + contLen
            return -1

        return -1

    def isHttpGetReceived(self, data):
        if self.getHttpHeader(data):
            if data[0:3] == "GET":
                return True
        return False

    def receiveHttpResponse(self, sslSock):
        data = ""
        responseLen = -1
        buffSize = 2048

        sslSock.settimeout(4)
        while True:
            try:
                recv = sslSock.read(buffSize)
                #print recv
            except Exception, e:
                print "Error: receiveHttpResponse, ", e
                #print "data:", [data]
                return None

            if not recv or len(recv) == 0:
                return data
            data += recv

            if responseLen == -1:
                if self.isHttpGetReceived(data):
                    return data

                responseLen = self.getResponseLength(data)
            else:
                dataLenLeft = responseLen - len(data)
                if dataLenLeft < buffSize:
                    buffSize = dataLenLeft

            if len(data) == responseLen:
                return data

        return data


class MY_SSL_CLIENT():
    def __init__(self, name, ip, port):
        self.name = name
        self.ip = ip
        self.port = port
        self.sock = None
        self.ssl_sock = None
        self.clientCa = None

        self.httpReader = MY_HTTP_READER()

        #self.clientInit()

        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.ssl_sock = ssl.wrap_socket(self.sock,
        #                                 ca_certs=self.clientCa,
        #                                 cert_reqs=ssl.CERT_NONE,
        #                                 ssl_version=ssl.PROTOCOL_SSLv2)

    #def setSocketTimeout(self, timeout):
    #    self.sock.settimeout(timeout)
    #    self.ssl_sock.settimeout(timeout)

    def clientInit(self):
        if self.clientCa is None:
            #print "\r\nclientInit"
            self.clientCa = self._get_ca_certs()


        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_sock = ssl.wrap_socket(self.sock,
                                        ca_certs=self.clientCa,
                                        cert_reqs=ssl.CERT_NONE,
                                        ssl_version=MY_SSL_PROTOCOL)


    def _get_ca_certs(self):
        path = os.path.split(os.path.realpath(__file__))[0]

        ca_path = 'pem\%s_%s.pem' % (self.name, self.ip)
        ca_path = os.path.join(path, ca_path)
        if os.path.exists(ca_path):
            #print "found client ca"
            return ca_path

        try:
            print "try get cert"
            ca = ssl.get_server_certificate((self.ip, self.port), ssl_version=MY_SSL_PROTOCOL)
        except Exception, e:
            print 'get_server_certificate failed: ', e
            return

        f = open(ca_path, 'w')
        f.write(ca)
        f.close()
        return ca_path

    def clientShutDown(self):
        self.ssl_sock.shutdown(socket.SHUT_RDWR)

    def clientClose(self):
        #self.ssl_sock.shutdown(socket.SHUT_RDWR)
        if self.ssl_sock:
            self.ssl_sock.close()
            
        if self.sock:
            self.sock.close()

    def clientConnect(self):
        try:
            self.clientInit()
            self.ssl_sock.connect((self.ip, self.port))
            #pprint.pprint(self.ssl_sock.getpeercert())

            #print self.ssl_sock.getsockname()

            return True
        except Exception, e:
            #print 'connect to %s:%s failed: %s' % (self.ip, self.port, e)

            #print "error", self.ssl_sock.getsockname(), e
            #time.sleep(2)
            return False

    def sendData(self, data):
        #if  self.clientConnect():
        dataSize = len(data)
        n = 0
        try:
            if dataSize > 0:
                n = self.ssl_sock.send(data)
                dataSize -= n
        except Exception, e:
            print "ssl send date failed:", e
            return -1
            #self.ssl_sock.close()
        return n

    def receiveData(self):
        #if  self.clientConnect():
        data = ""
        while True:
            try:
                recv = self.ssl_sock.read()
                #print "receiveData:", recv
                if len(recv) == 0:
                    return data

                data += recv
            except Exception, e:
                print "Error: receiveData", e
                return data

    def connReadData(self):
        return self.sslReceiveHttpResponse()

    def sslReceiveHttpResponse(self):
        return self.httpReader.receiveHttpResponse(self.ssl_sock)

    def getSockAddr(self):
        return self.sock.getsockname()


class MY_SSL_SERVER():
    def __init__(self, host, port, Certf, keyf):
        self.host = host
        self.port = port
        self.sock = None
        self.ssl_sock = None
        self.dataLen = 0
        self.Certf = Certf
        self.keyf = keyf
        self.sessionSock = None
        self.serverInit()
        self.httpReader = MY_HTTP_READER()

    def sslReceiveHttpResponse(self, sock):
            return self.httpReader.receiveHttpResponse(sock)

    def getPeerName(self):
        return self.sessionSock.getpeername()

    def serverInit(self):
        self.sock = socket.socket()
        #self.sock.setblocking(False)

        self.sock.bind((self.host, self.port))
        self.sock.listen(5)

    def shutdown(self):
        self.ssl_sock.shutdown(socket.SHUT_WR)
        self.ssl_sock.close()
        self.sessionSock.close()

    def sendData(self, data):
        n = 0
        if data is not None:
            try:
                n = self.ssl_sock.send(data)
            except Exception, e:
                print "sendData error:", e
        return n

    def sendBackResp(self, data):
        return  self.ssl_sock.send(data)

    def closeSSL(self):
        self.ssl_sock.close()
        self.sessionSock.close()

    def accept(self):
        self.sessionSock, addr = self.sock.accept()
        self.addr = addr
        #print "server accepted"
        try:
            self.ssl_sock = ssl.wrap_socket(self.sessionSock,
                                        server_side=True,
                                        certfile=self.Certf,
                                        keyfile=self.keyf,
                                        do_handshake_on_connect = True,
                                        ssl_version=MY_SSL_PROTOCOL)

            #print "server accetp done"
            print self.ssl_sock
            return True
        except Exception,e:
            print "accept failed", e
            return False


    def handleConnection(self, sessionSock, addr, sslSock, dataHandler):
        #sessionSock.settimeout(2)
        while True:
            #data = sslSock.read()

            # print "before recieve", addr
            # aa = time.time()
            data = self.sslReceiveHttpResponse(sslSock)
            # print "after recieve", time.time() - aa, addr
            #
            # print [data]


            if data and len(data):
                # print "data len =", len(data)
                # print
                # print [data]
                rsp = dataHandler.parseData(data)
                #srv.sendHttpRsp()
                if rsp :
                    n = 0
                    try:
                        n = sslSock.send(rsp)
                    except Exception, e:
                        print "sendData error:", e
                    print "\r\n send data done, ",n, addr

            else:

                print "peer sock closed, return"
                sslSock.close()
                sessionSock.close()
                return




    def readData(self):
        data = ""


        self.sessionSock.settimeout(2)
        # self.sessionSock.setblocking(False)
        while True:
            try:
                recv = self.ssl_sock.read()
                data += recv

                print "aaaaaaaaaaa"
                print "recv", recv

                print data
                # response = httplib.HTTPResponse(self.ssl_sock)
                # response.begin()
                # recv = response.read()
                # # data += recv
                # print "recv:", recv
                if len(recv) == 0:
                    return data
            except Exception, e:
                print e
                return data

        return data

    def __runTask(self, func, arg):
        tsk = threading.Thread(target=func, args=arg)
        tsk.start()

    def serverRun(self):
        dataHandler = BidDataHandler.BID_DATA_HANDLER()

        while True:
            if self.accept():
                sessionSock = self.sessionSock
                sslSock = self.ssl_sock
                addr = self.addr
                self.__runTask(self.handleConnection, (sessionSock, addr, sslSock, dataHandler))




def testSslClient():
    host = "104.36.192.238"
    port = 443

    client = MY_SSL_CLIENT("test", host, port)
    if client.clientConnect():

        data = "a"*100

        n = client.sendData(data)
        print "send data = ", n

        #client.clientClose()

        #client.clientClose()

        client.receiveData()





    pass

if __name__ == "__main__":

    testSslClient()

    while True:

        pass