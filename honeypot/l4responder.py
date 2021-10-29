import select
import socket
import sys
import time
import resource
import traceback
from threading import Thread
from threading import Lock
from collections import OrderedDict

#TODO: Get from config file
INNACTIVE_TIMEOUT = 5*(10**9)
CHECK_TIMEOUT     = 10

class ExternalSocket(Thread):

    def __init__(self, proxy, address, sock):
        self.proxy   = proxy
        self.address = address
        self.sock    = sock
        self.messages = 0
        self.first   = time.time_ns()
        self.last    = self.first


        Thread.__init__(self)
        self.proxy.logger.info("L4Responder: %s -- connected -- active sockets: %s",
                               self.address, str(1 + len(self.proxy.sockets)))

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception as err:
            self.proxy.logger.error("L4Responder: Exception on close() %s",
                                    self.address)

    def run(self):
        try:
            while True:
                data = self.sock.recv(9000)
                if not data: break

                self.messages += 1
                self.last = time.time_ns()
                #self.proxy.logger.info("L4Responder: %s -- sent %s messages -- active for %s s",
                #                       self.address,
                #                       str(self.messages),
                #                       str(1.0*(self.last-self.first)/10**9))

                # send something back
                self.sock.send(bytes(00))

                self.proxy.lock.acquire()
                self.proxy.sockets.move_to_end(self.address)
                self.proxy.lock.release()

        except ConnectionResetError as err:
            self.proxy.logger.error("L4Responder: %s -- connection reset by remote peer",
                                    self.address)
        except Exception as err:
            self.proxy.logger.error("L4Responder: %s -- exception on ExternalSocket.run(): %s",
                                    self.address,
                                    traceback.format_exc())

class CleanUp(Thread):
    def __init__(self, proxy):
        self.proxy = proxy
        Thread.__init__(self)

    def run(self):
        while True:
            try:
                # clean up expired sockets
                self.proxy.logger.info("L4Responder: Running cleaning thread -- %d active",  len(self.proxy.sockets))
                now = time.time_ns()
                self.proxy.lock.acquire()
                for i in list(self.proxy.sockets.keys()):
                    if (now - self.proxy.sockets[i].last) > INNACTIVE_TIMEOUT:
                        self.proxy.sockets[i].close()
                        del self.proxy.sockets[i]
                        self.proxy.logger.error("L4Responder: %s -- inactive connection closed", i)

                # Keep the flow table size bounded
                if len(self.proxy.sockets) > self.proxy.capacity:
                    (address, sckt) = self.proxy.sockets.popitem(last = False)
                    sckt.sock.close()
                self.proxy.lock.release()
                self.proxy.logger.info("L4Responder: Cleaning thread complete -- %d active",  len(self.proxy.sockets))
                time.sleep(CHECK_TIMEOUT)
            except Exception as err:
                self.proxy.logger.error("L4Responder: Exception on ExternalSocket.run(): %s", traceback.format_exc())

class L4Responder(Thread):

    def __init__(self, logger, conf_settings, host, port):
        self.logger = logger
        self.logger.info("L4Responder: Starting generic honeyport that saves 1st messages without answering")

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))

        self.host = host
        self.port = port

        self.lock = Lock()
        self.sockets = OrderedDict()
        self.capacity = 10000 # max number of concurrent connections
        Thread.__init__(self)

    def run(self):
        clean = CleanUp(self)
        clean.start()

        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy_socket.bind((self.host, self.port)) #client port
            proxy_socket.listen()
        except OSError as err:
            proxy_socket.close()
            self.logger.error("L4Responder: Exception on bind() %s", traceback.format_exc())
            return

        self.logger.info("L4Responder: Listing for external connections on %s %s", str(self.host), str(self.port))
        while True:
            try:
                sckt, address = proxy_socket.accept()

                self.lock.acquire()
                self.sockets[address] = ExternalSocket(self, address, sckt)
                self.lock.release()
                self.sockets[address].start()

            except Exception as err:
                self.logger.error("L4Responder: Exception on Proxy run() %s", traceback.format_exc())
