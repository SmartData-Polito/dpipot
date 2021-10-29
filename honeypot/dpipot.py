#!/usr/bin/env python3
# -*- coding: iso-8859-1 -*-

import os
import sys
import yaml
import socket
import traceback

from scapy.all import *
from collections import OrderedDict

import mmh3
from logger import Logger
from lru_cache import LRUCache
from optparse import OptionParser

from twisted.internet import defer
from twisted.protocols import basic
from twisted.internet import reactor
from twisted.application import service
from twisted.application import strports
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import ClientFactory
from twisted.protocols.policies import TimeoutMixin
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import TCP4ClientEndpoint

# TODO: Get from Settings
INNACTIVE_TIMEOUT = 10
BACKEND_TIMEOUT   = 5
SOCK_PATH         = "/tmp/dpisocket"

PORT = 1212
HOST = "127.0.0.1"
CACHE_CAPACITY = 10000
MAX_ACTIVE_BACKEND = 100

#*******************************************************************************
# usage
#*******************************************************************************
def process_opt():
    parser = OptionParser(usage="usage: %prog [options]\n\n ")

    parser.add_option("-c", "--config", dest="CONF_FILE",
                      default="etc/honeypot.yml", help="Honeypot configuration")

    parser.add_option("-p", "--program", dest="PROGRAM_NAME",
                      default="dpipot", help="Tag for the logs")

    parser.add_option("-l", "--log", dest="LOG_FOLDER",
                      default="/var/log/smartpot/", help="Where to save logs")

    opt, files = parser.parse_args()
    return opt

OPT = process_opt()

#*******************************************************************************
# Manages a single connection to a backend honeypot
#*******************************************************************************
class Backend(Protocol):
    def __init__(self, logger, caller, backend, backend_name, address):
        self.logger       = logger
        self.caller       = caller
        self.backend      = backend
        self.backend_name = backend_name
        self.address      = address

    def connectionMade(self):
        self.backend["active"] += 1
        self.logger.info("%s %s:%s Backend %s arrival. Occupied slots %s",
                         self.address.type,
                         self.address.host,
                         self.address.port,
                         self.backend_name,
                         self.backend["active"])

    def connectionLost(self, reason):
        self.backend["active"] -= 1
        self.logger.info("%s %s:%s Backend %s departure. Occupied slots %s",
                         self.address.type,
                         self.address.host,
                         self.address.port,
                         self.backend_name,
                         self.backend["active"])

    def dataReceived(self, data):
        self.caller.sendMessage(data)

    def sendMessage(self, data):
        self.transport.write(data)

#*******************************************************************************
# Manages the collection of backend honeypots
#*******************************************************************************
class BackendFactory(ClientFactory):

    def __init__(self, logger, caller, backend, backend_name, address):
        self.logger       = logger
        self.caller       = caller
        self.backend      = backend
        self.backend_name = backend_name
        self.address      = address

    def buildProtocol(self, addr):
        return Backend(self.logger,
                       self.caller,
                       self.backend,
                       self.backend_name,
                       self.address)

#*******************************************************************************
# Manages the DPIEngine, including with a cache to speed up lookup
#*******************************************************************************
class DPIEngine():
    def __init__(self, logger, settings):

        self.logger   = logger
        self.cache    = LRUCache(CACHE_CAPACITY)
        self.engine   = None
        self.backends = {}

        self.connect()

        # setup the backends
        honeypots = settings["honeypots"]
        dpi_backend = honeypots["dpipot"]["backend"]
        for b in dpi_backend:
            port = ""
            honey = dpi_backend[b]
            if ":" in honey:
                (honey, port) = honey.split(":")
            addr = honeypots[honey]["address"]

            if port == "":
                if "port" in honeypots[honey]:
                    port = honeypots[honey]["port"]
                else:
                    self.logger.error("DPIEngine port missing %s", honey)
                    continue

            ep = TCP4ClientEndpoint(reactor, addr, int(port), BACKEND_TIMEOUT)
            self.backends[b] = {"host": addr,
                                "port": int(port),
                                "endpoint": ep,
                                "active": 0}
            self.logger.info("DPIEngine registered %s %s %s", b, addr, port)

    def connect(self):
        try:
            self.engine = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.engine.connect(SOCK_PATH)
            self.engine.setsockopt(socket.SOL_SOCKET,
                                   socket.SO_LINGER, struct.pack('ii', 1, 0))
        except Exception as err:
            self.logger.info("DPIEngine exception connecting to backend")

    def performDPI(self, data, address, caller):
        payload_hash = mmh3.hash128(data)
        backend = self.cache.get(payload_hash)

        if backend:
          self.logger.info("%s %s:%s DPIEngine cache hit %s",
                          address.type,
                          address.host,
                          address.port,
                          backend)
        else:
            backend = "unknown"
            try:
                c_host = address.host
                c_port = address.port

                c2s = IP(src=c_host, dst=HOST)
                s2c = IP(src=HOST, dst=c_host)

                pkts = [Ether()/c2s/TCP(sport=c_port,dport=PORT,flags='S'),
                        Ether()/s2c/TCP(sport=PORT,dport=c_port,flags='SA'),
                        Ether()/c2s/TCP(sport=c_port,dport=PORT,flags='A'),
                        Ether()/c2s/TCP(sport=c_port,dport=PORT,flags='PA')/data]

                for pkt in pkts:
                    self.engine.sendall(bytes(pkt))
                    backend = self.engine.recv(1024).decode("utf-8").lower()

                if backend and backend not in ("", "unknown"):
                    self.cache.put(payload_hash, backend)
                self.logger.info("%s %s:%s DPIEngine cache miss %s",
                                address.type,
                                address.host,
                                address.port,
                                backend)
            except OSError as err:
                self.logger.info("%s %s:%s DPIEngine reconnect %s",
                                 address.type,
                                 address.host,
                                 address.port,
                                 traceback.format_exc())
                self.connect()
            except Exception as err:
                self.logger.info("%s %s:%s DPIEngine exception %s",
                                 address.type,
                                 address.host,
                                 address.port,
                                 traceback.format_exc())

        if backend in self.backends:
            backend_info = self.backends[backend]
            self.logger.info("%s %s:%s DPIEngine connecting to %s",
                             address.type,
                             address.host,
                             address.port,
                             backend)
        else:
            backend_info = self.backends["default"]
            self.logger.info("%s %s:%s DPIEngine missing %s",
                             address.type,
                             address.host,
                             address.port,
                             backend)

        if backend_info["active"] < MAX_ACTIVE_BACKEND:
            fact = BackendFactory(self.logger,
                                  caller,
                                  backend_info,
                                  backend,
                                  address)
            return backend_info["endpoint"].connect(fact)
        else:
            self.logger.info("%s %s:%s DPIEngine max %d slots for %s reached",
                             address.type,
                             address.host,
                             address.port,
                             MAX_ACTIVE_BACKEND,
                             backend)
            return None

#*******************************************************************************
# Process an incoming connection
#*******************************************************************************
class DPIProxy(Protocol, TimeoutMixin):
    def __init__(self, factory, addr):
        self.factory   = factory
        self.address   = addr
        self.backend   = None
        self.logger    = self.factory.logger
        self.dpiengine = self.factory.dpiengine

    def connectionMade(self):
        self.factory.active += 1
        self.setTimeout(INNACTIVE_TIMEOUT)
        self.logger.info("%s %s:%s DPIProxy arrived - %d active",
                         self.address.type,
                         self.address.host,
                         self.address.port,
                         self.factory.active)

    def connectionLost(self, reason):
        self.factory.active -= 1
        self.logger.info("%s %s:%s DPIProxy gone - %d active",
                         self.address.type,
                         self.address.host,
                         self.address.port,
                         self.factory.active)
        if self.backend:
            self.backend.transport.abortConnection()

    def timeoutConnection(self):
        self.transport.abortConnection()

    def sendMessage(self, data):
        self.resetTimeout()
        self.transport.write(data)

    def dataReceived(self, data):
        self.resetTimeout()

        def DPIProxyError(err):
            self.transport.loseConnection()
            self.logger.error("%s %s:%s DPIProxy exception %s",
                              self.address.type,
                              self.address.host,
                              self.address.port,
                              err)

        def DPIProxySaveBackend(backend):
            if not backend:
                self.transport.loseConnection()
            self.backend = backend
            return backend

        def DPIProxySendData(backend, data):
            if backend:
                backend.sendMessage(data)
            return data

        d = defer.Deferred()
        if not self.backend:
            d.addCallback(self.dpiengine.performDPI,
                          address=self.address, caller=self)
            d.addCallbacks(DPIProxySaveBackend, DPIProxyError)
            d.addCallback(DPIProxySendData, data=data)
            d.addErrback(DPIProxyError)
            d.callback(data)
        else:
            d.addCallback(DPIProxySendData, data=data)
            d.addErrback(DPIProxyError)
            d.callback(self.backend)

#*******************************************************************************
# Factory that listens to connections
#*******************************************************************************
class DPIFactory(ServerFactory):
    def __init__(self, port, settings, logger):
        self.active   = 0
        self.logger   = logger
        self.settings = settings
        self.port     = port

    def buildProtocol(self, addr):
        return DPIProxy(self, addr)

    def startFactory(self):
        self.logger.info("DPIFactory Starting")
        self.dpiengine = DPIEngine(self.logger, settings)

    def stopFactory(self):
        self.logger.info("DPIFactory Shutting down")

#*******************************************************************************
# Main
#*******************************************************************************
if __name__ == '__main__':
    # start loggers
    logger = Logger(OPT.LOG_FOLDER, OPT.PROGRAM_NAME).getLogger()

    with open(OPT.CONF_FILE) as f:
        settings = yaml.full_load(f)

    server = serverFromString(reactor, 'tcp:%i' % PORT)
    server_factory = DPIFactory(PORT, settings, logger)
    server_listen_deferred = server.listen(server_factory)

    @server_listen_deferred.addErrback
    def server_listen_failed(failure):
        logger.info(failure.value)
        reactor.stop()

    @server_listen_deferred.addCallback
    def server_listen_callback(twisted_port):
        logger.info("Listening on port %d", twisted_port.getHost().port)

    reactor.run()
