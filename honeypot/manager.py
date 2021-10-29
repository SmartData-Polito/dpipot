#!/usr/bin/env python3
# -*- coding: iso-8859-1 -*-

import os
import yaml

import time
import datetime
import threading

import socket
from logger import Logger
from optparse import OptionParser
from l4responder import L4Responder

#******************************************************************************
# usage
#******************************************************************************
def process_opt():
    parser = OptionParser(usage="usage: %prog [options]\n\n ")

    parser.add_option("-c", "--config", dest="CONF_FILE",
                      default="PREFIX/honeypot.yml",
                      help="Honeypot configuration")

    parser.add_option("-p", "--program", dest="PROGRAM_NAME",
                      default="smartpot", help="Tag for the logs")

    parser.add_option("-l", "--log", dest="LOG_FOLDER",
                      default="/var/log/smartpot/", help="Where to save logs")

    opt, files = parser.parse_args()
    return opt

OPT = process_opt()

#*******************************************************************************
# setup the traffic steering
#*******************************************************************************
def set_routing(conf_settings):

    # Clean up the chain "honeypot" on the nat table
    rule = "iptables -t nat -F chain-honeypot-prerouting"
    os.system(rule)
    logger.info("Clean up PREROUTING NAT table: %s", rule)

    # Clean up the chain "honeypot" on the filter table
    rule = "iptables -t filter -F chain-honeypot-input"
    os.system(rule)
    logger.info("Clean up filter INPUT table: %s", rule)

    # Clean up the chain "honeypot" on the forward table
    rule = "iptables -t filter -F chain-honeypot-forward"
    os.system(rule)
    logger.info("Clean up forward table: %s", rule)

    # Clean up the chain "honeypot" on the output table
    rule = "iptables -t nat -F chain-honeypot-output"
    os.system(rule)
    logger.info("Clean up output NAT table: %s", rule)

    # add one rule for each line in the configuration file
    honeypots = conf_settings["honeypots"]
    for h in honeypots.keys():
        honeypot = honeypots[h]

        # generic honeypot that saves the first packets of each flow
        if honeypot["type"] == "l4responder":
            rule = """iptables -t filter -A chain-honeypot-input -d {} -p tcp -m multiport --dport {} -j ACCEPT """.format(honeypot["address"], honeypot["port"])
            os.system(rule)
            logger.info("Setting: %s", rule)

        # generic backend honeypot running on a VM
        elif honeypot["type"] == "vm":
            rule = """iptables -t filter -A chain-honeypot-forward -d {} -j ACCEPT """.format(honeypot["address"])
            os.system(rule)
            logger.info("Setting: %s", rule)

        # second generation of honeypots that use nDPI to select most likely honeypot to steer traffic
        elif honeypot["type"] == "dpi":
            rule = """iptables -t filter -A chain-honeypot-input -d {} -p tcp -m multiport --dport {} -j ACCEPT """.format(honeypot["address"], honeypot["port"])
            os.system(rule)
            logger.info("Setting: %s", rule)

        # third generation of honeypots that use RL to learn how to answer sources
        elif honeypot["type"] == "rl-honeypot":
            pass

    for iprule in conf_settings["iptables_rules"]:
        honeypot = iprule["honeypot"]
        if "port" in honeypots[honeypot]:
            dst = "--to {}:{}".format(honeypots[honeypot]["address"], honeypots[honeypot]["port"])
        else:
            dst = "--to {}".format(honeypots[honeypot]["address"])

        # Forward rules
        if "interface" in iprule:
            rule = """iptables -t nat -A chain-honeypot-prerouting -i {} -p {} -d {} -m multiport --dport {} -j DNAT {}""".format(
                iprule["interface"], iprule["proto"], iprule["ip_dst"], iprule["ports"], dst)
        else:
            rule = """iptables -t nat -A chain-honeypot-prerouting -p {} -d {} -m multiport --dport {} -j DNAT {}""".format(
                iprule["proto"], iprule["ip_dst"], iprule["ports"], dst)
        os.system(rule)
        logger.info("Setting: %s", rule)

        # Input rules
        if "interface" in iprule:
            rule = """iptables -t nat -A chain-honeypot-output -i {} -p {} -d {} -m multiport --dport {} -j DNAT {}""".format(
                iprule["interface"], iprule["proto"], iprule["ip_dst"], iprule["ports"], dst)
        else:
            rule = """iptables -t nat -A chain-honeypot-output -p {} -d {} -m multiport --dport {} -j DNAT {}""".format(
                iprule["proto"], iprule["ip_dst"], iprule["ports"], dst)
        os.system(rule)
        logger.info("Setting: %s", rule)


#*******************************************************************************
# setup honeypots according to the requested type
#*******************************************************************************
class Manager(threading.Thread):

    def __init__(self, conf_settings):
        self.conf_settings = conf_settings
        threading.Thread.__init__(self)

    def run(self):

        # settings of VMs
        honeypots = self.conf_settings["honeypots"]

        logger.info("Starting manager thread")

        for honeypot in honeypots.keys():
            if honeypots[honeypot]["type"] == "l4responder":
                l4responder= L4Responder(logger, conf_settings,
                                          honeypots[honeypot]["address"],
                                          int(honeypots[honeypot]["port"]))
                l4responder.start()

            elif honeypots[honeypot]["type"] == "vm":
                # TODO make sure the vm is running
                logger.info("Backend VM image %s running on %s",
                            honeypots[honeypot]["image"],
                            honeypots[honeypot]["address"])

            elif honeypots[honeypot]["type"] == "dpi":
                # migrated to independent twisted process
                pass

#*******************************************************************************
# Main
#*******************************************************************************
if __name__ == '__main__':
    # start loggers
    logger = Logger(OPT.LOG_FOLDER, OPT.PROGRAM_NAME).getLogger()

    with open(OPT.CONF_FILE) as f:
        conf_settings = yaml.full_load(f)

    # set iptablres
    set_routing(conf_settings)

    # start manager thread
    t = Manager(conf_settings)
    t.start()
