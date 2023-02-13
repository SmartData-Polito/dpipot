#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: drago

"""

"""
from optparse import OptionParser

import sys
sys.path.insert(0, './label_extractor')

from tanner import TannerParser
from cowrie import CowrieParser
from dionaea import DionaeaParser
from l4 import L4Parser

parsers = {"tanner": TannerParser,
           "cowrie": CowrieParser,
           "dionaea": DionaeaParser,
           "l4": L4Parser}

#*******************************************************************************
# usage
#*******************************************************************************
def process_opt():
    parser = OptionParser(usage="usage: %prog [options]\n")

    parser.add_option("-i", "--input", dest="INPUT", default=None,
                      help="Input log file")

    parser.add_option("-o", "--output", dest="OUTPUT", default=None,
                      help="Output log file")

    parser.add_option("-p", "--parser", dest="PARSER", default=list(parsers.keys())[0],
                      help="Name of the parser to use")

    opt, files = parser.parse_args()
    if not opt.INPUT or opt.PARSER not in parsers.keys():
        parser.print_help()
        print("\nValid parsers are: {} \n".format(",".join(parsers)))
        sys.exit(1)
    return opt


#*******************************************************************************
# Main
#*******************************************************************************
if __name__ == '__main__':

    OPT = process_opt()
    extractor = parsers[OPT.PARSER](OPT.INPUT, OPT.OUTPUT)
    log = extractor.extract_labels()

    if not OPT.OUTPUT:
        for i in log:
            print(" ".join(list(i)))

