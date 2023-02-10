#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Luca Gioacchini

"""
This module contains the `DionaeaParser` class, which is used to parse and 
extract labels from log data collected by the Dionaea honeypot.
The `DionaeaParser` class is derived from the `HoneypotParser` base class and 
overrides its `extract_labels` method to extract labels specific to the Dionaea 
honeypot. It also defines two additional methods, `_extract_bruteforcer_label` 
and `_extract_exploiter_label`, which are used to extract bruteforcer and 
exploiter labels, respectively. The extracted labels can be saved to an output 
file if a filepath is provided when initializing an instance of the 
`DionaeaParser` class.
"""

from .parser import HoneypotParser
import os
import pandas as pd

class DionaeaParser(HoneypotParser):
    def __init__(self, filepath, outpath=None):
        """
        Class for parsing and extracting labels from Dionaea log data.

        Parameters
        ----------
        filepath : str
            Path to the file containing the Dionaea log data.
        outpath : str, optional
            Path to save the extracted labels. Default is None.

        Attributes
        ----------
        filepath : str
            Path to the file containing the Dionaea log data.
        outpath : str
            Path to save the extracted labels.

        Methods
        -------
        extract_labels()
            Extract labels from the Dionaea log data.
        _extract_bruteforcer_label(label1, label2, label3)
            Extract IPs labeled as bruteforcer from the log data.
        _extract_exploiter_label(label1, label2, label3)
            Extract IPs labeled as exploiter from the log data.
        """
        self.filepath = filepath
        self.outpath = outpath

    def _extract_bruteforcer_label(self, label1=None, label2=None, label3=None):
        """
        Extract IPs labeled as bruteforcer from the log data.

        Parameters
        ----------
        label1 : str, optional
            Label to apply to the extracted IPs. Default is 'malicious'.
        label2 : str, optional
            Label to apply to the extracted IPs. Default is 'bruteforcer'.
        label3 : str, optional
            Label to apply to the extracted IPs. Default is 'unk_bruteforcer'.

        Returns
        -------
        list
            List of tuples, where each tuple contains an IP and its 
            corresponding labels.

        """
        label1 = label1 or 'malicious'
        label2 = label2 or 'bruteforcer'
        label3 = label3 or 'unk_bruteforcer'

        # Uncompress the file and store it in /tmp/dionaea_parser
        os.system(f'cp {self.filepath} /tmp/dionaea.sqlite.gz && gunzip /tmp/dionaea.sqlite.gz && '
                  'echo "select * from logins inner join connections '
                  'on logins.connection = connections.connection;" | ' 
                  'sqlite3 /tmp/dionaea.sqlite -header -csv > /tmp/test.txt')

        # Remove the uncompressed file
        os.system(f'rm -rf /tmp/dionaea.sqlite')

        # Read the results of the SQL query into a Pandas DataFrame and count 
        # the number of occurrences of each value in the 'remote_host' column
        preprocessed = pd.read_csv('/tmp/test.txt', skiprows=[-1])\
                         .fillna('-').value_counts('remote_host')

        # Get the index (i.e. the unique values in the 'remote_host' column) of 
        # rows where the count is greater than or equal to 10
        bf_ips = preprocessed[preprocessed>=10].index
        bfs = []

        # Iterate over the IPs
        for ip in bf_ips:
            # Ignore the local host IP
            if ip != '10.0.0.1':
                # Create a tuple containing the IP and its corresponding labels
                label = (ip, label1, label2, label3)
                bfs.append(label)
        
        # Remove the temporary file
        os.system(f'rm -rf /tmp/test.txt')

        return bfs

    def _extract_exploiter_label(self, label1=None, label2=None, label3=None):
        """
        Extract IPs labeled as exploiter from the log data.

        Parameters
        ----------
        label1 : str, optional
            Label to apply to the extracted IPs. Default is 'malicious'.
        label2 : str, optional
            Label to apply to the extracted IPs. Default is 'exploiter'.
        label3 : str, optional
            Label to apply to the extracted IPs. Default is 'unk_bruteforcer'.

        Returns
        -------
        list
            List of tuples, where each tuple contains an IP and its 
            corresponding labels.

        """
        label1 = label1 or 'malicious'
        label2 = label2 or 'exploiter'
        label3 = label3 or 'unk_exploiter'

        # Uncompress the file and store it in /tmp/dionaea_parser
        os.system(f'cp {self.filepath} /tmp/dionaea.sqlite.gz && gunzip /tmp/dionaea.sqlite.gz && '
                  'echo "select * from downloads inner join connections '
                  'on downloads.connection = connections.connection;" | ' 
                  'sqlite3 /tmp/dionaea.sqlite -header -csv > /tmp/test.txt')
        
        # Remove the uncompressed file
        os.system(f'rm -rf /tmp/dionaea.sqlite')

        # Read the results of the SQL query into a Pandas DataFrame and count 
        # the number of occurrences of each value in the 'remote_host' column
        preprocessed = pd.read_csv('/tmp/test.txt', skiprows=[-1]).fillna('-')\
                         .value_counts('remote_host')

        # Get the index (i.e. the unique values in the 'remote_host' column)
        ex_ips = preprocessed.index
        exs = []

        # Iterate over the IPs
        for ip in ex_ips:
            # Ignore the local host IP
            if ip != '10.0.0.1':
                # Create a tuple containing the IP and its corresponding labels
                label = (ip, label1, label2, label3)
                exs.append(label)

        # Remove the temporary file
        os.system(f'rm -rf /tmp/test.txt')
                
        return exs

    def extract_labels(self):
        """
        Extract labels from the Dionaea log data.

        Returns
        -------
        list
            List of tuples, where each tuple contains an IP and its 
            corresponding labels.

        """
        # Parse the Dionaea log data and extract IPs labeled as bruteforcer
        bruteforcer_ips = self._extract_bruteforcer_label()
        # Parse the Dionaea log data and extract IPs labeled as exploiter
        exploiter_ips = self._extract_exploiter_label()
        # Concatenate extracted labels
        dionaea_all = bruteforcer_ips + exploiter_ips

        # If provided, save the labels to file
        if self.outpath:
            self.save_labels(dionaea_all)


        return dionaea_all