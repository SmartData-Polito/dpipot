#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Luca Gioacchini

""" 
This script is an implementation of the L4Parser class, which is a subclass of 
the HoneypotParser class. The L4Parser class is designed to process log data 
collected at the 4th layer (transport layer). It provides methods for 
extracting labels from the log data that identify sources of spam and Mirai 
zombie activity. The extracted labels can be saved to an output file if a 
filepath is provided when initializing an instance of the L4Parser class.
"""

from parser import HoneypotParser
import subprocess
import multiprocessing
import glob
import pandas as pd
import numpy as np
import os

class L4Parser(HoneypotParser):
    def __init__(self, filepath, outpath=None, file_list=False):
        """
        A subclass of HoneypotParser for parsing honypot log files generated at 
        layer 4. This subclass implements specific logic for extracting labels 
        related to spammers and zombie-mirai attacks from the log data.
        
        Parameters
        ----------
        filepath : str
            Path to the log files.
        outpath : str, optional
            Path to the output file. If not provided, labels will not be saved 
            to a file.
        
        Attributes
        ----------
        filepath : str
            Path to the log files.
        outpath : str
            Path to the output file.
        
        """
        self.filepath = filepath
        self.outpath = outpath
        self.file_list = file_list

    def _process_single_file_spam(self, fpath):
        """
        Processes a single file for extracting spammer labels.
        
        Parameters
        ----------
        fpath : str
            File path of the log file to be processed.
            
        Returns
        -------
        out : str
            Processed log data in string format.
        """
        # Start a subprocess that runs the 'zcat' command and pipes its output 
        # to the 'awk' process
        if not self.file_list:
            zcat_process = subprocess.Popen(
                                ['zcat', fpath],
                                stdout=subprocess.PIPE
                            )
        else:
            for _file in fpath.split(' '):
                os.system(f'zcat {_file} >> /tmp/dkbr.log')
        
            zcat_process = subprocess.Popen(
                                    ['cat', '/tmp/dkbr.log'],
                                    stdout=subprocess.PIPE
                                )
        # Create a subprocess running the 'awk' command, which filters the 
        # input by searching for lines where the 6th field ($6) is equal to 25, 
        # 110, 143, 465, 993, or 995, and then prints the 3rd, 6th, and 8th 
        # fields
        awk_process = subprocess.Popen(
                        ['awk', 
                        '$6 == "25" || $6 == "110" || $6 == "143" || '\
                            '$6 == "465" || $6 == "993" || $6 == "995" '\
                            '{print $3, $6, $8}'],
                        stdin=zcat_process.stdout,
                        stdout=subprocess.PIPE
        )
        # Close the stdout of the 'zcat' process
        zcat_process.stdout.close()

        # Retrieve the output of the 'awk' process, decode it from bytes to 
        # string, and remove the last character
        out = awk_process.communicate()[0].decode('utf-8')[:-1]
        
        return out

    def _extract_spammer_label(self, label1=None, label2=None, label3=None):
        """
        Extracts spammer labels from the log data.
        
        Parameters
        ----------
        label1 : str, optional
            Label to be used for the first column of the output data, by 
            default 'malicious'.
        label2 : str, optional
            Label to be used for the second column of the output data, by 
            default 'spammer'.
        label3 : str, optional
            Label to be used for the third column of the output data, by 
            default 'unk_spammer'.
            
        Returns
        -------
        spammers : list
            List of tuples containing the IP addresses and labels.

        """
        label1 = label1 or 'malicious'
        label2 = label2 or 'spammer'
        label3 = label3 or 'unk_spammer'

        # Create a new process pool with number of processes equal to the 
        # number of CPUs
        pool = multiprocessing.Pool(multiprocessing.cpu_count())
        # Process the log data using the _process_single_file_spam method on 
        # each file in the specified filepath
        if not self.file_list:
            res = pool.map(self._process_single_file_spam, glob.glob(self.filepath))
        else:
            res = pool.map(self._process_single_file_spam, self.filepath.split(' '))
        pool.close() # Close the process pool
        # Split the processed log data by newline, and then split each line by 
        # space
        to_df = [x.split(' ') for x in '\n'.join(res).split('\n')]
        # Create a dataframe from the processed log data, with column names 
        # 'src_ip', 'dst_port', 'bytes_len'
        df = pd.DataFrame(to_df, columns=['src_ip', 'dst_port', 'bytes_len'])
        # Convert the 'bytes_len' column to integer type
        df['bytes_len'] = df['bytes_len'].replace({'-':-1}).astype(int)
        # Filter the dataframe by rows where 'bytes_len' is greater than or 
        # equal to 80
        _filter = df['src_ip'][df['bytes_len']>=80]
        spammer_ips = np.unique(_filter.values)
        spammers = []

        # For each IP address, create a tuple of the IP address and the labels 
        # provided
        for ip in spammer_ips:
            label = (ip, label1, label2, label3)
            if label not in spammers:
                spammers.append(label)
                
        return spammers

    def _process_single_file_mirai(self, fpath):
        """
        Extract the IP addresses of sources that have been flagged as Mirai 
        botnet zombies in the provided file.

        Parameters
        ----------
        fpath : str
            The path to the file to be processed.

        Returns
        -------
        'pandas.core.frame.DataFrame'
            A dataframe containing the IP addresses of sources flagged as Mirai 
            botnet zombies and the number of times they were flagged as such.

        """
        # Start a subprocess that runs the 'zcat' command and pipes its output 
        # to the 'awk' process
        if not self.file_list:
            zcat_process = subprocess.Popen(
                                ['zcat', fpath],
                                stdout=subprocess.PIPE
                            )
        else:
            for _file in fpath.split(' '):
                os.system(f'zcat {_file} >> /tmp/dkbr.log')
        
            zcat_process = subprocess.Popen(
                                    ['cat', '/tmp/dkbr.log'],
                                    stdout=subprocess.PIPE
                                )
        # Create a subprocess running the 'awk' command, which prints the 3rd 
        # and 10th fields of the input
        awk_process = subprocess.Popen(
                        ['awk',
                        '{print $3, $10}'],
                        stdin=zcat_process.stdout,
                        stdout=subprocess.PIPE
        )
        # Close the stdout of the 'zcat' process
        zcat_process.stdout.close()

        # Get the stdout from the 'awk' process, decode it to utf-8, and remove 
        # the last character
        out = awk_process.communicate()[0].decode('utf-8')[:-1]
        # Create a dataframe from the set of the 'out' string, split by newline
        df = pd.DataFrame(set(out.split('\n')))
        # Split the first column of the dataframe by space and expand it into 
        # separate columns
        df = df[0].str.split(" ", expand = True)
        # Filter out rows where the first column is 'src_ip'
        df = df[df[0]!='src_ip']
        # Rename the columns of the dataframe to 'src_ip' and 'mirai'
        df = df.rename(columns={0:'src_ip', 1:'mirai'})

        return df

    def _extract_zombie_mirai_label(self, label1=None, label2=None, label3=None):
        """
        Extracts IP addresses that belong to Mirai zombie botnet.

        Parameters
        ----------
        label1 : str
            Label for type of traffic. Default is 'malicious'.
        label2 : str
            Label for type of attack. Default is 'zombie'.
        label3 : str
            Label for type of botnet. Default is 'mirai'.

        Returns
        -------
        list
            List of tuples containing the IP addresses and labels.
        """
        label1 = label1 or 'malicious'
        label2 = label2 or 'zombie'
        label3 = label3 or 'mirai'

        # Create a new process pool with number of processes equal to the 
        # number of CPUs
        pool = multiprocessing.Pool(multiprocessing.cpu_count())
        # Process the log data using the _process_single_file_mirai method on 
        # each file in the specified filepath
        if not self.file_list:
            res = pool.map(self._process_single_file_mirai, 
                           glob.glob(self.filepath))
        else:
            res = pool.map(self._process_single_file_mirai, self.filepath.split(' '))
        # Close the process pool
        pool.close()

        # Concatenate the processed log data into a single dataframe and drop 
        # duplicates
        df = pd.concat(res).drop_duplicates()
        # Filter the dataframe to only keep rows where the 'mirai' column is 
        # not equal to '-'
        df = df[df['mirai']!='-']
        df['cnt'] = 0 # Add a new column to count the number of packets
        # Convert the 'mirai' column to integer type
        df['mirai'] = df['mirai'].astype(int) 
        # Group the dataframe by 'src_ip' and aggregate 'mirai' by sum and 
        # 'cnt' by count
        df = df.groupby('src_ip').agg({'mirai':sum, 'cnt':'count'})
        # Get a list of IP addresses where the 'mirai' column is equal to the
        # 'cnt' column
        mirai_ips = df[df['mirai'] == df['cnt']].index

        # For each IP address in the list of 'mirai' IPs create a tuple of the 
        # IP address and the labels 'malicious', 'zombie', 'mirai'
        mirais = []
        for ip in mirai_ips:
            label = (ip, label1, label2, label3)
            # If the tuple is not already in the 'mirais' list, append it to 
            # the list
            if label not in mirais:
                mirais.append(label)

        return mirais

    def extract_labels(self):
        """
        Extract labels from log data.
        
        This function extracts IP addresses that are labeled as spammer or
        zombie-mirai from log data and saves the labels to a file if an output
        file path was specified.
        
        Returns
        -------
        list
            List of tuples containing the IP addresses and labels.
        """
        # Parse the L4 layer log data and extract IPs labeled as spammer
        spammer_ips = self._extract_spammer_label()
        # Parse the L4 layer log data and extract IPs labeled as zombie-mirai
        mirai_ips = self._extract_zombie_mirai_label()
        
        # Concatenate extracted labels
        l4_all = spammer_ips + mirai_ips

        # If provided, save the labels to file
        if self.outpath:
            self.save_labels(l4_all)

        return l4_all
