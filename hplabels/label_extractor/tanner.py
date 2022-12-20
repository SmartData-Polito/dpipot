from .parser import HoneypotParser
import gzip
from io import BytesIO
import json
import subprocess

class TannerParser(HoneypotParser):
    """
    A parser for Tanner honeypot log data. It parses the json-formatted logs
    of Tanner. For each entry check if the source IP address searched for 
    `robots.txt`. If so, label the source IP as `crawler`

    Example (Python usage)
    
    >>> # Create a TannerParser object
    >>> parser = TannerParser('path/to/log/file.gz', 
    ... 'path/to/output/file.csv')

    >>> # Extract the labels from the log data
    >>> labels = parser.extract_labels()

    >>> # Print the labels
    >>> print(labels)

    src_ip,label1,label2,label3
    XX.XX.87.98,benign,crawler,unk_crawler
    XX.XX.109.66,benign,crawler,unk_crawler
    XX.XX.236.43,benign,crawler,unk_crawler

    """
    def __init__(self, filepath, outpath=None):
        super().__init__(filepath, outpath)

    def load_log_file(self, filepath):
        """
        Load the log file from the specified file path.
        """
        # Read the bytes object into a file-like object
        with gzip.open(filepath, 'rb') as f_in:
            file_like_obj = BytesIO(f_in.read())

        # Convert the data in the file-like object to a string
        data_string = file_like_obj.getvalue()

        # Decode the string using the utf-8 character encoding and split the
        # rows
        data_string = data_string.decode('utf-8')
        logs = data_string.split('\n')

        return logs

    def _extract_crawler_label(self, label1='benign', label2='crawler'):
        """
        Extract the IP addresses of crawlers from the logs.
        """
        # Extract the IP addresses of crawlers from the logs
        crawlers = []
        for entry in self.logs:
            try:
                # Check if the entry contains 'robots.txt'
                if 'robots.txt' in entry:
                    # Parse the entry as JSON and extract the source IP address
                    obj = json.loads(entry)
                    src_ip = obj['peer']['ip']

                    # Add the IP address to the list of crawlers if it's not 
                    # '10.0.0.1'
                    if src_ip != '10.0.0.1':
                        label = (src_ip, label1, label2, f'unk_{label2}')
                        # Get only unique senders
                        if label not in crawlers:
                            crawlers.append(label)
            except:
                # Skip the entry if it can't be parsed as JSON
                continue

        return crawlers

    def _extract_zombie_log4j_label(
            self, label1='malicious', label2='zombie'):
        """
        Extract the IP addresses of log4j zombie from the logs.
        """
        # Extract the IP addresses from the logs
        log4j = []
        for entry in self.logs:
            # Check if the entry contains 'robots.txt'
            if 'jndi:ldap' in entry:
                # Parse the entry as JSON and extract the source IP address
                obj = json.loads(entry)
                src_ip = obj['peer']['ip']

                # Add the IP address to the list of crawlers if it's not 
                # '10.0.0.1'
                if src_ip != '10.0.0.1':
                    label = (src_ip, 'malicious', 'zombie', 'log4j')
                    # Get only unique senders
                    if label not in log4j:
                        log4j.append(label)

        return log4j

    def extract_labels(self):
        """
        Extract crawler labels from the Tanner log data.
        """
        # Extract the IP addresses labeled as crawler from the log data
        crawler_ips = self._extract_crawler_label()
        # Extract the IP addresses labeled as zombie-log4j from the log data
        log4j_ips = self._extract_zombie_log4j_label()
        
        # Concatenate labels
        tanner_all = crawler_ips + log4j_ips

        # If an output file path has been specified, save the labels to the file
        if self.outpath:
            self.save_labels(tanner_all)

        # Return the list of tuples containing the IP addresses and labels
        return tanner_all