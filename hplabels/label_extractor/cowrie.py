from .parser import HoneypotParser
import gzip
from io import BytesIO
import json
import pandas as pd

class CowrieParser(HoneypotParser):
    """
    A parser for Cowrie honeypot log data. 
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

    def _get_ips_frequency(self, entries):
        # Create a DataFrame from the list of bruteforcer IPs
        df = pd.DataFrame(entries, columns=['src_ip', 'label1', 
                                                 'label2', 'label3'])
        # Count the number of occurrences of each IP address in the DataFrame
        ip_counts = df.value_counts('src_ip')
        # Extract the IP addresses that occur at least 20 times
        bf_ips = ip_counts[ip_counts >= 20].index
        # Filter the DataFrame to include only the IP addresses that occur at 
        # least 20 times
        filtered_df = df[df['src_ip'].isin(bf_ips)]
        # Remove duplicate rows from the DataFrame
        filtered_df = filtered_df.drop_duplicates()
        # Update the bruteforcers list with the filtered list of IP addresses
        entries = filtered_df.values.tolist()

        return entries


    def _extract_bruteforcer_label(self, label1='malicious', 
                                   label2='bruteforcer'):
        """
        Extract the IP addresses of crawlers from the logs.
        """
        # Extract the IP addresses of bruteforcers from the logs
        bfs = []
        for entry in self.logs:
            try:
                # Check if the entry contains the word `login`
                if 'login' in entry:
                    # Parse the entry as JSON and extract the source IP address
                    obj = json.loads(entry)
                    src_ip = obj['src_ip']

                    # Add the IP address to the list of btuteforcers if it's 
                    # not '10.0.0.1'
                    if src_ip != '10.0.0.1':
                        label = (src_ip, label1, label2, f'unk_{label2}')
                        bfs.append(label)
            except:
                # Skip the entry if it can't be parsed as JSON
                continue
        
        # Trim the entries according to the number of login attempts
        bfs = self._get_ips_frequency(bfs)
        bfs = [tuple(x) for x in bfs]

        return bfs

    def _extract_exploiter_label(self, label1='malicious', label2='exploiter'):
        """
        Extract the IP addresses of crawlers from the logs.
        """
        # Extract the IP addresses of exploiters from the logs
        exploiters = []
        for entry in self.logs:
            try:
                # Check if the IP downloaded a file
                if 'download' in entry:
                    # Parse the entry as JSON and extract the IP address
                    obj = json.loads(entry)
                    src_ip = obj['src_ip']

                    # Add the IP address to the list of exploiters if it's not 
                    # '10.0.0.1'
                    if src_ip != '10.0.0.1':
                        label = (src_ip, label1, label2, f'unk_{label2}')
                        # Get only unique senders
                        if label not in exploiters:
                            exploiters.append(label)
            except:
                # Skip the entry if it can't be parsed as JSON
                continue

        return exploiters

    def extract_labels(self):
        """
        Extract crawler labels from the Tanner log data.
        """
        # Extract the IP addresses labeled as bruteforcer from the log data
        bfs_ips = self._extract_bruteforcer_label()
        # Extract the IP addresses labeled as expliter from the log data
        expl_ips = self._extract_exploiter_label()
        
        # Concatenate labels
        cowrie_all = bfs_ips + expl_ips

        # If an output file path has been specified, save the labels to the file
        if self.outpath:
            self.save_labels(cowrie_all)

        # Return the list of tuples containing the IP addresses and labels
        return cowrie_all