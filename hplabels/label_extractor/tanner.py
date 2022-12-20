from .parser import HoneypotParser
import gzip
from io import BytesIO
import json

class TannerParser(HoneypotParser):
    def __init__(self, filepath):
        super().__init__(filepath)

    def load_log_file(self, filepath):
        # Read the bytes object into a file-like object
        with gzip.open(filepath, 'rb') as f_in:
            file_like_obj = BytesIO(f_in.read())

        # Convert the data in the file-like object to a string
        data_string = file_like_obj.getvalue()

        # Decode the string using the utf-8 character encoding
        data_string = data_string.decode('utf-8')

        logs = data_string.split('\n')

        return logs

    def _extract_crawler_label(self, label1='benign', label2='crawler'):
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
                        crawlers.append(label)
            except:
                # Skip the entry if it can't be parsed as JSON
                continue

        return crawlers

    def extract_labels(self):
        """Extract crawler labels from the Tanner log data."""
        # Parse the Tanner log data and extract IPs labeled as crawler
        crawler_ips = self._extract_crawler_label()
        # ...
        return crawler_ips