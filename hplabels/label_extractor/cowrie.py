from .parser import HoneypotParser

class CowrieParser(HoneypotParser):
    def __init__(self, filepath):
        super().__init__(filepath)

    def load_log_file(self, filepath):
        # Process
        return logs

    def _extract_bruteforcer_label(self, label1='malicious', 
            label2='bruteforcer', label3='unk_bruteforcer'):
        bruteforcer_ips = [('ip', label1, label2, label3)]
        # Process
        return bruteforcer_ips

    def _extract_miner_label(self, label1='malicious', label2='miner', 
            label3='unk_miner'):
        miner_ips = [('ip', label1, label2, label3)]
        # Process
        return miner_ips

    def _extract_exploiter_label(self, label1='malicious', label2='exploiter', 
            label3='unk_exploiter'):
        exploiter_ips = [('ip', label1, label2, label3)]
        # Process
        return exploiter_ips

    def extract_labels(self):
        """Extract labels from the L4 log data."""
        # Parse the Cowrie layer log data and extract IPs labeled as bruteforcer
        bruteforcer_ips = self._extract_bruteforcer_label()
        # Parse the Cowrie layer log data and extract IPs labeled as miner
        miner_ips = self._extract_miner_label()
        # Parse the Cowrie layer log data and extract IPs labeled as exploiter
        exploiter_ips = self._extract_exploiter_label()
        # ...
        return bruteforcer_ips, miner_ips, exploiter_ips