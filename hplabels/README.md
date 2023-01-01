# Honeypot Labels Extractor
___

This tool provides a set of scripts for parsing and labeling the logs of honeypots.

## Dependencies

TBD

## Usage

To use the tool, navigate to the `scripts` directory and run the appropriate bash script for the honeypot you want to process:

```bash
cd scripts
./extract_ground_truth_honeypot_1.sh
```

This will invoke the Python backend script for honeypot 1 ...

## Supported Honeypots and Labels

```
|    Label     | L4 |       L7-Honeypot         |
|--------------|:--:|:------:|:------:|:-------:|
|              |    | Tanner | Cowrie | Dionaea |
| crawler      |    |   x    |        |         |
| bruteforcer  |    |        |    x   |    x    |
| exploiter    |    |        |    x   |    x    |
| miner        |    |        |    x   |    x    |
| spammer      |  x |        |        |         |
| zombie mirai |  x |        |        |         |
| zombie log4j |    |   x    |        |         |
```

- [ ] *L4*
    - [x] spammer: TBD
    - [x] zombie: sender exhibiting the fingerprint of known malwares
        - mirai: if a entry (sender) in the L4 log sent all of its packets 
         exhibiting the Mirai fingerprint (provided that it sent >=5 packets)
- [x] *Tanner* 
    - [x] crawler: if a entry (sender) in the JSON-formatted log of the Tanner 
    honeypot searched for `robot.txt` it is labelled as `(benign, crawler)`
    - [x] zombie: sender exhibiting the fingerprint of known malwares
        - log4j: if a entry (sender) in the Tanner log sent all of its packets 
         exhibiting the log4j fingerprint
- [ ] *Cowrie* 
    - [x] bruteforcer: if a entry (sender) in the JSON-formatted log of the 
    Cowrie honeypot tried more than 20 login attempts
    - [x] exploiter: if a entry (sender) in the JSON-formatted log of the 
    Cowrie honeypot tried to download something
    - [ ] miner: TBD
- [ ] *Dionaea* 
    - [x] bruteforcer: TBD
    - [x] exploiter: TBD
    - [ ] miner: TBD