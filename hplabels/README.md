# Honeypot Labels Extractor
___

This tool provides a set of scripts for parsing and labeling the logs of honeypots.


## Supported Honeypots and Labels

```
|    Label          | L4 |       L7-Honeypot         |
|-------------------|:--:|:------:|:------:|:-------:|
|                   |    | Tanner | Cowrie | Dionaea |
| crawler           |    |   x    |        |         |
| bruteforcer       |    |        |    x   |    x    |
| exploiter         |    |        |    x   |    x    |
| miner             |    |        |    x   |    x    |
| spammer           | ?! |        |        |         |
| zombie mirai      |  x |        |        |         |
| zombie log4j      |    |   x    |        |         |
| zombie shellshock |    |   x    |        |         |
| benign/security/* |    |   x    |        |         |

```

- [x] *L4*
    - [x] spammer: TBD
    - [x] zombie: sender exhibiting the fingerprint of known malwares
        - mirai: if a entry (sender) in the L4 log sent all of its packets 
         exhibiting the Mirai fingerprint (provided that it sent >=5 packets)
- [x] *Tanner* 
    - [x] crawler: if a entry (sender) in the JSON-formatted log of the Tanner 
    honeypot searched for `robot.txt` it is labelled as `(benign, crawler)`
    - [x] zombie: sender exhibiting the fingerprint of known attacks
        - log4j: if a entry (sender) in the Tanner log sent any packet
         exhibiting the log4j fingerprint
    - [x] benign/security/*: senders' crawler with known user-agent fingerprint
    of security companies such as Censys, Palo Alto Network, IPIP and driftnet
- [ ] *Cowrie* 
    - [x] bruteforcer: if a entry (sender) in the JSON-formatted log of the 
    Cowrie honeypot tried more than N login attempts (N hardcoded to 20)
    - [x] exploiter: if a entry (sender) in the JSON-formatted log of the 
    Cowrie honeypot tried to download a file suing curl/wget/tftp
    - [ ] miner: TBD
- [ ] *Dionaea* 
    - [x] TBD
