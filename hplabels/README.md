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

```

- [ ] *L4 : spammer* 
    - TBD
- [ ] *L4 : zombie - mirai*
    - TBD
- [ ] *Tanner : crawler* 
    - if a entry (sender) in the JSON-formatted log of the Tanner honeypot searched for `robot.txt` it is labelled as `(benign, crawler)`
- [ ] *Cowrie/Dionaea : bruteforcer* 
    - TBD
- [ ] *Cowrie/Dionaea : exploiter* 
    - TBD
- [ ] *Cowrie/Dionaea : miner* 
    - TBD