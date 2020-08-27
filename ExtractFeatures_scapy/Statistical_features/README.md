# scapy-based flow statistical feature extraction tool

# usage

Two mode: offline , online

```python
FlowFeatures.py [-p test.pcap]

optional arguments:
  -h, --help            show this help message and exit
  -p PCAP_FILE, --pcap PCAP_FILE
                        offline mode, read a pcap file
```

# output

test_tcp.json<br>test_udp.json

![alt text](https://github.com/helloriku/traffic-analysis/blob/master/pcap_process/json.png)

各变量解释见 FlowFeatures.py
