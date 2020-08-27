# DeepPacket features extraction 

Deep packet a novel approach for encrypted traffic classification using deep learning

# Usage

```python
import deeppacket_preprocess

pcap_file = 'AIMchat_test.pcapng'
deeppacket_preprocess.process_pcap(pcap_file)
```

# Function

Read a pcap file, and extract features(DeepPacket), finally store as csv files by batch.

such as: "DeepPacket_features\hangouts\audio3\hangouts_audio3_0.csv"

