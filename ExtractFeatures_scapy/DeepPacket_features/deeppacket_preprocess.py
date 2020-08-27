'''
 __author__: riku
 __time__: 2020/8/25
'''

from scapy.all import *
import time
import numpy as np
import pandas as pd
import os
from scipy import sparse

MAXLEN = 1500
BATCH_SIZE = 1000

# 移除Ether header
def remove_eth(packet):
    if packet.haslayer("Ether"):
        return packet['Ether'].payload
    return packet

# mask ip addr
def mask_ip(packet):
    if packet.haslayer("IP"):
        packet['IP'].src = '0.0.0.0'
        packet['IP'].dst = '0.0.0.0'
    return packet

# pad UDP header from 8 bytes to 20 bytes
def pad_udp(packet):
    if packet.haslayer('UDP'):
        # Padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        after = packet['UDP'].payload
        packet['UDP'].remove_payload()
        # “/” 构造包
        packet = packet / pad / after
        return packet
    return packet

# discard (SYN,ACK,FIN) and no payload; DNS
def need_discard(p):
    if DNS in p:
        return True

    # tcp flags wireshark显示共12位，常用后6位
    # 0x013: 000000 010011 (URG=0，ACK=1，PSH=0，RST=0、SYN=1、FIN=1)
    if TCP in p and (p['TCP'].flags & 0x2 or p['TCP'].flags & 0x1):
        if not p['TCP'].payload or (Padding in p['TCP'] and len(p['TCP'].payload) == 1):
            return True
    return False

# first transform packet to array,then matrix
def packet_to_matrix(p):
    # np.frombuffer :创建np.array对象,e.g. array([1, 2, 3], dtype=uint8)
    # raw(packet) : b'\xff\xff\xff
    arr = np.frombuffer(raw(p)[: MAXLEN], dtype= np.uint8) / 255
    if len(arr) < MAXLEN:
        # s = [1,2,3]
        # np.pad(s, (1,2), 'constant')
        # (1,2)表示前面填充1个，后面填充2个 ==> [0,1,2,3,0,0]
        # 若 s 为多维array,填充宽度为 [(1,2),(0,2), ...]，每个()代表 s 的第几维
        arr = np.pad(arr, (0, MAXLEN - len(arr)),'constant')

    # 返回稀疏存储结果，减少内存开销
    arr = sparse.csr_matrix(arr)
    return arr


# 处理packet
def process_packet(p):
    if need_discard(p):
        return None
    p = remove_eth(p)
    p = mask_ip(p)
    p = pad_udp(p)
    # print(p.summary())

    p = packet_to_matrix(p)
    return p

# process pcap file
# 分批存储CSV，便于后续统计总数，以及划分数据集
def process_pcap(pcap_file):
    # 每个data为包含label和feature的字典
    dic = []
    columns = ['feature', 'app_label', 'traffic_label']
    batch_index = 0

    # read pcap
    packets = rdpcap(pcap_file)
    print(len(packets))
    for i, p in enumerate(packets):
        mat = process_packet(p)
        if mat is not None:
            # filename : hangout_audio.pcap
            app_name = pcap_file.split('/')[-1].split('_')[0]
            traffic_name = pcap_file.split('_')[1].split('.')[0]
            data = {
                'app_label': app_name,
                'traffic_label': traffic_name,
                'feature': mat.todense().tolist()[0]
            }
            dic.append(data)

        cur_path = app_name + '/' + traffic_name
        if not os.path.isdir(cur_path):
            os.makedirs(cur_path)

        # every batch_size packets
        if dic and i > 0 and i % BATCH_SIZE == 0:
            print('The', batch_index,' batch.')
            # data key as dataframe colums title
            df = pd.DataFrame(dic, columns=columns)
            # print(df)
            df.to_csv(cur_path + '/' +app_name + '_' + traffic_name + '_' + str(batch_index) + '.csv')
            batch_index += 1
            dic = []
    # 剩余不足batchsize
    if dic:
        print('The', batch_index, ' batch.')
        # data key as dataframe colums title
        df = pd.DataFrame(dic, columns=columns)
        # print(df)
        df.to_csv(cur_path + '/' + app_name + '_' + traffic_name + '_' + str(batch_index) + '.csv')



if __name__ == '__main__':
    # pkt = sniff(count = 1, filter = "tcp") # udp小写
    # print(pkt)
    # print(pkt[0].summary())
    # array = process_packet(pkt[0])
    # # print(array.toarray()[0][:72])
    # print(array.todense().tolist()[0])
    # res = process_pcap('AIMchat_test.pcapng')
    process_pcap('../hangouts_audio3.pcapng')






