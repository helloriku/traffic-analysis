# coding: utf8

'''
 __author__: helloriku
 __time__: 2020/7/6
'''

import argparse
import threading
import multiprocessing
import time
import json
import signal
from scapy.all import *
# from scapy.utils import PcapReader


# TCP或UDP流
class tcp_udp_stream:
    def __init__(self):
        self.id = {}            # 四元组
        self.first_t = 0        # 首包time
        self.p_t = 0            # 最新包time
        self.s2c_t = 0          # 最新s2c包time
        self.c2s_t = 0          # 最新c2s包time

        # self.state = 0          # 当前TCP状态
        # self.timeout = 0        # 判断是否超时,超时标记 1 (流结束)

        self.p_count = 0        # 包个数
        self.s2c_count = 0      # s2c个数
        self.c2s_count = 0      # c2s个数

        self.c2s_t_inter = [0]  # c2s间隔序列
        self.s2c_t_inter = [0]  # s2c间隔序列
        self.sess_t_inter = [0] # 双向流间隔序列(即所有包间隔序列)

        self.c2s_len = []       # c2s字节数序列
        self.s2c_len = []       # s2c字节数序列
        self.p_len = []         # 双向字节数序列(即所有包字节数序列)

        self.total_len = 0      # 总字节数
        self.c2s_total_len = 0  # c2s总字节数
        self.s2c_total_len = 0  # s2c总字节数


def print_flows(flows,flows_type):
    global is_sigint_up
    # 无中断信号时
    while not is_sigint_up:
        print('='*50, flows_type, "="*50)
        print('client <==> server | packets | Bytes | c2s Packets | c2s Bytes | s2c Packets | s2c Bytes | Duration')
        for flow in flows.values():
            id = flow.id['c_addr'] + ':' + str(flow.id['c_port']) + ' <====> ' + flow.id['s_addr'] + ':' + str(flow.id['s_port'])
            print(id, ' | ', flow.p_count, ' | ', flow.total_len, ' | ', flow.c2s_count, ' | ',
                  flow.c2s_total_len, ' | ', flow.s2c_count, ' | ', flow.s2c_total_len, ' | ', flow.p_t - flow.first_t)
        time.sleep(15)


def store_flows(flows, flows_type, outfile):
    res = {}
    count = 0
    # print result
    print('=' * 50, flows_type, "=" * 50)
    print('    client       <=====>       server   | packets | Bytes | c2s Packets | c2s Bytes | s2c Packets | s2c Bytes | Duration')
    for flow in flows.values():
        id = flow.id['c_addr'] + ':' + str(flow.id['c_port']) + ' <====> ' + flow.id['s_addr'] + ':' + str(
            flow.id['s_port'])
        print(id, ' | ', flow.p_count, ' | ', flow.total_len, ' | ', flow.c2s_count, ' | ',
              flow.c2s_total_len, ' | ', flow.s2c_count, ' | ', flow.s2c_total_len, ' | ', flow.p_t - flow.first_t)

        # res.update({str(count) : flow.__dict__})
        res.update({str(count): {'id':flow.id,'p_count':flow.p_count, 's2c_count':flow.s2c_count, 'c2s_count':flow.c2s_count,
                                'total_len':flow.total_len, 's2c_total_len':flow.s2c_total_len,'c2s_total_len':flow.c2s_total_len,
                                'p_len':flow.p_len, 's2c_len':flow.s2c_len, 'c2s_len':flow.c2s_len,
                                'Duration':flow.p_t - flow.first_t,'sess_t_inter':flow.sess_t_inter, 's2c_t_inter':flow.s2c_t_inter,
                                'c2s_t_inter':flow.c2s_t_inter}})
        count += 1

    # store result
    with open(outfile, "w", encoding='utf-8') as f:
        json.dump(res, f, indent=2, ensure_ascii=False)


def tcp_udp_callback(p):
    global tcp_flows
    global udp_flows

    if p.haslayer("TCP"):
        prot = p.getlayer("TCP")
        flows = tcp_flows
        flow_type = 'TCP'
    elif p.haslayer("UDP"):
        prot = p.getlayer("UDP")
        flows = udp_flows
        flow_type = 'UDP'
    else:
        return

    try:
        dic = {}
        # server <--> client
        s2c = 0
        if prot.sport <= prot.dport:
            dic['s_addr'] = p[1].src    # s2c
            dic['c_addr'] = p[1].dst
            dic['s_port'] = prot.sport
            dic['c_port'] = prot.dport
            s2c = 1
        else:
            dic['s_addr'] = p[1].dst    # c2s
            dic['c_addr'] = p[1].src
            dic['s_port'] = prot.dport
            dic['c_port'] = prot.sport

        prot_s = tcp_udp_stream()
        p_len = len(corrupt_bytes(p))

        if str(dic) not in flows.keys():  # 新流
            prot_s.id = dic
            prot_s.first_t = prot_s.p_t = p.time
            prot_s.p_count = 1
            prot_s.p_len.append(p_len)
            prot_s.total_len = p_len
            # prot_s.state =

            if s2c:
                prot_s.s2c_count = 1
                prot_s.s2c_t = p.time
                prot_s.s2c_len.append(p_len)
                prot_s.s2c_total_len += p_len
            else:
                prot_s.c2s_count = 1
                prot_s.c2s_t = p.time
                prot_s.c2s_len.append(p_len)
                prot_s.c2s_total_len += p_len
            print("New ", flow_type, " stream: ", p[1].src, ':', prot.sport, "===>", p[1].dst, ':', prot.dport)
            flows[str(dic)] = prot_s

        else:   # old stream
            # print("Old stream: ", p[1].src, ':', prot.sport, "===>", p[1].dst, ':', prot.dport)
            flows[str(dic)].p_count += 1
            flows[str(dic)].p_len.append(p_len)
            flows[str(dic)].total_len += p_len
            flows[str(dic)].sess_t_inter.append(p.time - flows[str(dic)].p_t)
            flows[str(dic)].p_t = p.time
            # prot_s.state =

            if s2c:
                if flows[str(dic)].s2c_count > 0: # 如果是第一个s2c包，间隔时间仍为0
                    flows[str(dic)].s2c_t_inter.append(p.time - flows[str(dic)].s2c_t)
                flows[str(dic)].s2c_count += 1
                flows[str(dic)].s2c_t = p.time
                flows[str(dic)].s2c_len.append(p_len)
                flows[str(dic)].s2c_total_len += p_len
            else:
                if flows[str(dic)].c2s_count > 0:
                    flows[str(dic)].c2s_t_inter.append(p.time - flows[str(dic)].c2s_t)
                flows[str(dic)].c2s_count += 1
                flows[str(dic)].c2s_t = p.time
                flows[str(dic)].c2s_len.append(p_len)
                flows[str(dic)].c2s_total_len += p_len
    except AttributeError:
        pass

def local_sniff():
    sniff(prn=tcp_udp_callback)


# 处理ctrl+c
def sigint_handler(signum, frame):
    global is_sigint_up
    is_sigint_up = True
    print('catched interrupt signal!')
    print('Please do not close the window, the result is being stored...')


if __name__ == '__main__':
    print('welcome to scapy-based split-flow tool.\n')
    parser = argparse.ArgumentParser(description='online/offline split-flow tool')
    parser.add_argument('-p', '--pcap', dest='pcap_file', action='store', help='offline mode, read a pcap file')
    args = parser.parse_args()

    tcp_flows = {}
    udp_flows = {}
    tcp_type = 'TCP'
    udp_type = 'UDP'

    # 处理中断（online mode下）
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    is_sigint_up = False

    # offline
    if args.pcap_file:
        print('offline mode.\nread file: ', args.pcap_file)
        print('Please wait ......')
        start_t = time.time()

        packets = rdpcap(args.pcap_file)
        for p in packets:
            tcp_udp_callback(p)
        # sniff(offline = args.pcap_file, prn=tcp_udp_callback)

        file_tcp = args.pcap_file.split('.')[0] + '_tcp.json'
        file_udp = args.pcap_file.split('.')[0] + '_udp.json'
        store_flows(udp_flows, udp_type, file_tcp)
        store_flows(tcp_flows, tcp_type, file_udp)
        print('spend time : ',time.time() - start_t, 's.')
        print('output:')
        print(args.pcap_file.split('.')[0] + '_tcp.json')
        print(args.pcap_file.split('.')[0] + '_udp.json')
    # online
    else:
        threads = []
        t_tcp = threading.Thread(target=print_flows, args=(tcp_flows, tcp_type,), daemon=True) #守护线程，主线程结束，子线程也终止
        t_udp = threading.Thread(target=print_flows, args=(udp_flows, udp_type,), daemon=True)
        sn = threading.Thread(target=local_sniff, daemon=True)
        t_tcp.start()
        t_udp.start()
        sn.start()
        while 1:
            if not t_tcp.is_alive() and not t_udp.is_alive():
                break

        tmp = str(time.time())
        out_tcp = 'tcp_' + tmp + '.json'
        out_udp = 'udp_' + tmp + '.json'
        store_flows(udp_flows, udp_type, out_tcp)
        store_flows(tcp_flows, tcp_type, out_udp)
        print('output:')
        print('tcp_' + tmp + '.json')
        print('udp_' + tmp + '.json')


# sniff(session=TCPSession, prn=lambda x: x.summary(), store=False)
# sn = sniff(offline="H:\VPN-nonVPN(ISCXVPN2016)\pcaps\AIMchat2.pcapng",session = NetflowSession)
# print(sn)
# print(type(sn))
# print(len(sn))