from scapy.all import *
import random

def packet_loss(packet_list, drop_rate):
        drop_count = int(len(packet_list) * drop_rate)
        drop_indices = random.sample(range(len(packet_list)), drop_count)
        new_packet_list = [packet for i, packet in enumerate(packet_list) if i not in drop_indices]
        return new_packet_list


# 读取 pcap 文件
packets = rdpcap('test.pcap')
# 设置丢包率和乱序率
packet_loss_rate = 0.15

#对每个包增加丢包率
packets = packet_loss(packets, packet_loss_rate)

packets = list(filter(lambda p: p is not None, packets))
# 发送所有包
wrpcap('new_test.pcap', packets)


# 读取第一个pcap文件
packets1 = rdpcap('test.pcap')
# 统计第一个pcap文件中的数据包数量
num_packets1 = len(packets1)
print("Number of packets in file1.pcap:", num_packets1)

# 读取第二个pcap文件
packets2 = rdpcap('new_test.pcap')
# 统计第二个pcap文件中的数据包数量
num_packets2 = len(packets2)
print("Number of packets in file2.pcap:", num_packets2)
print("loss count is:",(num_packets1-num_packets2)/num_packets1)