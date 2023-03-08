from scapy.all import rdpcap
from scapy.all import wrpcap
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
import ast

infile = "test.pcap"
outfile = "modified_" + infile
dest_port = 65366  # usefull to make sure you only action packets that are RTP


m_bit_count = 0
m_start = 0
m_count = 0

# 初始化间隔数据包数量
interval_count = 0
modified_packets = []
# 隐秘信息数组array
secarray = []
# array = input('secret message:')
input_str = input("请输入隐秘信息：")
secarray = [int(char) for char in input_str]
packet_loss_rate = float(input("请输入丢包率: "))
pl = rdpcap(infile)

# print number of packets
#print(len(pl))
# # print rtp timestamp
# print(RTP(pl[0][UDP].payload).timestamp)
numberofpckts = len(pl)

# 遍历每个数据包
for pkt in range(numberofpckts):

    if pl[pkt].haslayer(UDP):
        packet = pl[pkt][UDP]
        if packet["UDP"].dport == 65366:  # Make sure its actually RTP
            packet["UDP"].payload = RTP(packet["Raw"].load)
            m_bit = packet[RTP].marker
            # print('m:', m_bit)
            # print('interval:', interval_count)
            # print('count:', m_bit_count)
            # 如果 m 位为 1

            if m_bit == 1:
                modified_packets.append(pl[pkt])
                #print('reach1')
                m_start = 1
                if m_start == 1:
                    m_bit_count += 1
                    # 如果是第二个 m 位为 1 的数据包
                    if m_bit_count == 2:
                        interval_count = 0
                    if m_bit_count == 3:
                        #print('reach2')
                        m_count += 1
                        m_bit_count = 1
                        # 判断间隔数据包数量的奇偶性，如果不符合要求，则重排数据包
                        if m_count - 1 < len(secarray) and interval_count % 2 != secarray[m_count - 1]:
                            #print('modify')
                            modified_packets.pop()
                            modified_packets.insert(-1, pl[pkt])
                            interval_count = 1
                        else:
                            interval_count = 0


            else:
                if random.random() > (packet_loss_rate * 1.5):
                    # 向新列表添加网络数据包
                    modified_packets.append(pl[pkt])
                # 如果 m 位不为 1，则间隔数据包数量加 1
                if m_start == 1:
                    interval_count += 1

            #### un-commment and change lines below to manipulate headers

            # packet[RTP].version = 0
            # packet[RTP].padding = 0
            # packet[RTP].extension = 0
            # packet[RTP].numsync = 0
            # packet[RTP].marker = 0
            # print(packet[RTP].marker)
            # packet[RTP].payload_type = 0
            # packet[RTP].sequence = 0

            # packet[RTP].timestamp = 0

            # packet[RTP].sourcesync = 0
            # print(packet[RTP].sourcesync)
            # packet[RTP].sync = 0

            # Calculate UDP Checksum or they will now be wrong!
            # 计算 udpchecksum

            # checksum_scapy_original = packet[UDP].chksum
            #
            # packet[UDP].chksum = None
            # packetchk = IP(raw(packet))
            # checksum_scapy = packet[UDP].chksum
            # packet_raw = raw(packetchk)
            # udp_raw = packet_raw[20:]
            #
            # chksum = in4_chksum(socket.IPPROTO_UDP, packetchk[IP], udp_raw)
            #
            # packet[UDP].chksum = checksum_scapy

        # Write out new capture file
for i in modified_packets:
    packet_i = i[UDP]
    #print(packet_i[RTP].marker)
wrpcap(outfile, modified_packets)

def packet_reorder(lst, reorder_rate):
    lst=list(lst)
    for i in range(len(lst) - 1):
        if random.random() < reorder_rate/2:
            lst[i], lst[i + 1] = lst[i + 1], lst[i]
    return PacketList(lst)


def compare_lists(list1, list2):
    """
    比较两个列表对应位置不同的概率
    """
    assert len(list1) == len(list2), "两个列表长度不同"
    diff_count = 0  # 不同元素计数器
    for i in range(len(list1)):
        if list1[i] != list2[i]:
            diff_count += 1
    return diff_count / len(list1)


def packet_loss(packet_list, drop_rate):
    drop_count = int(len(packet_list) * drop_rate)
    drop_indices = random.sample(range(len(packet_list)), drop_count)
    new_packet_list = [packet for i, packet in enumerate(packet_list) if i not in drop_indices]
    return new_packet_list


# 读取 pcap 文件
packets = rdpcap(outfile)
# 设置乱序率

packet_reorder_rate = float(input("请输入乱序率: "))
# 对每个包增加丢包率
# 对所有包增加乱序率
#packets = packet_loss(packets, packet_loss_rate)
#packets = list(filter(lambda p: p is not None, packets))
#wrpcap('parloss.pcap', packets)
# 保存丢包后的数据到pcap防止统计时长度不一
#packets = rdpcap('parloss.pcap')
repackets = packet_reorder(packets, packet_reorder_rate)

# 保存丢包乱序后的数据到pcap
wrpcap('modified_par.pcap', repackets)

packets1 = rdpcap(outfile)
packets2 = rdpcap('modified_par.pcap')
packets3 = rdpcap('test.pcap')
num_packets1 = len(packets1)
num_packets2 = len(packets3)
print("loss count is:", (num_packets2 - num_packets1) / num_packets2)
print("reorder rate is:", compare_lists(packets2, packets1))