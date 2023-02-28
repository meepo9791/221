import ast
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
from scapy.all import rdpcap
from scapy.all import wrpcap
import random

secarray = []
blenghlist = []
input_str = input("请输入隐秘信息：")
secarray = [int(char) for char in input_str]

infile = "test.pcap"
outfile = "blvmodified_" + infile
dest_port = 65364  # usefull to make sure you only action packets that are RTP

smp = 0
m_bit_count = 0
m_start = 0
m_count = 1
blcount = 0
# 初始化间隔数据包数量
interval_count = 0
modified_packets = []
pl = rdpcap(infile)
# print number of packets
print(len(pl))
# # print rtp timestamp
# print(RTP(pl[0][UDP].payload).timestamp)
numberofpckts = len(pl)
pkt = 0
k = 0
def gray_to_decimal(n):
    """
    将格雷码转换为十进制数
    :param n: 输入的格雷码，str类型
    :return: 十进制数，int类型
    """
    binary = ''
    for i in range(len(n)):
        binary += str(int(n[i]) ^ int(binary[i-1]) if i > 0 else int(n[i]))
    return int(binary, 2)
# 遍历每个数据包
while pkt < numberofpckts:
    if pl[pkt].haslayer(UDP):
        packet = pl[pkt][UDP]
        if packet["UDP"].dport == 65362:  # Make sure its actually RTP
            packet["UDP"].payload = RTP(packet["Raw"].load)
            m_bit = packet[RTP].marker
            # 向新列表添加网络数据包
            modified_packets.append(pl[pkt])
            if m_bit == 1:
                # print('reach1')
                m_start = 1
                if m_start == 1:
                    m_bit_count += 1
                    # 如果是第二个 m 位为 1 的数据包
                    if m_bit_count == 2:
                        # print('reach2')
                        # m_count += 1
                        m_bit_count = 1
                        # 判断间隔数据包数量，如果不符合要求，则重排数据包
                        if m_count - 1 < len(secarray):

                            binary_str = bin(interval_count)[2:]  # 将十进制数字转换为二进制字符串，并去掉前缀'0b'
                            binary_list = [int(bit) for bit in binary_str]  # 将二进制字符串转换为整型列表
                            if all(onenum == 1 for onenum in binary_list):
                                blengh = len(binary_list)

                            else:
                                blengh = len(binary_list) - 1

                                # 可变码长情况下取得当前间隔中的码长，该算法只会让数据包后移
                            sub_lst = secarray[m_count - 1:m_count - 1 + blengh]
                            smstr = ''.join(str(i) for i in sub_lst)
                            blenghlist.append(len(smstr))
                            smp = gray_to_decimal(smstr)
                            # 秘密信息列表向后挪动
                            m_count += blengh
                            if interval_count != smp:
                                # 此时需要把interval_count和smp差值数量的数据包往后挪动到这个视频帧结尾数据包的后面
                                if interval_count - smp > 0:
                                    blcount = interval_count - smp
                                    modified_packets.pop()
                                    modified_packets.insert(-blcount, pl[pkt])
                                    interval_count = blcount
                                    blcount = 0
                                # 此时需要把interval_count和smp差值数量的数据包向前挪动到视频帧结尾数据包的后面，
                                # 同时如果这些数据包包含了视频帧结尾包则进行丢弃

                            else:
                                interval_count = 0
            else:
                # 如果 m 位不为 1，则间隔数据包数量加 1
                if m_start == 1:
                    interval_count += 1

            checksum_scapy_original = packet[UDP].chksum

            packet[UDP].chksum = None
            packetchk = IP(raw(packet))
            checksum_scapy = packet[UDP].chksum
            packet_raw = raw(packetchk)
            udp_raw = packet_raw[20:]

            chksum = in4_chksum(socket.IPPROTO_UDP, packetchk[IP], udp_raw)

            packet[UDP].chksum = checksum_scapy
    pkt += 1
    # Write out new capture file
for i in modified_packets:
    packet_i = i[UDP]

    # print(packet_i[RTP].marker)
wrpcap(outfile, modified_packets)
print(blenghlist)


def packet_reorder(lst, reorder_rate):
    # 乱序函数
    """
        按照给定的乱序率对列表进行重新排序
        """
    if reorder_rate <= 0:
        return lst
    elif reorder_rate >= 1:
        return random.sample(lst, len(lst))

    # 计算需要乱序的元素个数
    num_reorder = int(len(lst) * reorder_rate)

    # 随机选择需要乱序的元素的下标
    reorder_indices = random.sample(range(len(lst)), num_reorder)

    # 对选择的元素进行乱序操作
    reorder_values = [lst[i] for i in reorder_indices]
    random.shuffle(reorder_values)

    # 将乱序后的元素放回原来的位置
    new_lst = list(lst)
    for i, j in zip(reorder_indices, reorder_values):
        new_lst[i] = j

    return new_lst


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
packet_loss_rate = float(input("请输入丢包率: "))
packet_reorder_rate = float(input("请输入乱序率: "))
# 对每个包增加丢包率
# 对所有包增加乱序率
packets = packet_loss(packets, packet_loss_rate)
packets = list(filter(lambda p: p is not None, packets))
wrpcap('new_test.pcap', packets)
# 保存丢包后的数据到pcap防止统计时长度不一
repackets = packet_reorder(packets, packet_reorder_rate)

# 保存丢包乱序后的数据到pcap
wrpcap('blv_mod.pcap', repackets)

packets1 = rdpcap(outfile)
packets2 = rdpcap('blv_mod.pcap')
packets3 = rdpcap('new_test.pcap')
num_packets1 = len(packets1)
num_packets2 = len(packets2)
print("loss count is:", (num_packets1 - num_packets2) / num_packets1)
print("reorder rate is:", compare_lists(packets2, packets3))
