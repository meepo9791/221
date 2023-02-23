import ast
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
from scapy.all import rdpcap
from scapy.all import wrpcap


new_array=[]
new_array = ast.literal_eval(input("请输入隐秘信息，使用逗号隔开: "))
bits = int(input("请输入秘密信息位数: "))
array = []
def binary_conversion(lst, n):
    decimal_lst = []
    for i in range(0, len(lst), n):
        binary_str = ''.join(map(str, lst[i:i+n]))
        decimal_num = int(binary_str, 2)
        decimal_lst.append(decimal_num)
    return decimal_lst
array = binary_conversion(new_array,bits)
print(array)


infile = "test.pcap"
outfile = "blnmodified_" + infile
dest_port = 65364  # usefull to make sure you only action packets that are RTP


m_bit_count = 0
m_start = 0
m_count = 0
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
# 遍历每个数据包
while pkt < numberofpckts:
    if pl[pkt].haslayer(UDP):
        packet = pl[pkt][UDP]
        if packet["UDP"].dport == 65362:  # Make sure its actually RTP
            packet["UDP"].payload = RTP(packet["Raw"].load)
            m_bit = packet[RTP].marker
            #向新列表添加网络数据包
            modified_packets.append(pl[pkt])
            if m_bit == 1:
                print('reach1')
                m_start = 1
                if m_start == 1:
                    m_bit_count += 1
                    # 如果是第二个 m 位为 1 的数据包
                    if m_bit_count == 2:
                        print('reach2')
                        m_count += 1
                        m_bit_count = 1
                        # 判断间隔数据包数量，如果不符合要求，则重排数据包
                        if m_count - 1 < len(array) and interval_count != array[m_count - 1]:
                            print('modify')
                            print('interval_count is',interval_count)
                            print('bl2 is', array[m_count - 1])
                            # 此时需要把interval_count和array[m_count - 1]差值数量的数据包往后挪动到这个视频帧结尾数据包的后面
                            if interval_count - array[m_count - 1] > 0:
                                blcount = interval_count - array[m_count - 1]
                                modified_packets.pop()
                                modified_packets.insert(-blcount, pl[pkt])
                                interval_count = blcount
                                blcount = 0
                            # 此时需要把interval_count和array[m_count - 1]差值数量的数据包向前挪动到视频帧结尾数据包的后面，
                            # 同时如果这些数据包包含了视频帧结尾包则进行丢弃
                            if interval_count - array[m_count - 1] < 0:
                                blcount = array[m_count - 1] - interval_count
                                modified_packets.pop()
                                while k < blcount:
                                    if pl[pkt+k+1].haslayer(UDP):
                                        packet = pl[pkt+k+1][UDP]
                                        if packet["UDP"].dport == 65362:  # Make sure its actually RTP
                                            packet["UDP"].payload = RTP(packet["Raw"].load)
                                            in_m_bit = packet[RTP].marker
                                    if in_m_bit == 1:
                                        blcount += 1
                                    if in_m_bit != 1:
                                        modified_packets.append(pl[pkt+k+1])
                                    k += 1
                                modified_packets.append(pl[pkt])
                                pkt += blcount
                                interval_count = 0
                                blcount = 0
                                k = 0

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

    #print(packet_i[RTP].marker)
wrpcap(outfile, modified_packets)
