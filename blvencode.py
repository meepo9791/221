import ast
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
from scapy.all import rdpcap
from scapy.all import wrpcap


array = []
blenghlist= []
input_str = input("请输入隐秘信息：")
array = [int(char) for char in input_str]

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
                #print('reach1')
                m_start = 1
                if m_start == 1:
                    m_bit_count += 1
                    # 如果是第二个 m 位为 1 的数据包
                    if m_bit_count == 2:
                        #print('reach2')
                        #m_count += 1
                        m_bit_count = 1
                        # 判断间隔数据包数量，如果不符合要求，则重排数据包
                        if m_count - 1 < len(array):

                            binary_str = bin(interval_count)[2:]  # 将十进制数字转换为二进制字符串，并去掉前缀'0b'
                            binary_list = [int(bit) for bit in binary_str]  # 将二进制字符串转换为整型列表
                            if all(onenum == 1 for onenum in binary_list):
                                blengh = len(binary_list)

                            else:
                                blengh = len(binary_list)-1

                                #可变码长情况下取得当前间隔中的码长，该算法只会让数据包后移
                            sub_lst = array[m_count - 1:m_count - 1+blengh]
                            smstr = ''.join(str(i) for i in sub_lst)
                            blenghlist.append(len(smstr))
                            smp = int(smstr, 2)
                            print('interval_count is', interval_count)
                            print('smp is:',smp)
                            #秘密信息列表向后挪动
                            m_count += blengh
                            if interval_count != smp:
                                print('modify')

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

    #print(packet_i[RTP].marker)
wrpcap(outfile, modified_packets)
print(blenghlist)