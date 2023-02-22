from scapy.all import rdpcap
from scapy.all import wrpcap
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
import ast

infile = "test.pcap"
outfile = "modified_" + infile
dest_port = 65364  # usefull to make sure you only action packets that are RTP

list = []
m_bit_count = 0
m_start = 0
m_count = 0

# 初始化间隔数据包数量
interval_count = 0
modified_packets = []
# 隐秘信息数组
# array=[0,1,1,1,1,1,1]
array = []
# array = input('secret message:')
array = ast.literal_eval(input("请输入隐秘信息，使用逗号隔开: "))
pl = rdpcap(infile)

# print number of packets
print(len(pl))
# # print rtp timestamp
# print(RTP(pl[0][UDP].payload).timestamp)
numberofpckts = len(pl)

# 遍历每个数据包
for pkt in range(numberofpckts):

    if pl[pkt].haslayer(UDP):
        packet = pl[pkt][UDP]
        if packet["UDP"].dport == 65362:  # Make sure its actually RTP
            packet["UDP"].payload = RTP(packet["Raw"].load)
            m_bit = packet[RTP].marker
            # print('m:', m_bit)
            # print('interval:', interval_count)
            # print('count:', m_bit_count)
            # 如果 m 位为 1
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
                        # 判断间隔数据包数量的奇偶性，如果不符合要求，则重排数据包
                        if m_count - 1 < len(array) and interval_count % 2 != array[m_count - 1]:
                            print('modify')
                            modified_packets.pop()
                            modified_packets.insert(-1, pl[pkt])
                            interval_count = 1
                        else:

                            interval_count = 0


            else:
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

            checksum_scapy_original = packet[UDP].chksum

            packet[UDP].chksum = None
            packetchk = IP(raw(packet))
            checksum_scapy = packet[UDP].chksum
            packet_raw = raw(packetchk)
            udp_raw = packet_raw[20:]

            chksum = in4_chksum(socket.IPPROTO_UDP, packetchk[IP], udp_raw)

            packet[UDP].chksum = checksum_scapy

        # Write out new capture file
for i in modified_packets:
    packet_i = i[UDP]

    print(packet_i[RTP].marker)
wrpcap(outfile, modified_packets)
