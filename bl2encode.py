import ast
from scapy.layers.inet import UDP, in4_chksum, IP
from scapy.layers.rtp import RTP
from scapy.all import *
from scapy.all import rdpcap
from scapy.all import wrpcap


new_array=[]
new_array = ast.literal_eval(input("请输入隐秘信息，使用逗号隔开: "))
array=[]
bl2=0
for i in range(len(new_array)):
    if i%2==0:   bl2 += new_array[i]*2
    else:
        bl2 += new_array[i]
        array.append(bl2)
        bl2=0
print(array)


infile = "test.pcap"
outfile = "bl2modified_" + infile
dest_port = 65364  # usefull to make sure you only action packets that are RTP


m_bit_count = 0
m_start = 0
m_count = 0
# 初始化间隔数据包数量
interval_count = 0
modified_packets = []
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
            #向新列表添加网络数据包
            #modified_packets.append(pl[pkt])
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
                        if m_count - 1 < len(array) and interval_count != array[m_count - 1]:
                            print('modify')
                            print('interval_count is',interval_count)
                            print('bl2 is', array[m_count - 1])
                            interval_count = 0
                            #此时需要把interval_count和array[m_count - 1]差值数量的数据包往后挪动到这个视频帧结尾数据包的后面
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

        # Write out new capture file
# for i in modified_packets:
#     packet_i = i[UDP]
#
#     print(packet_i[RTP].marker)
# wrpcap(outfile, modified_packets)
