import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
array=[0,1,1,1,1,1,1]

modified_packets = []
# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("modified_test.pcap", display_filter='udp', decode_as={'udp.port==65362': 'rtp'})


# 初始化 m 位为 1 的数据包数量
m_bit_count = 0
m_start = 0
m_count = 0
# 初始化间隔数据包数量
interval_count = 0

# 遍历每个数据包
for packet in capture:
    #print(packet.layers)
    #print(packet)
    #packet_data = packet.layers[2].raw_value
    #scapy_packet = Raw(packet_data)
    rtp_packet = packet.rtp
    # 获取 m 位的值
    m_bit = rtp_packet.marker
    print('m:',m_bit)
    #print('interval:',interval_count)
    #print('count:',m_bit_count)
    modified_packets.append(packet)
    # 如果 m 位为 1
    if m_bit == '1':

        m_start = 1
        if m_start == 1:
            m_bit_count += 1
            # 如果是第二个 m 位为 1 的数据包
            if m_bit_count == 2:

                m_count += 1
                #print(interval_count % 2)
                # 判断间隔数据包数量的奇偶性
                if m_count-1 < len(array):
                    print('interval:', interval_count % 2)
                    print('array:', array[m_count - 1])
                    print((interval_count % 2) != (array[m_count-1]))
                    if (interval_count % 2) != array[m_count-1]:
                        print('modify')
                        modified_packets.pop(-2)
                        #modified_packets.insert(-1,packet)


                m_bit_count = 1
                interval_count = 0



    else:
        # 如果 m 位不为 1，则间隔数据包数量加 1
        if m_start == 1:
         interval_count += 1

# 输出结果数组

#wrpcap("output.pcap", modified_packets)
for i in modified_packets:
    print(i.rtp.marker)

#wrpcap('output.pcap',modified_packets)