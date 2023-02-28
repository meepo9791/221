import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
from encode import secarray

array = []

# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("modified_par.pcap", display_filter='udp', decode_as={'udp.port==65362': 'rtp'},
                              tshark_path='D:\wireshark\\tshark.exe')
# 初始化 m 位为 1 的数据包数量
m_bit_count = 0
m_start = 0
m_count = 0
# 初始化间隔数据包数量
interval_count = 0

# 遍历每个数据包
for packet in capture:
    # print(packet.layers)
    # print(packet)
    # packet_data = packet.layers[2].raw_value
    # scapy_packet = Raw(packet_data)
    rtp_packet = packet.rtp
    # 获取 m 位的值
    m_bit = rtp_packet.marker
    # print('m:',m_bit)
    # print('interval:',interval_count)
    # print('count:',m_bit_count)
    # 如果 m 位为 1
    if m_bit == '1':
        m_start = 1
        if m_start == 1:
            m_bit_count += 1
            # 如果是第二个 m 位为 1 的数据包
            if m_bit_count == 2:
                m_count += 1
                # print(interval_count % 2)
                # 判断间隔数据包数量的奇偶性
                if m_count - 1 < len(secarray):
                 array.append(interval_count % 2)
                m_bit_count = 1
                interval_count = 0
    else:
        # 如果 m 位不为 1，则间隔数据包数量加 1
        if m_start == 1:
            interval_count += 1

# 输出结果数组
# wrpcap("output.pcap", modified_packets)
print('secret message  send is:   ', secarray)
print('secret message  recived is:', array)


# wrpcap('output.pcap',modified_packets)
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


print('bit error rate is:', compare_lists(array, secarray))
