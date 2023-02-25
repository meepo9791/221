import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
from blvencode import blenghlist

array = []
list2 = blenghlist
# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("blvmodified_test.pcap", display_filter='udp', decode_as={'udp.port==65362': 'rtp'}, tshark_path='D:\wireshark\\tshark.exe')
# 初始化 m 位为 1 的数据包数量
bln = 4
m_bit_count = 0
m_start = 0
m_count = 0
# 初始化间隔数据包数量
interval_count = 0

# 遍历每个数据包
for packet in capture:
    rtp_packet = packet.rtp
    # 获取 m 位的值
    m_bit = rtp_packet.marker
    # 如果 m 位为 1
    if m_bit == '1':
        m_start = 1
        if m_start == 1:
            m_bit_count += 1
            # 如果是第二个 m 位为 1 的数据包
            if m_bit_count == 2:
                m_count += 1
                # 判断间隔数据包数量
                array.append(interval_count)
                m_bit_count = 1
                interval_count = 0
    else:
        # 如果 m 位不为 1，则间隔数据包数量加 1
        if m_start == 1:
         interval_count += 1
def dec_to_bin_list(decimal_list, length_list):
    """
    Convert decimal numbers in decimal_list to binary numbers with lengths defined by corresponding elements in
    length_list. Stop when length_list is exhausted.

    Args:
        decimal_list (list): A list of decimal numbers.
        length_list (list): A list of integer values representing the length of the binary numbers to convert to.

    Returns:
        A list of binary numbers as strings.
    """
    binary_list = []
    for i, length in enumerate(length_list):
        if i >= len(decimal_list):
            break
        binary_str = format(decimal_list[i], 'b')
        binary_list.append(binary_str.zfill(length))
    return binary_list

# 输出结果数组
#wrpcap("output.pcap", modified_packets)
print('interval count is:',array)


binary_list = dec_to_bin_list(array, list2)


new_list = [item for sublist in binary_list for item in sublist]
print('secret message is:',new_list)
#wrpcap('output.pcap',modified_packets)
