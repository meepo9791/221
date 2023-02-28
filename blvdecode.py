import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
from blvencode import blenghlist,secarray

new_list = []
array = []
list2 = blenghlist
# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("blv_mod.pcap", display_filter='udp', decode_as={'udp.port==65362': 'rtp'}, tshark_path='D:\wireshark\\tshark.exe')
# 初始化 m 位为 1 的数据包数量
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

    binary_list = []
    for i, length in enumerate(length_list):
        if i >= len(decimal_list):
            break
        binary_str = bin(decimal_list[i] ^ (decimal_list[i] >> 1))[2:]
        binary_list.append(binary_str.zfill(length))
    return binary_list

# 输出结果数组
#wrpcap("output.pcap", modified_packets)



binary_list = dec_to_bin_list(array, list2)
new_list = [item for sublist in binary_list for item in sublist]

print('secret message is:',new_list)
#wrpcap('output.pcap',modified_packets)



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


int_list = [int(x) for x in new_list]
print('bit error rate is:',compare_lists(int_list, secarray))
# 计算考虑了乱序率和丢包率后的误码率