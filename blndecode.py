import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
from blnencode import new_array, bits

array = []

se_array = []
i = 0
# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("blnmodified_test.pcap", display_filter='udp', decode_as={'udp.port==65366': 'rtp'},
                              tshark_path='D:\wireshark\\tshark.exe')
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

# 输出结果数组
# wrpcap("output.pcap", modified_packets)
print('interval count is:', array)
for decimal in array:
    if i < (len(new_array) / bits):
        binary_str = bin(decimal ^ (decimal >> 1))[2:]  # 将十进制数字转换为二进制字符串，使其达到指定的二进制位数
        if len(binary_str) <= bits:
            binary_str = binary_str.zfill(bits)  # 补齐0
        else:
            binary_str = binary_str[-bits:]  # 如果因丢包乱序造成实际转码后位数变多则裁去高位
        binary_list = [int(bit) for bit in binary_str]  # 将二进制字符串中的每一位字符转换为整型，并将转换后的整型添加到列表中
        for bit in binary_list:
            se_array.append(bit)
    i += 1

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


#int_list = [int(x) for x in new_list]
print('secret message  send is:   ', new_array)
print('secret message  recived is:', se_array)
print('bit error rate is:',compare_lists(new_array, se_array))
# 计算考虑了乱序率和丢包率后的误码率

print('CTC capacity is:', 30*bits)