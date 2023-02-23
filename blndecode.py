import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
array = []
new_array = []

# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("blnmodified_test.pcap", display_filter='udp', decode_as={'udp.port==65362': 'rtp'}, tshark_path='D:\wireshark\\tshark.exe')
# 初始化 m 位为 1 的数据包数量

bits = int(input("请输入秘密信息位数: "))
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
#wrpcap("output.pcap", modified_packets)
print('interval count is:',array)
for decimal in array:
    binary_str = bin(decimal)[2:].zfill(bits)  # 将十进制数字转换为二进制字符串，并在前面补齐0，使其达到指定的二进制位数
    binary_list = [int(bit) for bit in binary_str]  # 将二进制字符串中的每一位字符转换为整型，并将转换后的整型添加到列表中
    #print(binary_list)  # 输出结果：[0, 0, 0, 0, 1, 0, 1, 0]

    #print(binary_list)
    for bit in binary_list:
        new_array.append(bit)
print('secret message is:',new_array)
#wrpcap('output.pcap',modified_packets)
