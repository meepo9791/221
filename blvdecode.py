import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
array = []
new_array = []
list2=[3, 2, 2, 2]
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
def convert_to_binary_list(nums, x):
    result = []
    for num in nums:
        binary = bin(num)[2:]
        if len(binary) < x:
            binary = '0' * (x - len(binary)) + binary
        result.append(list(binary))
    return result
# 输出结果数组
#wrpcap("output.pcap", modified_packets)
print('interval count is:',array)

for x in list2:
    binary_list = convert_to_binary_list(array, x)

    #print(binary_list)

print('secret message is:',binary_list)
#wrpcap('output.pcap',modified_packets)
