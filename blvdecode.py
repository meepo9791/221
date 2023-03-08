import pyshark
from scapy.utils import wrpcap
from scapy.all import Raw
from pyshark.capture.file_capture import FileCapture
from blvencode import blenghlist,secarray

new_list = []
array = []
list2 = blenghlist
# 使用 pyshark 读取 pcap 文件
capture = pyshark.FileCapture("blv_mod.pcap", display_filter='udp', decode_as={'udp.port==65366': 'rtp'}, tshark_path='D:\wireshark\\tshark.exe')
# 初始化 m 位为 1 的数据包数量
m_bit_count = 0
m_start = 0
m_count = 0
cap = 0
# 初始化间隔数据包数量
interval_count = 0
def adjust_str_length(s, length):
    if len(s) > length:
        s = s[-length:]  # 截取右边指定长度的部分
    elif len(s) < length:
        s = '0' * (length - len(s)) + s  # 左边补0，使字符串达到指定长度
    return s

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
                interval_count = 0
            if m_bit_count == 3:
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
        #为了防止噪声导致的错位，控制码长，舍弃多余码长列表的高位格雷码,或补充
        binary_list.append(adjust_str_length(binary_str,length))

    return binary_list

# 输出结果数组
#wrpcap("output.pcap", modified_packets)



binary_list = dec_to_bin_list(array, list2)
print(binary_list)
new_list = [item for sublist in binary_list for item in sublist]


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
print('secret message  send is:   ', secarray)
print('secret message  recived is:', int_list)
print('bit error rate is:',compare_lists(int_list, secarray))
# 计算考虑了乱序率和丢包率后的误码率
for ca in blenghlist:
    cap += ca
print('CTC capacity is:', round(30*(cap/len(blenghlist))))
