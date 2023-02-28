import pyshark


def getsecret(pcapname):
    capture = pyshark.FileCapture(pcapname, display_filter='udp', decode_as={'udp.port==65362': 'rtp'},
                                  tshark_path='D:\wireshark\\tshark.exe')
    array = []
    m_bit_count = 0
    m_start = 0
    m_count = 0
    interval_count = 0
    for packet in capture:
        rtp_packet = packet.rtp
        m_bit = rtp_packet.marker
        if m_bit == '1':
            m_start = 1
            if m_start == 1:
                m_bit_count += 1
                if m_bit_count == 2:
                    m_count += 1
                    array.append(interval_count % 2)
                    m_bit_count = 1
                    interval_count = 0
        else:
            if m_start == 1:
                interval_count += 1
    return array


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


s1 = getsecret("modified_test.pcap")
s2 = getsecret("new_test.pcap")
print('secret message is:', s1)
print('secret message is:', s2)
print(compare_lists(s1, s2))
# 计算考虑了乱序率和丢包率后的误码率
