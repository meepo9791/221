from scipy.stats import ks_2samp
import numpy as np
from scipy.stats import entropy
import pyshark
from scipy.stats import ttest_ind
from scipy.stats import mannwhitneyu



def rdipd(pcapname):
    array = []
    capture = pyshark.FileCapture(pcapname, display_filter='udp', decode_as={'udp.port==65366': 'rtp'})
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
                    # print(interval_count % 2)
                    # 判断间隔数据包数量的奇偶性
                    array.append(interval_count)
                    m_bit_count = 1
                    interval_count = 0
        else:
            # 如果 m 位不为 1，则间隔数据包数量加 1
            if m_start == 1:
                interval_count += 1
    # print(time_intervals)
    return array

def rdipd2(pcapname):
    array = []
    capture = pyshark.FileCapture(pcapname, display_filter='udp', decode_as={'udp.port==65362': 'rtp'})
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
                    # print(interval_count % 2)
                    # 判断间隔数据包数量的奇偶性
                    array.append(interval_count)
                    m_bit_count = 1
                    interval_count = 0
        else:
            # 如果 m 位不为 1，则间隔数据包数量加 1
            if m_start == 1:
                interval_count += 1
    # print(time_intervals)
    return array
# p1:test and modified_test  p2 test and blvmodified_test  p3 test blnmodified_test
def welch_ttest(x, y):
    t, p = ttest_ind(x, y, equal_var=False)
    return t, p


def mann_whitney_rank_test(x, y):
    U, p = mannwhitneyu(x, y, alternative='two-sided')
    return U, p

p = rdipd2("0302test.pcap")

q = rdipd('test.pcap')
print(welch_ttest(p,q))
print(mann_whitney_rank_test(p,q))
print(ks_2samp(p, q))
print(entropy(p))
print(entropy(q))

if len(p) < len(q):
    p += [0] * (len(q) - len(p))
else:
    q += [0] * (len(p) - len(q))
print(p)
print(q)
#p = np.asarray(p, dtype=np.float64)
#q = np.asarray(q, dtype=np.float64)
print(entropy(p, q))

