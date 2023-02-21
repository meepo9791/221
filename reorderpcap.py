from scapy.all import *
import random

def packet_reorder(lst, reorder_rate):
    # 乱序函数
        """
        按照给定的乱序率对列表进行重新排序
        """
        if reorder_rate <= 0:
            return lst
        elif reorder_rate >= 1:
            return random.sample(lst, len(lst))

        # 计算需要乱序的元素个数
        num_reorder = int(len(lst) * reorder_rate)

        # 随机选择需要乱序的元素的下标
        reorder_indices = random.sample(range(len(lst)), num_reorder)

        # 对选择的元素进行乱序操作
        reorder_values = [lst[i] for i in reorder_indices]
        random.shuffle(reorder_values)

        # 将乱序后的元素放回原来的位置
        new_lst = list(lst)
        for i, j in zip(reorder_indices, reorder_values):
            new_lst[i] = j

        return new_lst

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

# 读取 pcap 文件
packets = rdpcap('modified_test.pcap')
# 设置丢包率和乱序率

packet_reorder_rate = 0.05
#对每个包增加丢包率
# 对所有包增加乱序率
packets = packet_reorder(packets, packet_reorder_rate)
packets = list(filter(lambda p: p is not None, packets))
# 发送所有包
wrpcap('new_test.pcap', packets)

packets1=rdpcap('modified_test.pcap')
packets2=rdpcap('new_test.pcap')
print(compare_lists(packets1,packets2))



