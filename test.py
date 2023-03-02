from scipy.stats import entropy
from scipy.stats import ks_2samp

list1 = [6, 2, 1, 9,200]
list2 = [0.15, 0.25, 0.3, 0.3, 0.1]

# 使用相对熵计算两个列表的距离
distance = entropy(list1, list2)
print(ks_2samp(list1, list2))
print("距离:", distance)
