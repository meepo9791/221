import numpy as np
import matplotlib as mpl
# mpl.use("TkAgg") # Use TKAgg to show figures
import matplotlib.pyplot as plt

# A B C 可理解三个地方 每个地点有 类别1 2 3的数据

X_label = ["A", "B", "C"]  # 1.X轴上的各种选择
Value_1 = [1, 4, 7]  # 2.类别1 对应的A B C的值
Value_2 = [2, 5, 8]  # 3.类别2 对应的A B C的值
Value_3 = [3, 6, 9]  # 4.类别3 对应的A B C的值

# 创建分组柱状图，需要自己控制x轴坐标
xticks = np.arange(len(X_label))

fig, ax = plt.subplots(figsize=(10, 7))
# A B C 中x的数量
ax.bar(xticks, Value_1, width=0.15, label="1")  # 5.width是柱子的宽度

ax.bar(xticks + 0.22, Value_2, width=0.15, label="2")  # 6.0.22 是调整两个柱之间的距离

ax.bar(xticks + 0.44, Value_3, width=0.15, label="3")

plt.legend(['1', '2', '3'])  # 7.图例
# 最后调整x轴标签的位置
ax.set_xticks(xticks + 0.25)
ax.set_xticklabels(X_label)

plt.title('X-Y Test')  # 8. 图标题
plt.xlabel("X")  # 9. X轴名字
plt.ylabel("Y")  # 10. Y轴名字

plt.savefig("test2.png")

