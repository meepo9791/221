import numpy as np
import matplotlib.pyplot as plt

# 数据
y_values1 = [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.1]
y_values2 = [0.0003, 0.0007, 0.002, 0.006, 0.015, 0.03, 0.12]
y_values3 = [0.0005, 0.001, 0.003, 0.008, 0.02, 0.035, 0.15]

x_values = np.linspace(0, 1, len(y_values1))
x_labels = ['0.1%', '0.2%', '0.5%', '1%', '2%', '5%', '10%']

# 创建折线图
fig, ax = plt.subplots()
ax.plot(x_values, y_values1, marker='o', linestyle='-', linewidth=2, label='test1')
ax.plot(x_values, y_values2, marker='s', linestyle='-', linewidth=2, label='test2')
ax.plot(x_values, y_values3, marker='^', linestyle='-', linewidth=2, label='test3')

# 设置轴标签
ax.set_xlabel('X-axis')
ax.set_ylabel('Y-axis')

# 设置对数刻度
yticks = [0.0001,0.001, 0.01, 0.1, 1]
ax.set_yscale('log')
ax.set_yticks(yticks)

# 设置 X 轴固定刻度
ax.set_xticks(x_values)
ax.set_xticklabels(x_labels)

# 设置图例
ax.legend()
# 设置标题
ax.set_title('Log-Scale Line Chart with Uniformly Distributed X-axis Ticks')

# 显示图形
plt.savefig('误码率自身方案比较折线图.png',dpi=300)
