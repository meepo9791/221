import matplotlib.pyplot as plt
import numpy as np

# 示例数据
categories = ['A', 'B', 'C', 'D', 'E']
values = [0.002, 0.015, 0.05, 0.2, 1]

# 创建一个figure和axes对象
fig, ax = plt.subplots()

# 绘制柱状图
ax.bar(categories, values)

# 设置y轴的刻度和标签
yticks = [0.0001,0.001, 0.01, 0.1, 1]
ax.set_yscale('log')
ax.set_yticks(yticks)


# 设置x轴的标签
ax.set_xlabel('Categories')

# 设置y轴的标签
ax.set_ylabel('Values (log scale)')

# 设置图表的标题
ax.set_title('Bar Chart with Log Scale Y-axis')

# 显示图表
plt.tight_layout()
plt.savefig('误码率横向柱状图.png',dpi=300)
