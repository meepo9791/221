import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# 给定数据点（丢包率，乱序率，误码率）
data_points = [
    (0.1, 0.05, 0.01),
    (0.2, 0.1, 0.03),
    (0.3, 0.15, 0.08),
    (0.4, 0.2, 0.15),
    (0.5, 0.25, 0.23)
]

# 将数据点拆分为独立的数组
packet_loss = np.array([point[0] for point in data_points])
out_of_order = np.array([point[1] for point in data_points])
error = np.array([point[2] for point in data_points])

# 创建三维图形
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 绘制折线图
ax.plot(packet_loss, out_of_order, error, marker='o', linestyle='-', linewidth=2)

# 设置轴标签
ax.set_xlabel('Packet Loss Rate')
ax.set_ylabel('Out-of-Order Rate')
ax.set_zlabel('Bit Error Rate')

# 设置标题
ax.set_title('3D Line Plot of Error Rate with Given Packet Loss and Out-of-Order Rate Data')

# 显示图形
plt.savefig('3d_line_plot.png', dpi=300, bbox_inches='tight')
