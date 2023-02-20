import matplotlib as mpl
# mpl.use("TkAgg") # Use TKAgg to show figures
import matplotlib.pyplot as plt

x_data = [1,2,3,4,5,6]
y_data = [0.1,0.2,0.3,0.4,0.5,0.6]

fig2 = plt.figure(figsize=(7, 5))
plt.plot(x_data, y_data, c='g')  # 1.过点画线

# plt.plot(x_data1,y_data1)
# 一个图中要画出多条线的时候，只需要再使用plt.plot画出另一条线即可

plt.scatter(x_data, y_data)  # 2.画点

plt.title('X-Y Test')  # 3. 图标题
plt.xlabel("X")  # 4. X轴名字
plt.ylabel("Y")  # 5. Y轴名字

plt.savefig("test.png")
