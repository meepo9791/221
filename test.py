decimal = 10  # 十进制数字
bits = 8  # 指定的二进制位数
binary_str = bin(decimal)[2:].zfill(bits)  # 将十进制数字转换为二进制字符串，并在前面补齐0，使其达到指定的二进制位数
binary_list = [int(bit) for bit in binary_str]  # 将二进制字符串中的每一位字符转换为整型，并将转换后的整型添加到列表中
print(binary_list)  # 输出结果：[0, 0, 0, 0, 1, 0, 1, 0]
