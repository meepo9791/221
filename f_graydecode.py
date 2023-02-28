def decimal_to_gray(n):
    """
    将十进制数转换为格雷码
    :param n: 输入的十进制数，int类型
    :return: 格雷码，str类型
    """
    return bin(n ^ (n >> 1))[2:]  # 假设格雷码的位数为8位



def gray_to_decimal(n):
    """
    将格雷码转换为十进制数
    :param n: 输入的格雷码，str类型
    :return: 十进制数，int类型
    """
    binary = ''
    for i in range(len(n)):
        binary += str(int(n[i]) ^ int(binary[i-1]) if i > 0 else int(n[i]))
    return int(binary, 2)
a=decimal_to_gray(76)
print(a)
b=gray_to_decimal(a)
print(b)