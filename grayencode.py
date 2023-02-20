def binary_to_gray_op(n):
    n = int(n, 2)

    n ^= (n >> 1)

    return bin(n)[2:]


gray_val = input('Enter the binary number: ')

binary_val = binary_to_gray_op(gray_val)

print('Gray codeword is :', binary_val)

