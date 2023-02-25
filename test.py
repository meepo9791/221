def dec_to_bin_list(decimal_list, length_list):
    """
    Convert decimal numbers in decimal_list to binary numbers with lengths defined by corresponding elements in
    length_list. Stop when length_list is exhausted.

    Args:
        decimal_list (list): A list of decimal numbers.
        length_list (list): A list of integer values representing the length of the binary numbers to convert to.

    Returns:
        A list of binary numbers as strings.
    """
    binary_list = []
    for i, length in enumerate(length_list):
        if i >= len(decimal_list):
            break
        binary_str = format(decimal_list[i], 'b')
        binary_list.append(binary_str.zfill(length))
    return binary_list

array = [6, 1, 2, 1]
list2 = [3,2,3,1]

binary_list = dec_to_bin_list(array, list2)
print(binary_list)