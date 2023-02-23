array =[1,0,0,0,1,1]
sub_lst=array[0:3]
binary_str = ''.join(str(i) for i in sub_lst)
print(int(binary_str, 2))