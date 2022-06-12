def generate(rlen):
	letters = string.ascii_letters
	return ''.join(random.choice(letters) for i in range(int(rlen)))

def offset(hex, pattern):
	hexed = hex
	ascii = bytearray.fromhex(hexed).decode()[::-1]
	loc = pattern.find(ascii)
	return loc


import random
import sys
import string

print("""
######                                                             #     # ####### ### #       
#     # #####   ####  ###### ######  ####   ####   ####  #####     #     # #        #  #       
#     # #    # #    # #      #      #      #      #    # #    #    #     # #        #  #       
######  #    # #    # #####  #####   ####   ####  #    # #    #    #     # #####    #  #       
#       #####  #    # #      #           #      # #    # #####      #   #  #        #  #       
#       #   #  #    # #      #      #    # #    # #    # #   #       # #   #        #  #       
#       #    #  ####  #      ######  ####   ####   ####  #    #       #    ####### ### ####### 
""")
print()
print()

choice = input("Pattern or Static Character? P/S: ")
if choice == "S":
	iteration = int(input("Enter number of times you need to print A: "))
	print(str('A' * int(iteration)))

elif choice == "P":

	length = int(input("Enter Length of pattern: "))
	pattern = str(generate(length))
	print(pattern)
	print()
	
	while True:
		try:
			f_offset = input("Enter overwritten IP value in hex: ")
			print(f_offset)
			print (offset(f_offset, pattern))
			break
		except:
			print("Try Again! ")
			continue

	
