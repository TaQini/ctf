# // int __cdecl swap(const char *buf)
# // {
# // int i; // rax
# // int j;
# // char chr; // al

# // i = 0;
# // if ( strlen(buf) != 0 )
# // {
# // do
# // {
# // chr = buf[i];
# // if ( chr < 97 || chr > 122 )
# // {
# // if ( chr < 65 || chr > 90 )
# // goto LABEL_9;
# // j = chr + 0x20;
# // }
# // else
# // {
# // j = chr - 0x20;
# // }
# // buf[i] = j;
# // LABEL_9:
# // ++i;
# // }
# // while ( i < strlen(buf) );
# // }
# // return i;
# // }

def swap(buf):
	tep = ''
	for i in s:
		c = ord(i)
		if c < 97 or c > 122:
			if c < 65 or c > 90:
				tmp += i
				continue
			tmp += chr(c+0x20)
		else:
			tmp += chr(c-0x20)
	return tmp