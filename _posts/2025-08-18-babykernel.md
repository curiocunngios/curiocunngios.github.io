# Starting

This is the first time I am doing a kernel challenge that does not belong to pwn.college

Installing `zstd` and running `kali@pwncollege:~/Desktop/CTF/uiuc$ tar --zstd -xf handout.tar.zst`
Now I have got these files:
```
kali@pwncollege:~/Desktop/CTF/uiuc$ ls
handout  handout.tar.zst
kali@pwncollege:~/Desktop/CTF/uiuc$ cd handout/
kali@pwncollege:~/Desktop/CTF/uiuc/handout$ ls
bzImage  initrd.cpio.gz  run.sh  vuln.c  vuln.ko
```

here is `run.sh`:
```
#! /bin/sh

# Note: -serial mon:stdio is here for convenience purposes.
# Remotely the chal is run with -serial stdio.

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial mon:stdio \
  -display none \
  -monitor none \
  -vga none \
  -kernel bzImage \
  -initrd initrd.cpio.gz \
  -append "console=ttyS0" \
```

I am not sure what to do with `initrd.cpio.gz` tho, never seen this file before. I have usually just seens `vmlinux` (and I just do `gdb vmlinux` and `target remote :1234` to debug the entire kernel)

By asking gpt some questions. Turned out to start a kernel challenge, we need to:
1. Extract the filesystem from `initrd.cpio.gz`
2. Extract `vmlinux` from `bzImage`
3. Building solve scripts and moving it to the filesystem and rebuilding it with commands like:
`find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../new_initrd.cpio.gz`

# Babykernel writeup 
The vulnerability in the kernel module (vuln.ko) is UAF (Use After Free)
```
        case FREE: {
            if (!buf) {
                return -EFAULT;
            }
            kfree(buf);
            break;
        }
```
which means when a buffer is freed (deleted), we still have access to it. For example, there might be some memory addresses on the freed object, and since we still have access to the freed object, we might be able to print the addresses.

The main goal of kernel challenges is to gain root privileges and print the flag

## Simple explanation
And the following is what I did:

- allocate a buffer
- free it
- print a useful memory address
- allocate pipe_buffer (a kernel object that contains another kernel address)
- print another useful memory address
- Use the second leaked address to calculate kernel base address
- Once kernel base address is obtained, we have access to JOP/ROP gadgets (basically an instruction ended with `ret` so that we can chain the instructions to achieve something)
- Use a ROP chain to perform `commit_creds(&init_cred)` (basically calling `commit_creds` with the address of `init_cred` as `rdi` so that we get root.
- There is a function pointer on pipe_buffer that gets triggered when we close the pipe. We first overwrite that function pointer with our staring point of our ROP chain, which is a JOP (jump oriented programming) gadget. And then we close the pipe to trigger the ROP chain.
- Root gained!


# Detailed explanation

- allocate a buffer
- free it
- print a useful memory address, let's call this address `A` 
- allocate pipe_buffer (a kernel object that contains another kernel address)
- print another useful memory address, let's call this address `B`
- Use the second leaked address to calculate kernel base address
- Once kernel base address is obtained, we have access to JOP/ROP gadgets (basically an instruction ended with `ret` so that we can chain the instructions to achieve something)
- Use a ROP chain to perform `commit_creds(&init_cred)` (basically calling `commit_creds` with the address of `init_cred` as `rdi` so that we get root.
- There is a function pointer on pipe_buffer that gets triggered when we close the pipe. We first overwrite that function pointer with our staring point of our ROP chain, which is a JOP (jump oriented programming) gadget. And then we close the pipe to trigger the ROP chain.
- Root gained!

## How is address `A` used?

Still remember that we need to overwrite pipe_buffer function pointer to trigger ROP chain?

More specifcally, the execution flow of pipe_buffer when we closed the pipe is like the following:
```
jump to *(pipe_buffer+0x10) + 0x108
```
what if we make it `pipe_buffer+0x10` point to the starting pointer of our buffer:
```
jump to our_buffer + 0x108
```

AND!!! address `A` is contiguous in memory with the address of our buffer (where to write data to), which means I can obtain the my buffer address, so when I overwrite `pipe_buffer+0x10` with that and make `our_buffer+0x108`. It will execute `our_buffer+0x108`!!! Therefore we can hijack the control flow. 

## hijacking control flow

So after we have overwritten `pipe_buffer+0x10` to be the starting point of the buffer to write to, when we close the pipe_buffer, it will execute `our_buffer+0x108`, only once. 

So we need to chain instructions there with a bunch of gadgets.

I am not sure whether SMAP/SMEP were enabled or not so I did it the safe way, also the hard way, which is by using a jump gadget to stack pivot:

Since I have noticed that at the pointer we reached `our_buffer+0x108`, `rsi` is exactly  `our_buffer+0x0`. Therefore, we could stack pivot by:
```
Buffer offset

0x00	: add rsp, 0x48 ; ret
...
0x44	: pop rsp ; ret

...

0x50	: <standard krop chain>

0x108	: push rsi; jmp qword ptr [rsi + 0x44]

```
Execution flow:
```
push rsi; jmp qword ptr [rsi + 0x44] ---> pop rsp ; ret ---> add rsp, 0x48 ; ret --> <standard rop chain>

```
Explanation of the above gadgets
```
push rsi; jmp qword ptr [rsi + 0x44] 

# after this, rsi (our_buffer+0x0) would be on the stack and we jump to rsi+0x44, so we need to place something at offset 0x44

pop rsp ; ret 

# now since what's on top of the stack (rsp) is rsi (our_buffer), pop_rsp pops that into `rsp`, so the stack immediately switches to rsi, we have then pivoted the stack

add rsp, 0x48 ; ret 

# further move the stack downwards by 0x48 bytes to skip the gadget at 0x44, because we are writing to the same payload, we don't want <standard krop chain> to overwrite that
```
 In short, the ROP chain starts with a jump gadget ( gadgets that ends with `jmp` instruction. In most cases, I guess, is `jmp qword ptr [<REGISTER> + <OFFSET>]` with `<REGISTER>` being something we have control of)
 
 it starts with a jump gadget that first do a small setup (push rsi) for stack pivot, and then jump to a ROP gadget that stack pivots immediately to get on `<standard krop chain>`
 
`<standard krop chain>`  being:
```
    u64 *rop = (u64 *)(rop_payload + 0x48 + 8); // offset of standard krop chain as 0x50
    
    *rop++ = pop_rdi;               // pop rdi; ret
    *rop++ = init_cred;             // init_cred address  
    *rop++ = commit_creds;          // commit_creds(&init_cred)
    *rop++ = kernel_base + SWAPGS;  // return to userspace to pop a shell!
    *rop++ = kernel_base + IRETQ;
    
    *rop++ = (u64)get_shell;        // user rip
    *rop++ = user_cs;               // user cs
    *rop++ = user_rflags;           // user rflags
    *rop++ = user_sp;               // user rsp
    *rop++ = user_ss;               // user ss
```

For those who are new to rop and feeling confused, they are gadgets that ends with `ret`, which makes `rip` the instruction pointer to point to the next item on the stack. So for example:
``` 
    *rop++ = pop_rdi;              // ends with a ret!
    *rop++ = init_cred;             
    *rop++ = commit_creds; 
```

`pop rdi ; ret` first pop the top item, in this case, `init_cred` into `rdi`, and then `ret` would make `rip` point to `commit_creds` and then execute it! So that's doing: `commit_creds(&init_cred)` which would get us root privilege

# How is address `B` used

address `B` is the original pointer on `pipe_buffer+0x10`, which looks like something like this:
```
0xffffffffae41ec40
```
and we can use this to calculate the kernel base address to get a bunch of ROP gadgets

