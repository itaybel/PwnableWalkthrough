## Sudoku - Level 8

We need to solve 100 soduko boards with a twist.

I grabbed the first sudoku solver online, and added the new rules.
This is the code I have created:

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
            break
        new_p = [int(p[1]), int(p[3])]
        points.append(new_p)

    Suduko(grid, 0, 0, smaller, comp, points)  # solving sudoku

    server.sendline(str(grid))

recvAll(server)
```
