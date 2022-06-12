# Tunnels
Notice how we can represent this problem using numbers. For each of the middle 6 numbers, the value of it can be split between the 2 values next to it on the next round, but for the edges, all of it goes to the one next to it, because it has 1 neighbor. Let's write some code to simulate the problem:
```python
start = [1, 1, 1, 1, 1, 1, 1, 1]
nex = [1, 1, 1, 1, 1, 1, 1, 1]
a = [1, 1, 2, 3, 4, 5, 6, 6]
for j in range(8):
  start[a[j]] = 0
  sum = 0
  for i in range(8):
    if i == 0:
      nex[0] = start[1]/2
    elif i == 7:
      nex[7] = start[6]/2
    elif i == 1:
      nex[1] = start[0] + start[2]/2
    elif i == 6:
      nex[6] = start[7] + start[5]/2
    else:
      nex[i] = start[i-1]/2 + start[i+1]/2
    sum += nex[i]
  print(nex)
  print(sum)
  for i in range(8):
      start[i] = nex[i]
print(200*(1-(sum/8)))
```

Cool! Now that we have code to simulate it, and is pretty fast, let's bash all possible meaningful inputs (half of the inputs are equivalent). This gives us 4*8^7 possibilities to bash.
```python
start = [1, 1, 1, 1, 1, 1, 1, 1]
nex = [1, 1, 1, 1, 1, 1, 1, 1]
old = 0
for i in range(4):
    for j in range(8):
        for k in range(8):
            for l in range(8):
                for m in range(8):
                    for n in range(8):
                        for o in range(8):
                            for p in range(8):
                                start = [1, 1, 1, 1, 1, 1, 1, 1]
                                nex = [1, 1, 1, 1, 1, 1, 1, 1]
                                a = [i, j, k, l, m, n, o, p]
                                for q in range(8):
                                  start[a[q]] = 0
                                  sum = 0
                                  for r in range(8):
                                    if r == 0:
                                      nex[0] = start[1]/2
                                    elif r == 7:
                                      nex[7] = start[6]/2
                                    elif r == 1:
                                      nex[1] = start[0] + start[2]/2
                                    elif r == 6:
                                      nex[6] = start[7] + start[5]/2
                                    else:
                                      nex[r] = start[r-1]/2 + start[r+1]/2
                                    sum += nex[r]
                                  for s in range(8):
                                      start[s] = nex[s]
                                c = (200*(1-(sum/8)))
                                if c > old:
                                    print(a)
                                    print(c)
                                    old = c
                                c = 0
```


After a few minutes, the program spits out [3, 6, 1, 4, 4, 1, 6, 3], with an average value of 179.6875. This appears to be the optimal solution. 

Plugging it into some pwntools code, we can wait for the ~2.5% chance that we will succeed.

```python
from pwn import *

io = remote("tunnels.hsctf.com", 1337)
io.recvline()
success = 0
guesses = input() # input guess sequence e.g. "12345678"
for j in range(200):
    io.recvline()
    print("TRIAL: %d" % j)
    for i in range(8):
        io.sendline(guesses[i].encode())
        r = io.recvline()
        if b"incorrect" not in r:
            success += 1
            break

print("success rate: " + str(success/200))
print(io.recv())
```

After a few minutes of running this in a loop, we find the flag in the console: `flag{b4om1k3_15_4_v3ry_1nt3r35t1ng_p3r50n_924972020}`


# hacking
This seems like a typical algorithm problem, where you come up with an efficient algorithm to solve a problem. Let's think about the problem statement. Thinking for a bit, we realize that anything that points to something else in a loop would fail and increment our counter, while anything before the said loop is safe and doesn't increment the counter.

How do we find these loops though? We can iterate through every element in the array we're given, and follow where it points to. If it points to something already in our path, we can identify a loop, and anything before that isn't a loop. Additionally, when iterating through, every time you hit something you've already counted towards something, you can stop and add everything before that to the safe category.

Let's write some code for this:

```python
from pwn import *
import gmpy2

io = remote("hacking.hsctf.com", 1337)
io.readuntil(b"with:\n")
pow = io.readline().strip().decode()

solve = process(["python3", "solver.py", *list(pow[46:].split(' '))])
solve.readuntil(b"Solution: \n")
a = solve.read().strip().decode()
io.send(a + '\n')
print(a)
print("pow done")
sols = [0, 0, 0, 0, 0]

print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())

for k in range(5):
    print("trial: "+str(k+1))
    asdf = io.recvline().strip().decode()
    a = list(map(int, asdf.split(",")))
    length = len(a)
    deadalive = []
    for i in range(length):
        deadalive.append(-1)
    dead = []
    alive = []
    for i in range(len(a)):
        x = i
        visited = [i+1]
        if a[x] == i+1:
            deadalive[i] = 1
        elif deadalive[i] != 0 and deadalive[i] != 1:
            while a[x] not in visited and deadalive[a[x] - 1] == -1:
                visited.append(a[x])
                x = a[x] - 1
            if deadalive[a[x] - 1] != -1:
              y = len(visited)
            else:
              y = visited.index(a[x])
            for l in visited[y:len(visited)]:
                deadalive[l - 1] = 1
            for l in visited[0:y]:
                deadalive[l - 1] = 0
    for i in range(length):
        sols[k] += deadalive[i]
st = ""
for i in range(4):
    st += str(sols[i])
    st += ", "
asdff = st + str(sols[4])
io.send(asdff)
print(io.recv())
```

However, for some reason, our code doesn't work. Can you spot the error?

Of course! The output should have a newline after it (wtf why does this matter???). Fixing this error, we see that the flag is `flag{cOnGrAtS_yOu_ArE_nOw_A_hAcKeR}`


# hacking part 2

This one is more interesting. It seems like a minimal spanning tree problem this time. Because I don't know how to write code, I found an MST algorithm online. Let's implement it for the problem. The only difference between the algorithm and the problem is that an edge can have multiple values. Therefore, we need to take the minimum of it. Additionally, we have to account for input, and parse that correctly.

```python

from pwn import *
import gmpy2

io = remote("hacking-pt2.hsctf.com", 1337)
print(io.recvline())
class Graph:
    def __init__(self, num_of_nodes):
        self.m_num_of_nodes = num_of_nodes
        # Initialize the adjacency matrix with zeros
        self.m_graph = [[0 for column in range(num_of_nodes)] 
                    for row in range(num_of_nodes)]

    def add_edge(self, node1, node2, weight):
        if self.m_graph[node1][node2] == 0:
            self.m_graph[node1][node2] = weight
            self.m_graph[node2][node1] = weight
        elif self.m_graph[node1][node2] > weight or self.m_graph[node2][node1] > weight:
            self.m_graph[node1][node2] = weight
            self.m_graph[node2][node1] = weight
    def prims_mst(self):
        # Defining a really big number, that'll always be the highest weight in comparisons
        postitive_inf = float('inf')
    
        # This is a list showing which nodes are already selected 
        # so we don't pick the same node twice and we can actually know when stop looking
        selected_nodes = [False for node in range(self.m_num_of_nodes)]
    
        # Matrix of the resulting MST
        result = [[0 for column in range(self.m_num_of_nodes)] 
                    for row in range(self.m_num_of_nodes)]
        
        indx = 0
        for i in range(self.m_num_of_nodes):
            print(self.m_graph[i])
        
        print(selected_nodes)
    
        # While there are nodes that are not included in the MST, keep looking:
        while(False in selected_nodes):
            # We use the big number we created before as the possible minimum weight
            minimum = postitive_inf
    
            # The starting node
            start = 0
    
            # The ending node
            end = 0
    
            for i in range(self.m_num_of_nodes):
                # If the node is part of the MST, look its relationships
                if selected_nodes[i]:
                    for j in range(self.m_num_of_nodes):
                        # If the analyzed node have a path to the ending node AND its not included in the MST (to avoid cycles)
                        if (not selected_nodes[j] and self.m_graph[i][j]>0):  
                            # If the weight path analized is less than the minimum of the MST
                            if self.m_graph[i][j] < minimum:
                                # Defines the new minimum weight, the starting vertex and the ending vertex
                                minimum = self.m_graph[i][j]
                                start, end = i, j
            
            # Since we added the ending vertex to the MST, it's already selected:
            selected_nodes[end] = True
    
            # Filling the MST Adjacency Matrix fields:
            result[start][end] = minimum
            
            if minimum == postitive_inf:
                result[start][end] = 0
    
            print("(%d.) %d - %d: %d" % (indx, start, end, result[start][end]))
            indx += 1
            
            result[end][start] = result[start][end]
    
        # Print the resulting MST
        # for node1, node2, weight in result:
        totaltotal = 0
        for i in range(len(result)):
            for j in range(0+i, len(result)):
                if result[i][j] != 0:
                    totaltotal += result[i][j]
        print(totaltotal)
        return totaltotal
for k in range(5):
    print(io.recvline())
    asdf = io.recvline().strip().decode()
    a = int(asdf)
    print(a)
    asdfi = Graph(a)
    for i in range(a):
        asdf = io.recvline().strip('\n'.encode()).decode()
        print(asdf)
        b = list(map(str, asdf.split(" ")))
        for j in range(len(b) - 1):
            c, d = map(int, b[j].split(","))
            c -= 1
            asdfi.add_edge(i, c, d)
    asdff = asdfi.prims_mst()
    asdff += str(asdff) + "\n"
    io.send(asdff.encode())
    print(io.recvline())
    print(io.recvline())
    print(io.recvline())
    print(io.recvline())
print(io.recv())
```
Running this, we get the flag: `flag{eLjMiKe_Is_PrOuD_oF_yOu}`

