import sys, math, json, collections, itertools, re, random, heapq, bisect, functools, datetime, io, threading, time
# compute
tot=sum(i*i for i in range(100000))
d=collections.Counter("the quick brown fox"*50)
m=math.sqrt(tot); j=json.dumps({"a":[1,2,3],"m":m})
# regex + data structures
assert re.findall(r"\w+","a b c")==["a","b","c"]
h=[]; [heapq.heappush(h,random.random()) for _ in range(1000)]
# threads (legit concurrency)
out=[]
def work(n): out.append(sum(range(n)))
ts=[threading.Thread(target=work,args=(10000,)) for _ in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
# read own source, write stdout
src=open(__file__).read()
print("ok", len(src), d["o"], len(j), len(out))
