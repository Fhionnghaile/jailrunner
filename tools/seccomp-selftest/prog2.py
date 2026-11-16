import os,sys,time,subprocess,tempfile,decimal,fractions,statistics,hashlib,base64,struct,array,gzip,bz2,lzma,sqlite3,pickle,csv,io,datetime,uuid,secrets,string,textwrap,unicodedata
# tmpfs write+read (allowed /tmp)
p=tempfile.mkdtemp()
fn=os.path.join(p,"x.bin")
open(fn,"wb").write(os.urandom(4096)); d=open(fn,"rb").read(); assert len(d)==4096
# sqlite in-memory (uses mmap/futex/fcntl)
c=sqlite3.connect(":memory:"); c.execute("create table t(x)"); c.executemany("insert into t values(?)",[(i,) for i in range(1000)]); assert c.execute("select count(*) from t").fetchone()[0]==1000
# compression round-trips
raw=b"derry"*10000
for mod in (gzip,bz2,lzma): assert mod.decompress(mod.compress(raw))==raw
# crypto hashing, time
h=hashlib.sha256(raw).hexdigest(); time.sleep(0.05)
# subprocess (stays caged under inherited seccomp); echo via /bin/echo if present else skip
try:
    out=subprocess.run([sys.executable,"-c","print(6*7)"],capture_output=True,text=True,timeout=5)
    sp=out.stdout.strip()
except Exception as e:
    sp="subprocess-err:%s"%type(e).__name__
print("ok2", len(d), h[:8], decimal.Decimal(1)/decimal.Decimal(3), fractions.Fraction(2,4), sp)
