"""Generates a synthetic HTTP-request dataset for the Aho-Corasick IDS project.
Run:  python3 data/generate_dataset.py
Outputs: data/payloads.txt (one payload per line), data/payloads_labels.csv (ground truth)."""
import random, csv
random.seed(42)
SIGS = ["UNION SELECT", "DROP TABLE", "../etc/passwd", "cmd.exe", "<script>", "' OR '1'='1"]
paths = ["/index.html","/login","/search","/products","/cart","/api/users","/about","/contact","/download","/profile","/images/logo.png","/blog/post-12"]
params = ["q=laptop","user=alice","id=42","page=3","sort=price","lang=en","file=report.pdf","name=bob","token=a1b2c3","city=Bengaluru","comment=nice+product","category=books"]
hosts = ["example.com","shop.local","portal.edu","api.demo.org"]
def normal():
    m = random.choice(["GET","POST"]); p = random.choice(paths)
    q = "&".join(random.sample(params, random.randint(1,3)))
    return f"{m} {p}?{q} HTTP/1.1 Host: {random.choice(hosts)}"
attacks = [
 lambda: f"GET /products?id=1 UNION SELECT username,password FROM users HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"GET /search?q=x; DROP TABLE users;-- HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"GET /download?file=../../../etc/passwd HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"POST /api/run cmd=cmd.exe /c dir HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"POST /comment body=<script>alert(document.cookie)</script> HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"POST /login user=admin' OR '1'='1&pass=x HTTP/1.1 Host: {random.choice(hosts)}",
 lambda: f"GET /products?id=1 union select null,null-- HTTP/1.1 Host: {random.choice(hosts)}",   # lower case
 lambda: f"GET /x?a=1 Union Select 1; Drop Table logs; HTTP/1.1 Host: {random.choice(hosts)}",   # 2 matches, mixed case
 lambda: f"POST /api/run cmd=cmd.exe&q=<SCRIPT>x</SCRIPT>&f=../etc/passwd HTTP/1.1",              # 3 matches
]
tricky_clean = [   # look suspicious but contain NO signature
 "GET /search?q=union+select HTTP/1.1 Host: example.com",     # '+' instead of space
 "GET /blog/how-to-drop-a-table-in-sql HTTP/1.1",
 "GET /docs?topic=etc/passwd HTTP/1.1",                        # no ../ prefix
 "POST /comment body=<scr ipt> HTTP/1.1",
 "GET /run?cmd=cmd_exe HTTP/1.1",
]
lines = []
for _ in range(150): lines.append(normal())
for _ in range(45): lines.append(random.choice(attacks)())
lines += tricky_clean
random.shuffle(lines)
def count(line):
    low, n = line.lower(), 0
    for s in SIGS:
        s = s.lower(); i = low.find(s)
        while i != -1: n += 1; i = low.find(s, i+1)
    return n
open("data/payloads.txt","w").write("\n".join(lines)+"\n")
with open("data/payloads_labels.csv","w",newline="") as f:
    w = csv.writer(f); w.writerow(["line","expected_matches","label"])
    for i,l in enumerate(lines,1):
        c = count(l); w.writerow([i,c,"attack" if c else "clean"])
flagged = sum(1 for l in lines if count(l)); total = sum(count(l) for l in lines)
print(f"lines={len(lines)} flagged={flagged} clean={len(lines)-flagged} total_matches={total}")
