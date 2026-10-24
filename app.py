import concurrent.futures, hashlib, http.client, ipaddress, json, os, pathlib, re, secrets, socket, sqlite3, threading, time, subprocess, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qs, quote
import yaml, base64, io
import qrcode
from qrcode.image.svg import SvgPathFillImage
from converter import RULES, parse_source, generate, convert_rules
from subscriptions import parse_universal,prepare,uri_subscription,detect_target,target_override

ROOT=pathlib.Path(__file__).resolve().parent
DATA=pathlib.Path(os.environ.get('DATA_DIR',str(ROOT/'data')))
DATA.mkdir(parents=True,exist_ok=True)
BASE=os.environ.get('PUBLIC_URL','http://localhost:9088').rstrip('/')
MAX=4*1024*1024
RULE_LOCK=threading.Lock()
VALIDATOR_LOCK=threading.Lock()
JOBS=threading.BoundedSemaphore(16)

def subscription_qr(url):
    qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=4)
    qr.add_data(url); qr.make(fit=True)
    output=io.BytesIO(); qr.make_image(image_factory=SvgPathFillImage).save(output)
    return 'data:image/svg+xml;base64,'+base64.b64encode(output.getvalue()).decode('ascii')

def fetch(url,binary=False):
    for _ in range(5):
        u=urlsplit(url)
        if u.scheme not in {'http','https'} or not u.hostname or u.username or u.password: raise ValueError('订阅地址必须是 HTTP(S)，且不能含用户名密码')
        port=u.port if u.port is not None else (443 if u.scheme=='https' else 80)
        if not 1<=port<=65535: raise ValueError('订阅端口必须在 1–65535 之间')
        addresses=socket.getaddrinfo(u.hostname,port,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses): raise ValueError('订阅地址必须指向公网，不能访问内网、回环或保留地址')
        # Pin the connection to an address we checked; TLS still verifies the URL hostname.
        addresses.sort(key=lambda row:row[0]!=socket.AF_INET)
        def dial(*args,**kwargs):
            last=None
            for addr in addresses[:4]:
                s=socket.socket(addr[0],addr[1],addr[2]); s.settimeout(5)
                try: s.connect(addr[4]); return s
                except OSError as e: s.close(); last=e
            raise last or OSError('No address available')
        c=(http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.hostname,port,timeout=15)
        c._create_connection=dial
        try:
            c.request('GET',urlunsplit(('','',u.path or '/',u.query,'')),headers={'User-Agent':'Clash.Meta/zh-converter','Accept-Encoding':'identity'})
            r=c.getresponse()
            if r.status in {301,302,303,307,308}:
                target=r.getheader('Location')
                if not target: raise ValueError('订阅重定向无效')
                url=urljoin(url,target); continue
            if r.status!=200: raise ValueError(f'上游订阅返回 HTTP {r.status}')
            content=r.read(MAX+1)
            if len(content)>MAX: raise ValueError('订阅超过 4 MB')
            return content if binary else content.decode('utf-8-sig')
        finally: c.close()
    raise ValueError('订阅重定向次数过多')

def db():
    c=sqlite3.connect(DATA/'subscriptions.sqlite',timeout=15)
    c.execute('CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, body TEXT NOT NULL, created INTEGER NOT NULL)')
    return c

def rule_path(name,ext): return DATA/'rules'/f'{name.replace("/","_")}.{ext}'

def update_rules():
    try:
        staged=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            jobs={pool.submit(fetch,('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Tencent/Tencent.list' if name=='Ruleset/Tencent' else 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/'+name+'.list')):name for name,_ in RULES}
            for future in concurrent.futures.as_completed(jobs):
                name=jobs[future]; sb,clash=convert_rules(future.result())
                staged.extend([(name,'json',json.dumps(sb,ensure_ascii=False,separators=(',',':'))),(name,'yaml',yaml.safe_dump(clash,allow_unicode=True,sort_keys=False))])
                if name in {'ChinaDomain','Ruleset/Tencent'}:
                    dns={'version':3,'rules':[r for r in sb['rules'] if all(k in {'domain','domain_suffix','domain_keyword','domain_regex'} for k in r)]}
                    staged.append((('Tencent-DNS' if name=='Ruleset/Tencent' else 'ChinaDomain-DNS'),'json',json.dumps(dns,ensure_ascii=False,separators=(',',':'))))
        with RULE_LOCK:
            (DATA/'rules').mkdir(exist_ok=True)
            for name,ext,body in staged:
                p=rule_path(name,ext); tmp=p.with_suffix(p.suffix+'.tmp'); tmp.write_text(body,encoding='utf-8'); tmp.replace(p)
            (DATA/'rules-updated').write_text(str(int(time.time())))
        print('ACL4SSR rules updated',flush=True)
        return True
    except Exception as e:
        print('ACL4SSR update failed; last successful rules retained. '+type(e).__name__,flush=True)
        return False

def periodic():
    while True:
        succeeded=update_rules()
        succeeded=update_adblock() and succeeded
        time.sleep(28800 if succeeded else 300)

def update_adblock():
    try:
        staged=[]
        for filename,ext,magic in [('adblocksingbox.srs','srs',b'SRS'),('adblockmihomo.mrs','mrs',b'\x28\xb5\x2f\xfd')]:
            data=fetch('https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/'+filename,binary=True)
            if len(data)<128 or not data.startswith(magic): raise ValueError('Invalid rule binary')
            staged.append((ext,data))
        with RULE_LOCK:
            (DATA/'rules').mkdir(exist_ok=True)
            for ext,data in staged:
                p=rule_path('HeidaiAd',ext); tmp=p.with_suffix(p.suffix+'.tmp');tmp.write_bytes(data);tmp.replace(p)
            (DATA/'adblock-updated').write_text(str(int(time.time())))
        print('217heidai adblock rules updated',flush=True);return True
    except Exception as e:
        print('Adblock update failed; previous rules retained. '+type(e).__name__,flush=True);return False

def nodes_for(body,universal=False):
    source=body.get('source','').strip()
    if not source: raise ValueError('请填写订阅地址或节点内容')
    if body.get('input')=='url':
        urls=[x.strip() for x in source.splitlines() if x.strip()]
        nodes=[]
        for url in urls: nodes.extend((parse_universal if universal else parse_source)(fetch(url)))
        if len(nodes)>1000: raise ValueError('合并后节点数量不能超过 1000')
        return nodes
    return (parse_universal if universal else parse_source)(source)

def render(body,target=None):
    requested=body.get('format','singbox'); fmt=target or ('xray' if requested=='auto' else requested); device=body.get('device','mobile')
    if requested not in {'singbox','clash','auto','xray'} or fmt not in {'singbox','clash','xray'} or device not in {'mobile','desktop'}: raise ValueError('无效的输出格式或设备类型')
    if not isinstance(body.get('insecure',False),bool): raise ValueError('证书开关必须为布尔值')
    if not isinstance(body.get('ipv6',True),bool): raise ValueError('IPv6 开关必须为布尔值')
    if not isinstance(body.get('adblock',True),bool): raise ValueError('去广告开关必须为布尔值')
    if not (DATA/'rules-updated').exists() or not (DATA/'adblock-updated').exists(): raise ValueError('规则尚未初始化，请稍后重试')
    nodes=nodes_for(body,universal=requested in {'auto','xray'} or target is not None)
    meta={'target':fmt,'total_nodes':len(nodes),'omitted_nodes':[],'node_only':fmt=='xray'}
    if fmt=='xray':
        text,ctype,count=uri_subscription(nodes,body.get('insecure',False))
        return text,ctype,count,meta
    nodes,meta['omitted_nodes']=prepare(nodes,fmt)
    text,ctype=generate(nodes,fmt,device,body.get('insecure',False),BASE,{},body.get('mode'),body.get('adblock',True),body.get('ipv6',True))
    binary=os.environ.get('SINGBOX_BIN' if fmt=='singbox' else 'MIHOMO_BIN')
    if binary:
        with tempfile.TemporaryDirectory(prefix='validate-',dir=DATA) as directory:
            path=pathlib.Path(directory)/('config.json' if fmt=='singbox' else 'config.yaml')
            path.write_text(text,encoding='utf-8')
            args=[binary,'check','-c',str(path)] if fmt=='singbox' else [binary,'-t','-d',directory,'-f',str(path)]
            with VALIDATOR_LOCK:
                checked=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            if checked.returncode: raise ValueError('目标内核校验失败：节点含不兼容的协议、参数或密钥，请检查原始节点配置')
            if fmt=='singbox' and os.environ.get('SINGBOX_NEXT_BIN'):
                with VALIDATOR_LOCK:
                    checked=subprocess.run([os.environ['SINGBOX_NEXT_BIN'],'check','-c',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                if checked.returncode: raise ValueError('sing-box 1.15 配置校验失败，请检查节点选项')
    return text,ctype,len(nodes),meta

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def process_request(self,request,address):
        if not JOBS.acquire(blocking=False): request.close(); return
        try: super().process_request(request,address)
        except Exception: JOBS.release(); raise
    def process_request_thread(self,*args):
        try: super().process_request_thread(*args)
        finally: JOBS.release()

class Handler(BaseHTTPRequestHandler):
    def setup(self): super().setup(); self.connection.settimeout(60)
    def log_message(self,*args): pass  # URLs may contain subscription bearer tokens.
    def send(self,status,body,ctype='application/json; charset=utf-8',headers=None):
        if not isinstance(body,(str,bytes)): body=json.dumps(body,ensure_ascii=False)
        if isinstance(body,str): body=body.encode()
        self.send_response(status)
        self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store'); self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(body)
    def do_GET(self):
        path=urlsplit(self.path).path
        try:
            if path in {'/','/app.js','/style.css'}:
                name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
                return self.send(200,(ROOT/name).read_bytes(),{'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path])
            if path=='/health':
                stamp=DATA/'rules-updated'
                return self.send(200 if stamp.exists() else 503,{'ok':stamp.exists(),'rules_updated':int(stamp.read_text()) if stamp.exists() else None,'singbox':'1.14.3 / 1.15.0-alpha.12','outputs':['auto','singbox','clash','xray'],'desktop_modes':['tun','proxy']})
            if path.startswith('/rules/'):
                name=path[7:]
                if name not in {f'{n.replace("/","_")}.{e}' for n,_ in RULES for e in ['json','yaml']}|{'ChinaDomain-DNS.json','Tencent-DNS.json','HeidaiAd.srs','HeidaiAd.mrs'}: return self.send(404,{'error':'未找到规则'})
                with RULE_LOCK: content=(DATA/'rules'/name).read_bytes()
                return self.send(200,content,'application/octet-stream' if name.endswith(('.srs','.mrs')) else 'application/json' if name.endswith('.json') else 'text/yaml')
            m=re.fullmatch(r'/s/([A-Za-z0-9_-]{32})',path)
            if m:
                with db() as c: row=c.execute('select body from subscriptions where id=?',(m[1],)).fetchone()
                if not row: return self.send(404,{'error':'订阅不存在或已撤销'})
                body=json.loads(row[0]); query=parse_qs(urlsplit(self.path).query);ua=self.headers.get('User-Agent','')
                target=target_override(query['target'][0]) if query.get('target') else detect_target(ua) if body.get('format')=='auto' else None
                if body.get('format')=='auto':
                    if any(x in ua.lower() for x in ['windows','macintosh','macos','sfm','v2rayn/']):body['device']='desktop'
                    elif any(x in ua.lower() for x in ['android','iphone','ios','sfa/','sfi/']):body['device']='mobile'
                key=hashlib.sha256(('v17:'+json.dumps(body,sort_keys=True)+':'+str(target)).encode()).hexdigest(); cache=DATA/f'cache-{key}.json'
                if cache.exists() and time.time()-cache.stat().st_mtime<300: text,ctype,count,meta=json.loads(cache.read_text(encoding='utf-8'))
                else:
                    text,ctype,count,meta=render(body,target)
                    tmp=cache.with_name(cache.name+'.'+secrets.token_hex(4)); tmp.write_text(json.dumps([text,ctype,count,meta]),encoding='utf-8'); tmp.replace(cache)
                ext={'singbox':'json','clash':'yaml','xray':'txt'}[meta['target']]
                return self.send(200,text,ctype,{'profile-update-interval':'6','Vary':'User-Agent','X-Subscription-Format':meta['target'],'X-Subscription-Nodes':str(count),'X-Subscription-Omitted':str(len(meta['omitted_nodes'])),'Content-Disposition':f'attachment; filename="subscription.{ext}"'})
            self.send(404,{'error':'未找到页面'})
        except (ValueError,KeyError,TypeError,yaml.YAMLError): self.send(400,{'error':'订阅解析或转换失败；请在网页预览中检查格式'})
        except Exception: self.send(502,{'error':'无法获取订阅或规则，请稍后重试'})
    def do_HEAD(self): self.do_GET()
    def do_POST(self):
        path=urlsplit(self.path).path
        if self.headers.get('Origin') not in {None,BASE}: return self.send(403,{'error':'来源无效'})
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=MAX: return self.send(413,{'error':'请求大小无效或超过 4 MB'})
            body=json.loads(self.rfile.read(size))
            if path=='/api/revoke':
                token=body.get('id','')
                with db() as c: c.execute('delete from subscriptions where id=?',(token,))
                return self.send(200,{'ok':True})
            if path not in {'/api/preview','/api/create'}: return self.send(404,{'error':'未知接口'})
            text,ctype,count,meta=render(body)
            if path=='/api/preview': return self.send(200,{'content':text,'content_type':ctype,'nodes':count,**meta})
            token=secrets.token_urlsafe(24)
            with db() as c:
                if c.execute('select count(*) from subscriptions').fetchone()[0]>=1000: raise ValueError('订阅数量达到上限，请先撤销旧订阅')
                c.execute('insert into subscriptions values(?,?,?)',(token,json.dumps(body),int(time.time())))
            url=BASE+'/s/'+token
            import_url=('sing-box://import-remote-profile?url='+quote(url,safe='')+'#'+quote('ZH-'+body.get('device','mobile'),safe='')) if body.get('format','singbox')=='singbox' else url
            singbox_url='sing-box://import-remote-profile?url='+quote(url+'?target=singbox',safe='')+'#'+quote('ZH-统一订阅',safe='')
            return self.send(200,{'url':url,'import_url':import_url,'singbox_import_url':singbox_url,'singbox_qr':subscription_qr(singbox_url),'id':token,'nodes':count,'qr':subscription_qr(import_url),**meta})
        except ValueError as e:
            # Never return source lines, URLs or library exception text with credentials.
            msg=str(e)
            if any(x in msg for x in ['://','password','uuid','line ','column ']) or len(msg)>180: msg='订阅解析失败，请检查内容和支持的节点类型'
            return self.send(400,{'error':msg})
        except Exception: return self.send(502,{'error':'上游连接失败或节点选项不兼容；没有生成不完整的订阅'})

if __name__=='__main__':
    os.umask(0o077)
    with db(): pass
    threading.Thread(target=periodic,daemon=True).start()
    print('Converter listening',flush=True)
    Server((os.environ.get('BIND','127.0.0.1'),int(os.environ.get('PORT','9088'))),Handler).serve_forever()
