"""Common share-link subscriptions and UA content negotiation."""
import base64,copy,json,re
from urllib.parse import urlsplit,urlunsplit,parse_qs,urlencode,quote,unquote
import yaml
from converter import parse_source,uri_node,clash_node,normalize,SUPPORTED

def detect_target(ua):
    ua=ua.lower()
    if any(s in ua for s in ['clash','mihomo','flclash']):return 'clash'
    if any(s in ua for s in ['sing-box','singbox']) or re.search(r'\b(sf[aimw]|sfa)\b',ua):return 'singbox'
    return 'xray' # v2rayN, v2rayNG, Shadowrocket and unknown/custom UA share URI subscriptions.

def target_override(value):
    aliases={'v2rayn':'xray','v2rayng':'xray','shadowrocket':'xray','mihomo':'clash','sing-box':'singbox'}
    value=aliases.get(value.lower(),value.lower())
    if value not in {'singbox','clash','xray'}:raise ValueError('无效的订阅目标格式')
    return value

def parse_universal(text,depth=0):
    text=text.strip().lstrip('\ufeff')
    if not text or depth>1:raise ValueError('订阅格式无效')
    if re.match(r'^(ss|vmess|vless|trojan|hy2|hysteria2|tuic|socks5?|https?|anytls)://',text):
        nodes=[]
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith('#'):continue
            u=urlsplit(line);q=parse_qs(u.query)
            if q.get('type',[''])[0] in {'xhttp','splithttp'}:
                original=dict(q);q['type']=['tcp']
                n=uri_node(urlunsplit((u.scheme,u.netloc,u.path,urlencode(q,doseq=True),u.fragment)))
                n['transport']={'type':'xhttp','path':original.get('path',['/'])[0],'host':original.get('host',[u.hostname])[0],'mode':original.get('mode',['auto'])[0]}
                if original.get('extra'):
                    n['transport']['extra']=json.loads(original['extra'][0])
            else:n=uri_node(line)
            n['_original_uri']=line;nodes.append(n)
        if not 0<len(nodes)<=1000:raise ValueError('节点数量必须在 1–1000 之间')
        return nodes
    try: obj=yaml.safe_load(text)
    except yaml.YAMLError:obj=None
    if isinstance(obj,dict) and isinstance(obj.get('proxies'),list):
        nodes=[]
        for p in obj['proxies']:
            if p.get('network') in {'xhttp','splithttp'}:
                p=copy.deepcopy(p);opts=p.pop('xhttp-opts',{});p['network']='tcp';n=clash_node(p);n['transport']={'type':'xhttp',**opts}
            else:n=clash_node(p)
            nodes.append(n)
        return nodes
    if isinstance(obj,(dict,list)):return parse_source(text)
    try:decoded=base64.urlsafe_b64decode(re.sub(r'\s','',text)+'='*(-len(re.sub(r'\s','',text))%4)).decode('utf-8-sig')
    except Exception:raise ValueError('无法识别统一订阅输入格式') from None
    return parse_universal(decoded,depth+1)

def prepare(nodes,target):
    ready=[];omitted=[]
    for original in nodes:
        n=copy.deepcopy(original);n.pop('_original_uri',None)
        if target=='singbox' and n.get('transport',{}).get('type') in {'xhttp','splithttp'}:
            omitted.append(n.get('tag','XHTTP'));continue
        ready.append(n)
    if not ready:raise ValueError('所选客户端没有兼容节点；XHTTP 节点请使用支持它的客户端')
    return ready,omitted

def node_uri(n,insecure):
    if n.get('_original_uri') and n['type']!='vmess':
        u=urlsplit(n['_original_uri']);q=parse_qs(u.query,keep_blank_values=True)
        for k in ['insecure','allowInsecure','allowinsecure','skip-cert-verify']:q.pop(k,None)
        if n.get('tls',{}).get('enabled'):q['allowInsecure']=['1' if insecure else '0'];q['insecure']=['1' if insecure else '0']
        return urlunsplit((u.scheme,u.netloc,u.path,urlencode(q,doseq=True),quote(n['tag'],safe='')))
    t=n['type'];host=n['server'];host='['+host+']' if ':' in host else host;host+=':'+str(n['server_port']);q={};tls=n.get('tls',{});tr=n.get('transport',{})
    if tls.get('enabled'):
        unknown=set(tls)-{'enabled','server_name','insecure','alpn','utls','reality'}
        if unknown:raise ValueError('节点含无法转换成分享链接的 TLS 选项')
        q.update(security='reality' if tls.get('reality',{}).get('enabled') else 'tls',sni=tls.get('server_name',n['server']),allowInsecure='1' if insecure else '0',insecure='1' if insecure else '0')
        if tls.get('alpn'):q['alpn']=','.join(tls['alpn'])
        if tls.get('utls',{}).get('enabled'):q['fp']=tls['utls'].get('fingerprint','chrome')
        if tls.get('reality',{}).get('enabled'):q.update(pbk=tls['reality']['public_key'],sid=tls['reality'].get('short_id',''))
    if tr:
        q['type']=tr['type'];q['path']=tr.get('path','/');q['host']=tr.get('headers',{}).get('Host',tr.get('host',''))
        if tr['type']=='grpc':q['serviceName']=tr.get('service_name','')
        if tr['type']=='xhttp':
            q['mode']=tr.get('mode','auto')
            if tr.get('extra'):q['extra']=json.dumps(tr['extra'],separators=(',',':'))
    if n.get('flow'):q['flow']=n['flow']
    scheme={'shadowsocks':'ss','socks':'socks5'}.get(t,t)
    if t=='shadowsocks':
        auth=base64.urlsafe_b64encode((n['method']+':'+n['password']).encode()).decode().rstrip('=')
        if n.get('plugin'):q['plugin']=n['plugin']+(';'+n['plugin_opts'] if n.get('plugin_opts') else '')
    elif t=='vmess':
        v={'v':'2','ps':n['tag'],'add':n['server'],'port':str(n['server_port']),'id':n['uuid'],'aid':str(n.get('alter_id',0)),'scy':n.get('security','auto'),'net':tr.get('type','tcp'),'tls':'tls' if tls.get('enabled') else '','sni':tls.get('server_name',''),'path':tr.get('path',tr.get('service_name','')),'host':tr.get('headers',{}).get('Host',''),'allowInsecure':insecure}
        if tr.get('type') not in {None,'ws','grpc','http'}:raise ValueError('不支持的 VMess 分享传输')
        return 'vmess://'+base64.b64encode(json.dumps(v).encode()).decode()
    elif t in {'vless','tuic'}:
        auth=quote(n['uuid'],safe='')
        if t=='tuic':auth+=':'+quote(n.get('password',''),safe='');q['congestion_control']=n.get('congestion_control','cubic')
    elif t in {'trojan','hysteria2','anytls'}:auth=quote(n['password'],safe='')
    elif t in {'socks','http'}:auth=quote(n.get('username',''),safe='')+(':'+quote(n.get('password',''),safe='') if n.get('password') else '')
    else:raise ValueError('不能转换的分享协议：'+t)
    if t=='hysteria2' and n.get('obfs'):q.update(obfs=n['obfs']['type'],**{'obfs-password':n['obfs']['password']})
    return scheme+'://'+(auth+'@' if auth else '')+host+('?'+urlencode(q) if q else '')+'#'+quote(n['tag'],safe='')

def uri_subscription(nodes,insecure=False):
    # Preserve original protocol-specific parameters while normalizing names and certificate choices.
    normalized=normalize(nodes,insecure)
    text='\n'.join(node_uri(n,insecure) for n in normalized)+'\n'
    return base64.b64encode(text.encode()).decode(),'text/plain; charset=utf-8',len(normalized)
