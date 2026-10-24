"""Node normalization and ACL4SSR configuration generation. Python 3.11+."""
import base64, copy, json, re
from urllib.parse import urlsplit, parse_qs, unquote
import yaml

SUPPORTED={'shadowsocks','vmess','vless','trojan','hysteria2','tuic','socks','http','anytls'}
RULES=[('Ruleset/Tencent','DIRECT'),('LocalAreaNetwork','DIRECT'),('UnBan','DIRECT'),('BanAD','REJECT'),
       ('BanProgramAD','REJECT'),('ChinaDomain','DIRECT'),('GoogleCN','DIRECT'),('Telegram','Telegram'),
       ('Netflix','流媒体'),('Microsoft','Microsoft'),('Apple','Apple'),
       ('ChinaCompanyIp','DIRECT'),('ChinaIp','DIRECT'),('ProxyLite','PROXY')]

def b64(s):
    s=re.sub(r'\s','',s)
    return base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode('utf-8-sig')

def uri_node(line):
    if line.startswith('vmess://'):
        v=json.loads(b64(line[8:])); q={}
        n={'type':'vmess','tag':v.get('ps','VMess'),'server':v['add'],'server_port':int(v['port']),
           'uuid':v['id'],'security':v.get('scy','auto'),'alter_id':int(v.get('aid',0))}
        if v.get('tls')=='tls': n['tls']={'enabled':True,'server_name':v.get('sni') or v.get('host') or v['add']}
        net=v.get('net','tcp')
        if net=='ws': n['transport']={'type':'ws','path':v.get('path','/'),'headers':{'Host':v.get('host',v['add'])}}
        elif net=='grpc': n['transport']={'type':'grpc','service_name':v.get('path','')}
        elif net!='tcp': raise ValueError('VMess 传输不支持：'+net)
        return n
    u=urlsplit(line); q={k:v[0] for k,v in parse_qs(u.query,keep_blank_values=True).items()}
    t={'ss':'shadowsocks','hy2':'hysteria2','socks5':'socks','https':'http'}.get(u.scheme,u.scheme)
    if t not in SUPPORTED: raise ValueError('不支持的节点协议：'+u.scheme)
    if t=='shadowsocks':
        if '@' not in u.netloc:
            plain=b64(u.netloc); u=urlsplit('ss://'+plain+'#'+u.fragment)
        auth=unquote(u.netloc.rsplit('@',1)[0])
        if ':' not in auth: auth=b64(auth)
        method,password=auth.split(':',1)
        n={'type':t,'method':method,'password':password}
        if q.get('plugin'):
            parts=q['plugin'].split(';',1); n['plugin']=parts[0]
            if len(parts)>1: n['plugin_opts']=parts[1]
    else:
        n={'type':t}
        if t in {'vmess','vless','tuic'}: n['uuid']=unquote(u.username or '')
        if t in {'trojan','hysteria2','anytls'}: n['password']=unquote((u.username or '')+(':'+u.password if u.password else ''))
        if t=='tuic': n['password']=unquote(u.password or ''); n['congestion_control']=q.get('congestion_control','cubic')
        if t in {'socks','http'}:
            if u.username: n['username']=unquote(u.username)
            if u.password: n['password']=unquote(u.password)
        security=q.get('security','tls' if t in {'trojan','hysteria2','tuic','anytls'} or u.scheme=='https' else 'none')
        if security in {'tls','reality'}:
            tls={'enabled':True,'server_name':q.get('sni') or q.get('peer') or u.hostname,
                 'insecure':q.get('insecure',q.get('allowInsecure','0')) in {'1','true'}}
            if q.get('alpn'): tls['alpn']=q['alpn'].split(',')
            if q.get('fp'): tls['utls']={'enabled':True,'fingerprint':q['fp']}
            if security=='reality': tls['reality']={'enabled':True,'public_key':q.get('pbk',''),'short_id':q.get('sid','')}
            n['tls']=tls
        if q.get('flow'): n['flow']=q['flow']
        net=q.get('type','tcp')
        if net=='ws': n['transport']={'type':'ws','path':q.get('path','/'),'headers':{'Host':q.get('host',u.hostname)}}
        elif net=='grpc': n['transport']={'type':'grpc','service_name':q.get('serviceName','')}
        elif net=='http': n['transport']={'type':'http','path':q.get('path','/'),'host':q.get('host',u.hostname).split(',')}
        elif net!='tcp': raise ValueError('不支持的传输：'+net+'；请换用兼容节点')
        if t=='hysteria2' and q.get('obfs'): n['obfs']={'type':q['obfs'],'password':q.get('obfs-password','')}
    n.update(tag=unquote(u.fragment) or t,server=u.hostname,server_port=u.port or 443)
    return n

def clash_node(p):
    t={'ss':'shadowsocks','socks5':'socks'}.get(p['type'],p['type'])
    if t not in SUPPORTED: raise ValueError('不支持的 Clash 节点类型：'+p['type'])
    n={'type':t,'tag':str(p.get('name',t)),'server':p['server'],'server_port':int(p['port'])}
    for k in ['uuid','password','username','flow','alterId','congestion-controller']:
        if k in p: n[{'alterId':'alter_id','congestion-controller':'congestion_control'}.get(k,k)]=p[k]
    if t=='shadowsocks':
        n['method']=p['cipher']
        if p.get('plugin'):
            n['plugin']=p['plugin']; n['plugin_opts']=';'.join(f'{k}={v}' if not isinstance(v,bool) else k for k,v in p.get('plugin-opts',{}).items() if v is not False)
    if t=='vmess': n['security']=p.get('cipher','auto')
    if p.get('tls') or t in {'trojan','hysteria2','tuic','anytls'}:
        tls={'enabled':True,'server_name':p.get('servername',p.get('sni',p['server'])),'insecure':bool(p.get('skip-cert-verify',False))}
        if p.get('alpn'): tls['alpn']=p['alpn']
        if p.get('client-fingerprint'): tls['utls']={'enabled':True,'fingerprint':p['client-fingerprint']}
        if p.get('reality-opts'):
            r=p['reality-opts']; tls['reality']={'enabled':True,'public_key':r['public-key'],'short_id':str(r.get('short-id',''))}
        n['tls']=tls
    net=p.get('network','tcp')
    if net=='ws':
        ws=p.get('ws-opts',{}); n['transport']={'type':'ws','path':ws.get('path','/'),'headers':ws.get('headers',{})}
        if ws.get('max-early-data'): n['transport'].update(max_early_data=ws['max-early-data'],early_data_header_name=ws.get('early-data-header-name','Sec-WebSocket-Protocol'))
    elif net=='grpc': n['transport']={'type':'grpc','service_name':p.get('grpc-opts',{}).get('grpc-service-name','')}
    elif net=='http': n['transport']={'type':'http','host':p.get('http-opts',{}).get('headers',{}).get('Host',[]),'path':(p.get('http-opts',{}).get('path') or ['/'])[0]}
    elif net!='tcp': raise ValueError('不支持的 Clash 传输：'+net)
    if t=='hysteria2':
        if p.get('obfs'): n['obfs']={'type':p['obfs'],'password':p.get('obfs-password','')}
        for k in ['up','down']:
            if p.get(k): n[k+'_mbps']=int(re.search(r'\d+',str(p[k]))[0])
    if p.get('dialer-proxy'): raise ValueError('暂不支持带 dialer-proxy 的链式代理')
    return n

def parse_source(text,depth=0):
    text=text.strip().lstrip('\ufeff')
    if not text or depth>1: raise ValueError('订阅内容为空或格式不支持')
    if len(text)>4*1024*1024: raise ValueError('订阅超过 4 MB')
    if text[0] in '{[' or text.startswith('proxies:') or '\nproxies:' in text or text.startswith('mixed-port:'):
        obj=yaml.safe_load(text)
        if isinstance(obj,dict) and 'proxies' in obj: nodes=[clash_node(p) for p in obj['proxies']]
        else:
            rows=obj.get('outbounds',[]) if isinstance(obj,dict) else obj
            if not isinstance(rows,list): raise ValueError('需要节点列表或含 outbounds 的 JSON')
            nodes=[]
            for n in rows:
                if n.get('type') in {'selector','urltest','direct','block','dns'}: continue
                if n.get('type') not in SUPPORTED: raise ValueError('不支持的 sing-box 节点类型：'+str(n.get('type')))
                n=copy.deepcopy(n)
                if n.get('detour'): raise ValueError('暂不支持带 detour 的链式代理')
                nodes.append(n)
    elif re.match(r'^(ss|vmess|vless|trojan|hy2|hysteria2|tuic|socks5?|https?|anytls)://',text):
        nodes=[]
        for i,line in enumerate(text.splitlines(),1):
            line=line.strip()
            if not line or line.startswith('#'): continue
            try: nodes.append(uri_node(line))
            except Exception as e: raise ValueError(f'第 {i} 行节点无法转换：{e}') from None
    else:
        try: decoded=b64(text)
        except Exception: raise ValueError('无法识别订阅；支持 Clash YAML、sing-box JSON、节点链接或 Base64 订阅') from None
        return parse_source(decoded,depth+1)
    if not nodes or len(nodes)>1000: raise ValueError('节点数量必须在 1–1000 之间')
    return nodes

def normalize(nodes,insecure=False):
    result=[]; used={'DIRECT','REJECT','PROXY','AUTO','Telegram','流媒体','Microsoft','Apple','全球拦截','故障转移','去广告'}
    for original in nodes:
        node=copy.deepcopy(original)
        if not node.get('server') or not 0<int(node.get('server_port',0))<65536: raise ValueError('节点服务器或端口无效')
        name=str(node.get('tag') or node['type']); tag=name; i=2
        while tag in used: tag=f'{name} ({i})'; i+=1
        used.add(tag); node['tag']=tag
        if node.get('tls',{}).get('enabled'): node['tls']['insecure']=bool(insecure)
        result.append(node)
    return result

def to_clash(n):
    t=n['type']; p={'name':n['tag'],'type':{'shadowsocks':'ss','socks':'socks5'}.get(t,t),'server':n['server'],'port':n['server_port'],'udp':True}
    for k in ['uuid','password','username','flow','alter_id','congestion_control']:
        if k in n: p[{'alter_id':'alterId','congestion_control':'congestion-controller'}.get(k,k)]=n[k]
    if t=='shadowsocks':
        p['cipher']=n['method']
        if n.get('plugin'):
            p['plugin']=n['plugin']; opts={}
            for s in n.get('plugin_opts','').split(';'):
                if s:
                    kv=s.split('=',1); opts[kv[0]]=kv[1] if len(kv)>1 else True
            p['plugin-opts']=opts
    if t=='vmess': p['cipher']=n.get('security','auto')
    tls=n.get('tls',{})
    if tls.get('enabled'):
        p.update(tls=True,servername=tls.get('server_name',n['server']),**{'skip-cert-verify':tls.get('insecure',False)})
        if t in {'hysteria2','tuic'}: p['sni']=p.pop('servername')
        if tls.get('alpn'): p['alpn']=tls['alpn']
        if tls.get('utls',{}).get('enabled'): p['client-fingerprint']=tls['utls'].get('fingerprint','chrome')
        if tls.get('reality',{}).get('enabled'):
            r=tls['reality']; p['reality-opts']={'public-key':r['public_key'],'short-id':r.get('short_id','')}
        unknown=set(tls)-{'enabled','server_name','insecure','alpn','utls','reality'}
        if unknown: raise ValueError('Clash 无法无损转换此 TLS 选项：'+','.join(sorted(unknown)))
    tr=n.get('transport',{})
    if tr:
        net=tr['type']; p['network']=net
        if net=='ws': p['ws-opts']={'path':tr.get('path','/'),'headers':tr.get('headers',{})}
        elif net=='grpc': p['grpc-opts']={'grpc-service-name':tr.get('service_name','')}
        elif net=='http': p['http-opts']={'path':[tr.get('path','/')],'headers':{'Host':tr.get('host',[])}}
        elif net=='xhttp': p['xhttp-opts']={k:v for k,v in tr.items() if k!='type'}
        else: raise ValueError('Clash 不支持此传输：'+net)
    if t=='hysteria2':
        if n.get('obfs'): p.update(obfs=n['obfs']['type'],**{'obfs-password':n['obfs']['password']})
        for k in ['up','down']:
            if n.get(k+'_mbps'): p[k]=n[k+'_mbps']
    allowed={'type','tag','server','server_port','uuid','password','username','flow','alter_id','congestion_control','method','plugin','plugin_opts','security','tls','transport','obfs','up_mbps','down_mbps'}
    unknown=set(n)-allowed
    if unknown: raise ValueError('Clash 无法无损转换此节点选项：'+','.join(sorted(unknown)))
    return p

def generate(nodes,fmt,device,insecure,base,rule_data,mode=None,adblock=True,ipv6=True):
    mode=mode or ('tun' if device=='mobile' else 'proxy')
    if mode not in {'tun','proxy'}: raise ValueError('无效的接管模式')
    tun=device=='mobile' or mode=='tun'
    nodes=normalize(nodes,insecure); tags=[n['tag'] for n in nodes]
    groups=['Telegram','流媒体','Microsoft','Apple']
    if fmt=='clash':
        providers={name.replace('/','_'):{'type':'http','behavior':'classical','proxy':'DIRECT','format':'yaml','url':f'{base}/rules/{name.replace("/","_")}.yaml','path':f'./rules/{name.replace("/","_")}.yaml','interval':86400} for name,_ in RULES}
        providers['HeidaiAd']={'type':'http','behavior':'domain','format':'mrs','proxy':'DIRECT','url':f'{base}/rules/HeidaiAd.mrs','path':'./rules/HeidaiAd.mrs','interval':28800}
        cfg={'mixed-port':7890,'allow-lan':False,'mode':'rule','log-level':'warning','ipv6':ipv6,'bind-address':'127.0.0.1',
             'dns':{'enable':True,'listen':'127.0.0.1:1053','enhanced-mode':'fake-ip','fake-ip-range':'198.18.0.1/16','default-nameserver':['223.5.5.5','119.29.29.29'],'nameserver':['https://dns.alidns.com/dns-query','https://doh.pub/dns-query']},
             'proxies':[to_clash(n) for n in nodes],
             'proxy-groups':[{'name':'PROXY','type':'select','proxies':['AUTO']+tags+['DIRECT']},{'name':'AUTO','type':'url-test','proxies':tags,'url':'https://www.gstatic.com/generate_204','interval':300,'tolerance':50},{'name':'故障转移','type':'fallback','proxies':tags,'url':'https://www.gstatic.com/generate_204','interval':60,'lazy':False},{'name':'全球拦截','type':'select','proxies':['REJECT','DIRECT','PROXY']},{'name':'去广告','type':'select','proxies':['REJECT','DIRECT','PROXY']}]+[{'name':g,'type':'select','proxies':['PROXY','故障转移','DIRECT']+tags} for g in groups],
             'rule-providers':providers,'rules':['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve','IP-CIDR,10.0.0.0/8,DIRECT,no-resolve','IP-CIDR,172.16.0.0/12,DIRECT,no-resolve','IP-CIDR,192.168.0.0/16,DIRECT,no-resolve']+[f'RULE-SET,{name.replace("/","_")},{"去广告" if group=="REJECT" else group}' for name,group in RULES]+['MATCH,PROXY']}
        # The adblock switch controls both connection and DNS filtering.
        cfg['rules'].insert(5,'RULE-SET,HeidaiAd,去广告')
        # CCB Life waits on its launch endpoint; exempt it before ad filtering.
        cfg['rules'].insert(5,'DOMAIN-SUFFIX,adv.ccb.com,DIRECT')
        cfg['dns']['nameserver-policy']={'rule-set:Ruleset_Tencent':'https://dns.alidns.com/dns-query','rule-set:ChinaDomain':'https://dns.alidns.com/dns-query','+.adv.ccb.com':'https://dns.alidns.com/dns-query'}
        cfg['dns']['fake-ip-filter']=['rule-set:Ruleset_Tencent','rule-set:ChinaDomain','+.adv.ccb.com']
        if adblock:
            cfg['dns']['nameserver-policy']['rule-set:HeidaiAd']='https://1.1.1.1/dns-query#去广告'
            cfg['dns']['fake-ip-filter'].append('rule-set:HeidaiAd')
            cfg['dns']['proxy-server-nameserver']=['https://dns.alidns.com/dns-query']
        if not adblock:
            cfg['rules']=[r for r in cfg['rules'] if not r.endswith(',去广告')]
            cfg['rule-providers']={k:v for k,v in cfg['rule-providers'].items() if k not in {'HeidaiAd','BanAD','BanProgramAD'}}
        if tun: cfg['tun']={'enable':True,'stack':'mixed','auto-route':True,'auto-detect-interface':True,'dns-hijack':['any:53']}
        cfg['dns']['ipv6']=ipv6
        if ipv6:
            cfg['listeners']=[{'name':'mixed-ipv6','type':'mixed','listen':'::1','port':7890,'udp':True}]
            if tun: cfg['tun']['inet6-address']=['fdfe:dcba:9876::1/126']
        return yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),'text/yaml; charset=utf-8'
    rules=[{'action':'sniff'},{'protocol':'dns','action':'hijack-dns'},{'ip_is_private':True,'action':'route','outbound':'DIRECT'},{'rule_set':'Ruleset_Tencent','action':'route','outbound':'DIRECT'},{'domain_suffix':['adv.ccb.com'],'action':'route','outbound':'DIRECT'},{'rule_set':'HeidaiAd','action':'route','outbound':'去广告'}]
    for name,group in RULES:
        r={'rule_set':name.replace('/','_'),'action':'route','outbound':'去广告' if group=='REJECT' else group}
        rules.append(r)
    cfg={'log':{'level':'warn','timestamp':True},
         'dns':{'servers':[{'type':'https','tag':'dns-local','server':'223.5.5.5','path':'/dns-query'},{'type':'https','tag':'dns-remote','server':'1.1.1.1','path':'/dns-query','detour':'PROXY'}],
                'rules':[{'rule_set':'Tencent-DNS','action':'route','server':'dns-local'},{'domain_suffix':['adv.ccb.com'],'action':'route','server':'dns-local'},{'rule_set':'HeidaiAd','action':'route','server':'dns-adblock'},{'rule_set':['ChinaDomain-DNS','GoogleCN','UnBan'],'action':'route','server':'dns-local'}],'final':'dns-remote'},
         'inbounds':([{'type':'tun','tag':'tun-in','address':['172.31.255.1/30']+(['fdfe:dcba:9876::1/126'] if ipv6 else []),'auto_route':True,'strict_route':True}] if tun else [])+([{'type':'mixed','tag':'mixed-in','listen':'127.0.0.1','listen_port':7890}] if device=='desktop' else []),
         'http_clients':[{'tag':'rules-download'}],
         'outbounds':[{'type':'selector','tag':'PROXY','outbounds':['AUTO']+tags+['DIRECT'],'default':'AUTO'},{'type':'urltest','tag':'AUTO','outbounds':tags,'url':'https://www.gstatic.com/generate_204','interval':'5m','tolerance':50},{'type':'urltest','tag':'故障转移','outbounds':tags,'url':'https://www.gstatic.com/generate_204','interval':'1m','tolerance':50},{'type':'selector','tag':'全球拦截','outbounds':['REJECT','DIRECT','PROXY'],'default':'REJECT'},{'type':'selector','tag':'去广告','outbounds':['DIRECT','PROXY','REJECT'],'default':'REJECT'}]+[{'type':'selector','tag':g,'outbounds':['PROXY','故障转移','DIRECT']+tags,'default':'DIRECT' if g in {'Apple','Microsoft'} else 'PROXY'} for g in groups]+nodes+[{'type':'direct','tag':'DIRECT'},{'type':'block','tag':'REJECT'}],
         'route':{'default_http_client':'rules-download','default_domain_resolver':'dns-local','auto_detect_interface':True,'final':'PROXY','rules':rules,
                  'rule_set':[{'type':'remote','tag':name.replace('/','_'),'format':'source','url':f'{base}/rules/{name.replace("/","_")}.json','http_client':'rules-download','update_interval':'1d'} for name,_ in RULES]+[{'type':'remote','tag':'Tencent-DNS','format':'source','url':f'{base}/rules/Tencent-DNS.json','http_client':'rules-download','update_interval':'1d'},{'type':'remote','tag':'ChinaDomain-DNS','format':'source','url':f'{base}/rules/ChinaDomain-DNS.json','http_client':'rules-download','update_interval':'1d'}]},
         'experimental':{'cache_file':{'enabled':True}}}
    cfg['route']['rule_set'].append({'type':'remote','tag':'HeidaiAd','format':'binary','url':f'{base}/rules/HeidaiAd.srs','http_client':'rules-download','update_interval':'8h'})
    if adblock:
        cfg['dns']['servers'].append({'type':'https','tag':'dns-adblock','server':'1.1.1.1','path':'/dns-query','detour':'去广告'})
    if not adblock:
        cfg['dns']['rules']=[r for r in cfg['dns']['rules'] if r.get('server')!='dns-adblock']
        cfg['route']['rules']=[r for r in cfg['route']['rules'] if r.get('outbound')!='去广告']
        cfg['route']['rule_set']=[r for r in cfg['route']['rule_set'] if r['tag'] not in {'HeidaiAd','BanAD','BanProgramAD'}]
    if device=='desktop' and ipv6:
        cfg['inbounds'].append({'type':'mixed','tag':'mixed-in-ipv6','listen':'::1','listen_port':7890})
    if not ipv6: cfg['dns']['strategy']='ipv4_only'
    cfg['route']['rules']=list({json.dumps(r,sort_keys=True):r for r in cfg['route']['rules']}.values())
    return json.dumps(cfg,ensure_ascii=False,separators=(',',':')),'application/json; charset=utf-8'

def convert_rules(text):
    fields={'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword','IP-CIDR':'ip_cidr','IP-CIDR6':'ip_cidr','IP-ASN':'ip_asn'}
    result={}
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';','//')): continue
        a=line.split(',');kind=a[0].upper()
        if kind not in fields or len(a)<2: raise ValueError('ACL4SSR 出现未支持规则：'+kind)
        value=a[1].strip();key=fields[kind]
        if key in {'domain','domain_suffix'}: value=value.lower().rstrip('.')
        result.setdefault(key,[]).append(int(value) if key=='ip_asn' else value)
    if not result: raise ValueError('空规则集')
    result={key:list(dict.fromkeys(values)) for key,values in result.items()}
    suffixes=set(result.get('domain_suffix',[]))
    def covered(domain,include_self):
        labels=domain.split('.')
        return any('.'.join(labels[i:]) in suffixes for i in range(0 if include_self else 1,len(labels)))
    if 'domain_suffix' in result:
        result['domain_suffix']=[d for d in result['domain_suffix'] if not covered(d,False)]
    if 'domain' in result:
        result['domain']=[d for d in result['domain'] if not covered(d,True)]
    result={key:values for key,values in result.items() if values}
    reverse={v:k for k,v in fields.items() if k!='IP-CIDR6'}
    clash=[reverse[key]+','+str(value) for key,values in result.items() for value in values]
    # Only deduplicate within a rule set: overlaps across policies preserve precedence.
    return {'version':3,'rules':[{key:values} for key,values in result.items()]},{'payload':clash}
