"""Encrypted domestic DNS with a verified primary/backup rule chain (sing-box 1.14+)."""
import copy

PRIMARY='https://223.5.5.5/dns-query'
BACKUP='https://doh.pub/dns-query'

def singbox(cfg):
    dns=cfg.setdefault('dns',{})
    servers=dns.setdefault('servers',[])
    for server in servers:
        if server.get('tag') in {'dns-local','daed-dns'}:
            tag=server['tag'];mark=server.get('routing_mark')
            server.clear();server.update(type='https',tag=tag,server='223.5.5.5',path='/dns-query')
            if mark is not None:server['routing_mark']=mark
    if not any(x.get('tag')=='dns-tencent' for x in servers):
        servers.append({'type':'https','tag':'dns-tencent','server':'1.12.12.12','path':'/dns-query','tls':{'enabled':True,'server_name':'doh.pub'}})
    # Rendering an already generated profile must not duplicate fallback chains.
    original=[];rules=dns.get('rules',[]);i=0
    while i<len(rules):
        r=rules[i]
        if r.get('action')=='evaluate' and str(r.get('tag','')).startswith('domestic-primary-') and i+2<len(rules):
            r=copy.deepcopy(r)
            for key in ['tag','timeout']:r.pop(key,None)
            r['action']='route';original.append(r);i+=3
        else:original.append(copy.deepcopy(r));i+=1
    result=[]
    for index,r in enumerate(original):
        if r.get('server') not in {'dns-local','daed-dns'} or r.get('action','route')!='route':
            result.append(r);continue
        tag='domestic-primary-'+str(index)
        primary=copy.deepcopy(r);primary.update(action='evaluate',tag=tag,timeout='2s')
        result.append(primary)
        result.append({'match_response':tag,'response_rcode':'NOERROR','action':'respond'})
        fallback=copy.deepcopy(r);fallback.update(action='route',server='dns-tencent',timeout='4s')
        result.append(fallback)
    dns['rules']=result
    return cfg

def mihomo(cfg):
    dns=cfg['dns']
    # HTTPS-only upstreams, including bootstrap; DNSPod uses validated doh.pub TLS.
    cfg.setdefault('hosts',{})['doh.pub']=['1.12.12.12','120.53.53.53']
    dns['use-hosts']=True
    dns['default-nameserver']=[PRIMARY]
    dns['nameserver']=[PRIMARY,BACKUP]
    for key,value in list(dns.get('nameserver-policy',{}).items()):
        if value in ('https://dns.alidns.com/dns-query',PRIMARY):dns['nameserver-policy'][key]=[PRIMARY,BACKUP]
    if 'proxy-server-nameserver' in dns:dns['proxy-server-nameserver']=[PRIMARY,BACKUP]
    return cfg
