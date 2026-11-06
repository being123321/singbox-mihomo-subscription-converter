"""Private per-deployment domain exceptions; no account credentials are stored."""
import json,os,pathlib,re

def configured_domains(path=None):
    if path is None:path=pathlib.Path(os.environ.get('DATA_DIR',str(pathlib.Path(__file__).parent/'data')))/'direct-domains.json'
    path=pathlib.Path(path)
    if not path.exists():return []
    values=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(values,list) or len(values)>1000:raise ValueError('Invalid direct-domain configuration')
    result=[]
    for value in values:
        if not isinstance(value,str):raise ValueError('Invalid direct domain')
        value=value.strip().rstrip('.').lower().encode('idna').decode('ascii')
        if '.' not in value or len(value)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):raise ValueError('Invalid direct domain')
        if value not in result:result.append(value)
    return result

def singbox(cfg,domains):
    if not domains:return cfg
    route=cfg.setdefault('route',{}).setdefault('rules',[])
    if not any(r.get('outbound')=='DIRECT' and set(r.get('domain_suffix',[]))==set(domains) for r in route):
        index=0
        while index<len(route) and route[index].get('action') in {'sniff','hijack-dns'}:index+=1
        route.insert(index,{'domain_suffix':domains,'action':'route','outbound':'DIRECT'})
    dns=cfg.setdefault('dns',{}).setdefault('rules',[])
    # Existing subscription rules may sit behind router-specific overrides.
    # Move the whole owned-domain chain, not just its evaluate action.
    tags={r.get('tag') for r in dns if r.get('server')=='dns-local' and set(r.get('domain_suffix',[]))==set(domains) and r.get('action')=='evaluate'}
    tags.discard(None)
    dns[:]=[r for r in dns if not ((set(r.get('domain_suffix',[]))==set(domains) and r.get('server') in {'dns-local','dns-tencent'}) or (isinstance(r.get('match_response'),str) and r['match_response'] in tags))]
    dns.insert(0,{'domain_suffix':domains,'action':'route','server':'dns-local'})
    return cfg

def mihomo(cfg,domains):
    if not domains:return cfg
    rules=cfg.setdefault('rules',[])
    additions=['DOMAIN-SUFFIX,'+domain+',DIRECT' for domain in domains]
    cfg['rules']=additions+[r for r in rules if r not in additions]
    dns=cfg['dns'];policy=dns.setdefault('nameserver-policy',{});filters=dns.setdefault('fake-ip-filter',[])
    for domain in domains:
        policy['+.'+domain]='https://dns.alidns.com/dns-query'
        if '+.'+domain not in filters:filters.append('+.'+domain)
    return cfg
