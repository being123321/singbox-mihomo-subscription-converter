"""Avoid browser retry delays while respecting the existing ad selector."""
DOMAIN='data.bilibili.com'
SERVER='bili-ad-dns'
RESPONSE='bili-ad-response'

def apply(cfg):
    dns=cfg.get('dns',{})
    servers=dns.get('servers',[])
    if not any(x.get('tag')=='dns-adblock' for x in servers):return cfg
    server=next((x for x in servers if x.get('tag')==SERVER),None)
    if server is None:
        server={};servers.append(server)
    server.clear();server.update({'type':'https','tag':SERVER,'server':'223.5.5.5','path':'/dns-query','detour':'去广告'})
    rules=dns.setdefault('rules',[])
    rules[:]=[r for r in rules if not (r.get('server')==SERVER or r.get('match_response')==RESPONSE or (r.get('action')=='predefined' and r.get('rcode')=='NXDOMAIN' and r.get('domain_suffix')==[DOMAIN]))]
    rules[0:0]=[{'domain_suffix':[DOMAIN],'action':'evaluate','server':SERVER,'tag':RESPONSE,'timeout':'2s'},
                {'match_response':RESPONSE,'response_rcode':'NOERROR','action':'respond'},
                {'domain_suffix':[DOMAIN],'action':'predefined','rcode':'NXDOMAIN'}]
    return cfg
