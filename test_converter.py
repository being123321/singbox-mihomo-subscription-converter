import base64, json, unittest, socket
from unittest.mock import patch
from converter import *

class ConversionTests(unittest.TestCase):
    def test_url_and_base64(self):
        link='vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=1234&fp=chrome&flow=xtls-rprx-vision#test'
        nodes=parse_source(base64.b64encode(link.encode()).decode())
        self.assertEqual(nodes[0]['tls']['reality']['short_id'],'1234')
        self.assertFalse(normalize(nodes,False)[0]['tls']['insecure'])
        self.assertTrue(normalize(nodes,True)[0]['tls']['insecure'])
        self.assertEqual(nodes[0]['tag'],'test')
    def test_yaml_hy2_roundtrip(self):
        p={'name':'HY2','type':'hysteria2','server':'example.com','port':443,'password':'test','sni':'example.com','skip-cert-verify':True,'obfs':'salamander','obfs-password':'secret'}
        nodes=parse_source(yaml.safe_dump({'proxies':[p]}))
        c=to_clash(normalize(nodes,False)[0]); self.assertFalse(c['skip-cert-verify']);self.assertEqual(c['obfs-password'],'secret')
    def test_ss_uri_and_duplicates(self):
        auth=base64.b64encode(b'aes-128-gcm:secret').decode().rstrip('=')
        n=parse_source(f'ss://{auth}@example.com:8443#PROXY')
        self.assertEqual(n[0]['password'],'secret');self.assertEqual(normalize(n+n)[1]['tag'],'PROXY (3)')
    def test_profiles(self):
        nodes=parse_source('trojan://secret@example.com:443#test')
        for fmt in ['singbox','clash']:
            for device in ['mobile','desktop']:
                text,ctype=generate(nodes,fmt,device,False,'https://sub.example.com',{})
                c=yaml.safe_load(text)
                self.assertTrue(c.get('inbounds') if fmt=='singbox' else c.get('proxies'))
                if fmt=='singbox':self.assertEqual(c['inbounds'][0]['type'],'tun' if device=='mobile' else 'mixed')
    def test_rules(self):
        sb,clash=convert_rules('DOMAIN-SUFFIX,example.cn\nIP-CIDR,1.2.3.0/24,no-resolve\nIP-CIDR6,2001:db8::/32')
        self.assertEqual(next(r['ip_cidr'] for r in sb['rules'] if 'ip_cidr' in r),['1.2.3.0/24','2001:db8::/32'])
        self.assertTrue(all(len(r)==1 for r in sb['rules']))
        self.assertEqual(clash['payload'][1],'IP-CIDR,1.2.3.0/24')
        with self.assertRaises(ValueError):convert_rules('UNSUPPORTED,test')
    def test_desktop_tun_and_migration(self):
        nodes=parse_source('trojan://secret@example.com:443#test')
        text,_=generate(nodes,'singbox','desktop',False,'https://sub.example.com',{},'tun')
        cfg=json.loads(text)
        self.assertEqual([x['type'] for x in cfg['inbounds']],['tun','mixed','mixed'])
        self.assertNotIn('stack',cfg['inbounds'][0])
        self.assertEqual(cfg['route']['default_http_client'],'rules-download')
        self.assertNotIn('detour',cfg['http_clients'][0])
        self.assertIn('ChinaDomain-DNS',next(r['rule_set'] for r in cfg['dns']['rules'] if isinstance(r.get('rule_set'),list)))
        self.assertNotIn('ChinaDomain',next(r['rule_set'] for r in cfg['dns']['rules'] if isinstance(r.get('rule_set'),list)))
        self.assertTrue(all(r['http_client']=='rules-download' for r in cfg['route']['rule_set']))
        c=yaml.safe_load(generate(nodes,'clash','desktop',False,'https://sub.example.com',{},'tun')[0])
        self.assertTrue(c['tun']['enable'])
        c=yaml.safe_load(generate(nodes,'clash','desktop',False,'https://sub.example.com',{},'proxy')[0])
        self.assertNotIn('tun',c)
    def test_rejection_and_failover_groups(self):
        n=parse_source('trojan://test@example.com:443#test')
        c=yaml.safe_load(generate(n,'clash','mobile',False,'https://sub.example.com',{})[0])
        g={x['name']:x for x in c['proxy-groups']}
        self.assertEqual(g['全球拦截']['proxies'][0],'REJECT')
        self.assertEqual(g['故障转移']['type'],'fallback')
        self.assertEqual(g['PROXY']['proxies'][0],'AUTO')
        self.assertNotIn('故障转移',g['PROXY']['proxies'])
        self.assertIn('RULE-SET,BanAD,去广告',c['rules'])
        s=json.loads(generate(n,'singbox','mobile',False,'https://sub.example.com',{})[0])
        g={x['tag']:x for x in s['outbounds']}
        self.assertEqual(g['全球拦截']['default'],'REJECT')
        self.assertEqual(g['REJECT']['type'],'block')
        self.assertEqual(g['故障转移']['type'],'urltest')
        self.assertNotIn('故障转移',g['PROXY']['outbounds'])
        self.assertEqual(g['PROXY']['default'],'AUTO')
    def test_adblock_switch_controls_both_layers(self):
        n=parse_source('trojan://test@example.com:443#test')
        for enabled in [True,False]:
            c=yaml.safe_load(generate(n,'clash','mobile',False,'https://sub.example.com',{},'tun',enabled)[0])
            self.assertEqual('HeidaiAd' in c['rule-providers'],enabled)
            self.assertEqual('rule-set:HeidaiAd' in c['dns']['nameserver-policy'],enabled)
            self.assertEqual(any(r.endswith(',去广告') for r in c['rules']),enabled)
            s=json.loads(generate(n,'singbox','mobile',False,'https://sub.example.com',{},'tun',enabled)[0])
            self.assertEqual(any(r.get('server')=='dns-adblock' for r in s['dns']['rules']),enabled)
            self.assertEqual(any(r.get('outbound')=='去广告' for r in s['route']['rules']),enabled)
    def test_reject_incompatible(self):
        with self.assertRaises(ValueError):parse_source('vless://id@example.com:443?type=xhttp')
        with self.assertRaises(ValueError):parse_source(yaml.safe_dump({'proxies':[{'type':'ssr'}]}))
        n=parse_source('trojan://test@example.com:443')[0];n['tls']['certificate_path']='/etc/private'
        with self.assertRaises(ValueError):to_clash(n)
    def test_ssrf(self):
        from app import fetch
        for url in ['http://127.0.0.1/','http://169.254.169.254/','http://[::1]/','file:///etc/passwd','http://example.com:0/','http://example.com:65536/']:
            with self.assertRaises(ValueError):fetch(url)
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',443))]):
            with self.assertRaises(ValueError):fetch('https://public.example/')

if __name__=='__main__':
    import socket
    unittest.main()

class ClashAPITests(unittest.TestCase):
    def test_loopback_auth_and_disable(self):
        nodes=parse_source('trojan://example-secret@example.com:443#test')
        for fmt in ['singbox','clash']:
            for enabled in [True,False]:
                cfg=yaml.safe_load(generate(nodes,fmt,'desktop',False,'https://example.com',{},clash_api=enabled,api_secret='test-secret-abcdefghijklmnop')[0])
                api=cfg.get('experimental',{}).get('clash_api',{}) if fmt=='singbox' else cfg
                field='external_controller' if fmt=='singbox' else 'external-controller'
                self.assertEqual(field in api,enabled)
                if enabled:
                    self.assertEqual(api[field],'127.0.0.1:9090')
                    self.assertEqual(api['secret'],'test-secret-abcdefghijklmnop')
                else: self.assertNotIn('secret',api)

class ToutiaoTests(unittest.TestCase):
    def test_toutiao_precedes_adblock(self):
        nodes=parse_source('trojan://test@example.com:443#test')
        for fmt in ['singbox','clash']:
            cfg=yaml.safe_load(generate(nodes,fmt,'desktop',False,'https://example.com',{})[0])
            if fmt=='singbox':
                route=cfg['route']['rules'];dns=cfg['dns']['rules']
                allow=next(i for i,r in enumerate(route) if 'toutiao.com' in r.get('domain_suffix',[]))
                block=next(i for i,r in enumerate(route) if r.get('outbound')=='去广告')
                self.assertLess(allow,block);self.assertEqual(route[allow]['outbound'],'DIRECT')
                self.assertTrue({'snssdk.com','toutiaostatic.com','bytegecko.com','api-normal-toutiao-v3.doubao.com'}.issubset(next(x['domain_suffix'] for x in dns if 'toutiao.com' in x.get('domain_suffix',[]))));self.assertEqual(next(x['server'] for x in dns if 'toutiao.com' in x.get('domain_suffix',[])),'dns-local')
            else:
                self.assertLess(cfg['rules'].index('DOMAIN-SUFFIX,toutiao.com,DIRECT'),cfg['rules'].index('RULE-SET,HeidaiAd,去广告'))
                self.assertEqual(cfg['dns']['nameserver-policy']['+.snssdk.com'],['https://223.5.5.5/dns-query','https://doh.pub/dns-query'])
                self.assertIn('+.toutiao.com',cfg['dns']['fake-ip-filter'])

class EncryptedDNSTests(unittest.TestCase):
    def test_encrypted_backup_and_idempotence(self):
        import dns_policy
        nodes=parse_source('trojan://test@example.com:443#test')
        cfg=json.loads(generate(nodes,'singbox','desktop',False,'https://example.com',{})[0])
        self.assertEqual(cfg,dns_policy.singbox(json.loads(json.dumps(cfg))))
        self.assertTrue(all(x['type']=='https' for x in cfg['dns']['servers']))
        self.assertEqual(next(x for x in cfg['dns']['servers'] if x['tag']=='dns-tencent')['tls']['server_name'],'doh.pub')
        self.assertTrue(any(x.get('action')=='evaluate' and x.get('timeout')=='2s' for x in cfg['dns']['rules']))
        self.assertTrue(any(x.get('server')=='dns-tencent' and x.get('action')=='route' for x in cfg['dns']['rules']))
        clash=yaml.safe_load(generate(nodes,'clash','desktop',False,'https://example.com',{})[0])
        self.assertTrue(all(x.startswith('https://') for x in clash['dns']['default-nameserver']))
        self.assertEqual(clash['dns']['nameserver-policy']['+.toutiao.com'],[dns_policy.PRIMARY,dns_policy.BACKUP])

class OwnedDomainTests(unittest.TestCase):
    def test_owned_domains_precede_proxy_and_adblock(self):
        import direct_domains,dns_policy
        domains=['example.com','tenant.eu.org']
        nodes=parse_source('trojan://test@example.net:443#test')
        with patch('converter.configured_domains',return_value=domains):
            sb=json.loads(generate(nodes,'singbox','desktop',False,'https://example.net',{})[0])
            r=next(x for x in sb['route']['rules'] if x.get('domain_suffix')==domains)
            self.assertEqual(r['outbound'],'DIRECT')
            self.assertLess(sb['route']['rules'].index(r),next(i for i,x in enumerate(sb['route']['rules']) if x.get('outbound')=='去广告'))
            self.assertTrue(any(r.get('domain_suffix')==domains and r.get('server')=='dns-local' for r in sb['dns']['rules']))
            self.assertEqual(sb,dns_policy.singbox(__import__('bili_dns').apply(direct_domains.singbox(json.loads(json.dumps(sb)),domains))))
            cl=yaml.safe_load(generate(nodes,'clash','desktop',False,'https://example.net',{})[0])
            self.assertEqual(cl['rules'][:2],['DOMAIN-SUFFIX,example.com,DIRECT','DOMAIN-SUFFIX,tenant.eu.org,DIRECT'])
            self.assertEqual(cl['dns']['nameserver-policy']['+.example.com'],[dns_policy.PRIMARY,dns_policy.BACKUP])
            self.assertNotIn('DOMAIN-SUFFIX,eu.org,DIRECT',cl['rules'])
            self.assertNotIn('DOMAIN-SUFFIX,cloudflare.com,DIRECT',cl['rules'])

class BiliDNSTests(unittest.TestCase):
    def test_fast_failure_respects_adblock_switch(self):
        import bili_dns,dns_policy
        nodes=parse_source('trojan://test@example.net:443#test')
        for enabled in [True,False]:
            cfg=json.loads(generate(nodes,'singbox','desktop',False,'https://example.net',{},adblock=enabled)[0])
            self.assertEqual(any(x.get('tag')==bili_dns.SERVER for x in cfg['dns']['servers']),enabled)
            if enabled:
                server=next(x for x in cfg['dns']['servers'] if x['tag']==bili_dns.SERVER)
                self.assertEqual(server['type'],'https');self.assertEqual(server['detour'],'去广告')
                self.assertEqual(cfg['dns']['rules'][0]['domain_suffix'],[bili_dns.DOMAIN])
                self.assertEqual(cfg['dns']['rules'][2]['rcode'],'NXDOMAIN')
                self.assertEqual(cfg,dns_policy.singbox(bili_dns.apply(json.loads(json.dumps(cfg)))))
