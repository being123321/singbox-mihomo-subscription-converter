import unittest,json,base64
from urllib.parse import urlsplit,parse_qs
from subscriptions import *
from converter import generate

class SubscriptionTests(unittest.TestCase):
    def test_ua(self):
        for ua in ['sing-box/1.15','SFA/1.14','SFI (sing-box 1.14)','SFM/1.14']:self.assertEqual(detect_target(ua),'singbox')
        for ua in ['Clash.Meta/1.19','mihomo/1.19','FlClash/0.9']:self.assertEqual(detect_target(ua),'clash')
        for ua in ['v2rayN/7.0','v2rayNG/1.10','Shadowrocket/2500','Mozilla/5.0','']:self.assertEqual(detect_target(ua),'xray')
    def test_xhttp_adaptation(self):
        text='vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=xhttp&path=%2Fx&mode=auto#XHTTP\ntrojan://test@example.com:443#Trojan'
        nodes=parse_universal(text)
        clean,omitted=prepare(nodes,'singbox');self.assertEqual(len(clean),1);self.assertEqual(omitted,['XHTTP'])
        clean,omitted=prepare(nodes,'clash');self.assertEqual(len(clean),2)
        c=__import__('yaml').safe_load(generate(clean,'clash','mobile',False,'https://example.com',{})[0]);self.assertEqual(c['proxies'][0]['network'],'xhttp')
        data,_,count=uri_subscription(nodes,False);links=base64.b64decode(data).decode().splitlines();self.assertEqual(count,2)
        self.assertEqual(parse_qs(urlsplit(links[0]).query)['type'],['xhttp'])
    def test_uri_roundtrip(self):
        nodes=parse_universal('hy2://secret@example.com:443?sni=example.com#test')
        for insecure in [True,False]:
            data,_,_=uri_subscription(nodes,insecure);links=base64.b64decode(data).decode();n=parse_universal(links)[0]
            self.assertEqual(n['password'],'secret');self.assertEqual(n['tls']['insecure'],insecure)
    def test_manual_override(self):
        self.assertEqual(target_override('shadowrocket'),'xray')
        with self.assertRaises(ValueError):target_override('invalid')

if __name__=='__main__':unittest.main()
