import importlib
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from converter import RULES, generate, parse_source


class AppTests(unittest.TestCase):
    def test_more_than_five_subscriptions(self):
        import app
        urls = ['https://sub.example.com:' + str(9000 + i) for i in range(12)]
        with patch.object(app, 'fetch', return_value='trojan://test@example.com:443#test') as fetch:
            result = app.nodes_for({'input': 'url', 'source': '\n'.join(urls)})
            self.assertEqual(len(result), 12)
            self.assertEqual(fetch.call_count, 12)

    def test_arbitrary_public_subscription_ports(self):
        import app
        import socket
        from unittest.mock import MagicMock
        for scheme in ('http', 'https'):
            for port in (1, 22, 9000, 65535):
                response = MagicMock(status=200)
                response.read.return_value = b'content'
                connection = MagicMock()
                connection.getresponse.return_value = response
                constructor = 'HTTPSConnection' if scheme == 'https' else 'HTTPConnection'
                with patch.object(app.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]), patch.object(app.http.client, constructor, return_value=connection) as connect:
                    self.assertEqual(app.fetch(f'{scheme}://sub.example.com:{port}/sub'), 'content')
                    self.assertEqual(connect.call_args.args[1], port)
        with patch.object(app.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 9000))]):
            with self.assertRaises(ValueError):
                app.fetch('http://sub.example.com:9000/sub')

    def test_domestic_direct_before_proxy(self):
        import yaml
        nodes = parse_source('trojan://test@example.com:443#test')
        for enabled in (True, False):
            sb = json.loads(generate(nodes, 'singbox', 'mobile', False, 'https://sub.example.com', {}, 'tun', enabled)[0])
            rules = sb['route']['rules']
            position = {r['rule_set']: i for i, r in enumerate(rules) if isinstance(r.get('rule_set'), str)}
            for name in ('ChinaDomain', 'ChinaCompanyIp', 'ChinaIp'):
                self.assertLess(position[name], position['ProxyLite'])
                self.assertEqual(rules[position[name]]['outbound'], 'DIRECT')
            if enabled:
                self.assertLess(position['HeidaiAd'], position['ChinaDomain'])
            cfg = yaml.safe_load(generate(nodes, 'clash', 'mobile', False, 'https://sub.example.com', {}, 'tun', enabled)[0])
            for name in ('ChinaDomain', 'ChinaCompanyIp', 'ChinaIp'):
                self.assertLess(cfg['rules'].index(f'RULE-SET,{name},DIRECT'), cfg['rules'].index('RULE-SET,ProxyLite,PROXY'))
            self.assertIn('rule-set:ChinaDomain', cfg['dns']['nameserver-policy'])

    def test_tencent_priority_and_dns_without_adblock(self):
        import yaml
        nodes = parse_source('trojan://test@example.com:443#test')
        for enabled in (True, False):
            sb = json.loads(generate(nodes, 'singbox', 'mobile', False,
                                     'https://sub.example.com', {}, 'tun', enabled)[0])
            routing = sb['route']['rules']
            tencent = next(i for i, r in enumerate(routing) if r.get('rule_set') == 'Ruleset_Tencent')
            self.assertEqual(routing[tencent]['outbound'], 'DIRECT')
            self.assertEqual(sb['dns']['rules'][0]['rule_set'], 'Tencent-DNS')
            if enabled:
                self.assertLess(tencent, next(i for i, r in enumerate(routing) if r.get('rule_set') == 'HeidaiAd'))
            else:
                self.assertFalse(any(r.get('server') == 'dns-adblock' for r in sb['dns']['rules']))
            clash = yaml.safe_load(generate(nodes, 'clash', 'mobile', False,
                                           'https://sub.example.com', {}, 'tun', enabled)[0])
            self.assertIn('rule-set:Ruleset_Tencent', clash['dns']['nameserver-policy'])
            if enabled:
                self.assertLess(clash['rules'].index('RULE-SET,Ruleset_Tencent,DIRECT'),
                                next(i for i, r in enumerate(clash['rules']) if r.startswith('RULE-SET,HeidaiAd,')))

    def test_every_generated_rule_url_is_served(self):
        # No downloads or real subscriber data: seed files and exercise the HTTP handler.
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'DATA_DIR': directory}):
            import app
            app = importlib.reload(app)
            rules = Path(directory) / 'rules'
            rules.mkdir()
            for name, _ in RULES:
                for extension in ('json', 'yaml'):
                    (rules / (name.replace('/', '_') + '.' + extension)).write_text('{}')
            for name in ('ChinaDomain-DNS.json', 'Tencent-DNS.json', 'HeidaiAd.srs', 'HeidaiAd.mrs'):
                (rules / name).write_text('{}')
            server = app.Server(('127.0.0.1', 0), app.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = 'http://127.0.0.1:' + str(server.server_port)
                nodes = parse_source('trojan://test@example.com:443#test')
                cfg = json.loads(generate(nodes, 'singbox', 'mobile', False, base, {})[0])
                for rule in cfg['route']['rule_set']:
                    with urllib.request.urlopen(rule['url']) as response:
                        self.assertEqual(response.status, 200, rule['tag'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
