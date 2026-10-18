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
