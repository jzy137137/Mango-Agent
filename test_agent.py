"""Protocol and safety regression checks. ALL code/model observations here are synthetic."""
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import agent

class TestAgent(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.model_prompts = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if self.path == '/v1/chat/completions':
                    owner.model_prompts.append(data['messages'])
                    packet = None if data['messages'][0]['content'].startswith('Return strictly valid JSON') else json.loads(data['messages'][1]['content'])
                    if packet is None:
                        decision = {'status': 'ok'}
                    elif packet['round'] == 0:
                        decision = {'action':'tools','requests':[{'tool':'callers',
                            'args':{'address':'0x1000'},'reason':'synthetic: inspect caller'}]}
                    else:
                        decision = {'action':'finish','status':'insufficient_evidence',
                            'summary':'SYNTHETIC TEST ONLY: no dynamic evidence',
                            'evidence':[{'id':'E0002','claim':'synthetic caller inspected'}],
                            'missing_evidence':['external reachability'], 'next_steps':['manual review']}
                    result = {'choices':[{'message':{'content':json.dumps(decision)}}]}
                else:
                    owner.calls.append(data['method'])
                    values = {'get_metadata':{'sha256':'abc'},
                              'decompile_function':'SYNTHETIC_CODE_ONLY',
                              'get_callers':[{'address':'0x2000','name':'synthetic_caller'}]}
                    result = {'jsonrpc':'2.0','id':1,'result':values.get(data['method'])}
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        base = f'http://127.0.0.1:{self.server.server_port}'
        self.config = {'ida_url':base+'/mcp','llm_base_url':base+'/v1','llm_model':'synthetic',
                       'api_key_env':'SYNTHETIC_TEST_KEY','timeout_seconds':3,'max_rounds':3,
                       'max_tool_calls':5,'max_evidence_chars':10000}
        self.state = {'mode':'api-SYNTHETIC','status':'pending_model','candidate':
                      {'sink':{'function':'synthetic_sink','ins_addr':'0x1000'},'rank':0.7},
                      'binary_sha256':'abc','round':0,'seen':[],'tool_calls':0,'evidence':[]}
        self.ida = agent.IDA(self.config)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_http_agent_requests_more_evidence_and_writes_report(self):
        agent.check_identity({'sha256':'abc'},self.ida.metadata())
        agent.record(self.state,'decompile',{'address':'0x1000'},'seed',self.ida,self.config)
        with tempfile.TemporaryDirectory(dir=agent.ROOT) as folder, patch.dict('os.environ',{'SYNTHETIC_TEST_KEY':'synthetic-not-a-secret'}):
            agent.run_loop(Path(folder),self.state,self.ida,self.config)
            self.assertEqual(self.state['status'],'completed')
            self.assertIn('get_callers',self.calls)
            report = agent.read_json(Path(folder)/'report.json')
            self.assertEqual(report['dynamic_validation'],'not_performed')
            self.assertEqual(report['review']['status'],'insufficient_evidence')
            self.assertNotIn('synthetic-not-a-secret',(Path(folder)/'state.json').read_text())

    def test_wrong_binary_rejected(self):
        with self.assertRaises(ValueError):
            agent.check_identity({'sha256':'wrong'},self.ida.metadata())

    def test_unobserved_citation_rejected(self):
        with self.assertRaises(ValueError):
            agent.validate_finish({'status':'supported','summary':'x','evidence':[{'id':'FAKE','claim':'x'}],
                                   'missing_evidence':[],'next_steps':[]},self.state)

    def test_mutation_tool_rejected(self):
        with self.assertRaises(ValueError):
            self.ida.execute('rename_function',{'address':'0x1000'})

    def test_duplicate_requests_do_not_query_ida_twice(self):
        for _ in range(2):
            agent.record(self.state,'decompile',{'address':'0x1000'},'seed',self.ida,self.config)
        self.assertEqual(self.calls.count('decompile_function'),1)

    def test_exhausted_budget(self):
        self.state['tool_calls'] = 5
        result = agent.record(self.state,'decompile',{'address':'0x1000'},'seed',self.ida,self.config)
        self.assertEqual(result['error'],'tool_budget_exhausted')

    def test_context_truncation_preserves_original_evidence(self):
        original = 'X' * 12000
        self.state['evidence'] = [{'id':'E0001','ok':True,'result':original}]
        packet = agent.request_packet(self.state,self.config)
        self.assertTrue(packet['observations'][0]['truncated'])
        self.assertEqual(self.state['evidence'][0]['result'],original)

    def test_connection_probe_sends_no_firmware(self):
        with patch.dict('os.environ',{'SYNTHETIC_TEST_KEY':'synthetic-not-a-secret'}):
            result = agent.test_model(self.config)
        self.assertFalse(result['firmware_sent'])
        self.assertEqual(len(self.model_prompts[0]), 2)
        self.assertNotIn('candidate', json.dumps(self.model_prompts[0]))

    def test_saved_key_is_encrypted_and_retrievable(self):
        import credentials
        with tempfile.TemporaryDirectory(dir=agent.ROOT) as folder:
            path = Path(folder) / 'api-key.dpapi'
            with patch.object(credentials, 'KEY_FILE', path):
                credentials.save_key('dummy-key-for-test-only')
                self.assertNotIn(b'dummy-key-for-test-only', path.read_bytes())
                self.assertEqual(credentials.load_key('NONEXISTENT_MANGO_TEST_KEY'), 'dummy-key-for-test-only')

if __name__ == '__main__':
    unittest.main()
