"""No network, wallets, payer keys or real commands.

Regression coverage for maintainer-requested followup to #27:
legacy priced CLI call, public witness --checks and chat protect KEY=VALUE,
plus numeric-overflow bypass of strict_json.
"""
from contextlib import redirect_stdout, redirect_stderr
import io
import types
import unittest
from unittest.mock import patch

import swarmmemo as memo


class JsonBoundarySweep(unittest.TestCase):
    def test_strict_parser_rejects_exponent_overflow_to_nonfinite_floats(self):
        for raw in ['{"price":1e999}', '{"price":-1e999}',
                    '{"items":[1e999]}', '{"nested":{"fee":1e999}}']:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "invalid_json_number"):
                    memo.strict_json(raw)

    def test_strict_parser_allows_ordinary_floats_and_nested_object_values(self):
        self.assertEqual(memo.strict_json('{"price":0.125,"i":2,"data":{"b":true}}'),
                         {"price":0.125,"i":2,"data":{"b":True}})

    def test_original_legacy_call_cli_rejects_invalid_paid_args_without_dispatch(self):
        calls = []

        class FakeNoNetwork:
            def service_method(self, *args):
                calls.append(args)
                return {"ok":True}

        invalids = [
            '{"to":"expected","to":"hidden"}',
            '{"nested":{"recipient":"one","recipient":"two"}}',
            '{"amount":NaN}', '{"amount":Infinity}',
            '{"amount":-Infinity}', '{"amount":1e999}',
        ]
        with patch.object(memo, "Client", return_value=FakeNoNetwork()):
            for raw in invalids:
                with self.subTest(raw=raw):
                    out,err=io.StringIO(),io.StringIO()
                    with redirect_stdout(out),redirect_stderr(err):
                        rc=memo.main(["call","service","write",raw,"--max-cost","5"])
                    self.assertEqual(rc,1)
                    self.assertEqual(calls,[], "Malformed paid request must never dispatch")
                    self.assertIn("ValueError",err.getvalue())
                    self.assertNotIn(raw,err.getvalue(), "Redact original input from CLI error")

    def test_original_legacy_call_valid_object_remains_usable(self):
        calls=[]

        class FakeNoNetwork:
            def service_method(self,*args):
                calls.append(args)
                return {"ok":True}

        with patch.object(memo, "Client", return_value=FakeNoNetwork()):
            with redirect_stdout(io.StringIO()):
                rc=memo.main(["call","service","write",
                    '{"amount":0.25,"nested":{"to":"example"}}',
                    "--max-cost","5"])
        self.assertEqual(rc,0)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][:3],
            ("service","write",{"amount":0.25,"nested":{"to":"example"}}))
        self.assertEqual(calls[0][3],5)

    def test_witness_checks_rejects_nonstandard_duplicate_json_before_auth(self):
        prefix=["witness","AGENT","url","https://example.org",
                "--nonce","n"*24,"--verdict","verified","--checks"]
        invalid=[
            '[{"property":"signature","state":"pass","state":"fail"}]',
            '[{"property":"signature","score":NaN}]',
            '[{"property":"signature","score":Infinity}]',
            '[{"property":"signature","score":1e999}]',
        ]
        parser=memo.build_parser()
        for raw in invalid:
            with self.subTest(raw=raw):
                out,err=io.StringIO(),io.StringIO()
                with redirect_stdout(out),redirect_stderr(err):
                    with self.assertRaises(SystemExit) as captured:
                        parser.parse_args(prefix+[raw])
                self.assertEqual(captured.exception.code,2)

    def test_witness_checks_preserves_valid_list_type(self):
        checks=[{"property":"signature","state":"pass","confidence":0.95}]
        # No network: argparse parses only.
        args=memo.build_parser().parse_args([
            "witness","AGENT","url","https://example.org",
            "--nonce","n"*24,"--verdict","verified",
            "--checks",'[{"property":"signature","state":"pass","confidence":0.95}]'
        ])
        self.assertEqual(args.checks,checks)

    def test_chat_protect_user_provided_object_refuses_ambiguous_keys(self):
        sends=[]
        def fake(raw):
            context=types.SimpleNamespace(
                args=types.SimpleNamespace(
                    protect_action="set",pairs=["outbound.actions="+raw]
                ),
                set_messaging=lambda **kw:sends.append(kw),
                settings_own=lambda:{},
                say=lambda msg:None
            )
            return memo.Chat.protect(context)
        for raw in ('{"phishing":"hold","phishing":"warn"}',
                    '{"phishing":NaN}', '{"phishing":1e999}',
                    '{"phishing":"hold"'):
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError,memo.ChatStop)):
                    fake(raw)
                self.assertEqual(sends,[])

    def test_chat_protect_accepts_existing_plain_and_valid_json(self):
        writes=[]

        def fake(pairs):
            x=types.SimpleNamespace(
                args=types.SimpleNamespace(protect_action="set",pairs=pairs),
                set_messaging=lambda **kw:writes.append(kw),
                settings_own=lambda:{"inbound":{},"outbound":{}},
                say=lambda msg:None
            )
            memo.Chat.protect(x)

        fake(["inbound.mode=server",
              "inbound.threshold=0.7",
              "inbound.categories=prompt_injection,phishing",
              'outbound.actions={"phishing":"hold"}'])
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0]["inbound"]["mode"],"server")
        self.assertEqual(writes[0]["inbound"]["threshold"],0.7)
        self.assertEqual(writes[0]["inbound"]["categories"],["prompt_injection","phishing"])
        self.assertEqual(writes[0]["outbound"]["actions"],{"phishing":"hold"})


if __name__=="__main__":
    unittest.main()
