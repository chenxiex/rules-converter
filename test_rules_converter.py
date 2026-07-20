import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("rules-converter.py")
SPEC = importlib.util.spec_from_file_location("rules_converter", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
rules_converter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules_converter)


class ClashOutputTests(unittest.TestCase):
    def test_clash_format_is_available(self) -> None:
        args = rules_converter.build_parser().parse_args(
            ["input.json", "output", "--to-format", "clash"]
        )
        self.assertEqual(args.to_format, "clash")

    def test_writes_classical_yaml_without_outbound_tag(self) -> None:
        rules = [
            {
                "outboundTag": "proxy",
                "domain": [
                    "full:api.example.com",
                    "domain:example.com",
                    "keyword:example",
                    "regexp:^www\\d+\\.example\\.com$",
                    "geosite:google",
                ],
            },
            {
                "outboundTag": "direct",
                "ip": ["127.0.0.1", "2001:db8::/32", "geoip:cn"],
            },
            {
                "outboundTag": "direct",
                "port": "53,443,1000-2000",
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            rules_converter.write_rules(rules, output, "clash")

            self.assertEqual(
                (output / "proxy.yaml").read_text(encoding="utf-8").splitlines(),
                [
                    "payload:",
                    '  - "DOMAIN,api.example.com"',
                    '  - "DOMAIN-SUFFIX,example.com"',
                    '  - "DOMAIN-KEYWORD,example"',
                    r'  - "DOMAIN-REGEX,^www\\d+\\.example\\.com$"',
                    '  - "GEOSITE,google"',
                ],
            )
            direct = (output / "direct.yaml").read_text(encoding="utf-8")
            self.assertEqual(
                direct.splitlines(),
                [
                    "payload:",
                    '  - "IP-CIDR,127.0.0.1/32"',
                    '  - "IP-CIDR6,2001:db8::/32"',
                    '  - "GEOIP,CN"',
                    '  - "DST-PORT,53/443/1000-2000"',
                ],
            )
            self.assertNotIn("direct", direct)

    def test_preserves_and_and_inverse_ip_semantics(self) -> None:
        rule = {
            "outboundTag": "proxy",
            "domain": ["domain:example.com", "geosite:google"],
            "ip": ["!geoip:cn", "!geoip:us", "geoip:telegram"],
            "network": "tcp",
        }

        self.assertEqual(
            rules_converter.xray_rule_to_clash_lines(rule),
            [
                "AND,((OR,((DOMAIN-SUFFIX,example.com),(GEOSITE,google))),"
                "(OR,((GEOIP,TELEGRAM),(AND,((NOT,((GEOIP,CN))),"
                "(NOT,((GEOIP,US))))))),(NETWORK,tcp))"
            ],
        )

    def test_omits_rule_with_unsupported_and_condition(self) -> None:
        rule = {
            "outboundTag": "proxy",
            "domain": ["domain:example.com"],
            "protocol": ["bittorrent"],
        }
        self.assertEqual(rules_converter.xray_rule_to_clash_lines(rule), [])

    def test_omits_dst_port_catch_all(self) -> None:
        self.assertEqual(
            rules_converter.xray_rule_to_clash_lines(
                {"outboundTag": "proxy", "port": "0-65535"}
            ),
            [],
        )
        self.assertEqual(
            rules_converter.xray_rule_to_clash_lines(
                {
                    "outboundTag": "proxy",
                    "domain": ["domain:example.com"],
                    "port": "0-65535",
                }
            ),
            ["DOMAIN-SUFFIX,example.com"],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            rules_converter.write_clash(
                [
                    {
                        "outboundTag": "direct",
                        "domain": ["domain:example.com"],
                    },
                    {"outboundTag": "direct", "port": "0-65535"},
                ],
                output,
            )
            direct = (output / "direct.yaml").read_text(encoding="utf-8")
            self.assertNotIn("DST-PORT,0-65535", direct)


if __name__ == "__main__":
    unittest.main()
