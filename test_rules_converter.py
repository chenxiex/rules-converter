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


class ClashSingleTests(unittest.TestCase):
    def test_format_is_available_for_input_and_output(self) -> None:
        args = rules_converter.build_parser().parse_args(
            [
                "input.yaml",
                "output.json",
                "--from-format",
                "clash-single",
            ]
        )
        self.assertEqual(args.from_format, "clash-single")

        args = rules_converter.build_parser().parse_args(
            ["input.json", "output.yaml", "--to-format", "clash-single"]
        )
        self.assertEqual(args.to_format, "clash-single")

    def test_writes_one_rules_file_with_mapped_policies(self) -> None:
        rules = [
            {
                "outboundTag": "proxy",
                "domain": ["full:api.example.com", "domain:example.com"],
            },
            {"outboundTag": "direct", "ip": ["127.0.0.1"]},
            {"outboundTag": "block", "domain": ["keyword:ads"]},
            {"outboundTag": "Work Group", "network": "udp"},
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "rules.yaml"
            rules_converter.write_rules(rules, output, "clash-single")
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                [
                    "rules:",
                    '  - "DOMAIN,api.example.com,PROXY"',
                    '  - "DOMAIN-SUFFIX,example.com,PROXY"',
                    '  - "IP-CIDR,127.0.0.1/32,DIRECT"',
                    '  - "DOMAIN-KEYWORD,ads,REJECT"',
                    '  - "NETWORK,udp,Work Group"',
                ],
            )

    def test_reads_rules_and_maps_policies_to_outbound_tags(self) -> None:
        content = """\
rules:
- DOMAIN,api.example.com,PROXY
- 'DOMAIN-SUFFIX,example.com,DIRECT'
- "GEOIP,CN,REJECT"
- DST-PORT,53/443,Custom Group
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "rules.yaml"
            input_path.write_text(content, encoding="utf-8")
            self.assertEqual(
                rules_converter.read_rules(input_path, "clash-single"),
                [
                    {
                        "outboundTag": "proxy",
                        "domain": ["full:api.example.com"],
                        "enabled": True,
                    },
                    {
                        "outboundTag": "direct",
                        "domain": ["domain:example.com"],
                        "enabled": True,
                    },
                    {
                        "outboundTag": "block",
                        "ip": ["geoip:cn"],
                        "enabled": True,
                    },
                    {
                        "outboundTag": "Custom Group",
                        "port": "53,443",
                        "enabled": True,
                    },
                ],
            )

    def test_round_trips_generated_logical_rule(self) -> None:
        source_rule = {
            "outboundTag": "proxy",
            "domain": ["domain:example.com", "geosite:google"],
            "ip": ["geoip:telegram", "!geoip:cn", "!geoip:us"],
            "network": "tcp",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "rules.yaml"
            rules_converter.write_clash_single([source_rule], output)
            self.assertEqual(
                rules_converter.read_clash_single(output),
                [{**source_rule, "enabled": True}],
            )

    def test_preserves_rule_order_and_writes_catch_all_as_match(self) -> None:
        rules = [
            {
                "outboundTag": "proxy",
                "domain": ["domain:example.com"],
            },
            {"outboundTag": "direct", "port": "0-65535"},
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "rules.yaml"
            rules_converter.write_clash_single(rules, output)
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                [
                    "rules:",
                    '  - "DOMAIN-SUFFIX,example.com,PROXY"',
                    '  - "MATCH,DIRECT"',
                ],
            )

    def test_writes_conditionless_and_routing_all_rules_as_match(self) -> None:
        rules = [
            {"outboundTag": "proxy"},
            {"outboundTag": "block", "all": []},
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "rules.yaml"
            rules_converter.write_clash_single(rules, output)
            self.assertEqual(
                output.read_text(encoding="utf-8").splitlines(),
                ["rules:", '  - "MATCH,PROXY"', '  - "MATCH,REJECT"'],
            )

    def test_yaml_extension_is_inferred_as_clash_single(self) -> None:
        self.assertEqual(
            rules_converter.infer_input_format(Path("rules.yml")),
            "clash-single",
        )
        self.assertEqual(
            rules_converter.infer_output_format(Path("rules.yaml")),
            "clash-single",
        )


if __name__ == "__main__":
    unittest.main()
