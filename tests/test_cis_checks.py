import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cis_checks  # noqa: E402


class FakeIAMPolicy:
    def get_account_password_policy(self):
        return {
            "PasswordPolicy": {
                "MinimumPasswordLength": 16,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
            }
        }


class FakeEC2:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-closed",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                },
            ]
        }


def test_password_policy_accepts_strong_policy():
    results = cis_checks.check_password_policy(FakeIAMPolicy())
    assert results[0]["status"] == "PASS"


def test_sg_ssh_flags_only_the_open_group():
    results = cis_checks.check_sg_ssh(FakeEC2())
    by_group = {r["resource"]: r["status"] for r in results}
    assert by_group == {"sg-open": "FAIL", "sg-closed": "PASS"}


def test_sg_port_range_covers_rdp():
    results = cis_checks.check_sg_rdp(FakeEC2())
    assert all(r["status"] == "PASS" for r in results)


def test_metrics_match_report():
    import json

    out = os.path.join(os.path.dirname(__file__), "..", "outputs")
    metrics = json.load(open(os.path.join(out, "metrics.json")))
    report = json.load(open(os.path.join(out, "compliance_report.json")))
    assert metrics["resource_results"] == len(report["results"])
    assert metrics["pass"] + metrics["fail"] == metrics["resource_results"]
