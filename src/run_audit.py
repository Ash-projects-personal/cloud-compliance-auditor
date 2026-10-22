"""Run the CIS checks against the mocked fixture environment.

The environment is moto, an AWS mock running in this process. It
is labelled as mocked everywhere because it is: no real account is
touched. What is real is the check logic in cis_checks.py, which
makes genuine boto3 calls and is scored here against the known
fixture states.

Writes outputs/compliance_report.json, outputs/metrics.json and
outputs/run_log.txt.
"""
import json
import os
import sys
from datetime import datetime, timezone

import boto3
from moto import mock_aws

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from cis_checks import run_all_checks  # noqa: E402
from fixture_env import build_fixture  # noqa: E402

OUT = os.path.join(ROOT, "outputs")
REGION = "us-east-1"


def main():
    os.makedirs(OUT, exist_ok=True)
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    stamp = datetime.now(timezone.utc).isoformat()
    log = [
        "cloud compliance auditor rebuild run at %s" % stamp,
        "environment: moto mocked AWS (NOT a real account), region %s" % REGION,
    ]

    with mock_aws():
        clients = {
            "iam": boto3.client("iam", region_name=REGION),
            "s3": boto3.client("s3", region_name=REGION),
            "ec2": boto3.client("ec2", region_name=REGION),
        }
        expected = build_fixture(clients)
        results = run_all_checks(clients)

    matched = 0
    mismatches = []
    for r in results:
        want = expected.get((r["check_id"], r["resource"]))
        r["expected"] = want
        if want is None:
            mismatches.append("no expectation recorded for %s %s" % (r["check_id"], r["resource"]))
        elif want == r["status"]:
            matched += 1
        else:
            mismatches.append(
                "%s %s expected %s got %s" % (r["check_id"], r["resource"], want, r["status"])
            )
    unrun = [
        "%s %s" % k for k in expected if not any(
            (r["check_id"], r["resource"]) == k for r in results
        )
    ]
    mismatches.extend("expected result never produced for %s" % k for k in unrun)

    passes = sum(1 for r in results if r["status"] == "PASS")
    fails = sum(1 for r in results if r["status"] == "FAIL")
    metrics = {
        "environment": "moto mocked AWS environment with known fixture states (not a real account)",
        "checks_run": len({r["check_id"] for r in results}),
        "resource_results": len(results),
        "pass": passes,
        "fail": fails,
        "note": "pass and fail counts describe the fixture states I designed, not any real account. The measured result of this run is the agreement rate between check verdicts and fixture expectations.",
        "verdicts_matching_fixture_expectation": matched,
        "verdicts_total": len(results),
        "agreement_rate": round(matched / len(results), 3) if results else 0.0,
        "mismatches": mismatches,
        "run_at": stamp,
    }
    report = {
        "generated_at": stamp,
        "environment": metrics["environment"],
        "results": results,
        "summary": metrics,
    }
    with open(os.path.join(OUT, "compliance_report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    with open(os.path.join(OUT, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    for r in results:
        log.append(
            "%-8s %-28s %-28s %s (%s)"
            % (r["check_id"], r["control"], r["resource"], r["status"], r["detail"])
        )
    log.append(
        "results %d, pass %d, fail %d, matched fixture expectation %d/%d"
        % (len(results), passes, fails, matched, len(results))
    )
    if mismatches:
        log.append("MISMATCHES: %s" % "; ".join(mismatches))
    with open(os.path.join(OUT, "run_log.txt"), "w") as f:
        f.write("\n".join(log) + "\n")
    print("\n".join(log))


if __name__ == "__main__":
    main()
