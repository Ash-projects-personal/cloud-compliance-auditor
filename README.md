# Cloud compliance auditor: real CIS checks, mocked account

I rebuilt this project from scratch. The old version had two
halves that never met: a documented entry point that decided
pass or fail with a random coin flip and called that an audit,
and a file of genuine boto3 checks that the README never
mentioned and nothing ran. It also claimed automatic remediation
and a Security Hub score improvement. None of that code existed.
Those claims are gone.

This version is built around the part that was real: checks that
make genuine boto3 calls. I run them against a mocked AWS
environment with known states and score them on calling every
state correctly.

## The checks

`src/cis_checks.py` implements 8 read only checks:

- CIS-1.4 access keys rotated within 90 days
- CIS-1.5 account password policy strength
- CIS-1.10 MFA enabled for users with a console password
- CIS-2.1 S3 server access logging enabled
- CIS-2.3 S3 public access block enabled
- CIS-4.1 no security group opens port 22 to the world
- CIS-4.2 no security group opens port 3389 to the world
- CIS-4.3 VPC flow logs enabled

The same code runs against a real account unchanged. It never
modifies anything: there is no remediation in this tool, and I
do not claim any score improvement for any account.

## The test environment

`src/fixture_env.py` builds a mocked AWS account with moto:
users with and without console passwords and MFA, a weak password
policy set on purpose, buckets with logging on and off and public
access blocked and unblocked, security groups open and closed,
VPCs with no flow logs. Every resource's expected verdict is
recorded as it is built.

## Results

One run: 8 checks, 21 per resource results. By fixture design
12 of those states are compliant and 9 are not, and the checks
returned the expected verdict on 21 of 21 results, agreement
rate 1.0. Full results in `outputs/compliance_report.json` and
`outputs/metrics.json`.

Read those pass and fail counts for what they are: they describe
fixture states I chose, in a mock. The result that means
something is the agreement rate: the check logic correctly reads
real boto3 responses for every state I built, good and bad.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/run_audit.py
python -m pytest tests/
```

## Limits

- Moto is not AWS. A few behaviours differ (resource IDs are
  random per run, and some services are shallower than the real
  ones). The checks would need a run against a real account
  before I trusted them in production, and that run has not
  happened.
- CloudTrail and RDS controls are not implemented. The old
  README listed them; listing a control is not checking it, so
  they stay out until there is code.

## Files

- `src/cis_checks.py` the 8 checks, written against boto3
- `src/fixture_env.py` the mocked environment and its expected verdicts
- `src/run_audit.py` builds the mock, runs the checks, scores, writes outputs
- `EXPLAIN.md` how it works and what was re scoped
