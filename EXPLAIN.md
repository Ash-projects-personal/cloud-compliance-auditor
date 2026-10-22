# How this works, in plain words

## Why a mocked account

I have no AWS account I am free to publish audit results from,
and a checker that never runs proves nothing. Moto stands up a
fake AWS inside the process that answers real boto3 calls. So
the checks do the exact work they would do on a real account:
list the users, read the password policy, ask each bucket about
its logging and public access settings, read the security
groups, look for flow logs. The fixture builds each resource in
a state I picked, half compliant and half not, and writes down
the verdict each one should get. If a check misreads a response,
the agreement count shows it.

## How a check is written

Each check is a small function over one service client. It asks
the API for the facts, applies the CIS rule to those facts, and
returns one result per resource with the reason in plain words
(for example, which password policy settings failed). No check
catches a random number, and no check edits anything.

Two design points worth knowing in an interview:

- The S3 public access check treats a missing configuration as a
  failure, because the API raises an error when no block exists
  and that absence is exactly the non compliant state.
- The security group checks test whether the port falls inside
  each rule's port range and whether any range is 0.0.0.0/0, so
  a rule opening a wide range that covers port 22 is flagged,
  not just an exact port 22 rule.

## What was re scoped and why

The original project claimed it audited real environments,
automatically remediated Level 1 controls, ran continuously
through AWS Config and Lambda, and raised a Security Hub score
from one specific figure to another within 30 days. The audit of
the old code found: the entry point never imported boto3 and
flipped a weighted coin per control, remediation was flipping a
status string and printing a sentence, and there was no Lambda,
Config, or Security Hub code at all. The buried genuine work was
seven real check predicates in a file nothing ran.

This rebuild keeps the genuine part, extends it to 8 checks,
and proves the logic on a mock. Remediation, continuous running,
and score claims stay out until they exist and are measured.

## Weak points

- Moto's IAM password policy and S3 behaviours are close to real
  AWS but not identical. Edge cases could differ on a real account.
- Checks read current state only. They say nothing about how
  long a resource has been non compliant.
- The fixture states are mine. A state I did not think of is a
  state the agreement score cannot vouch for.
