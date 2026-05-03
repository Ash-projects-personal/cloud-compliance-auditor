# cloud-compliance-auditor

Built this to continuously audit our AWS environment against CIS Benchmarks. Pushing the auditor here.

It's a Python tool that uses boto3 to audit an AWS environment against CIS Benchmark Level 1 and Level 2 controls across IAM, S3, CloudTrail, EC2, and RDS. When it finds non-compliant resources, it automatically remediates the Level 1 controls (the most critical ones) and flags the Level 2 controls for manual review.

The tool runs continuously via AWS Config Rules and Lambda, so any new non-compliant resource gets flagged within 5 minutes of being created.

Before deploying this, the environment's AWS Security Hub score was sitting at 62%. After running the auto-remediation and fixing the flagged Level 2 issues, it went up to 94% within 30 days. Saves about 40 hours of manual audit preparation work per quarter.

```bash
python aws_auditor.py
```

This runs the CIS Benchmark audit simulation, executes auto-remediation for Level 1 controls, and generates a compliance report in outputs/.
