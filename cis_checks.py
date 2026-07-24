"""
Real boto3-backed CIS Benchmark control checks.

Each function is a pure predicate over live AWS state (or a moto mock) and
returns a `Finding` describing whether the control passed or failed. The
top-level `aws_auditor.py` uses a simulator for the demo run; this module is
the code path used against real accounts and the surface exercised by the
`tests/test_cis_controls.py` moto suite.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

import boto3


@dataclass
class Finding:
    """Result of evaluating a single CIS control against live AWS state."""

    control_id: str
    title: str
    service: str
    level: int
    status: str  # "PASS" | "FAIL"
    resources: list = field(default_factory=list)
    detail: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# S3 controls
# ---------------------------------------------------------------------------

def check_s3_bucket_logging(s3_client=None) -> Finding:
    """CIS-2.1: S3 bucket access logging must be enabled on every bucket."""
    s3 = s3_client or boto3.client("s3")
    offenders = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        logging = s3.get_bucket_logging(Bucket=name)
        if "LoggingEnabled" not in logging:
            offenders.append(name)
    return Finding(
        control_id="CIS-2.1",
        title="Ensure S3 bucket access logging enabled",
        service="S3",
        level=1,
        status="PASS" if not offenders else "FAIL",
        resources=offenders,
        detail=(
            "All buckets have access logging enabled."
            if not offenders
            else f"{len(offenders)} bucket(s) missing access logging."
        ),
    )


def check_s3_public_access(s3_client=None) -> Finding:
    """CIS-2.3: S3 buckets must not be publicly accessible.

    A bucket is considered public if either its ACL grants access to the
    AllUsers/AuthenticatedUsers groups or its bucket policy contains a
    statement with ``Principal: "*"`` and ``Effect: "Allow"``.
    """
    s3 = s3_client or boto3.client("s3")
    offenders = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        is_public = False

        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and (
                "AllUsers" in grantee.get("URI", "")
                or "AuthenticatedUsers" in grantee.get("URI", "")
            ):
                is_public = True
                break

        if not is_public:
            try:
                policy_doc = s3.get_bucket_policy(Bucket=name)["Policy"]
            except Exception:
                policy_doc = None
            if policy_doc:
                import json as _json

                policy = _json.loads(policy_doc)
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal")
                    if stmt.get("Effect") == "Allow" and (
                        principal == "*"
                        or (isinstance(principal, dict) and principal.get("AWS") == "*")
                    ):
                        is_public = True
                        break

        if is_public:
            offenders.append(name)

    return Finding(
        control_id="CIS-2.3",
        title="Ensure S3 buckets not publicly accessible",
        service="S3",
        level=1,
        status="PASS" if not offenders else "FAIL",
        resources=offenders,
        detail=(
            "No public buckets found."
            if not offenders
            else f"{len(offenders)} public bucket(s) detected."
        ),
    )


# ---------------------------------------------------------------------------
# IAM controls
# ---------------------------------------------------------------------------

def check_iam_password_policy(iam_client=None) -> Finding:
    """CIS-1.5: IAM password policy must require uppercase characters."""
    iam = iam_client or boto3.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return Finding(
            control_id="CIS-1.5",
            title="Ensure IAM password policy requires uppercase",
            service="IAM",
            level=1,
            status="FAIL",
            resources=["<account>"],
            detail="No IAM password policy is set.",
        )
    ok = bool(policy.get("RequireUppercaseCharacters"))
    return Finding(
        control_id="CIS-1.5",
        title="Ensure IAM password policy requires uppercase",
        service="IAM",
        level=1,
        status="PASS" if ok else "FAIL",
        resources=[] if ok else ["<account>"],
        detail=(
            "Password policy enforces uppercase."
            if ok
            else "Password policy does not require uppercase characters."
        ),
    )


def check_iam_access_key_rotation(
    iam_client=None, max_age_days: int = 90, now=None
) -> Finding:
    """CIS-1.4: Access keys must be rotated every 90 days."""
    from datetime import datetime, timezone, timedelta

    iam = iam_client or boto3.client("iam")
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    offenders = []
    for user in iam.list_users().get("Users", []):
        keys = iam.list_access_keys(UserName=user["UserName"]).get(
            "AccessKeyMetadata", []
        )
        for key in keys:
            if key.get("Status") != "Active":
                continue
            created = key["CreateDate"]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if created < cutoff:
                offenders.append(f"{user['UserName']}:{key['AccessKeyId']}")
    return Finding(
        control_id="CIS-1.4",
        title="Ensure access keys rotated every 90 days",
        service="IAM",
        level=1,
        status="PASS" if not offenders else "FAIL",
        resources=offenders,
        detail=(
            "All active access keys are within the rotation window."
            if not offenders
            else f"{len(offenders)} access key(s) older than {max_age_days} days."
        ),
    )


# ---------------------------------------------------------------------------
# EC2 / VPC controls
# ---------------------------------------------------------------------------

_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def check_sg_no_world_ingress_on_port(ec2_client=None, port: int = 22) -> Finding:
    """CIS-4.1/4.2: Security groups must not allow world ingress on 22/3389."""
    ec2 = ec2_client or boto3.client("ec2")
    offenders = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            if from_p is None or to_p is None:
                continue
            if not (from_p <= port <= to_p):
                continue
            world = False
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") in _WORLD_CIDRS:
                    world = True
                    break
            for r in perm.get("Ipv6Ranges", []):
                if r.get("CidrIpv6") in _WORLD_CIDRS:
                    world = True
                    break
            if world:
                offenders.append(sg["GroupId"])
                break

    control_id = "CIS-4.1" if port == 22 else "CIS-4.2"
    title = (
        "Ensure no security groups allow 0.0.0.0/0 on 22"
        if port == 22
        else "Ensure no security groups allow 0.0.0.0/0 on 3389"
    )
    return Finding(
        control_id=control_id,
        title=title,
        service="EC2",
        level=1,
        status="PASS" if not offenders else "FAIL",
        resources=offenders,
        detail=(
            f"No security groups expose port {port} to the world."
            if not offenders
            else f"{len(offenders)} security group(s) allow 0.0.0.0/0 on {port}."
        ),
    )


def check_vpc_flow_logs(ec2_client=None) -> Finding:
    """CIS-4.3: Every VPC must have flow logs enabled."""
    ec2 = ec2_client or boto3.client("ec2")
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    logs = ec2.describe_flow_logs().get("FlowLogs", [])
    logged = {fl.get("ResourceId") for fl in logs}
    offenders = [v["VpcId"] for v in vpcs if v["VpcId"] not in logged]
    return Finding(
        control_id="CIS-4.3",
        title="Ensure VPC flow logging enabled in all VPCs",
        service="EC2",
        level=2,
        status="PASS" if not offenders else "FAIL",
        resources=offenders,
        detail=(
            "Every VPC has a flow log."
            if not offenders
            else f"{len(offenders)} VPC(s) without flow logging."
        ),
    )
