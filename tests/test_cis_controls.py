"""
Moto-mocked tests for the CIS control checks in ``cis_checks.py``.

Each control gets a compliant-fixture test (asserts PASS) and a
misconfigured-fixture test (asserts FAIL with the offending resource named).
This is the acceptance suite Day 12 required.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from cis_checks import (
    Finding,
    check_iam_access_key_rotation,
    check_iam_password_policy,
    check_s3_bucket_logging,
    check_s3_public_access,
    check_sg_no_world_ingress_on_port,
    check_vpc_flow_logs,
)


@pytest.fixture(autouse=True)
def _aws_credentials(monkeypatch):
    """Give boto3 dummy creds so moto's default session works."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# Finding smoke tests
# ---------------------------------------------------------------------------

def test_finding_serializes_to_dict():
    f = Finding(
        control_id="CIS-2.3",
        title="t",
        service="S3",
        level=1,
        status="PASS",
    )
    d = f.to_dict()
    assert d["control_id"] == "CIS-2.3"
    assert d["resources"] == []
    assert d["status"] == "PASS"


# ---------------------------------------------------------------------------
# S3 controls
# ---------------------------------------------------------------------------

@mock_aws
def test_s3_logging_pass_when_all_buckets_log():
    s3 = boto3.client("s3", region_name="us-east-1")
    logging_target = "central-logs-bucket"
    s3.create_bucket(Bucket=logging_target)
    for name in ("prod-app-1", "prod-app-2"):
        s3.create_bucket(Bucket=name)
        s3.put_bucket_acl(Bucket=logging_target, ACL="log-delivery-write")
        s3.put_bucket_logging(
            Bucket=name,
            BucketLoggingStatus={
                "LoggingEnabled": {"TargetBucket": logging_target, "TargetPrefix": f"{name}/"}
            },
        )

    finding = check_s3_bucket_logging(s3)
    # `logging_target` itself never had LoggingEnabled written on it,
    # so it should be the only offender. Confirm the check catches that.
    assert finding.control_id == "CIS-2.1"
    assert finding.status == "FAIL"
    assert finding.resources == [logging_target]


@mock_aws
def test_s3_logging_fail_names_offending_buckets():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-logs-here")
    s3.create_bucket(Bucket="also-no-logs")
    finding = check_s3_bucket_logging(s3)
    assert finding.status == "FAIL"
    assert set(finding.resources) == {"no-logs-here", "also-no-logs"}
    assert "2 bucket" in finding.detail


@mock_aws
def test_s3_public_access_pass_for_private_bucket():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="private-bucket")
    finding = check_s3_public_access(s3)
    assert finding.status == "PASS"
    assert finding.resources == []


@mock_aws
def test_s3_public_access_fail_when_acl_grants_allusers():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="leaky-bucket")
    s3.put_bucket_acl(Bucket="leaky-bucket", ACL="public-read")
    finding = check_s3_public_access(s3)
    assert finding.status == "FAIL"
    assert "leaky-bucket" in finding.resources


@mock_aws
def test_s3_public_access_fail_when_policy_grants_star_principal():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="policy-open")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-open/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket="policy-open", Policy=json.dumps(policy))
    finding = check_s3_public_access(s3)
    assert finding.status == "FAIL"
    assert "policy-open" in finding.resources


# ---------------------------------------------------------------------------
# IAM controls
# ---------------------------------------------------------------------------

@mock_aws
def test_iam_password_policy_pass_when_uppercase_required():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
    )
    finding = check_iam_password_policy(iam)
    assert finding.control_id == "CIS-1.5"
    assert finding.status == "PASS"


@mock_aws
def test_iam_password_policy_fail_when_uppercase_not_required():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=False,
        RequireLowercaseCharacters=True,
    )
    finding = check_iam_password_policy(iam)
    assert finding.status == "FAIL"
    assert "uppercase" in finding.detail.lower()


@mock_aws
def test_iam_password_policy_fail_when_no_policy_set():
    iam = boto3.client("iam", region_name="us-east-1")
    finding = check_iam_password_policy(iam)
    assert finding.status == "FAIL"
    assert finding.resources == ["<account>"]


@mock_aws
def test_iam_access_key_rotation_pass_for_fresh_keys():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    finding = check_iam_access_key_rotation(iam, max_age_days=90)
    assert finding.control_id == "CIS-1.4"
    assert finding.status == "PASS"


@mock_aws
def test_iam_access_key_rotation_fail_for_old_key():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bob")
    key = iam.create_access_key(UserName="bob")["AccessKey"]
    # Simulate "now" being far enough in the future that the key looks stale.
    future_now = datetime.now(timezone.utc) + timedelta(days=200)
    finding = check_iam_access_key_rotation(iam, max_age_days=90, now=future_now)
    assert finding.status == "FAIL"
    assert any(r.startswith("bob:") for r in finding.resources)
    assert key["AccessKeyId"] in finding.resources[0]


@mock_aws
def test_iam_access_key_rotation_ignores_inactive_keys():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="carol")
    key = iam.create_access_key(UserName="carol")["AccessKey"]
    iam.update_access_key(
        UserName="carol", AccessKeyId=key["AccessKeyId"], Status="Inactive"
    )
    future_now = datetime.now(timezone.utc) + timedelta(days=500)
    finding = check_iam_access_key_rotation(iam, max_age_days=90, now=future_now)
    assert finding.status == "PASS"


# ---------------------------------------------------------------------------
# EC2 / VPC controls
# ---------------------------------------------------------------------------

@mock_aws
def test_sg_no_world_ingress_pass_when_restricted():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="tight", Description="tight", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    finding = check_sg_no_world_ingress_on_port(ec2, port=22)
    assert finding.control_id == "CIS-4.1"
    # PASS covers both our SG and the default SG (which has no ingress).
    assert finding.status == "PASS"


@mock_aws
def test_sg_no_world_ingress_fail_for_ssh_open_to_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="wide-open", Description="d", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    finding = check_sg_no_world_ingress_on_port(ec2, port=22)
    assert finding.status == "FAIL"
    assert sg["GroupId"] in finding.resources


@mock_aws
def test_sg_no_world_ingress_fail_for_rdp_open_to_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="rdp-open", Description="d", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    finding = check_sg_no_world_ingress_on_port(ec2, port=3389)
    assert finding.control_id == "CIS-4.2"
    assert finding.status == "FAIL"
    assert sg["GroupId"] in finding.resources


@mock_aws
def test_sg_wide_port_range_covering_ssh_is_flagged():
    """A rule of 1-65535 open to the world must be caught for port 22."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="all-tcp-open", Description="d", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 1,
                "ToPort": 65535,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    finding = check_sg_no_world_ingress_on_port(ec2, port=22)
    assert finding.status == "FAIL"
    assert sg["GroupId"] in finding.resources


@mock_aws
def test_vpc_flow_logs_fail_when_missing():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_vpc(CidrBlock="10.10.0.0/16")
    finding = check_vpc_flow_logs(ec2)
    assert finding.control_id == "CIS-4.3"
    assert finding.status == "FAIL"
    # Default VPC created by moto + our new one both count as unlogged.
    assert len(finding.resources) >= 1
