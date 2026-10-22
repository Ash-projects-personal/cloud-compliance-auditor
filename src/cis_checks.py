"""CIS style checks written against real boto3 client calls.

Every check takes boto3 clients (IAM, S3, EC2) and returns a list of
per resource results. The checks only read; they never change
anything. They run unchanged against a real AWS account or against
a mocked one (moto), which is how this repo exercises them: the
fixture environment in fixture_env.py builds resources in known
good and bad states, and the checks have to call them correctly.

Checks:
- CIS-1.4  access keys rotated within 90 days
- CIS-1.5  account password policy strength
- CIS-1.10 MFA enabled for users with a console password
- CIS-2.1  S3 server access logging enabled
- CIS-2.3  S3 public access block enabled
- CIS-4.1  no security group opens port 22 to the world
- CIS-4.2  no security group opens port 3389 to the world
- CIS-4.3  VPC flow logs enabled
"""
from datetime import datetime, timezone

from botocore.exceptions import ClientError


def _result(check_id, control, resource, passed, detail):
    return {
        "check_id": check_id,
        "control": control,
        "resource": resource,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    }


def check_access_key_rotation(iam):
    """CIS-1.4: every IAM access key is 90 days old or younger."""
    results = []
    users = iam.list_users().get("Users", [])
    if not users:
        results.append(
            _result("CIS-1.4", "access key rotation", "account", True, "no IAM users")
        )
    for user in users:
        keys = iam.list_access_keys(UserName=user["UserName"]).get(
            "AccessKeyMetadata", []
        )
        for key in keys:
            created = key["CreateDate"]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            results.append(
                _result(
                    "CIS-1.4",
                    "access key rotation",
                    "%s/%s" % (user["UserName"], key["AccessKeyId"]),
                    age_days <= 90,
                    "key age %d days (limit 90)" % age_days,
                )
            )
    return results


def check_password_policy(iam):
    """CIS-1.5: password policy meets the CIS minimums."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError:
        return [
            _result(
                "CIS-1.5", "password policy", "account", False, "no password policy set"
            )
        ]
    problems = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        problems.append("minimum length %s < 14" % policy.get("MinimumPasswordLength"))
    for field in (
        "RequireSymbols",
        "RequireNumbers",
        "RequireUppercaseCharacters",
        "RequireLowercaseCharacters",
    ):
        if not policy.get(field):
            problems.append("%s not required" % field)
    max_age = policy.get("MaxPasswordAge", 0)
    if not max_age or max_age > 90:
        problems.append("max password age %s not within 90 days" % max_age)
    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse < 24:
        problems.append("reuse prevention %s < 24" % reuse)
    return [
        _result(
            "CIS-1.5",
            "password policy",
            "account",
            not problems,
            "; ".join(problems) if problems else "policy meets CIS minimums",
        )
    ]


def check_mfa_for_console_users(iam):
    """CIS-1.10: users with a console password have MFA enabled."""
    results = []
    for user in iam.list_users().get("Users", []):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
            has_console = True
        except ClientError:
            has_console = False
        if not has_console:
            results.append(
                _result(
                    "CIS-1.10",
                    "MFA for console users",
                    name,
                    True,
                    "no console password, check not applicable",
                )
            )
            continue
        devices = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
        results.append(
            _result(
                "CIS-1.10",
                "MFA for console users",
                name,
                len(devices) > 0,
                "%d MFA devices registered" % len(devices),
            )
        )
    return results


def check_s3_logging(s3):
    """CIS-2.1: every bucket has server access logging enabled."""
    results = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        logging = s3.get_bucket_logging(Bucket=name)
        enabled = "LoggingEnabled" in logging
        results.append(
            _result(
                "CIS-2.1",
                "S3 server access logging",
                name,
                enabled,
                "logging enabled" if enabled else "logging disabled",
            )
        )
    return results


def check_s3_public_access_block(s3):
    """CIS-2.3: every bucket blocks public access on all four settings."""
    results = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            ok = all(
                cfg.get(k)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
            detail = "all four block settings on" if ok else "some block settings off"
        except ClientError:
            ok = False
            detail = "no public access block configured"
        results.append(_result("CIS-2.3", "S3 public access block", name, ok, detail))
    return results


def _check_sg_port(ec2, check_id, port):
    results = []
    groups = ec2.describe_security_groups().get("SecurityGroups", [])
    for group in groups:
        open_to_world = False
        for perm in group.get("IpPermissions", []):
            if perm.get("IpProtocol") == "-1":
                covers = True
            else:
                covers = perm.get("FromPort", 0) <= port <= perm.get("ToPort", 0)
            if covers and any(
                r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
            ):
                open_to_world = True
        results.append(
            _result(
                check_id,
                "no world open ingress on port %d" % port,
                group["GroupId"],
                not open_to_world,
                "port %d open to 0.0.0.0/0" % port
                if open_to_world
                else "port %d not open to the world" % port,
            )
        )
    return results


def check_sg_ssh(ec2):
    """CIS-4.1: no security group opens SSH to the world."""
    return _check_sg_port(ec2, "CIS-4.1", 22)


def check_sg_rdp(ec2):
    """CIS-4.2: no security group opens RDP to the world."""
    return _check_sg_port(ec2, "CIS-4.2", 3389)


def check_vpc_flow_logs(ec2):
    """CIS-4.3: every VPC has flow logs enabled."""
    results = []
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    with_logs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
    for vpc in ec2.describe_vpcs().get("Vpcs", []):
        vpc_id = vpc["VpcId"]
        results.append(
            _result(
                "CIS-4.3",
                "VPC flow logs",
                vpc_id,
                vpc_id in with_logs,
                "flow log active" if vpc_id in with_logs else "no flow log",
            )
        )
    return results


ALL_CHECKS = [
    ("iam", check_access_key_rotation),
    ("iam", check_password_policy),
    ("iam", check_mfa_for_console_users),
    ("s3", check_s3_logging),
    ("s3", check_s3_public_access_block),
    ("ec2", check_sg_ssh),
    ("ec2", check_sg_rdp),
    ("ec2", check_vpc_flow_logs),
]


def run_all_checks(clients):
    results = []
    for service, fn in ALL_CHECKS:
        results.extend(fn(clients[service]))
    return results
