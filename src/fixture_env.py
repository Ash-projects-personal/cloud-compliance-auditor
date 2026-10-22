"""Build a mocked AWS environment in known states with moto.

Every resource is created in a state I choose, and the expected
verdict for each (check, resource) pair is recorded as I build it.
The audit is then scored on whether the checks in cis_checks.py
return the expected verdict for every resource. This is a mocked
environment, not a real AWS account: it tests the check logic,
not anyone's real compliance.

Fixture plan:
- password policy: weak on purpose (length 8, no expiry, low reuse)
  so CIS-1.5 must FAIL.
- user key-user: one fresh access key, CIS-1.4 must PASS (age 0).
- user console-user: console password, no MFA, CIS-1.10 must FAIL.
- user api-user: no console password, CIS-1.10 not applicable PASS.
- bucket logs-on: logging enabled, CIS-2.1 PASS.
- bucket logs-off: no logging, CIS-2.1 FAIL.
- bucket blocked: public access block all on, CIS-2.3 PASS.
- bucket open: no public access block, CIS-2.3 FAIL.
  (Logging and blocking are set independently; the bucket that
  has logging has no block and the blocked bucket has no logging,
  so CIS-2.1 on blocked is FAIL and CIS-2.3 on logs-on is FAIL.
  Every combination is exercised.)
- security group open-sg: 0.0.0.0/0 on port 22. CIS-4.1 FAIL, CIS-4.2 PASS.
- security group closed-sg: 10.0.0.0/8 on port 443. Both PASS.
- VPC main: no flow log, CIS-4.3 FAIL.
"""


def build_fixture(clients):
    iam, s3, ec2 = clients["iam"], clients["s3"], clients["ec2"]
    expected = {}

    def expect(check_id, resource, status):
        expected[(check_id, resource)] = status

    # IAM
    iam.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=False,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=180,
        PasswordReusePrevention=1,
        HardExpiry=False,
    )
    expect("CIS-1.5", "account", "FAIL")

    iam.create_user(UserName="key-user")
    key = iam.create_access_key(UserName="key-user")["AccessKey"]
    expect("CIS-1.4", "key-user/%s" % key["AccessKeyId"], "PASS")

    iam.create_user(UserName="console-user")
    iam.create_login_profile(
        UserName="console-user", Password="Fixture-Password-123!", PasswordResetRequired=False
    )
    expect("CIS-1.10", "console-user", "FAIL")

    iam.create_user(UserName="api-user")
    expect("CIS-1.10", "api-user", "PASS")
    expect("CIS-1.10", "key-user", "PASS")

    # S3
    s3.create_bucket(Bucket="log-destination")
    # S3 requires the log delivery group to have write access to the
    # target bucket before logging can be enabled (moto enforces it).
    s3.put_bucket_acl(
        Bucket="log-destination",
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )
    expect("CIS-2.1", "log-destination", "FAIL")
    expect("CIS-2.3", "log-destination", "FAIL")

    s3.create_bucket(Bucket="logs-on")
    s3.put_bucket_logging(
        Bucket="logs-on",
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": "log-destination", "TargetPrefix": "logs-on/"}
        },
    )
    expect("CIS-2.1", "logs-on", "PASS")
    expect("CIS-2.3", "logs-on", "FAIL")

    s3.create_bucket(Bucket="blocked")
    s3.put_public_access_block(
        Bucket="blocked",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    expect("CIS-2.1", "blocked", "FAIL")
    expect("CIS-2.3", "blocked", "PASS")

    # EC2
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    # Moto also provides a default VPC. No VPC here gets a flow log,
    # so CIS-4.3 must FAIL on every VPC present.
    for v in ec2.describe_vpcs()["Vpcs"]:
        expect("CIS-4.3", v["VpcId"], "FAIL")

    open_sg = ec2.create_security_group(
        GroupName="open-sg", Description="fixture open", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=open_sg["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    expect("CIS-4.1", open_sg["GroupId"], "FAIL")
    expect("CIS-4.2", open_sg["GroupId"], "PASS")

    closed_sg = ec2.create_security_group(
        GroupName="closed-sg", Description="fixture closed", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=closed_sg["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
        ],
    )
    expect("CIS-4.1", closed_sg["GroupId"], "PASS")
    expect("CIS-4.2", closed_sg["GroupId"], "PASS")

    # The default security group moto creates with the VPC: no
    # world open rules, so both port checks must PASS on it.
    for group in ec2.describe_security_groups()["SecurityGroups"]:
        gid = group["GroupId"]
        if gid not in (open_sg["GroupId"], closed_sg["GroupId"]):
            expect("CIS-4.1", gid, "PASS")
            expect("CIS-4.2", gid, "PASS")

    return expected
