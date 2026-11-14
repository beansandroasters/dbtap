# /// script
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Check CFN private networking, TLS defaults, and permissions without deploying."""
from pathlib import Path
import yaml


class Loader(yaml.SafeLoader):
    pass


def intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag: value}


Loader.add_multi_constructor("!", intrinsic)
template = yaml.load(Path(__file__).with_name("verify.yaml").read_text(), Loader=Loader)
resources = template["Resources"]
for name, r in resources.items():
    kind, p = r["Type"], r.get("Properties", {})
    assert kind not in {"AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "AWS::EC2::EIP"}, name
    if kind == "AWS::EC2::Subnet":
        assert p["MapPublicIpOnLaunch"] is False, name
    if kind == "AWS::RDS::DBInstance":
        assert p["PubliclyAccessible"] is False, name
    if kind == "AWS::EC2::Instance":
        assert p["MetadataOptions"]["HttpTokens"] == "required", name
        assert p["MetadataOptions"]["HttpPutResponseHopLimit"] == 1, name
        assert all(m["Ebs"]["Encrypted"] for m in p["BlockDeviceMappings"]), name
    if kind == "AWS::EC2::SecurityGroup":
        assert p.get("SecurityGroupEgress"), name
        for rule in p.get("SecurityGroupIngress", []) + p["SecurityGroupEgress"]:
            assert rule.get("CidrIp") != "0.0.0.0/0" and rule.get("CidrIpv6") != "::/0", name
    if kind == "AWS::EC2::SecurityGroupIngress":
        assert p.get("CidrIp") != "0.0.0.0/0" and p.get("CidrIpv6") != "::/0", name
    if kind in {"AWS::RDS::DBCluster", "AWS::RDS::DBInstance"} and "MasterUsername" in p:
        assert p["StorageEncrypted"], name
        assert "resolve:secretsmanager:" in p["MasterUserPassword"]["Sub"], name

assert template["Parameters"]["PlaintextWireTest"]["Default"] == "false"
for name, parameter, secure in [
    ("AuroraParams", "rds.force_ssl", "1"), ("MysqlParams", "require_secure_transport", "1"),
]:
    assert resources[name]["Properties"]["Parameters"][parameter]["If"] == ["AllowPlaintext", "0", secure]
bucket = resources["Bucket"]["Properties"]
assert all(bucket["PublicAccessBlockConfiguration"].values())
deny = resources["BucketPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
assert deny["Effect"] == "Deny" and deny["Condition"]["Bool"]["aws:SecureTransport"] == "false"
assert len(deny["Resource"]) == 2  # The bucket and bucket/* are separate resources.
assert resources["FlowLog"]["Properties"]["TrafficType"] == "ALL"
monitor_policies = str(resources["InstanceRole"]["Properties"]["Policies"])
assert "secretsmanager:" not in monitor_policies
print(f"{len(resources)} resources: private networking / TLS defaults / IAM boundary assertions passed")
