import json
from datetime import datetime

# Optional live cloud SDK imports (gracefully handled if credentials aren't configured)
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:
    BlobServiceClient = None

try:
    from google.cloud import storage as gcs_storage
except ImportError:
    gcs_storage = None


class MultiCloudStorageScanner:
    """
    Audits AWS S3, Azure Blob Storage, and Google Cloud Storage configurations
    strictly via control-plane metadata APIs without reading or downloading objects.
    """

    def __init__(self):
        self.findings = []

    def _add_finding(self, provider, resource, issue, severity, remediation, standard):
        self.findings.append({
            "provider": provider,
            "resource": resource,
            "issue": issue,
            "severity": severity,
            "remediation": remediation,
            "compliance": standard,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        })

    # ---------------- AWS S3 LIVE METADATA AUDIT ----------------
    def scan_aws_live(self):
        if not boto3:
            return {"error": "boto3 not installed"}
        s3 = boto3.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            # 1. Public Access Block Check (Metadata only)
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls"),
                    pab.get("IgnorePublicAcls"),
                    pab.get("BlockPublicPolicy"),
                    pab.get("RestrictPublicBuckets")
                ]):
                    self._add_finding(
                        "AWS S3", name,
                        "Public Access Block is partially or fully disabled",
                        "CRITICAL",
                        f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        "CIS AWS 2.1.5"
                    )
            except ClientError:
                self._add_finding(
                    "AWS S3", name,
                    "No Public Access Block configured on bucket",
                    "CRITICAL",
                    f"Enable all 4 Block Public Access settings on s3://{name}",
                    "CIS AWS 2.1.5"
                )

            # 2. Server-Side Encryption Check
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                self._add_finding(
                    "AWS S3", name,
                    "Default Server-Side Encryption (SSE) is not enabled",
                    "HIGH",
                    f"Enable SSE-S3 or SSE-KMS default encryption on s3://{name}",
                    "CIS AWS 2.1.1"
                )

            # 3. Versioning Check
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                self._add_finding(
                    "AWS S3", name,
                    "Object Versioning is disabled (ransomware/accidental deletion risk)",
                    "MEDIUM",
                    f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                    "CIS AWS 2.1.3"
                )

    # ---------------- AZURE BLOB LIVE METADATA AUDIT ----------------
    def scan_azure_live(self, connection_string):
        if not BlobServiceClient:
            return {"error": "azure-storage-blob not installed"}
        service = BlobServiceClient.from_connection_string(connection_string)
        for container in service.list_containers():
            name = container["name"]
            public_access = container.get("public_access")
            if public_access in ("blob", "container"):
                self._add_finding(
                    "Azure Blob", name,
                    f"Anonymous public read access enabled (Level: {public_access})",
                    "CRITICAL",
                    f"az storage container set-permission --name {name} --public-access off",
                    "CIS Azure 3.7"
                )

    # ---------------- GCP GCS LIVE METADATA AUDIT ----------------
    def scan_gcp_live(self):
        if not gcs_storage:
            return {"error": "google-cloud-storage not installed"}
        client = gcs_storage.Client()
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    self._add_finding(
                        "GCP GCS", bucket.name,
                        f"Bucket IAM policy exposes data to {members}",
                        "CRITICAL",
                        f"gsutil iam ch -d allUsers -d allAuthenticatedUsers gs://{bucket.name}",
                        "CIS GCP 5.1"
                    )
            if not bucket.versioning_enabled:
                self._add_finding(
                    "GCP GCS", bucket.name,
                    "Object versioning is disabled",
                    "MEDIUM",
                    f"gsutil versioning set on gs://{bucket.name}",
                    "CIS GCP 5.2"
                )

    # ---------------- DEMO / SIMULATION AUDIT (SAFE & INSTANT) ----------------
    def run_demo_scan(self):
        self.findings = []
        mock_configs = [
            {
                "provider": "AWS S3",
                "resource": "corp-financial-backups-2026",
                "public_access_block": False,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "https_only": False,
                "logging_enabled": False
            },
            {
                "provider": "AWS S3",
                "resource": "prod-app-assets-secure",
                "public_access_block": True,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "https_only": True,
                "logging_enabled": True
            },
            {
                "provider": "Azure Blob",
                "resource": "customer-kyc-documents",
                "public_access_level": "container",
                "https_only": False,
                "soft_delete_enabled": False
            },
            {
                "provider": "GCP GCS",
                "resource": "ml-training-datasets-bucket",
                "iam_public_members": ["allUsers"],
                "uniform_bucket_level_access": False,
                "versioning_enabled": False
            }
        ]

        for cfg in mock_configs:
            prov = cfg["provider"]
            res = cfg["resource"]

            if prov == "AWS S3":
                if not cfg["public_access_block"]:
                    self._add_finding(
                        prov, res,
                        "Public Access Block disabled; bucket ACL/Policy allows public read",
                        "CRITICAL",
                        f"aws s3api put-public-access-block --bucket {res} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        "CIS AWS 2.1.5"
                    )
                if not cfg["encryption_enabled"]:
                    self._add_finding(
                        prov, res,
                        "Default Server-Side Encryption (SSE-KMS/SSE-S3) disabled",
                        "HIGH",
                        f"Enable default AES-256 or KMS encryption on s3://{res}",
                        "CIS AWS 2.1.1"
                    )
                if not cfg["https_only"]:
                    self._add_finding(
                        prov, res,
                        "Bucket policy allows unencrypted HTTP transport (aws:SecureTransport=false)",
                        "HIGH",
                        f"Attach bucket policy denying requests where aws:SecureTransport is false",
                        "CIS AWS 2.1.2"
                    )
                if not cfg["versioning_enabled"]:
                    self._add_finding(
                        prov, res,
                        "Bucket versioning is disabled",
                        "MEDIUM",
                        f"aws s3api put-bucket-versioning --bucket {res} --versioning-configuration Status=Enabled",
                        "CIS AWS 2.1.3"
                    )

            elif prov == "Azure Blob":
                if cfg["public_access_level"] != "none":
                    self._add_finding(
                        prov, res,
                        f"Anonymous public container access enabled ({cfg['public_access_level']})",
                        "CRITICAL",
                        f"az storage container set-permission --name {res} --public-access off",
                        "CIS Azure 3.7"
                    )
                if not cfg["https_only"]:
                    self._add_finding(
                        prov, res,
                        "Secure transfer (HTTPS only) is not enforced on storage account",
                        "HIGH",
                        f"az storage account update --name {res} --https-only true",
                        "CIS Azure 3.1"
                    )

            elif prov == "GCP GCS":
                if cfg["iam_public_members"]:
                    self._add_finding(
                        prov, res,
                        f"IAM binding grants public access to {', '.join(cfg['iam_public_members'])}",
                        "CRITICAL",
                        f"gsutil iam ch -d allUsers gs://{res}",
                        "CIS GCP 5.1"
                    )
                if not cfg["uniform_bucket_level_access"]:
                    self._add_finding(
                        prov, res,
                        "Uniform bucket-level access is disabled (legacy ACLs active)",
                        "MEDIUM",
                        f"gsutil uniformbucketlevelaccess set on gs://{res}",
                        "CIS GCP 5.2"
                    )

        summary = {
            "total_resources_scanned": len(mock_configs),
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
            "zero_data_access_verified": True
        }
        return {"summary": summary, "findings": self.findings}


if __name__ == "__main__":
    scanner = MultiCloudStorageScanner()
    report = scanner.run_demo_scan()
    print(json.dumps(report, indent=2))