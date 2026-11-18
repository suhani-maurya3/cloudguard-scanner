# CloudGuard: Multi-Cloud Storage Misconfiguration & Data Exposure Scanner (PS-06)

## Overview
CloudGuard audits **AWS S3**, **Azure Blob Storage**, and **Google Cloud Storage (GCS)** configurations to detect public exposure, missing encryption, insecure transport, and disabled versioning—**without reading, listing, or downloading any private customer objects**.

## Key Features
- **Zero-Data-Access Architecture:** Uses only control-plane metadata APIs (`get_public_access_block`, `get_bucket_encryption`, container properties, IAM policies). Never invokes `get_object` or blob download APIs.
- **Unified Multi-Cloud Coverage:** Single dashboard and CLI engine covering AWS, Azure, and GCP mapped to CIS Benchmarks.
- **Actionable CLI Remediation:** Generates copy-paste AWS CLI, Azure CLI, and `gsutil` commands to fix every detected issue.
- **JSON Compliance Export:** Downloadable audit reports for security teams.

## Tech Stack
- Python 3, Flask
- AWS SDK (`boto3`), Azure SDK (`azure-storage-blob`), Google Cloud SDK (`google-cloud-storage`)

## Quick Start
```bash
pip install -r requirements.txt
python app.py