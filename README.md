\# AWS Security Auditor



A Python-based security auditing tool that uses Boto3 to inspect Amazon EC2 resources and identify common security configuration issues.



The auditor connects to AWS, evaluates EC2 instances and associated resources, generates severity-based security findings, handles incomplete API scans, and exports the results to timestamped JSON reports.



\## Features



\- Discovers EC2 instances in the configured AWS environment

\- Detects EC2 instances with public IPv4 addresses

\- Verifies that IMDSv2 is required

\- Checks attached EBS volumes for encryption

\- Detects security groups exposing SSH (port 22) to `0.0.0.0/0`

\- Categorizes findings by severity

\- Tracks affected instances without double-counting resources

\- Separates confirmed security findings from scan/API errors

\- Detects incomplete audits when AWS checks cannot be completed

\- Calculates an overall security health rate

\- Generates timestamped JSON audit reports

\- Provides human-readable terminal output



\## Security Checks



| Check | Condition | Severity |

| --- | --- | --- |

| Public Access | EC2 instance has a public IPv4 address | MEDIUM |

| IMDSv2 | IMDSv2 is not required | HIGH |

| EBS Encryption | Attached EBS volume is not encrypted | HIGH |

| SSH Exposure | Port 22 is accessible from `0.0.0.0/0` | HIGH |



\## Technologies



\- Python

\- AWS

\- Boto3

\- Amazon EC2

\- Amazon EBS

\- EC2 Security Groups

\- JSON

\- Git / GitHub



\## How It Works



The auditor retrieves EC2 instances using the AWS SDK for Python (Boto3).



For each instance, it evaluates:



1\. Public network exposure

2\. Instance Metadata Service configuration

3\. EBS volume encryption

4\. Security group inbound SSH exposure



Confirmed security issues are stored separately from API or scan errors.



The program then calculates the number of healthy, affected, and incompletely scanned instances before generating a security summary and JSON report.



\## Example Output



```text

=== SECURITY AUDIT SUMMARY ===

Overall Status: NEEDS ATTENTION

Instances Scanned: 2

Total Findings: 1

Healthy Instances: 1

Incomplete Instances: 0

Health Rate: 50%

Instances With Findings: 1

CRITICAL: 0

HIGH: 0

MEDIUM: 1

LOW: 0

Error Handling
The auditor distinguishes between a confirmed security finding and a check that could not be completed.

For example, an AWS API failure during an EBS encryption check is recorded under scan_errors instead of being incorrectly reported as a vulnerability.

If one or more instances cannot be completely evaluated, the overall audit status becomes:

SCAN INCOMPLETE

Installation
Clone the repository:
git clone <repository-url>
cd AWS-Security-Auditor

Install the required dependency:
pip install -r requirements.txt

AWS Authentication
The tool uses the AWS credentials available to Boto3.
Authenticate/configure your AWS environment before running the auditor. Do not store AWS access keys or credentials in this repository.
Usage
Run:
python aws_security_auditor.py

The auditor displays its results in the terminal and creates a timestamped JSON report.
Example Report
A sanitized example report is available here:
reports/example_audit_report.json
Testing
The project was tested against several scenarios, including:
- Healthy EC2 resources
- Multiple findings on a single instance
- No EC2 instances
- Expired AWS authentication
- Simulated EBS API failures
- Incomplete scans
- Duplicate resource handling
Project Goals
I built this project to strengthen my Python, AWS, and cloud security skills by creating a practical security automation tool rather than relying solely on manual AWS configuration reviews.

The project gave me hands-on experience working with AWS APIs, nested API responses, exception handling, Python collections, security findings, structured reporting, and testing failure conditions.

Future Improvements
Potential future versions could include:
- Additional security group checks
- Multi-region scanning
- Additional AWS services
- CSV/HTML reporting
- Automated remediation options
- Unit testing
- CI/CD security testing

Disclaimer
This project is intended for educational and authorized security auditing purposes. Only use it against AWS environments you own or have permission to assess.
