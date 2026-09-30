import boto3
import json
from datetime import datetime

def check_public_access(instance):
    public_ip = instance.get("PublicIpAddress")
    if public_ip:
        return "WARNING: Public IP detected"
    else:
        return "PASS"
    
def check_imdsv2(instance):
    imdsv2 = instance.get("MetadataOptions")
    if imdsv2["HttpTokens"] == "required":
        return "PASS"
    else:
        return "WARNING"
    
def check_ebs_encryption(volume_response):
    if volume_response["Volumes"][0]["Encrypted"]:
        return "PASS"
    else:
        return "WARNING"

def check_security_group(security_group_response):
    ip_permissions = security_group_response["SecurityGroups"][0]["IpPermissions"]
    if not ip_permissions:
        return "No inbound rules are configured"
    for permissions in ip_permissions:
        port = permissions.get("FromPort")
        if permissions.get("IpRanges"):
            for ip_range in permissions["IpRanges"]:
                cidr = ip_range.get("CidrIp")
                if port == 22 and cidr == "0.0.0.0/0":
                    return "WARNING: SSH open to the internet"
    return "PASS"
def create_finding(resource_id, check, severity, status, message):
    finding = {
        "resource_id": resource_id,
        "check": check,
        "severity": severity,
        "status": status,
        "message": message
    }
    return finding

def severity_findings(findings):
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    affected_instances = set()
    
    for finding in findings:
        resource_id = finding["resource_id"]
        affected_instances.add(resource_id)

        if finding["severity"] == "CRITICAL":
            critical_count += 1
        elif finding["severity"] == "HIGH":
            high_count += 1
        elif finding["severity"] == "MEDIUM":
            medium_count += 1
        elif finding["severity"] == "LOW":
            low_count += 1

    return(
        affected_instances,
        critical_count,
        high_count,
        medium_count,
        low_count
    )
def print_findings(findings):
    for finding in findings:
        print("=== SECURITY FINDING ===")
        print("Resource:", finding["resource_id"])
        print("Check:", finding["check"])
        print("Severity:", finding["severity"])
        print("Status:", finding["status"])
        print("Message:", finding["message"], "\n")

def print_summary(summary):
    print("=== SECURITY AUDIT SUMMARY ===")
    print("overall_status:", summary["overall_status"])
    print("instances_scanned:", summary["instances_scanned"])
    print("total_findings:", summary["total_findings"]) 
    print("healthy_instances:", summary["healthy_instances"])
    print("incomplete_instances:", summary["incomplete_instances"])
    print(f"health_rate: {summary['health_rate']}%")
    print("instances_with_findings:", summary["instances_with_findings"])
    print("CRITICAL:", summary["critical"])
    print("HIGH:", summary["high"])
    print("MEDIUM:", summary["medium"])
    print("LOW:", summary["low"])

def list_instances():
    now = datetime.now().astimezone()
    audit_time = now.isoformat()
    file_timestamp = now.strftime("%Y-%m-%d_%H%M%S")
    report_filename = f"security_audit_report_{file_timestamp}.json"
    try:
        ec2 = boto3.client("ec2")
        response = ec2.describe_instances()
    except Exception as error:
        print("ERROR: Unable to retrieve EC2 instances")
        print(f"Reason: {error}")
        return
    findings = []
    scan_errors = []
    instance_count = 0
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_count += 1
            security_group_id = "UNKNOWN"
            public_access_result = check_public_access(instance)
            imdsv2_result = check_imdsv2(instance)
            if imdsv2_result == "WARNING":
                result = create_finding(instance["InstanceId"], "IMDSv2","HIGH","WARNING","IMDSv2 is not required")
                findings.append(result)
            if public_access_result == "WARNING: Public IP detected":
                result = create_finding(instance["InstanceId"], "Public Access", "MEDIUM", "WARNING", "Public Ip Detected")
                findings.append(result)
            ebs_results = []
            for device_mapping in instance["BlockDeviceMappings"]:
                if device_mapping.get("Ebs"):
                    try:
                        volume_id = device_mapping["Ebs"]["VolumeId"]
                        volume_response = ec2.describe_volumes(
                            VolumeIds=[volume_id]
                            )
                        ebs_results.append(check_ebs_encryption(volume_response))
                    except Exception as error:
                        error_info = {
                            "resource_id": instance["InstanceId"],
                            "volume_id": volume_id,
                            "check": "EBS Encryption",
                            "error": str(error)
                        }
                        scan_errors.append(error_info)
                        print(f"ERROR scanning EBS volume {volume_id}: {error}")
            if "WARNING" in ebs_results:
                result = create_finding(instance["InstanceId"], "EBS Encryption", "HIGH", "WARNING", "EBS volume is not encrypted")
                findings.append(result)
            if not ebs_results:
                ebs_status = "NOT CHECKED"
            elif "WARNING" in ebs_results:
                ebs_status = "WARNING"
            elif "PASS" in ebs_results:
                ebs_status = "PASS" 
            else:
                ebs_status = "Unexpected error"
            security_group_results = []
            for security_group in instance["SecurityGroups"]:
                if security_group.get("GroupId"):
                    try:
                        security_group_id = security_group["GroupId"]
                        security_group_response = ec2.describe_security_groups(
                                GroupIds = [security_group_id]
                            )
                        security_group_results.append(check_security_group(security_group_response))
                    except Exception as error:
                        error_info ={
                            "resource_id": instance["InstanceId"],
                            "security_group_id": security_group_id,
                            "check": "Security Group",
                            "error": str(error)
                        }
                        scan_errors.append(error_info)
                        print(f"ERROR: Unable to check security group {security_group_id}: {error}")
            if "WARNING: SSH open to the internet" in security_group_results:
                result = create_finding(instance["InstanceId"], "Security Group", "HIGH", "WARNING", "SSH Open to the internet")
                findings.append(result)
            if not security_group_results:
                security_group_status = "NOT CHECKED"
            elif "WARNING: SSH open to the internet" in security_group_results:
                security_group_status = "WARNING"
            else:
                security_group_status = "PASS"
            
            print("=== EC2 INSTANCE ===")
            print("Instance ID:", instance["InstanceId"])
            print("Instance Type:", instance["InstanceType"])
            print("State:", instance["State"]["Name"])
            print("Public IP:", instance.get("PublicIpAddress"))
            print("Public Access:", public_access_result)
            print("IMDSv2:", imdsv2_result)
            print("EBS Encryption:", ebs_status)
            print("Security Group ID:", security_group_id)
            print("Inbound Rules:", security_group_status, "\n")      
    affected_instances, critical_count, high_count, medium_count, low_count = severity_findings(findings)
    incomplete_instances = set()
    for error in scan_errors:
        resource_id = error["resource_id"]
        incomplete_instances.add(resource_id)
    non_healthy_instances = affected_instances | incomplete_instances
    healthy_instances = instance_count - len(non_healthy_instances)
    if instance_count > 0:
        health_rate = round((healthy_instances / instance_count)*100)
    else:
        health_rate = 0
    if instance_count == 0:
        overall_status = "NO INSTANCES"
    elif incomplete_instances:
        overall_status = "SCAN INCOMPLETE"
    elif health_rate >= 80:
        overall_status = "HEALTHY"
    elif health_rate >= 50:
        overall_status = "NEEDS ATTENTION"
    else:
        overall_status = "HIGH RISK"

    summary = {
    "instances_scanned": instance_count,
    "total_findings": len(findings),
    "healthy_instances": healthy_instances,
    "overall_status": overall_status,
    "health_rate": health_rate,
    "instances_with_findings": len(affected_instances),
    "incomplete_instances": len(incomplete_instances),
    "critical": critical_count,
    "high": high_count,
    "medium": medium_count,
    "low": low_count
}

    print_summary(summary)
    print_findings(findings)

    report = {
            "audit_time": audit_time,
            "summary": summary,
            "findings": findings,
            "scan_errors": scan_errors

        }
    with open(report_filename, "w") as file:
        json.dump(report, file, indent=4)
    print("Report saved:", report_filename)

if __name__ == "__main__":
    list_instances()