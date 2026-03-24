import json
import boto3
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

COMPROMISE_DATE = datetime(2026, 3, 24, tzinfo=timezone.utc)
MALICIOUS_VERSION = "1.82.8"
MALICIOUS_FILE = "litellm_init.pth"
EXFIL_DOMAIN = "models.litellm.cloud"

findings = []

def add_finding(service, resource, severity, detail):
    findings.append({
        "service": service,
        "resource": resource,
        "severity": severity,
        "detail": detail
    })
    logger.warning(f"[{severity}] {service} | {resource} | {detail}")


# --- Lambda ---
def check_lambda():
    client = boto3.client("lambda")
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page["Functions"]:
            name = fn["FunctionName"]
            # Check env vars for litellm version hints
            env_vars = fn.get("Environment", {}).get("Variables", {})
            for k, v in env_vars.items():
                if "litellm" in v.lower() and MALICIOUS_VERSION in v:
                    add_finding("Lambda", name, "HIGH",
                        f"Env var {k} references litellm {MALICIOUS_VERSION}")

            # Check container image URI
            image = fn.get("PackageType") == "Image" and fn.get("Code", {}).get("ImageUri", "")
            if image and "litellm" in image.lower():
                add_finding("Lambda", name, "MEDIUM",
                    f"Container image references litellm: {image}")

            # Check layers
            for layer in fn.get("Layers", []):
                arn = layer["Arn"]
                try:
                    layer_info = client.get_layer_version_by_arn(Arn=arn)
                    desc = layer_info.get("Description", "")
                    if "litellm" in desc.lower():
                        add_finding("Lambda", name, "HIGH",
                            f"Layer {arn} references litellm")
                except ClientError:
                    pass


# --- ECR ---
def check_ecr():
    ecr = boto3.client("ecr")
    try:
        repos = ecr.describe_repositories()["repositories"]
    except ClientError as e:
        logger.error(f"ECR error: {e}")
        return

    for repo in repos:
        repo_name = repo["repositoryName"]
        try:
            images = ecr.describe_images(repositoryName=repo_name)["imageDetails"]
            for image in images:
                # Check image tags for litellm references
                tags = image.get("imageTags", [])
                for tag in tags:
                    if "litellm" in tag.lower():
                        add_finding("ECR", f"{repo_name}:{tag}", "MEDIUM",
                            "Image tag references litellm — inspect for litellm_init.pth")

                # Flag images pushed after compromise date
                pushed_at = image.get("imagePushedAt")
                if pushed_at and pushed_at.replace(tzinfo=timezone.utc) >= COMPROMISE_DATE:
                    digest = image.get("imageDigest", "unknown")[:20]
                    add_finding("ECR", f"{repo_name}@{digest}", "INFO",
                        f"Image pushed after {COMPROMISE_DATE.date()} — verify litellm not included")
        except ClientError as e:
            logger.error(f"ECR image scan error for {repo_name}: {e}")


# --- ECS ---
def check_ecs():
    ecs = boto3.client("ecs")
    paginator = ecs.get_paginator("list_task_definitions")
    for page in paginator.paginate(status="ACTIVE"):
        for arn in page["taskDefinitionArns"]:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                for container in td.get("containerDefinitions", []):
                    image = container.get("image", "")
                    env = container.get("environment", [])
                    if "litellm" in image.lower():
                        add_finding("ECS", arn, "HIGH",
                            f"Container image references litellm: {image}")
                    for e in env:
                        if "litellm" in e.get("value", "").lower() and MALICIOUS_VERSION in e.get("value", ""):
                            add_finding("ECS", arn, "HIGH",
                                f"Env var {e['name']} references litellm {MALICIOUS_VERSION}")
            except ClientError as e:
                logger.error(f"ECS task def error {arn}: {e}")


# --- CodeBuild ---
def check_codebuild():
    cb = boto3.client("codebuild")
    try:
        project_names = cb.list_projects()["projects"]
    except ClientError as e:
        logger.error(f"CodeBuild error: {e}")
        return

    for i in range(0, len(project_names), 100):
        batch = project_names[i:i+100]
        projects = cb.batch_get_projects(names=batch)["projects"]
        for project in projects:
            name = project["name"]
            # Check environment variables
            for env_var in project.get("environment", {}).get("environmentVariables", []):
                if "litellm" in env_var.get("value", "").lower():
                    add_finding("CodeBuild", name, "HIGH",
                        f"Env var {env_var['name']} references litellm")
            # Check buildspec inline
            buildspec = project.get("source", {}).get("buildspec", "")
            if buildspec and "litellm" in buildspec.lower():
                if MALICIOUS_VERSION in buildspec:
                    add_finding("CodeBuild", name, "CRITICAL",
                        f"Buildspec installs litellm=={MALICIOUS_VERSION}")
                else:
                    add_finding("CodeBuild", name, "MEDIUM",
                        "Buildspec references litellm — verify version")


# --- SSM (EC2) ---
def check_ssm():
    ssm = boto3.client("ssm")
    ec2 = boto3.client("ec2")

    # Get all running instances
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )["Reservations"]
    except ClientError as e:
        logger.error(f"EC2 describe error: {e}")
        return

    instance_ids = [
        i["InstanceId"]
        for r in reservations
        for i in r["Instances"]
    ]

    if not instance_ids:
        logger.info("No running EC2 instances found")
        return

    # Send SSM command to check for malicious file and litellm version
    try:
        response = ssm.send_command(
            InstanceIds=instance_ids[:50],  # SSM limit per call
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": [
                    f"find / -name '{MALICIOUS_FILE}' 2>/dev/null && echo 'MALICIOUS_FILE_FOUND' || echo 'clean'",
                    f"pip show litellm 2>/dev/null | grep -E 'Version|Location' || echo 'litellm_not_installed'"
                ]
            },
            Comment="litellm malware scan",
            TimeoutSeconds=60
        )
        command_id = response["Command"]["CommandId"]
        add_finding("EC2/SSM", f"CommandId:{command_id}", "INFO",
            f"SSM scan dispatched to {len(instance_ids[:50])} instances — check SSM Run Command console for results")
    except ClientError as e:
        logger.error(f"SSM send_command error: {e}")
        add_finding("EC2/SSM", "all-instances", "INFO",
            f"SSM scan could not be dispatched: {e} — check instances manually")


# --- CloudTrail ---
def check_cloudtrail():
    ct = boto3.client("cloudtrail")
    suspicious_events = [
        "CreateUser", "CreateAccessKey", "AttachUserPolicy",
        "AttachRolePolicy", "PutUserPolicy", "CreateRole",
        "UpdateAssumeRolePolicy", "AddUserToGroup"
    ]

    for event_name in suspicious_events:
        try:
            response = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=COMPROMISE_DATE,
                MaxResults=10
            )
            for event in response.get("Events", []):
                detail = json.loads(event.get("CloudTrailEvent", "{}"))
                source_ip = detail.get("sourceIPAddress", "unknown")
                user = detail.get("userIdentity", {}).get("arn", "unknown")
                add_finding("CloudTrail", event_name, "MEDIUM",
                    f"IAM modification after compromise date | user={user} | ip={source_ip} | time={event['EventTime']}")
        except ClientError as e:
            logger.error(f"CloudTrail lookup error for {event_name}: {e}")


# --- GuardDuty ---
def check_guardduty():
    gd = boto3.client("guardduty")
    try:
        detectors = gd.list_detectors()["DetectorIds"]
    except ClientError as e:
        logger.error(f"GuardDuty error: {e}")
        add_finding("GuardDuty", "N/A", "INFO", "GuardDuty not accessible or not enabled")
        return

    if not detectors:
        add_finding("GuardDuty", "N/A", "INFO", "GuardDuty is not enabled — recommend enabling it")
        return

    credential_finding_types = [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "Recon:IAMUser/MaliciousIPCaller",
        "CredentialAccess:IAMUser/AnomalousBehavior"
    ]

    for detector_id in detectors:
        try:
            finding_ids = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "type": {"Eq": credential_finding_types},
                        "updatedAt": {"Gte": int(COMPROMISE_DATE.timestamp() * 1000)}
                    }
                }
            )["FindingIds"]

            if not finding_ids:
                logger.info(f"No GuardDuty credential findings since {COMPROMISE_DATE.date()}")
                continue

            gd_findings = gd.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids[:50]
            )["Findings"]

            for f in gd_findings:
                add_finding("GuardDuty", f["Id"], "CRITICAL",
                    f"type={f['Type']} | severity={f['Severity']} | title={f['Title']}")
        except ClientError as e:
            logger.error(f"GuardDuty findings error: {e}")


# --- Main handler ---
def handler(event, context):
    logger.info("Starting litellm malware environment scan")

    check_lambda()
    check_ecr()
    check_ecs()
    check_codebuild()
    check_ssm()
    check_cloudtrail()
    check_guardduty()

    summary = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
        "findings": findings
    }

    logger.info(f"Scan complete: {json.dumps(summary, default=str)}")
    return summary
