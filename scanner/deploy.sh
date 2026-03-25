#!/bin/bash

MODE=$1
REGION=us-east-1

usage() {
    echo "Usage:"
    echo "  ./deploy.sh single [email] [profile]                              - Single account deployment"
    echo "  ./deploy.sh org <org-id> <target-ou> [email] [profile] [regions] - AWS Organizations deployment"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh single your@email.com my-profile"
    echo "  ./deploy.sh org o-abc123xyz r-xxxx your@email.com my-profile \"us-east-1,us-west-2\""
    exit 1
}

if [ "$MODE" = "single" ]; then
    EMAIL=$2
    PROFILE=${3:-default}
    STACK=litellm-scanner-single

    echo "========================================"
    echo "litellm Scanner - Single Account"
    echo "========================================"
    echo "Profile: $PROFILE"
    echo "Region:  $REGION"
    echo "Email:   $EMAIL"
    echo "========================================"

    if [ -z "$EMAIL" ]; then
        aws cloudformation deploy \
            --template-file scanner-single-account.yaml \
            --stack-name $STACK \
            --capabilities CAPABILITY_NAMED_IAM \
            --region $REGION \
            --profile $PROFILE
    else
        aws cloudformation deploy \
            --template-file scanner-single-account.yaml \
            --stack-name $STACK \
            --capabilities CAPABILITY_NAMED_IAM \
            --region $REGION \
            --profile $PROFILE \
            --parameter-overrides NotificationEmail=$EMAIL
    fi

    echo ""
    echo "Deployment complete. Manual invoke command:"
    aws cloudformation describe-stacks --stack-name $STACK --region $REGION --profile $PROFILE \
        --query "Stacks[0].Outputs[?OutputKey=='ManualInvokeCommand'].OutputValue" --output text

elif [ "$MODE" = "org" ]; then
    ORG_ID=$2
    TARGET_OU=$3
    EMAIL=$4
    PROFILE=${5:-default}
    REGIONS=${6:-us-east-1}
    STACK=litellm-scanner-org

    if [ -z "$ORG_ID" ]; then
        echo "Error: org-id is required for org deployment"
        usage
    fi
    if [ -z "$TARGET_OU" ]; then
        echo "Error: target-ou is required for org deployment (e.g. r-xxxx or ou-xxxx-xxxxxxxx)"
        usage
    fi

    echo "========================================"
    echo "litellm Scanner - AWS Organizations"
    echo "========================================"
    echo "Org ID:    $ORG_ID"
    echo "Target OU: $TARGET_OU"
    echo "Profile:   $PROFILE"
    echo "Region:    $REGION"
    echo "Regions:   $REGIONS"
    echo "Email:     $EMAIL"
    echo "========================================"
    echo "NOTE: Deploy this from the MANAGEMENT account only."
    echo ""

    if [ -z "$EMAIL" ]; then
        aws cloudformation deploy \
            --template-file scanner-org.yaml \
            --stack-name $STACK \
            --capabilities CAPABILITY_NAMED_IAM \
            --region $REGION \
            --profile $PROFILE \
            --parameter-overrides OrganizationId=$ORG_ID DeploymentTargetOU=$TARGET_OU DeploymentRegions=$REGIONS
    else
        aws cloudformation deploy \
            --template-file scanner-org.yaml \
            --stack-name $STACK \
            --capabilities CAPABILITY_NAMED_IAM \
            --region $REGION \
            --profile $PROFILE \
            --parameter-overrides OrganizationId=$ORG_ID DeploymentTargetOU=$TARGET_OU NotificationEmail=$EMAIL DeploymentRegions=$REGIONS
    fi

    echo ""
    echo "Deployment complete."
    echo ""
    echo "StackSet is deploying member scanners to all accounts in org $ORG_ID."
    echo "Check StackSet status:"
    echo "  aws cloudformation describe-stack-set --stack-set-name litellm-member-scanner --profile $PROFILE --region $REGION"
    echo ""
    echo "Manual aggregate command:"
    aws cloudformation describe-stacks --stack-name $STACK --region $REGION --profile $PROFILE \
        --query "Stacks[0].Outputs[?OutputKey=='ManualAggregateCommand'].OutputValue" --output text

else
    usage
fi
