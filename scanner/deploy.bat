@echo off
setlocal

set MODE=%1
set REGION=us-east-1

if "%MODE%"=="single" goto single
if "%MODE%"=="org" goto org

echo Usage:
echo   deploy.bat single [email] [profile]     - Single account deployment
echo   deploy.bat org ^<org-id^> ^<target-ou^> [email] [profile] [regions]  - AWS Organizations deployment
echo.
echo Examples:
echo   deploy.bat single your@email.com my-profile
echo   deploy.bat org o-abc123xyz r-xxxx your@email.com my-profile "us-east-1,us-west-2"
goto end

:single
set EMAIL=%2
set PROFILE=%3
if "%PROFILE%"=="" set PROFILE=default
set STACK=litellm-scanner-single

echo ========================================
echo litellm Scanner - Single Account
echo ========================================
echo Profile: %PROFILE%
echo Region:  %REGION%
echo Email:   %EMAIL%
echo ========================================

if "%EMAIL%"=="" (
    aws cloudformation deploy ^
        --template-file scanner-single-account.yaml ^
        --stack-name %STACK% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION% ^
        --profile %PROFILE%
) else (
    aws cloudformation deploy ^
        --template-file scanner-single-account.yaml ^
        --stack-name %STACK% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION% ^
        --profile %PROFILE% ^
        --parameter-overrides NotificationEmail=%EMAIL%
)

echo.
echo Deployment complete. Manual invoke command:
aws cloudformation describe-stacks --stack-name %STACK% --region %REGION% --profile %PROFILE% ^
    --query "Stacks[0].Outputs[?OutputKey=='ManualInvokeCommand'].OutputValue" --output text
goto end

:org
set ORG_ID=%2
set EMAIL=%3
set PROFILE=%4
set REGIONS=%5
set TARGET_OU=%6
if "%PROFILE%"=="" set PROFILE=default
if "%REGIONS%"=="" set REGIONS=us-east-1
if "%ORG_ID%"=="" (
    echo Error: org-id is required for org deployment
    echo Usage: deploy.bat org ^<org-id^> ^<target-ou^> [email] [profile] [regions]
    goto end
)
if "%TARGET_OU%"=="" (
    echo Error: target-ou is required for org deployment (e.g. r-xxxx or ou-xxxx-xxxxxxxx)
    echo Usage: deploy.bat org ^<org-id^> ^<target-ou^> [email] [profile] [regions]
    goto end
)
set STACK=litellm-scanner-org

echo ========================================
echo litellm Scanner - AWS Organizations
echo ========================================
echo Org ID:    %ORG_ID%
echo Target OU: %TARGET_OU%
echo Profile:   %PROFILE%
echo Region:    %REGION%
echo Regions:   %REGIONS%
echo Email:     %EMAIL%
echo ========================================
echo NOTE: Deploy this from the MANAGEMENT account only.
echo.

if "%EMAIL%"=="" (
    aws cloudformation deploy ^
        --template-file scanner-org.yaml ^
        --stack-name %STACK% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION% ^
        --profile %PROFILE% ^
        --parameter-overrides OrganizationId=%ORG_ID% DeploymentTargetOU=%TARGET_OU% DeploymentRegions=%REGIONS%
) else (
    aws cloudformation deploy ^
        --template-file scanner-org.yaml ^
        --stack-name %STACK% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION% ^
        --profile %PROFILE% ^
        --parameter-overrides OrganizationId=%ORG_ID% DeploymentTargetOU=%TARGET_OU% NotificationEmail=%EMAIL% DeploymentRegions=%REGIONS%
)

echo.
echo Deployment complete.
echo.
echo StackSet is deploying member scanners to all accounts in org %ORG_ID%.
echo Check StackSet status:
echo   aws cloudformation describe-stack-set --stack-set-name litellm-member-scanner --profile %PROFILE% --region %REGION%
echo.
echo Manual aggregate command:
aws cloudformation describe-stacks --stack-name %STACK% --region %REGION% --profile %PROFILE% ^
    --query "Stacks[0].Outputs[?OutputKey=='ManualAggregateCommand'].OutputValue" --output text

:end
endlocal
