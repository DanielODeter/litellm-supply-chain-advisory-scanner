@echo off
set STACK_NAME=litellm-scanner
set REGION=us-east-1
set EMAIL=%1

if "%EMAIL%"=="" (
    echo Usage: deploy.bat your@email.com
    echo Deploying without email notifications...
    aws cloudformation deploy ^
        --template-file scanner.yaml ^
        --stack-name %STACK_NAME% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION%
) else (
    aws cloudformation deploy ^
        --template-file scanner.yaml ^
        --stack-name %STACK_NAME% ^
        --capabilities CAPABILITY_NAMED_IAM ^
        --region %REGION% ^
        --parameter-overrides NotificationEmail=%EMAIL%
)

echo.
echo Stack deployed. Retrieving manual invoke command...
aws cloudformation describe-stacks ^
    --stack-name %STACK_NAME% ^
    --region %REGION% ^
    --query "Stacks[0].Outputs[?OutputKey=='ManualInvokeCommand'].OutputValue" ^
    --output text
