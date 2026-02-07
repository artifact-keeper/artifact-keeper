#!/usr/bin/env bash
# Setup + Run + Teardown for STS Credential Rotation Test
#
# This script provides FULL IAM role coverage regardless of whether
# the caller is root or an IAM user. When running as root, it creates
# a temporary IAM user to perform the AssumeRole test.
#
# Resources created (all auto-deleted on exit):
#   - S3 bucket (unless S3_BUCKET is provided)
#   - IAM role with S3 access
#   - IAM policy for S3 access
#   - IAM user + access keys (only when running as root)
#   - IAM policy for sts:AssumeRole (only when running as root)
#
# Prerequisites:
#   - AWS CLI v2 configured with admin/root credentials
#   - Backend binary built (cargo build)
#   - PostgreSQL running locally (or via Docker)
#
# Optional environment variables:
#   S3_BUCKET          - Use existing bucket instead of creating one
#   S3_REGION          - AWS region (default: us-east-1)
#   WAIT_FOR_EXPIRY    - Set to "true" for definitive expiry proof (~16 min)
#   KEEP_RESOURCES     - Set to "true" to skip teardown (for debugging)
#   DATABASE_URL       - PostgreSQL URL
#
# Usage:
#   ./setup-sts-test.sh                               # Quick IAM role test (~30s)
#   WAIT_FOR_EXPIRY=true ./setup-sts-test.sh          # Full expiry proof (~16 min)
#   S3_BUCKET=my-bucket ./setup-sts-test.sh           # Use existing bucket
#   KEEP_RESOURCES=true ./setup-sts-test.sh           # Don't cleanup (for debugging)
#
# Cost: ~$0.05 (temp S3 bucket, a few API calls)
#       All resources are deleted immediately after the test.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
S3_REGION="${S3_REGION:-us-east-1}"
KEEP_RESOURCES="${KEEP_RESOURCES:-false}"
DATABASE_URL="${DATABASE_URL:-postgresql://registry:registry@localhost:30432/artifact_registry}"

# Capture the caller's original AWS credentials BEFORE we override them
# for the temp user. These are needed for IAM admin operations (key rotation test).
ORIGINAL_AWS_ACCESS_KEY="${AWS_ACCESS_KEY_ID:-$(aws configure get aws_access_key_id 2>/dev/null || echo "")}"
ORIGINAL_AWS_SECRET_KEY="${AWS_SECRET_ACCESS_KEY:-$(aws configure get aws_secret_access_key 2>/dev/null || echo "")}"

# Unique suffix for all resources
SUFFIX="$(date +%s)"
ROLE_NAME="ak-sts-test-role-${SUFFIX}"
S3_POLICY_NAME="ak-sts-test-s3-${SUFFIX}"
ASSUME_POLICY_NAME="ak-sts-test-assume-${SUFFIX}"
USER_NAME="ak-sts-test-user-${SUFFIX}"

# Track created resources for teardown
CREATED_BUCKET=""
CREATED_ROLE=""
CREATED_S3_POLICY_ARN=""
CREATED_ASSUME_POLICY_ARN=""
CREATED_USER=""
CREATED_ACCESS_KEY_ID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${BLUE}[setup]${NC} $1"; }
warn() { echo -e "${YELLOW}[setup]${NC} $1"; }
ok()   { echo -e "${GREEN}[setup]${NC} $1"; }
err()  { echo -e "${RED}[setup]${NC} $1"; }

# ---------------------------------------------------------------------------
# Teardown — deletes ALL created resources in reverse order
# ---------------------------------------------------------------------------
teardown() {
    local exit_code=$?
    echo ""
    echo -e "${CYAN}=== Teardown ===${NC}"

    if [ "$KEEP_RESOURCES" = "true" ]; then
        warn "KEEP_RESOURCES=true — skipping teardown"
        warn "Clean up manually:"
        [ -n "$CREATED_USER" ] && warn "  IAM User: $CREATED_USER (access key: ${CREATED_ACCESS_KEY_ID:-none})"
        [ -n "$CREATED_ROLE" ] && warn "  IAM Role: $CREATED_ROLE"
        [ -n "$CREATED_S3_POLICY_ARN" ] && warn "  S3 Policy: $CREATED_S3_POLICY_ARN"
        [ -n "$CREATED_ASSUME_POLICY_ARN" ] && warn "  Assume Policy: $CREATED_ASSUME_POLICY_ARN"
        [ -n "$CREATED_BUCKET" ] && warn "  S3 Bucket: $CREATED_BUCKET"
        return $exit_code
    fi

    # 1. Delete IAM user (must delete access keys and detach policies first)
    if [ -n "$CREATED_USER" ]; then
        if [ -n "$CREATED_ACCESS_KEY_ID" ]; then
            info "Deleting access key for user $CREATED_USER..."
            aws iam delete-access-key \
                --user-name "$CREATED_USER" \
                --access-key-id "$CREATED_ACCESS_KEY_ID" 2>/dev/null || true
        fi
        if [ -n "$CREATED_ASSUME_POLICY_ARN" ]; then
            info "Detaching assume-role policy from user..."
            aws iam detach-user-policy \
                --user-name "$CREATED_USER" \
                --policy-arn "$CREATED_ASSUME_POLICY_ARN" 2>/dev/null || true
        fi
        if [ -n "$CREATED_S3_POLICY_ARN" ]; then
            info "Detaching S3 policy from user..."
            aws iam detach-user-policy \
                --user-name "$CREATED_USER" \
                --policy-arn "$CREATED_S3_POLICY_ARN" 2>/dev/null || true
        fi
        info "Deleting IAM user: $CREATED_USER"
        aws iam delete-user --user-name "$CREATED_USER" 2>/dev/null || true
        ok "IAM user deleted"
    fi

    # 2. Delete IAM role (must detach policy first)
    if [ -n "$CREATED_ROLE" ]; then
        if [ -n "$CREATED_S3_POLICY_ARN" ]; then
            info "Detaching S3 policy from role..."
            aws iam detach-role-policy \
                --role-name "$CREATED_ROLE" \
                --policy-arn "$CREATED_S3_POLICY_ARN" 2>/dev/null || true
        fi
        info "Deleting IAM role: $CREATED_ROLE"
        aws iam delete-role --role-name "$CREATED_ROLE" 2>/dev/null || true
        ok "IAM role deleted"
    fi

    # 3. Delete IAM policies
    if [ -n "$CREATED_ASSUME_POLICY_ARN" ]; then
        info "Deleting assume-role policy..."
        aws iam delete-policy --policy-arn "$CREATED_ASSUME_POLICY_ARN" 2>/dev/null || true
        ok "Assume-role policy deleted"
    fi
    if [ -n "$CREATED_S3_POLICY_ARN" ]; then
        info "Deleting S3 policy..."
        aws iam delete-policy --policy-arn "$CREATED_S3_POLICY_ARN" 2>/dev/null || true
        ok "S3 policy deleted"
    fi

    # 4. Delete S3 bucket
    if [ -n "$CREATED_BUCKET" ]; then
        info "Emptying S3 bucket: $CREATED_BUCKET"
        aws s3 rm "s3://${CREATED_BUCKET}" --recursive --quiet 2>/dev/null || true
        info "Deleting S3 bucket: $CREATED_BUCKET"
        aws s3 rb "s3://${CREATED_BUCKET}" --force 2>/dev/null || true
        ok "S3 bucket deleted"
    fi

    ok "All AWS resources cleaned up"
    return $exit_code
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo -e "${CYAN}=== STS Credential Rotation Test Setup ===${NC}"
echo ""

for cmd in aws jq curl; do
    if ! command -v "$cmd" &> /dev/null; then
        err "$cmd is not installed"
        exit 1
    fi
done

info "Verifying AWS credentials..."
CALLER=$(aws sts get-caller-identity --output json 2>/dev/null) || {
    err "AWS credentials not configured"
    exit 1
}
ACCOUNT_ID=$(echo "$CALLER" | jq -r '.Account')
CALLER_ARN=$(echo "$CALLER" | jq -r '.Arn')
ok "AWS account: $ACCOUNT_ID (identity: $CALLER_ARN)"

# Detect if running as root
IS_ROOT=false
if echo "$CALLER_ARN" | grep -q ":root$"; then
    IS_ROOT=true
    info "Running as root — will create a temporary IAM user for AssumeRole test"
fi

# ---------------------------------------------------------------------------
# Step 1: Create S3 bucket
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}=== Creating AWS Resources ===${NC}"

S3_BUCKET="${S3_BUCKET:-}"
if [ -z "$S3_BUCKET" ]; then
    S3_BUCKET="ak-sts-test-${SUFFIX}"
    CREATED_BUCKET="$S3_BUCKET"

    info "Creating S3 bucket: $S3_BUCKET (region: $S3_REGION)"
    if [ "$S3_REGION" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "$S3_BUCKET" \
            --region "$S3_REGION" > /dev/null
    else
        aws s3api create-bucket \
            --bucket "$S3_BUCKET" \
            --region "$S3_REGION" \
            --create-bucket-configuration "LocationConstraint=${S3_REGION}" > /dev/null
    fi

    aws s3api put-public-access-block \
        --bucket "$S3_BUCKET" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
        > /dev/null

    ok "S3 bucket created (public access blocked)"
else
    info "Using existing S3 bucket: $S3_BUCKET"
fi

# ---------------------------------------------------------------------------
# Step 2: Create IAM role with S3 access
# ---------------------------------------------------------------------------
info "Creating S3 access policy: $S3_POLICY_NAME"
S3_POLICY_DOC=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::${S3_BUCKET}", "arn:aws:s3:::${S3_BUCKET}/*"]
        }
    ]
}
EOF
)
S3_POLICY_RESP=$(aws iam create-policy \
    --policy-name "$S3_POLICY_NAME" \
    --policy-document "$S3_POLICY_DOC" \
    --output json)
CREATED_S3_POLICY_ARN=$(echo "$S3_POLICY_RESP" | jq -r '.Policy.Arn')
ok "S3 policy created: $CREATED_S3_POLICY_ARN"

# ---------------------------------------------------------------------------
# Step 3: Create temporary IAM user (if running as root)
# ---------------------------------------------------------------------------
if [ "$IS_ROOT" = true ]; then
    info "Creating temporary IAM user: $USER_NAME"
    aws iam create-user --user-name "$USER_NAME" --output json > /dev/null
    CREATED_USER="$USER_NAME"

    # Create access keys
    KEY_RESP=$(aws iam create-access-key --user-name "$USER_NAME" --output json)
    CREATED_ACCESS_KEY_ID=$(echo "$KEY_RESP" | jq -r '.AccessKey.AccessKeyId')
    USER_SECRET_KEY=$(echo "$KEY_RESP" | jq -r '.AccessKey.SecretAccessKey')
    ok "IAM user created with access key: ${CREATED_ACCESS_KEY_ID:0:8}..."

    # Give user permission to assume the test role
    info "Creating assume-role policy: $ASSUME_POLICY_NAME"
    ASSUME_POLICY_DOC=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
        }
    ]
}
EOF
)
    ASSUME_POLICY_RESP=$(aws iam create-policy \
        --policy-name "$ASSUME_POLICY_NAME" \
        --policy-document "$ASSUME_POLICY_DOC" \
        --output json)
    CREATED_ASSUME_POLICY_ARN=$(echo "$ASSUME_POLICY_RESP" | jq -r '.Policy.Arn')

    aws iam attach-user-policy \
        --user-name "$USER_NAME" \
        --policy-arn "$CREATED_ASSUME_POLICY_ARN"
    ok "User can assume role: $ROLE_NAME"

    # Also give the user direct S3 access (for uploading test artifacts)
    aws iam attach-user-policy \
        --user-name "$USER_NAME" \
        --policy-arn "$CREATED_S3_POLICY_ARN"
    ok "User has direct S3 access"

    # The trust policy must allow this user (not root) to assume the role
    ASSUME_PRINCIPAL_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${USER_NAME}"
fi

# ---------------------------------------------------------------------------
# Step 4: Create IAM role (trusted by the user/caller)
# ---------------------------------------------------------------------------
info "Creating IAM role: $ROLE_NAME"
# Use account root as the trust principal. This allows any IAM entity in
# the account to assume the role IF they have sts:AssumeRole permission.
# Our temp user gets that permission via the attached assume-role policy.
# This avoids the IAM propagation delay that occurs when referencing a
# just-created user ARN as a principal.
TRUST_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
)

aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --max-session-duration 3600 \
    --description "Temp role for artifact-keeper STS credential rotation test" \
    --output json > /dev/null
CREATED_ROLE="$ROLE_NAME"

aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$CREATED_S3_POLICY_ARN"
ok "IAM role created and S3 policy attached"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

# IAM propagation delay — new users/roles/policies need time to replicate
info "Waiting for IAM propagation (15s)..."
sleep 15

# Verify the role is assumable
info "Verifying role can be assumed..."
MAX_RETRIES=3
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if [ "$IS_ROOT" = true ]; then
        # Use the temporary user's credentials to assume the role
        VERIFY=$(AWS_ACCESS_KEY_ID="$CREATED_ACCESS_KEY_ID" \
                 AWS_SECRET_ACCESS_KEY="$USER_SECRET_KEY" \
                 AWS_SESSION_TOKEN="" \
                 aws sts assume-role \
                     --role-arn "$ROLE_ARN" \
                     --role-session-name "verify-test" \
                     --duration-seconds 900 \
                     --output json 2>&1) && break
    else
        VERIFY=$(aws sts assume-role \
                     --role-arn "$ROLE_ARN" \
                     --role-session-name "verify-test" \
                     --duration-seconds 900 \
                     --output json 2>&1) && break
    fi
    RETRY=$((RETRY + 1))
    if [ $RETRY -lt $MAX_RETRIES ]; then
        warn "AssumeRole failed (attempt $RETRY/$MAX_RETRIES), waiting 10s for propagation..."
        sleep 10
    fi
done

if [ $RETRY -ge $MAX_RETRIES ]; then
    err "Cannot assume role after $MAX_RETRIES attempts."
    err "Last error: $VERIFY"
    exit 1
fi
ok "Role is assumable: $ROLE_ARN"

# ---------------------------------------------------------------------------
# Step 5: Run the test
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}=== Running STS Credential Rotation Test ===${NC}"
echo ""

# Export common vars
export S3_BUCKET S3_REGION DATABASE_URL
export STS_ROLE_ARN="$ROLE_ARN"
export SKIP_CLEANUP=true
export WAIT_FOR_EXPIRY="${WAIT_FOR_EXPIRY:-false}"

if [ "$IS_ROOT" = true ]; then
    # Run the test AS the temporary IAM user (so AssumeRole works)
    # Pass admin creds separately for IAM operations (fast rotation test)
    info "Running test as IAM user: $USER_NAME"
    AWS_ACCESS_KEY_ID="$CREATED_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$USER_SECRET_KEY" \
    AWS_SESSION_TOKEN="" \
    IAM_ADMIN_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY" \
    IAM_ADMIN_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_KEY" \
    SIGNING_USER_NAME="$CREATED_USER" \
        "${SCRIPT_DIR}/test-s3-sts-rotation.sh"
    TEST_EXIT=$?
else
    # Non-root: caller has admin perms; extract username from ARN for rotation test
    IAM_USER_NAME=$(echo "$CALLER_ARN" | sed -n 's|.*:user/||p')
    IAM_ADMIN_ACCESS_KEY_ID="$ORIGINAL_AWS_ACCESS_KEY" \
    IAM_ADMIN_SECRET_ACCESS_KEY="$ORIGINAL_AWS_SECRET_KEY" \
    SIGNING_USER_NAME="${IAM_USER_NAME}" \
        "${SCRIPT_DIR}/test-s3-sts-rotation.sh"
    TEST_EXIT=$?
fi

# The trap will handle teardown
echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo -e "${GREEN}=== STS CREDENTIAL ROTATION TEST PASSED ===${NC}"
else
    echo -e "${RED}=== STS CREDENTIAL ROTATION TEST FAILED (exit code: $TEST_EXIT) ===${NC}"
fi

exit $TEST_EXIT
