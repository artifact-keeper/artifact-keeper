#!/usr/bin/env bash
# Setup + Run + Teardown for STS Credential Rotation Test
#
# This script:
#   1. Creates a temporary S3 bucket (or uses existing)
#   2. Optionally creates a temporary IAM role (if caller is an IAM user, not root)
#   3. Runs test-s3-sts-rotation.sh
#   4. Tears down ALL AWS resources it created
#
# Prerequisites:
#   - AWS CLI v2 configured with admin credentials
#   - Backend binary built (cargo build)
#   - PostgreSQL running locally (or via Docker)
#
# Optional environment variables:
#   S3_BUCKET        - Use existing bucket instead of creating one
#   S3_REGION        - AWS region (default: us-east-1)
#   KEEP_RESOURCES   - Set to "true" to skip teardown (for debugging)
#   DATABASE_URL     - PostgreSQL URL (default: postgresql://registry:registry@localhost:30432/artifact_registry)
#   CREATE_ROLE      - Set to "true" to create an IAM role (requires IAM user, not root)
#
# Usage:
#   ./setup-sts-test.sh                          # Create bucket, test, cleanup
#   S3_BUCKET=my-bucket ./setup-sts-test.sh      # Use existing bucket
#   KEEP_RESOURCES=true ./setup-sts-test.sh      # Don't cleanup (for debugging)
#
# Cost: ~$0.05 (S3 bucket exists briefly, a few API calls)
#       Resources are deleted immediately after the test.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
S3_REGION="${S3_REGION:-us-east-1}"
KEEP_RESOURCES="${KEEP_RESOURCES:-false}"
CREATE_ROLE="${CREATE_ROLE:-false}"
DATABASE_URL="${DATABASE_URL:-postgresql://registry:registry@localhost:30432/artifact_registry}"

# Unique suffix for all resources
SUFFIX="$(date +%s)"
ROLE_NAME="artifact-keeper-sts-test-${SUFFIX}"
POLICY_NAME="artifact-keeper-sts-test-policy-${SUFFIX}"
CREATED_BUCKET=""
CREATED_ROLE=""
CREATED_POLICY_ARN=""

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
# Teardown
# ---------------------------------------------------------------------------
teardown() {
    echo ""
    echo -e "${CYAN}=== Teardown ===${NC}"

    if [ "$KEEP_RESOURCES" = "true" ]; then
        warn "KEEP_RESOURCES=true - skipping teardown"
        warn "Resources to clean up manually:"
        [ -n "$CREATED_ROLE" ] && warn "  IAM Role: $CREATED_ROLE"
        [ -n "$CREATED_POLICY_ARN" ] && warn "  IAM Policy: $CREATED_POLICY_ARN"
        [ -n "$CREATED_BUCKET" ] && warn "  S3 Bucket: $CREATED_BUCKET"
        return
    fi

    # Delete IAM role (must detach policy first)
    if [ -n "$CREATED_ROLE" ]; then
        info "Detaching policy from role..."
        aws iam detach-role-policy \
            --role-name "$CREATED_ROLE" \
            --policy-arn "$CREATED_POLICY_ARN" 2>/dev/null || true

        info "Deleting IAM role: $CREATED_ROLE"
        aws iam delete-role --role-name "$CREATED_ROLE" 2>/dev/null || true
        ok "IAM role deleted"
    fi

    # Delete IAM policy
    if [ -n "$CREATED_POLICY_ARN" ]; then
        info "Deleting IAM policy: $CREATED_POLICY_ARN"
        aws iam delete-policy --policy-arn "$CREATED_POLICY_ARN" 2>/dev/null || true
        ok "IAM policy deleted"
    fi

    # Delete S3 bucket (must empty first)
    if [ -n "$CREATED_BUCKET" ]; then
        info "Emptying S3 bucket: $CREATED_BUCKET"
        aws s3 rm "s3://${CREATED_BUCKET}" --recursive --quiet 2>/dev/null || true

        info "Deleting S3 bucket: $CREATED_BUCKET"
        aws s3 rb "s3://${CREATED_BUCKET}" --force 2>/dev/null || true
        ok "S3 bucket deleted"
    fi

    ok "All AWS resources cleaned up"
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

# Detect if running as root (root can't assume roles)
IS_ROOT=false
if echo "$CALLER_ARN" | grep -q ":root$"; then
    IS_ROOT=true
    if [ "$CREATE_ROLE" = "true" ]; then
        warn "Running as root account - root cannot assume IAM roles"
        warn "Will use get-session-token instead (CREATE_ROLE=true ignored)"
        CREATE_ROLE=false
    fi
fi

# ---------------------------------------------------------------------------
# Step 1: Create S3 bucket (if not provided)
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}=== Creating AWS Resources ===${NC}"

S3_BUCKET="${S3_BUCKET:-}"
if [ -z "$S3_BUCKET" ]; then
    S3_BUCKET="artifact-keeper-sts-test-${SUFFIX}"
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

    # Block public access
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
# Step 2: Optionally create IAM role (for IAM users, not root)
# ---------------------------------------------------------------------------
ROLE_ARN=""
if [ "$CREATE_ROLE" = "true" ]; then
    info "Creating IAM policy: $POLICY_NAME"
    POLICY_DOC=$(cat <<POLICY_EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::${S3_BUCKET}",
                "arn:aws:s3:::${S3_BUCKET}/*"
            ]
        }
    ]
}
POLICY_EOF
)
    POLICY_RESP=$(aws iam create-policy \
        --policy-name "$POLICY_NAME" \
        --policy-document "$POLICY_DOC" \
        --output json)
    CREATED_POLICY_ARN=$(echo "$POLICY_RESP" | jq -r '.Policy.Arn')
    ok "IAM policy created: $CREATED_POLICY_ARN"

    info "Creating IAM role: $ROLE_NAME"
    TRUST_POLICY=$(cat <<TRUST_EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "${CALLER_ARN}"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
TRUST_EOF
)
    aws iam create-role \
        --role-name "$ROLE_NAME" \
        --assume-role-policy-document "$TRUST_POLICY" \
        --max-session-duration 3600 \
        --description "Temporary role for artifact-keeper STS credential rotation test" \
        --output json > /dev/null
    CREATED_ROLE="$ROLE_NAME"

    aws iam attach-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-arn "$CREATED_POLICY_ARN"
    ok "IAM role created and policy attached"

    info "Waiting for IAM role propagation (15s)..."
    sleep 15
    ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
    ok "Role ready: $ROLE_ARN"
else
    info "Skipping IAM role creation (using get-session-token mode)"
fi

# ---------------------------------------------------------------------------
# Step 3: Run the test
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}=== Running STS Credential Rotation Test ===${NC}"
echo ""

export S3_BUCKET S3_REGION DATABASE_URL
export SKIP_CLEANUP=true
[ -n "$ROLE_ARN" ] && export STS_ROLE_ARN="$ROLE_ARN"

"${SCRIPT_DIR}/test-s3-sts-rotation.sh"
TEST_EXIT=$?

# The trap will handle teardown
echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo -e "${GREEN}=== STS CREDENTIAL ROTATION TEST PASSED ===${NC}"
else
    echo -e "${RED}=== STS CREDENTIAL ROTATION TEST FAILED (exit code: $TEST_EXIT) ===${NC}"
fi

exit $TEST_EXIT
