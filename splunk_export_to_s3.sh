#!/bin/bash

# Splunk streaming export — single file, piped directly to S3
# Usage: Set SPLUNK_ES_TOKEN env var, then run this script

SPLUNK_URL="$SPLUNK_URL:8089"
S3_BUCKET="$S3_BUCKET"
S3_REGION="$REGION"
AWS_PROF="$AWS_PROF"
SEARCH="search index=main sourcetype=*"
EARLIEST="2026-01-01T00:00:00"
LATEST="2026-03-17T00:00:00"
S3_PATH="${S3_BUCKET}/test.log"

echo "Streaming Splunk export directly to S3..."
echo "Search: $SEARCH"
echo "Time range: $EARLIEST to $LATEST"
echo "Destination: $S3_PATH"
echo "AWS Profile: $AWS_PROF"
echo "Started: $(date)"
echo ""

curl -k -s -X POST \
    -H "Authorization: Bearer $SPLUNK_ES_TOKEN" \
    "${SPLUNK_URL}/services/search/jobs/export" \
    -d search="$SEARCH" \
    -d earliest_time="$EARLIEST" \
    -d latest_time="$LATEST" \
    -d output_mode=raw \
| aws s3 cp - "$S3_PATH" --region "$S3_REGION" --profile "$AWS_PROF"

# Verify
S3_SIZE=$(aws s3 ls "$S3_PATH" --region "$S3_REGION" --profile "$AWS_PROF" 2>/dev/null | awk '{print $3}')
if [ -n "$S3_SIZE" ] && [ "$S3_SIZE" -gt 0 ] 2>/dev/null; then
    SIZE_MB=$((S3_SIZE / 1048576))
    echo ""
    echo "Done! Uploaded ${SIZE_MB}MB"
    echo "File: $S3_PATH"
    echo "Finished: $(date)"
else
    echo ""
    echo "ERROR: Upload failed or file is empty."
fi
