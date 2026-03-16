#!/bin/bash

# Splunk streaming export — single file, saved locally
# Usage: Set SPLUNK_ES_TOKEN env var, then run this script

SPLUNK_URL="$SPLUNK_URL:8089"
OUTFILE="test.log"
SEARCH="search index=main sourcetype=*"
EARLIEST="2026-01-01T00:00:00"
LATEST="2026-03-17T00:00:00"

echo "Streaming Splunk export to $OUTFILE..."
echo "Search: $SEARCH"
echo "Time range: $EARLIEST to $LATEST"
echo "Started: $(date)"
echo ""

HTTP_CODE=$(curl -k -s -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $SPLUNK_ES_TOKEN" \
    "${SPLUNK_URL}/services/search/jobs/export" \
    -d search="$SEARCH" \
    -d earliest_time="$EARLIEST" \
    -d latest_time="$LATEST" \
    -d output_mode=raw \
    -o "$OUTFILE")

if [ "$HTTP_CODE" -eq 200 ] && [ -s "$OUTFILE" ]; then
    echo "Done!"
    echo "File: $OUTFILE"
    echo "Size: $(ls -lh "$OUTFILE" | awk '{print $5}')"
    echo "Lines: $(wc -l < "$OUTFILE")"
    echo "Finished: $(date)"
else
    echo "ERROR: Export failed (HTTP $HTTP_CODE)"
    rm -f "$OUTFILE"
fi
