#!/bin/bash
# Check if all tasks in tasks.md are complete
# Returns 0 if all complete, 1 if incomplete tasks remain

TASKS_FILE="specs/003-frontend-ui-parity/tasks.md"

if [ ! -f "$TASKS_FILE" ]; then
    echo "Tasks file not found: $TASKS_FILE"
    exit 1
fi

# Count incomplete tasks (lines with "- [ ]")
INCOMPLETE=$(grep -E '^- \[ \]' "$TASKS_FILE" 2>/dev/null | wc -l | tr -d ' ')

# Count complete tasks (lines with "- [x]" or "- [X]")
COMPLETE=$(grep -E '^- \[[xX]\]' "$TASKS_FILE" 2>/dev/null | wc -l | tr -d ' ')

TOTAL=$((INCOMPLETE + COMPLETE))

echo "Tasks: $COMPLETE/$TOTAL complete ($INCOMPLETE remaining)"

if [ "$INCOMPLETE" -eq 0 ]; then
    echo "ALL TASKS COMPLETE!"
    exit 0
else
    echo "Remaining tasks:"
    grep -nE '^- \[ \]' "$TASKS_FILE" | head -20
    exit 1
fi
