#!/bin/bash
# Check if all tasks in tasks.md are complete
# Returns 0 if all complete, 1 if incomplete tasks remain

TASKS_FILE="specs/001-artifact-registry/tasks.md"

if [ ! -f "$TASKS_FILE" ]; then
    echo "Tasks file not found: $TASKS_FILE"
    exit 1
fi

# Count incomplete tasks (lines with "- [ ]")
INCOMPLETE=$(grep -c '^- \[ \]' "$TASKS_FILE" 2>/dev/null || echo "0")

# Count complete tasks (lines with "- [x]" or "- [X]")
COMPLETE=$(grep -cE '^- \[[xX]\]' "$TASKS_FILE" 2>/dev/null || echo "0")

TOTAL=$((INCOMPLETE + COMPLETE))

echo "Tasks: $COMPLETE/$TOTAL complete ($INCOMPLETE remaining)"

if [ "$INCOMPLETE" -eq 0 ]; then
    echo "ALL TASKS COMPLETE!"
    exit 0
else
    echo "Remaining tasks:"
    grep -n '^- \[ \]' "$TASKS_FILE" | head -20
    exit 1
fi
