#!/bin/bash
# Conda build script for test-package
mkdir -p "$PREFIX/opt/test-package"
echo "Hello from test-package!" > "$PREFIX/opt/test-package/test-file.txt"

# Copy data file if present
if [ -f "data.bin" ]; then
    cp data.bin "$PREFIX/opt/test-package/"
fi
