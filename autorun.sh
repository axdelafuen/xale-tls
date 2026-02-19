#!/bin/sh

# Clean
rm -rf build
rm -rf Logs

# Configure CMake
cmake -B ./build

# Build
cmake --build ./build

# Run
if [ $? -eq 0 ]; then
    if [ "$1" = "server" ]; then
        ./build/xale-tls-server
    elif [ "$1" = "client" ]; then
        ./build/xale-tls-client
    fi
else
    exit 1
fi
