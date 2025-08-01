#!/bin/bash

# Configuration
HOST="localhost"
PORT=8080  # Adjust if you use a different port
SERVER_PID=""
OUTPUT_FILE="test_output.txt"

# Ensure server is running
if ! pgrep -f "./nexus" > /dev/null; then
    echo "Starting Node Nexus server..."
    ./nexus $PORT > server_log.txt 2>&1 &
    SERVER_PID=$!
    sleep 3  # Give server time to start
else
    echo "Server already running."
fi

# Commands to send (one per line, newline-terminated)
{
    echo "register danny bjj"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register daniel fat"
    sleep 0.5
    echo "newdir media"
    sleep 0.5
    echo "addfile curr monday -s"
    sleep 1
    echo "I am very happy today"
    sleep 0.5
    echo "addfile curr icon.png -f ../static/img/small.png"
    sleep 1
    echo "root"
    sleep 0.5
    echo "newdir misc"
    sleep 0.5
    echo "newdir randoms"
    sleep 0.5
    echo "exit"
} | nc $HOST $PORT | tee $OUTPUT_FILE

# Optionally stop the server if started by the script
if [ -n "$SERVER_PID" ]; then
    echo "Stopping server (PID: $SERVER_PID)..."
    kill $SERVER_PID
    sleep 1
fi

echo "Test output saved to $OUTPUT_FILE"
