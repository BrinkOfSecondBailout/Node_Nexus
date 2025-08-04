#!/bin/bash

# Configuration
HOST="localhost"
PORT=8000  # Adjust if you use a different port
SERVER_PID=""
OUTPUT_FILE="test_output2.txt"

# Ensure server is running
if ! pgrep -f "./nexus" > /dev/null; then
    echo "Starting Node Nexus server..."
    ./nexus $PORT > server_log.txt 2>&1 &
    SERVER_PID=$!
    sleep 3  # Give server time to start
else
    echo "Server already running."
fi

#Ensure admin password is set
if [ -z "$NODE_NEXUS_ADMIN_PASSWORD" ]; then
	echo "Error: NODE_NEXUS_ADMIN_PASSWORD environment variable not set"
	exit 1
fi

# Commands to send (one per line, newline-terminated)
{
    echo "register gustavo carpio"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "login danny bjj"
    sleep 0.5
    echo "newdir images"
    sleep 0.5
    echo "root"
    sleep 0.5
    echo "newdir users"
    sleep 0.5
    echo "addfile users users_log -s"
    sleep 1
    echo "danny gustavo lindsey nick daniel shawn irv"
    sleep 0.5
    echo "jump images"
    sleep 0.5
    echo "addfile curr icon.png -f ../static/img/small.png"
    sleep 1
    echo "root"
    sleep 0.5
    echo "open users_log"
    sleep 0.5
    echo "open icon.png"
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
