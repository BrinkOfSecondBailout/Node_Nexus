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

#Ensure admin password is set
if [ -z "$NODE_NEXUS_ADMIN_PASSWORD" ]; then
	echo "Error: NODE_NEXUS_ADMIN_PASSWORD environment variable not set"
	exit 1
fi

# Commands to send (one per line, newline-terminated)
{
    echo "register danny bjj"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register daniel pokemon"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "login danny bjj"
    sleep 0.5
    echo "newdir media"
    sleep 0.5
    echo "root"
    sleep 0.5
    echo "newdir journals"
    sleep 0.5
    echo "addfile journals monday -s"
    sleep 1
    echo "I am very happy today"
    sleep 0.5
    echo "jump media"
    sleep 0.5
    echo "addfile curr icon.png -f ../static/img/small.png"
    sleep 1
    echo "root"
    sleep 0.5
    echo "newdir misc"
    sleep 0.5
    echo "newdir randoms"
    sleep 0.5
    echo "change_pw daniel pokemon"
    sleep 0.5
    echo "elevated"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "login daniel elevated"
    sleep 0.5
    echo "open monday"
    sleep 0.5
    echo "open icon.png"
    sleep 0.5
    echo "destroy -f monday"
    sleep 0.5
    echo "destroy -f icon.png"
    sleep 0.5
    echo "destroy -d journals"
    sleep 0.5
    echo "Y"
    sleep 0.5
    echo "root"
    sleep 0.5
    echo "newdir journals"
    sleep 0.5
    echo "addfile journals monday -s" 
    sleep 1
    echo "I am very happy today"
    sleep 0.5
    echo "addfile media icon.png -f ../static/img/small.png"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register irv triangle"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register shawn bar"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register lindsey bible"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "register nick mole"
    sleep 0.5
    echo "logout"
    sleep 0.5
    echo "login admin $NODE_NEXUS_ADMIN_PASSWORD"
    sleep 0.5
    echo "users"
    sleep 0.5
    echo "banish nick"
    sleep 0.5
    echo "classify monday"
    sleep 0.5
    echo "tree"
    sleep 0.5
    echo "nuke"
    sleep 0.5
    echo "Y"
    sleep 1
    echo "tree"
    sleep 0.5
    echo "newdir users"
    sleep 0.5
    echo "tree"
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
