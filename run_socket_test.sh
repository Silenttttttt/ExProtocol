#!/bin/bash

# Path to your virtual environment activation script
VENV_ACTIVATE="/home/silent/Documents/PRogramms/ForgeBot_wb/.venv/bin/activate"

# Ensure the virtual environment activation script exists
if [ ! -f "$VENV_ACTIVATE" ]; then
    echo "Virtual environment activation script not found at $VENV_ACTIVATE"
    exit 1
fi

# Run Server in a new terminal
xfce4-terminal --title="Protocol Server" --command="bash -c 'source $VENV_ACTIVATE; cd \"$(dirname \"$0\")\"; python -m ExProtocol.protocol_socket server; exec bash'" &
# Wait for 1 seconds before running the client
sleep 1

# Run Client in a new terminal
xfce4-terminal --title="Protocol Client" --command="bash -c 'source $VENV_ACTIVATE; cd \"$(dirname \"$0\")\"; python -m ExProtocol.protocol_socket client; exec bash'" & 