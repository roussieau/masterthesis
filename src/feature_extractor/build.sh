#!/bin/bash
DOCKERCOMMAND=""

if groups $USER | grep &>/dev/null '\bdocker\b'
	then
		DOCKERCOMMAND="docker"
	else
		DOCKERCOMMAND="sudo docker"
fi

$DOCKERCOMMAND build -t pepac .