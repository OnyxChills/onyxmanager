#!/usr/bin/env bash

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:
agent_uuid=""

while getopts "h?a:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    a)  agent_uuid=$OPTARG
        ;;
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

echo "Agent UUID: ${agent_uuid}, Leftovers: $@"

# End of file

exec 4<>/dev/tcp/localhost/27068

echo -n "ADD.AGENT${agent_uuid}" >&4
