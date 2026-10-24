#!/bin/sh
# Runs signing-keys-tool with the arguments you give it, for example:
#   ./signing-keys-tool.sh generate --env prod --client acme
#   ./signing-keys-tool.sh check keys/prod/acme
# It is the same as: java -jar signing-keys-tool.jar <arguments>
# Build the jar first with: mvn package

# Follow a symbolic link to this script, so the jar is found next to the real file.
script=$0
while [ -h "$script" ]; do
    link=$(readlink "$script")
    case $link in
        /*) script=$link ;;
        *) script=$(dirname "$script")/$link ;;
    esac
done
dir=$(cd "$(dirname "$script")" && pwd)

exec java -jar "$dir/signing-keys-tool.jar" "$@"
