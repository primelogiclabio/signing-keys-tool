@echo off
rem Runs signing-keys-tool with the arguments you give it, for example:
rem   signing-keys-tool.cmd generate --env prod --client acme
rem   signing-keys-tool.cmd check keys\prod\acme
rem Build the jar first with: mvn package
java -jar "%~dp0signing-keys-tool.jar" %*
