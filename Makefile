build-GitHubActionHookFunction:
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bootstrap
	cp ./bootstrap $(ARTIFACTS_DIR)/.
