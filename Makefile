set-env:
	@echo "Reading public key from pub.key"
	@export SHADOW_KEY=$$(cat key.txt)

upload:
	SHADOW_KEY=$$(cat key.txt) go test -v -run TestUpload

test-sign:
	SHADOW_KEY=$$(cat key.txt) go test -v -run TestSign