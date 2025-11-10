#!/usr/bin/env bats

@test "Accept a valid pod" {
	run kwctl run  --request-path test_data/pod_creation.json --settings-path test_data/settings.json policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid liveness probe" {
	run kwctl run  --request-path test_data/pod_creation_invalid_liveness.json --settings-path test_data/settings.json policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "Reject invalid readiness probe" {
	run kwctl run  --request-path test_data/pod_creation_invalid_readiness.json --settings-path test_data/settings.json policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
}

@test "Reject invalid periodSeconds" {
	run kwctl run  --request-path test_data/pod_creation_invalid_period_seconds.json --settings-path test_data/settings.json policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*periodSeconds validation failed: 30 is above the limit of 10.*') -ne 0 ]
}
