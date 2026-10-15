#!/usr/bin/env bats

setup() {
	SCRIPTPATH="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." >/dev/null 2>&1 && pwd -P)"
	source "${SCRIPTPATH}/modules/utils.sh"
}

@test "sanitize_domain strips shell metacharacters" {
	result="$(sanitize_domain 'exam;ple.com && rm -rf /')"
	[ "$result" = "examplecomrm-rf" ]
}

@test "sanitize_domain keeps a clean domain unchanged" {
	result="$(sanitize_domain 'sub.example.com')"
	[ "$result" = "sub.example.com" ]
}

@test "is_valid_domain accepts a normal domain" {
	run is_valid_domain "example.com"
	[ "$status" -eq 0 ]
}

@test "is_valid_domain rejects garbage" {
	run is_valid_domain "not a domain"
	[ "$status" -ne 0 ]
}

@test "count_lines returns 0 for a missing file" {
	result="$(count_lines /tmp/does_not_exist_rvnxc_test.txt)"
	[ "$result" = "0" ]
}
