module github.com/stxkxs/hsm/sdks/go

// The `go` directive is the MINIMUM toolchain a consumer needs, not the version
// this SDK is developed/tested with. It is deliberately kept low: this is a
// public client library, nothing in it uses post-1.21 language or stdlib
// features, and the only dependency (testify) declares go 1.17. Raising it
// would force downstream users onto a newer toolchain for no benefit, and would
// hard-fail builds under GOTOOLCHAIN=local. CI still builds and tests with the
// current release (1.26.x); GOTOOLCHAIN=auto makes that work unchanged.
//
// Caveat for contributors: because the directive is < 1.22, `for` loop
// variables keep the old per-loop (shared) semantics. No code here captures a
// range variable in a closure or goroutine; keep it that way, or raise the
// directive to 1.22+ in the same change.
go 1.21

require github.com/stretchr/testify v1.12.1

require go.yaml.in/yaml/v3 v3.0.5 // indirect
