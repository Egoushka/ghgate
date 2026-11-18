//go:build !unix

package ca

// tightenOwn does nothing where file ownership is not a uid; requirePrivate still decides.
func tightenOwn(string, int) error { return nil }
