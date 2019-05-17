package vault

import (
	v "github.com/hashicorp/vault/api"
)

//
// Interface behavior for vault extendable lease secrets
// (not every secret resource in vault does support lease extension).
//
type ExtendableSecret interface {
	Extend(path string)

	// this is unit function for measuring when to extend
	// checking whether secret is need to be extended or not
	// the logic mostly 2/3 total time
	IsOutdated(path string) bool
}

//
// Interface behavior for vault renewable secret
//
type RenewableSecret interface {
	Renew(path string)

	// this is unit function for measuring when to renew
	IsValid(path string) bool
}

type SecretTrait interface {
	// this function make sure whether the current path
	// are being supported in this lifecycle or not
	IsDynamic(string) bool

	// lookup method to fetch secret
	// it resolves around :
	// - local cache first
	// - remote
	Lookup(path string) (*v.Secret, error)
}

const (
	Invalid = iota
	Outdated
	Valid
)

//
// this enum represents whether current secret
// need to be renewed or extended
//
// Invalid ~ renew
// Outdated ~ extend
//
type Status int

type SecretLifecycle interface {
	SecretTrait

	//
	// This combine whether secret are still valid/invalid or outdated
	//
	// see ExtendableSecret#IsOutdated and RenewableSecret#IsValid
	//
	Status(path string) Status

	//
	// this sums up and hide the underlying logic of SecretLifecycle implementation.
	// since the underlying implementation might not support ExtendableSecret.
	//
	Refresh(path string)
}

//
// Most credential lifecycle interface
//
type CredentialLifecycle interface {
	ExtendableSecret
	RenewableSecret
	SecretLifecycle
}

//
// PKI certificate lifecycle interface
//
type CertificateLifecycle interface {
	RenewableSecret
	SecretLifecycle
}
