package vault

import (
	v "github.com/hashicorp/vault/api"
	"strings"
	"sync"
)

// impl CertificateLifecycle
type certificateLifecycle struct {
	client *v.Client
	data   map[string]*v.Secret
	lock   sync.RWMutex
}

func NewCertificateLifecycle(client *v.Client) certificateLifecycle {
	return certificateLifecycle{
		client, make(map[string]*v.Secret), sync.RWMutex{},
	}
}

func (lifecycle *certificateLifecycle) IsDynamic(path string) bool {
	paths := strings.Split(path, "/")
	// this supports PKI certificate
	return len(paths) > 2 && paths[0] == "pki" && paths[1] == "issue"
}
