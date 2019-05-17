package vault

import (
	"errors"
	"fmt"
	v "github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/confd/log"
	"strings"
	"sync"
	"time"
)

// impl CredentialLifecycle
type credentialLifecycle struct {
	client *v.Client
	// map of path to secret value
	data       map[string]*v.Secret
	lock       sync.RWMutex
	tollerance float64
}

func NewCredentialLifecycle(client *v.Client, tollerance float64) *credentialLifecycle {
	return &credentialLifecycle{
		client, make(map[string]*v.Secret), sync.RWMutex{}, tollerance,
	}
}

func (lifecycle *credentialLifecycle) IsDynamic(path string) bool {
	paths := strings.Split(path, "/")
	// this supports any /*/creds/* paths
	return len(paths) > 2 && paths[1] == "creds"
}

func (lifecycle *credentialLifecycle) Extend(path string) (err error) {
	lifecycle.lock.Lock()
	defer lifecycle.lock.Unlock()

	var secret *v.Secret
	var ok bool

	// extending need secret rather than path or id
	if secret, ok = lifecycle.data[path]; !ok {
		return errors.New(fmt.Sprintf("path %v not found", path))
	} else {
		renewer, err := lifecycle.client.NewRenewer(&v.RenewerInput{
			Secret: secret,
		})

		go renewer.Renew()
		defer renewer.Stop()

		// just do blocking logic in here since
		// we have our own global ticker that renew everything elses
		select {
		case err = <-renewer.DoneCh():
			return err
		case renewal := <-renewer.RenewCh():
			log.Info("secret with path: %#v", path)
			lifecycle.data[path] = renewal.Secret
			return nil
		}
	}

}

func (lifecycle *credentialLifecycle) Renew(path string) (err error) {
	lifecycle.lock.Lock()
	defer lifecycle.lock.Unlock()

	if _, ok := lifecycle.data[path]; !ok {
		log.Info("path %v doesn't exist when renewing but will do renew instead")
	}

	newSecret, err := lifecycle.client.Logical().Read(path)

	if err != nil {
		return err
	}

	delete(lifecycle.data, path)
	lifecycle.data[path] = newSecret

	return nil
}

//
// Check whether current path of secret are outdated or not.
//
// notes:
// - all network error will make this condition to true
//
func (lifecycle *credentialLifecycle) IsOutdated(path string) bool {
	lifecycle.lock.RLock()
	defer lifecycle.lock.RUnlock()

	if secret, ok := lifecycle.data[path]; ok {
		if metadata, err := LookupLease(lifecycle.client, secret.LeaseID); err == nil {
			return !inBetween(metadata.LastRenewalTime, metadata.ExpireTime, lifecycle.tollerance)
		} else {
			return true
		}

	} else {
		return true
	}
}

//
// Check whether current path of secret are outdated or not.
//
// notes:
// - all network error will make this condition to false
//
func (lifecycle *credentialLifecycle) IsValid(path string) bool {
	lifecycle.lock.RLock()
	defer lifecycle.lock.RUnlock()

	if secret, ok := lifecycle.data[path]; ok {
		if metadata, err := LookupLease(lifecycle.client, secret.LeaseID); err == nil {
			return metadata.ExpireTime.Before(time.Now())
		} else {
			return false
		}
	} else {
		return false
	}
}

//
// Check whether current path of secret are valid/outdated/invalid.
//
// notes:
// - all network error will make this function returns Invalid by default
//
func (lifecycle *credentialLifecycle) Status(path string) Status {
	lifecycle.lock.RLock()
	defer lifecycle.lock.RUnlock()

	if secret, ok := lifecycle.data[path]; ok {
		if metadata, err := LookupLease(lifecycle.client, secret.LeaseID); err == nil {
			if inBetween(metadata.LastRenewalTime, metadata.ExpireTime, lifecycle.tollerance) {
				return Valid
			} else if metadata.ExpireTime.After(time.Now()) {
				return Outdated
			} else {
				return Invalid
			}
		} else {
			return Invalid
		}
	} else {
		return Invalid
	}
}

func (lifecycle *credentialLifecycle) Refresh(path string) {
	switch lifecycle.Status(path) {
	case Invalid:
		lifecycle.Renew(path)
	case Outdated:
		lifecycle.Extend(path)
	case Valid:
		log.Info("credential %#v are still valid", path)
	}
}

//
// Lookup secret by given path.
//
// notes:
// - this method has default retry when error happens in network (3 times)
//
func (lifecycle *credentialLifecycle) Lookup(path string) (secret *v.Secret, err error) {
	lifecycle.lock.RLock()
	defer lifecycle.lock.RUnlock()

	if secret, ok := lifecycle.data[path]; ok {
		return secret, nil
	} else {
		if err := lifecycle.Renew(path); err != nil {
			return nil, err
		} else {
			return retrySecret(lifecycle.Lookup, path, 3, 0)
		}
	}
}
