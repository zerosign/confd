package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	v "github.com/hashicorp/vault/api"
	"time"
)

//
// Factory function of many lifecycle
//
//
func NewLifecycle(client *v.Client, paths []string, tollerance float64) (lifecycles map[string]SecretLifecycle) {
	for _, path := range paths {
		if path == "creds" {
			lifecycles[path] = NewCredentialLifecycle(client, tollerance)
		} else if path == "certs" {
			// lifecycles[path] = &NewCertificateLifecycle(client)
		}
	}

	return lifecycles
}

func LookupLease(client *v.Client, id string) (metadata *leaseMetadata, err error) {
	request := client.NewRequest("PUT", "/v1/sys/leases/lookup")

	if err := request.SetJSONBody(map[string]interface{}{
		"lease_id": id,
	}); err != nil {
		return nil, errors.New(fmt.Sprintf("%v, malformed JSONBody for leases/lookup %v", err, id))
	}

	response, err := client.RawRequest(request)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%v, can't create raw request for leases/lookup %v", err, id))
	}

	err = json.NewDecoder(response.Body).Decode(metadata)

	return metadata, err
}

//
// method to check whether both date are still in acceptance tollerance or not.
//
func inBetween(last, expire time.Time, tollerance float64) bool {
	current := time.Now()
	runtime := float64(current.Sub(last).Seconds())
	total := float64(expire.Sub(last).Seconds())

	return (runtime / total) < tollerance
}

//
// simple retry function to wrap lookup function remotely.
//
func retrySecret(fn func(path string) (*v.Secret, error), path string, max int, times int) (*v.Secret, error) {
	secret, err := fn(path)

	if err != nil {
		if times < max {
			return retrySecret(fn, path, max, times+1)
		} else {
			return nil, errors.New(fmt.Sprintf("can't resolve %v after trying %v", path, max))
		}
	} else {
		return secret, nil
	}
}
