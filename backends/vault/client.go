package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/confd/log"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type secretVault struct {
	key     string
	secret  *vaultapi.Secret
	created time.Time
}

//
// Lifecycle management of vault dynamic secret
//
type secretLifecycle struct {
	client   *vaultapi.Client
	data     map[string]atomic.Value
	lock     *sync.RWMutex
	interval int
}

// extend lease id ~ renew lease id
func (s *secretLifecycle) Extend(id string) (err error) {
	secret := s.data[id]
	renewer, err := s.client.NewRenewer(&vaultapi.RenewerInput{
		Secret: secret.Load().(*vaultapi.Secret),
	})

	go renewer.Renew()
	defer renewer.Stop()

	// just do blocking logic in here since
	// we have our own global ticker that renew everything elses
	select {
	case err = <-renewer.DoneCh():
		return err

	case renewal := <-renewer.RenewCh():
		log.Info("Secret with id: %#v succesfully renewed", id)

		value := s.data[id]
		secret := value.Load().(secretVault)
		value.Store(secretVault{secret.key, renewal.Secret, renewal.RenewedAt})
		return nil
	}
}

// renew credential
func (s *secretLifecycle) Renew(id string) (err error) {
	s.lock.Lock()
	value := s.data[id]
	secret := value.Load().(secretVault)
	newSecret, err := s.client.Logical().Read(secret.key)

	if err != nil {
		return err
	}

	delete(s.data, id)
	value = atomic.Value{}
	value.Store(secretVault{secret.key, newSecret, time.Now()})
	s.data[newSecret.LeaseID] = value

	s.lock.Unlock()

	return nil
}

func (s *secretLifecycle) Handle(ctx context.Context) (quit chan struct{}) {
	// TODO: handle secret lifecycle
	ticker := time.NewTicker(time.Duration(s.interval) * time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				// do something
				// for all dynamic secrets do extend in parallel
				var wg sync.WaitGroup
				wg.Add(len(s.data))

				for k, value := range s.data {
					go func() {
						secret := value.Load().(secretVault)
						data := map[string]string{"lease_id": secret.secret.LeaseID}

						//
						// You know what I confuse on how vault abstract their code flows or maybe I'm not just
						// into Go language anymore.
						//
						// TODO: checks whether PUT request for "sys/leases/lookup" do mutation or not in the code
						//       and what the returns of this thing
						// fsecret, err := s.client.Logical().Write("sys/leases/lookup", data); err == nil && fsecret != nil {

						if secret.secret.Renewable {
							s.Extend(k)
						}
						// TODO add s.Renew
						wg.Done()
					}()
				}
				wg.Wait()

			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	return quit
}

// Client is a wrapper around the vault client
//
// We will use IntervalProcessor as frontends to our
// vault dynamic secret lifecycle.
//
// Apparently, StoreClient impl are being shared accross
// TemplateResource instance, so we could implement dynamic secret engine
// by piggy-backing this Client struct.
//
type Client struct {
	lifecycle secretLifecycle
	client    *vaultapi.Client
	// cache (dynamics) here is important since if you read more than once to
	// dynamic secret, it will generate new credential data for you
	// { path => value }
	dynamicSecrets map[string]atomic.Value
	lock           sync.RWMutex
}

// get a
func getParameter(key string, parameters map[string]string) string {
	value := parameters[key]
	if value == "" {
		// panic if a configuration is missing
		panic(fmt.Sprintf("%s is missing from configuration", key))
	}
	return value
}

// panicToError converts a panic to an error
func panicToError(err *error) {
	if r := recover(); r != nil {
		switch t := r.(type) {
		case string:
			*err = errors.New(t)
		case error:
			*err = t
		default: // panic again if we don't know how to handle
			panic(r)
		}
	}
}

// authenticate with the remote client
func authenticate(c *vaultapi.Client, authType string, params map[string]string) (err error) {
	var secret *vaultapi.Secret

	// handle panics gracefully by creating an error
	// this would happen when we get a parameter that is missing
	defer panicToError(&err)

	path := params["path"]
	if path == "" {
		path = authType
		if authType == "app-role" {
			path = "approle"
		}
	}
	url := fmt.Sprintf("/auth/%s/login", path)

	switch authType {
	case "app-role":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"role_id":   getParameter("role-id", params),
			"secret_id": getParameter("secret-id", params),
		})
	case "app-id":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"app_id":  getParameter("app-id", params),
			"user_id": getParameter("user-id", params),
		})
	case "github":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"token": getParameter("token", params),
		})
	case "token":
		c.SetToken(getParameter("token", params))
		secret, err = c.Logical().Read("/auth/token/lookup-self")
	case "userpass":
		username, password := getParameter("username", params), getParameter("password", params)
		secret, err = c.Logical().Write(fmt.Sprintf("%s/%s", url, username), map[string]interface{}{
			"password": password,
		})
	case "kubernetes":
		jwt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return err
		}
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"jwt":  string(jwt[:]),
			"role": getParameter("role-id", params),
		})
	case "cert":
		secret, err = c.Logical().Write(url, map[string]interface{}{})
	}

	if err != nil {
		return err
	}

	// if the token has already been set
	if c.Token() != "" {
		return nil
	}

	if secret == nil || secret.Auth == nil {
		return errors.New("Unable to authenticate")
	}

	log.Debug("client authenticated with auth backend: %s", authType)
	// the default place for a token is in the auth section
	// otherwise, the backend will set the token itself
	c.SetToken(secret.Auth.ClientToken)
	return nil
}

func getConfig(address, cert, key, caCert string) (*vaultapi.Config, error) {
	conf := vaultapi.DefaultConfig()
	conf.Address = address

	tlsConfig := &tls.Config{}
	if cert != "" && key != "" {
		clientCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		tlsConfig.BuildNameToCertificate()
	}

	if caCert != "" {
		ca, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	conf.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return conf, nil
}

// New returns an *vault.Client with a connection to named machines.
// It returns an error if a connection to the cluster cannot be made.
func New(address, authType string, params map[string]string) (*Client, error) {
	if authType == "" {
		return nil, errors.New("you have to set the auth type when using the vault backend")
	}
	log.Info("Vault authentication backend set to %s", authType)
	conf, err := getConfig(address, params["cert"], params["key"], params["caCert"])

	if err != nil {
		return nil, err
	}

	c, err := vaultapi.NewClient(conf)
	if err != nil {
		return nil, err
	}

	if err := authenticate(c, authType, params); err != nil {
		return nil, err
	}

	data := make(map[string]atomic.Value)
	lock := sync.RWMutex{}

	// spawn background thread that checks
	interval, err := strconv.Atoi(params["interval"])

	if err != nil {
		return nil, err
	}

	lifecycle := secretLifecycle{c, data, &lock, interval}

	go lifecycle.Handle(context.Background())

	return &Client{lifecycle, c, data, lock}, nil
}

//
// Vault credential paths
//
// sadly, there were no exact global variable path for credential in
// vault. Most creds pattern are just being implemented directly in each plugin.
//
// example: https://github.com/hashicorp/vault/blob/278bdd1f4e3ca4653f4a11d8591ecebeafb196bd/builtin/logical/mongodb/path_creds_create.go#L14
//
func isCredential(key string) bool {
	paths := strings.Split(key, "/")
	return len(paths) > 2 && paths[1] == "creds"
}

//
// Get secret from (in order) :
// - dynamic secrets if is credential
// - read from vault api directly
//
func (c *Client) getSecret(key string) (secret *vaultapi.Secret, err error) {
	if isCredential(key) {
		if value, ok := c.dynamicSecrets[key]; ok {
			secret = value.Load().(*vaultapi.Secret)
		} else {
			secret, err = c.client.Logical().Read(key)
		}
	} else {
		secret, err = c.client.Logical().Read(key)
	}

	return secret, err
}

// GetValues queries etcd for keys prefixed by prefix.
func (c *Client) GetValues(keys []string) (map[string]string, error) {
	branches := make(map[string]bool)
	for _, key := range keys {
		walkTree(c, key, branches)
	}
	vars := make(map[string]string)
	for key := range branches {

		log.Debug("getting %s from vault", key)

		secret, err := c.getSecret(key)

		if err != nil {
			log.Debug("there was an error extracting %s", key)
			return nil, err
		}
		if secret == nil || secret.Data == nil {
			continue
		}

		// if the key has only one string value
		// treat it as a string and not a map of values
		if val, ok := isKV(secret.Data); ok {
			vars[key] = val
		} else {
			// save the json encoded response
			// and flatten it to allow usage of gets & getvs
			js, _ := json.Marshal(secret.Data)
			vars[key] = string(js)
			flatten(key, secret.Data, vars)
		}
	}
	return vars, nil
}

// isKV checks if a given map has only one key of type string
// if so, returns the value of that key
func isKV(data map[string]interface{}) (string, bool) {
	if len(data) == 1 {
		if value, ok := data["value"]; ok {
			if text, ok := value.(string); ok {
				return text, true
			}
		}
	}
	return "", false
}

// recursively walks on all the values of a specific key and set them in the variables map
func flatten(key string, value interface{}, vars map[string]string) {
	switch value.(type) {
	case string:
		log.Debug("setting key %s to: %s", key, value)
		vars[key] = value.(string)
	case map[string]interface{}:
		inner := value.(map[string]interface{})
		for innerKey, innerValue := range inner {
			innerKey = path.Join(key, "/", innerKey)
			flatten(innerKey, innerValue, vars)
		}
	default: // we don't know how to handle non string or maps of strings
		log.Warning("type of '%s' is not supported (%T)", key, value)
	}
}

// recursively walk the branches in the Vault, adding to branches map
func walkTree(c *Client, key string, branches map[string]bool) error {
	log.Debug("listing %s from vault", key)

	// strip trailing slash as long as it's not the only character
	if last := len(key) - 1; last > 0 && key[last] == '/' {
		key = key[:last]
	}
	if branches[key] {
		// already processed this branch
		return nil
	}
	branches[key] = true

	resp, err := c.client.Logical().List(key)

	if err != nil {
		log.Debug("there was an error extracting %s", key)
		return err
	}
	if resp == nil || resp.Data == nil || resp.Data["keys"] == nil {
		return nil
	}

	switch resp.Data["keys"].(type) {
	case []interface{}:
		// expected
	default:
		log.Warning("key list type of '%s' is not supported (%T)", key, resp.Data["keys"])
		return nil
	}

	keyList := resp.Data["keys"].([]interface{})
	for _, innerKey := range keyList {
		switch innerKey.(type) {

		case string:
			innerKey = path.Join(key, "/", innerKey.(string))
			walkTree(c, innerKey.(string), branches)

		default: // we don't know how to handle other data types
			log.Warning("type of '%s' is not supported (%T)", key, keyList)
		}
	}
	return nil
}

// WatchPrefix - not implemented at the moment
func (c *Client) WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) (uint64, error) {
	<-stopChan
	return 0, nil
}
