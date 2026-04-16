package main

import "github.com/olljanat-ai/firewall4ai/internal/secret"

// sealStateSecrets encrypts every persisted secret field in d in place.
// Idempotent — values already carrying the envelope prefix are left alone.
func sealStateSecrets(d *storeData) {
	for i := range d.Skills {
		d.Skills[i].Token = secret.Seal(d.Skills[i].Token)
	}
	for i := range d.Creds {
		d.Creds[i].Password = secret.Seal(d.Creds[i].Password)
		d.Creds[i].Token = secret.Seal(d.Creds[i].Token)
		d.Creds[i].HeaderValue = secret.Seal(d.Creds[i].HeaderValue)
		d.Creds[i].ParamValue = secret.Seal(d.Creds[i].ParamValue)
	}
	for i := range d.Databases {
		d.Databases[i].Password = secret.Seal(d.Databases[i].Password)
	}
}

// openStateSecrets decrypts every persisted secret field in place before the
// data is handed to runtime managers. Plaintext values from pre-encryption
// state.json files pass through unchanged; the next save re-encrypts them.
func openStateSecrets(d *storeData) {
	for i := range d.Skills {
		d.Skills[i].Token = secret.Open(d.Skills[i].Token)
	}
	for i := range d.Creds {
		d.Creds[i].Password = secret.Open(d.Creds[i].Password)
		d.Creds[i].Token = secret.Open(d.Creds[i].Token)
		d.Creds[i].HeaderValue = secret.Open(d.Creds[i].HeaderValue)
		d.Creds[i].ParamValue = secret.Open(d.Creds[i].ParamValue)
	}
	for i := range d.Databases {
		d.Databases[i].Password = secret.Open(d.Databases[i].Password)
	}
}
