Vault OCSP
==========

Vault OCSP provides OCSP support for
[Hashicorp Vault](https://www.vaultproject.io/)
[PKI backends](https://www.vaultproject.io/docs/secrets/pki/index.html)
it uses Vault to retrieve a CA certificate at startup and the
`cert/{serial}` API to fetch the revocation status of certificates.
Responses for revoked certificates are cached in memory.

Vault OCSP is based on Hashicorp's Vault API and OCSP code from [Cloudflare's PKI and TLS toolkit](https://cfssl.org/).

License
-------

Vault OCSP is licensed under the Mozilla Public License 2.0.

The file `vendor/github.com/cloudflare/cfssl/ocsp/responder.go` is
copied from Cloudflare's cfssl repository and is licensed under cfssl's
BSD 2-clause "Simplified" License

Building Vault OCSP
-------------------

```bash
git clone https://github.com/T-Systems-MMS/vault-ocsp.git
cd vault-ocsp
go get
go build -o vault-ocsp
```

Running Vault OCSP
------------------

Vault OCSP is helpful:

```bash
./vault-ocsp -help
Usage of ./vault-ocsp:
  -pkimount string
        vault PKI mount to use (default "pki")
  -responderCert string
        OCSP responder signing certificate file
  -responderKey string
        OCSP responder signing private key file
  -serverAddr string
        Server IP and Port to use (default ":8080")
```

Vault OCSP supports the same environment variables as the Vault command
line interface. You will probably need to set `VAULT_ADDR`,
`VAULT_CACERT` and `VAULT_TOKEN` to use it.

The command line arguments `-responderCert` and `-responderKey` are
mandatory and should point to a PEM encoded X.509 certificate file and
a corresponding PEM and PKCS#1 encoded RSA private key file.

The key can be generated using `openssl rsa` and the certificate should
be signed by a CA that is trusted by the OCSP clients that will query
the Vault OCSP instance.

Make Vault OCSP known to Vault
------------------------------

You can use the
[`/pki/config/urls` API](https://www.vaultproject.io/api/secret/pki/index.html#set-urls)
to define Vault OCSP as OCSP responder. You should use an OCSP URL that
will be reachable from your OCSP clients. If you want to make the OCSP
responder available via https itself you will need a reverse proxy like
nginx or Apache httpd in front of Vault OCSP.
