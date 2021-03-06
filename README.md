cryptographic identity toolkit
==============================


a generalization of the devguard sovereign identity managment

implementation:

- [x] golang
- [ ] C
- [ ] rust



## introduction

Privacy and security both start with Identity. Identity is a way to ensure you are in fact you.
While in traditional technical design an identity would be a username and password that is stored by a third party,
devguard uses cryptographic primitives to enable you to give an identity to yourself without registering with anyone.

Identitykit takes the idea further into other use cases, such as email, TLS ("https") or file signatures.


install the identitykit commandline util with go:

```
go install github.com/devguardio/identity/go/ik@latest
```

and initialize your secrets
```
ik init
```
your secrets are stored in ~/.identitykit and you should probably make a backup
do not share those files with anyone. instead share your public identity

```
ik id
```


### sequential file signatures and encryption

ik doc was moved to https://github.com/devguardio/ikdoc


### using identity as x509 CA

it's possible to use identitykit with TLS.
An identity becomes a CA, which can either sign temporary client and server certs or used directly.
Unless you call 'ik pem' , the local secret remains cold.

for example if you want to use cold identity that acts as a "CA" and emits hot server certs:

ik tls ca > /tmp/ca.pem
ik tls cert server.domain.com --dns localhost > /tmp/server.pem
openssl s_server -accept 8443 -www -cert /tmp/server.pem
curl  https://localhost:8443   --cacert /tmp/ca.pem

a regular tls client can then verify that the server acts on behalf of the cold identity "ik identity".

You could use export the identity as cert directly.
note that this means the secrets are now in the pem key file, and there's a danger of leaking them.
You probably want to avoid this.

ik tls serve
ik tls ca > /tmp/client.pem
ik tls pem > /tmp/client.key
curl  https://localhost:8443 --cacert /tmp/ca.pem --cert /tmp/client.pem --key /tmp/client.key


"ik tls serve" is an example tls server implemented using

```
tls.Config {
    ClientAuth: tls.RequireAnyClientCert,
    VerifyPeerCertificate: identity.VerifyPeerCertificate,
}
```

which verifies that the peer either has direct posession of the secret key with "ik pem"
or otherwise has a signature chain leading to "ik ca".


### etcd example

for example here's how to setup etcd with a cold CA:

```
ik tls ca > ca.pem
ik tls cert localhost --ip 127.0.0.1 > server.pem
ik tls cert localhost --ip 127.0.0.1 > client.pem
etcd \
    --client-cert-auth=true     \
    --trusted-ca-file ca.pem    \
    --cert-file server.pem      \
    --key-file server.pem       \
    --listen-client-urls='https://localhost:2379' \
    --advertise-client-urls='https://localhost:2379'

etcdctl member list  --cert=client.pem --key=client.pem --cacert=ca.pem
```

