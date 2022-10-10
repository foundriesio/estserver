# EST Server
The project is an open source implementation of the Enrollment over Secure Transport
(EST) protocol as defined in [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html).
The primary use for this server is to allow Linux microPlatform devices to
renew their certificates after they've been deployed to production. 

## Key Features from RFC 7030

  * 4.1 Distribution of CA Certificates `/cacerts`
  * 4.2.1 Client certificate enrollement `/simpleenroll`
  * 4.2.2 Client certificate renewal `/simplereenroll`

## Deviations from RFC 7030
As this project's primary aim is handling device certificate renewal, optional
features of the RFC have been omitted including:

  * 4.3 - CMC
  * 4.4 - Server side key generation
  * 4.5 - CSR attributes 

## Contributing

Pull requests are welcome. Run `make check` to verify changes will pass CI.

## Building
The simple "standalone" server can be built with:

`make bin/estserver`

## Using

TODO - how to generate TLS cert and CA
```
$ ./bin/estserver \
    -root-cert <pkidir>/factory_ca.pem \
    -tls-cert <pkidir>/local-tls.pem \
    -tls-key <pkidir>/local-tls.key \
    -ca-cert <pkidir>/local-ca.pem  \
    -ca-key <pkidir>/local-ca.key \
```

TODO - point to fioconfig once implementation is merged