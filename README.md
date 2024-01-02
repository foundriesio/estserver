# EST Server

The project is an open source implementation of the Enrollment over Secure Transport
(EST) protocol as defined in [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html)
with added notes from [RFC 8951](https://www.rfc-editor.org/rfc/rfc8951) and
[RFC 8996](https://www.rfc-editor.org/rfc/rfc8996).
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

First you must create a TLS certificate for this server that your factory
devices will trust. This can be generated using the helper script
`contrib/mk-tls-keypair.sh`.

Next you need to create an intermediate "device CA" this service can use to
sign certificates with. There is a Fioctl helper for this:

```bash
fioctl keys ca add-device-ca <path to your PKI dir> --local-ca --local-ca-filename est-ca.pem
```

Finally, the this server needs a list of intermediate CAs to trust. This can
be obtained with:
```bash
fioctl keys ca show --just-device-cas > client-cas.pem
```

If you have devices that were registered **before** you configured your
Factory's PKI, then you'll also need to get a copy of the Foundries default
"online CA" that was used to sign certificates for those devices. You can
download this certificate by running:
```bash
fioctl get https://api.foundries.io/ota/default-online-ca.pem >> client-cas.pem
```

You can tell if a device was registered with the default online CA by looking
at it's certificate under ``/var/sota/client.pem``:
```bash
openssl x509 -in ./client.pem -issuer -noout

If the output looks something like:
```
issuer=CN=ota-devices-CA
```

Then the device was created using the default online CA.

Now the server can be run with:

```bash
$ ./bin/estserver \
    -root-cert <pkidir>/factory_ca.pem \
    -tls-cert <pkidir>/local-tls.pem  # cert from mk-tls-keypair above \
    -tls-key <pkidir>/local-tls.key   # key from mk-tls-keypair above \
    -ca-cert <pkidir>/est-ca.pem      # cert from fioctl keys ca add-device-ca \
    -ca-key <pkidir>/est-ca.key       # key from fioctl keys ca add-device-ca \
    -client-cas  client-cas.pem
```

fioconfig can then be pointed at this service to rotate certificates with:
```bash
$ fioconfig renew-cert https://<SERVER_NAME>/.well-known/est
```
