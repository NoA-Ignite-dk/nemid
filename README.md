# `nemid`

[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://conventionalcommits.org)

> Node.js module for NemID authentication and signing

## Install

```sh
npm install @noaignite/nemid
```

Note that the module is private, and as such cannot be installed unless you are authenticated with the NOA Ignite npm org.

You can create a `.npmrc` file in your repository with following contents:
`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`

Ensure you have NPM_TOKEN set as environment variable on your local machine & CI/CD server.

Read more [here](https://docs.npmjs.com/creating-and-viewing-access-tokens)

## Usage

Server:

```js
const { NemID } = require('@noaignite/nemid')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

// Example origin
const ORIGIN = 'https://localhost:8080'

// Paths to keys and certificates
const cert = path.join(__dirname, 'cert.der')
const key = path.join(__dirname, 'key.pem')
const issuer = path.join(__dirname, 'issuer.der')

const nemid = new NemID({
  clientKey: crypto.createPrivateKey({
    key: fs.readFileSync(key),
    format: 'pem',
    type: 'pkcs1'
  }),
  clientCert: fs.readFileSync(cert),
  serverCA: fs.readFileSync(issuer)
})

server.get('/authenticate', (req, res) => {
  return res.send(nemid.authenticate({ origin: ORIGIN }))
})

server.post('/authenticate/verify', (req, res) => {
  const response = req.body

  nemid.verifyAuthenticate(response)
    .then((userInfo) => {
      if (userInfo === false) {
        return res.send({ success: false })
      }

      // Can do stuff with userInfo now
      console.log(userInfo.serialNumber) // contains the user PID

      return res.send({ success: true })
    })
    .catch((err) => {
      // err is a NemIDError
      // Log the cause of the error on the server somehow
      console.error(err)
      // And send a user message to the client
      return res.send(err.userMessage.da)
    })
  })
})
```

Client:

```js
const { getNemIDAuthContext } = require('@noaignite/nemid')
const { data: parameters } = await get('http://localhost:8080/authenticate')

const context = getNemIDAuthContext(parameters)

document.body.appendChild(context.element)

const result = await context.done;

const { data: success } = await post('http://localhost:8080/authenticate/verify', result)
```

## Server API

### `const nemid = new NemID({ spid, clientKey, clientCert, serverCA, env = NemID.TEST })`

Create a new NemID instance. Takes 5 arguments:

* `spid` is the Service Provider ID, provided by Nets at registration.
* `clientKey` must be the client private key provided by Nets. See the section
  below for how to extract the key from the service provider bundle.
* `clientCert` must be the client certificate, including intermediate certs.
  See the section below for how to extract this from the service provider bundle.
* `serverCA` must be the Nets root certificate. This can be downloaded from
  NemIDs website.
* `env` is an object of endpoints for the different environments. Comes with
  `NemID.TEST` and `NemID.PROD` built in.

### `const parameters = nemid.authenticate({ origin })`

Create a new authentication attempt, by generating the appropriate parameters to
be passed to the client side script.

### `const userInfo = await nemid.verifyAuthenticate(response)`

Verify the response from the NemID applet. May throw an error if the
result was malformed or an error code from NemID. Otherwise returns `false`
for an invalid attempt or a object describing the authenticated user.

### `const valid = nemid.matchCPR(pid, cpr)`

Verify whether `pid` and `cpr` refer to the same person.

## Client API

```ts
import { getNemIDAuthContext } from '@noeignite/nemid`;
```

### `const context = getNemIDAuthContext(parameters, prod = false)`

Initialise a new NemID authentication context with `parameters` from the Server
API and which origin frame to load. Defaults to test (`appletk.danid.dk`).
Returns a context containing `{ element, done }`.

### `const iframeElm = context.element`

`HTMLIFrameElement` that you can place in the DOM.

### `const result = await context.done`

Wait for the authentication to be done. Rejects in case of unexpected failure or
resolves when there's a reply from NemID (which might not be a successful auth).

### Styling

The `element` can be targeted by the CSS class `nemid-iframe`. Below is the
default styling from NemID:

```css
.nemid-iframe {
  border: 0;
  width: 320px;
  height: 480px;
}
```

## Working with `.p12`

To extract all certificates, and print them to `stdout`:

```sh
openssl pkcs12 -in bundle.p12 -nokeys
```

Find you company certificate, and copy `-----BEGIN CERTIFICATE-----` to
`-----END CERTIFICATE-----` inclusive and paste into a new file, eg `cert.pem`.
This file is now in PEM format, but Nets requires it to be in DER format. It can
be converted with:

```sh
openssl x509 -inform pem -outform der -text -in cert.pem -out cert.der
```

The remaining certificates from the first command were part of the certificate
chain and need to be placed in their own file. Start by copying the sections
including the start and end markers to their own file, eg. `issuer.pem`.
Then convert them to DER format with:

```sh
openssl x509 -inform pem -outform der -text -in issuer.pem -out issuer.der
```

To extract the private key:

```sh
openssl pkcs12 -in bundle.p12 -nocerts -nodes
```

And copy the output including the start and end markers
`-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` to `key.pem`.
This file does not need to be converted to DER format.

**Note** `-nodes` removes the passphrase from the private key. If you want to
keep this, remove the option and supply your passphrase to
`crypto.createPrivateKey`

## License

[ISC](LICENSE)
