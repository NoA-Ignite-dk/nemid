const compare = require('compare')
const assert = require('nanoassert')
const crypto = require('crypto')
const WebCrypto = require('node-webcrypto-ossl')
const XmlDSigJs = require('xmldsigjs')
const PIDCPRRequest = require('./pid-cpr-request')

// Unfortunately a singleton
XmlDSigJs.Application.setEngine('OpenSSL', new WebCrypto())

function derToPem (buf) {
  return `-----BEGIN CERTIFICATE-----
${buf.toString('base64').match(/.{1,64}/g).join('\n')}
-----END CERTIFICATE-----`
}

class NemID {
  static PROD = { pid: PIDCPRRequest.PROD }
  static TEST = { pid: PIDCPRRequest.TEST }

  constructor ({ spid, clientKey, clientCert, serverCA, env = NemID.TEST }) {
    this._clientKey = clientKey
    this._clientCert = clientCert
    this._serverCA = serverCA

    this._lookup = new PIDCPRRequest(spid, clientKey, derToPem(clientCert), env.pid)
  }

  authenticate ({ origin }) {
    const parameters = {
      clientflow: 'OcesLogin2',
      clientmode: 'standard',
      timestamp: Buffer.from(new Date().toISOString().slice(0, -5).replace('T', ' ') + '+0000').toString('base64'),
      ORIGIN: origin
    }

    return NemID.signParameters({
      parameters,
      privateKey: this._clientKey,
      spCert: this._clientCert
    })
  }

  verifyAuthenticate (nemIdResponse, cb) {
    assert(typeof nemIdResponse === 'string', 'nemIdResponse must be string')
    assert(typeof cb === 'function', 'callback must be given')

    const responseData = Buffer.from(nemIdResponse, 'base64').toString()
    const error = NemID.errorsByCode.get(responseData)
    if (error != null) return process.nextTick(cb, new NemIDError(error))

    // An RSA signature is well beyond 32 bytes
    if (responseData.length < 32) {
      const err = new NemIDError(NemID.errorByCode.get('NODE001'))
      err.cause += '. Input: ' + responseData

      return process.nextTick(cb, err)
    }

    try {
      var doc = XmlDSigJs.Parse(responseData)
      var signature = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')

      var signedXml = new XmlDSigJs.SignedXml(doc)
      signedXml.LoadXml(signature[0])
    } catch (ex) {
      const err = new NemIDError(NemID.errorByCode.get('NODE001'))
      err.cause += '. Exception: ' + ex

      return process.nextTick(cb, err)
    }

    signedXml.Verify().then(isValid => {
      if (isValid === false) return cb(null, false)

      const x509 = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Data')

      const certs = Array.from(x509).flatMap(c => XmlDSigJs.KeyInfoX509Data.LoadXml(c).X509CertificateList)

      const subjects = certs
        .map(c => c.Subject
          .split(', ')
          .reduce((o, kv) => {
            var [k, v] = kv.split('=')
            // remap this OID to the identifier name
            if (k === '2.5.4.5') k = 'serialNumber'

            o[k] = v
            return o
          }, {})
        )

      const user = subjects
        .find(c => c.serialNumber != null)

      if (user == null) return cb(null, false)

      return cb(null, user)
    }).catch(ex => {
      process.nextTick(cb, ex)
    })
  }

  matchCPR (pid, cpr, cb) {
    return this._lookup.match(pid, cpr, cb)
  }

  static signParameters ({ parameters, privateKey, spCert }) {
    const _keys = Object.keys(parameters).map(k => k.toLowerCase())
    assert(_keys.includes('sp_cert') === false)
    assert(_keys.includes('params_digest') === false)
    assert(_keys.includes('digest_signature') === false)

    parameters.SP_CERT = spCert.toString('base64')

    const input = this.normalizedParameters(parameters)

    parameters.PARAMS_DIGEST = crypto.createHash('sha256')
      .update(input)
      .digest('base64')

    parameters.DIGEST_SIGNATURE = crypto.createSign('sha256')
      .update(input)
      .sign(privateKey, 'base64')

    return parameters
  }

  static normalizedParameters (parameters) {
    const keys = Object.keys(parameters).sort(function (a, b) {
      return compare(a.toLowerCase(), b.toLowerCase())
    })

    return keys.reduce(concat, '')

    function concat (sum, key) {
      sum += key + parameters[key]
      return sum
    }
  }
}

class NemIDError extends Error {
  constructor (error) {
    super(error.cause)

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NemIDError)
    }

    this.code = error.code
    this.userMessage = error.message
  }
}

NemID.Error = NemIDError
NemID.errors = [
  {
    code: 'NODE001',
    cause: 'The XMLSig response could not be parsed',
    message: {
      en: `A technical error has occurred.
Please try again.
Contact [Service Provider] if the problem persists.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.
Kontakt [Tjenesteudbyder], hvis problemet fortsætter.`
    }
  },
  {
    code: 'APP001',
    cause: `Error while parsing the parameters by the NemID client library. Possible causes include:
- The parameters are not structured correctly (must be valid JSON for the JS client).
- A mandatory parameter is missing.
- An unsupported parameter was submitted.
- [JS Client: The ORIGIN parameter does not match the actual origin.]
- An unsupported value was provided for an otherwise supported parameter.
- The calculated digest does not match the value submitted in the PARAMS_DIGEST parameter.`,
    message: {
      en: `A technical error has occurred.
Please try again.
Contact [Service Provider] if the problem persists.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.
Kontakt [Tjenesteudbyder], hvis problemet fortsætter.`
    }
  },
  {
    code: 'APP002',
    cause: 'The sign text was illegal, e.g. the HTML document contained illegal tags or the PDF document did not match its hash.',
    message: {
      en: `A technical error has occurred.
Please try again.
Contact [Service Provider] if the problem persists.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.
Kontakt [Tjenesteudbyder], hvis problemet fortsætter.`
    }
  },
  {
    code: 'APP003',
    cause: 'An unrecoverable, internal error occurred in the client. Stack traces from this kind of errors are automatically transmitted to Nets-DanID for analysis.',
    message: {
      en: 'A technical error has occurred. Please contact NemID support [https://www.nemid.nu/dken/support/contact/].',
      da: 'Der er opstået en teknisk fejl. Kontakt NemID support [https://www.nemid.nu/dkda/support/faa_hjaelp_til_nemid/kontakt/].'
    }
  },
  {
    code: 'APP004',
    cause: `Returned by the client if it is unable to resume an existing user session and the
[JS Client: ALLOW_STEPUP parameter is not set to TRUE.]
[Others: NO_FALLBACK parameter is set]`,
    message: {
      en: `A technical error has occurred.
Please try again.
Contact [Service Provider] if the problem persists.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.
Kontakt [Tjenesteudbyder], hvis problemet fortsætter.`
    }
  },
  {
    code: 'APP007',
    cause: `Returned by the client if a mandatory parameter is missing, if an unrecognized parameter has been received,
    [JS Client: or if the ORIGIN parameter does not match the actual origin.]`,
    message: {
      en: `A technical error has occurred.
Contact [Service Provider].`,
      da: `Der er opstået en teknisk fejl.
Kontakt [Tjenesteudbyder].`
    }
  },
  {
    code: 'APP008',
    cause: `Returned by the client if an invalid combination of parameters has been received.
[JS Client: One example of an invalid combination would be if the client receives both CLIENTMODE=LIMITED and CREDENTIAL_UPDATE=ALIAS (since Limited mode does not support any of the administrative flows such as changing the user alias).]`,
    message: {
      en: `A technical error has occurred.
Contact [Service Provider].`,
      da: `Der er opstået en teknisk fejl.
Kontakt [Tjenesteudbyder]`
    }
  },
  {
    code: 'APP009',
    cause: 'Invalid HSession.',
    message: {
      en: `A technical error has occurred.
Please try again.
Contact [Service Provider] if the problem persists.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.
Kontakt [Tjenesteudbyder], hvis problemet fortsætter.`
    }
  },
  {
    code: 'APP010',
    cause: 'The JavaScript Client could not start.',
    message: {
      en: `A technical error has occurred.
Please try again.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.`
    }
  },
  {
    code: 'AUTH001',
    cause: 'Number of allowed pin code attempts exceeded. The pin code has been revoked. The client has informed the user of this.',
    message: {
      en: `Your NemID is blocked.
Please contact NemID support. [https://www.nemid.nu/dken/support/contact/]`,
      da: `Dit NemID er spærret.
Kontakt NemID support [https://www.nemid.nu/dkda/support/faa_hjaelp_til_ne
mid/kontakt/].`
    }
  },
  {
    code: 'AUTH003',
    cause: 'The user does not have an established agreement with the bank.',
    message: {
      en: `Login succeeded but you have no bank agreement.
Please contact your bank for mere details`,
      da: `Login er gennemført korrekt, men du har ikke en bankaftale.
Kontakt din bank for at høre nærmere.`
    }
  },
  {
    code: 'AUTH004',
    cause: 'The user’s OTP device is currently quarantined, due to too many failed authentication attempts. This error code is returned if the user attempts to authenticate with an OTP device that has been quarantined during a previous session.',
    message: {
      en: 'Your NemID is temporarily locked and you cannot log on until the 8 hour time lock has been lifted.',
      da: 'Dit NemID er midlertidigt låst i 8 timer og du kan ikke logge på før spærringen er ophævet.'
    }
  },
  {
    code: 'AUTH005',
    cause: 'The user’s OTP device is locked permanently, due to too many failed password attempts. This error code is returned if the user attempts to authenticate with an OTP device that has been locked during a previous session.',
    message: {
      en: `Your NemID has been blocked.
Please contact NemID support [https://www.nemid.nu/dken/support/contact/]`,
      da: `Dit NemID er spærret.
Kontakt NemID support [https://www.nemid.nu/dkda/support/faa_hjaelp_til_nemid/kontakt/].`
    }
  },
  {
    code: 'AUTH006',
    cause: 'The user has run out of OTP codes and does not have a pending OTP card.',
    message: {
      en: `You have used all the codes on your code card.
You can order a new code card on the Lost code card page [https://service.nemid.nu/dken/nemid/code_cards/lost_code
_card/]`,
      da: `Du har brugt alle nøgler på nøglekortet.
Du kan bestille et nyt på siden Mistet nøglekort [https://service.nemid.nu/dk-da/nemid/noeglekort/mistet_noeglekort/]`
    }
  },
  {
    code: 'AUTH007',
    cause: 'The user’s OTP device password is revoked either because it was marked as compromised or because the user has made too many failed OTP attempts. This error code is returned if the user attempts to authenticate with an OTP device that has been revoked during a previous session.',
    message: {
      en: `Your NemID password is blocked due to too many failed password attempts.
Please contact NemID support [https://www.nemid.nu/dken/support/contact/]`,
      da: `Din NemID-adgangskode er spærret på grund af for mange fejlede forsøg.
Kontakt NemID support [https://www.nemid.nu/dkda/support/faa_hjaelp_til_nemid/kontakt/].`
    }
  },
  {
    code: 'AUTH008',
    cause: 'The user’s OTP device is not activated and does not have an active pin code.',
    message: {
      en: `Your NemID is not active and you need support to issue a new activation password to activate.
Please call NemID support [https://www.nemid.nu/dken/support/contact/]`,
      da: `Dit NemID er ikke aktivt og du skal bestille en ny midlertidig adgangskode til aktivering hos support.
Ring til NemID support [https://www.nemid.nu/dkda/support/faa_hjaelp_til_nemid/kontakt/].`
    }
  },
  {
    code: 'AUTH009',
    cause: 'The client was unable to resume the user’s established session (either because the user logged in with only one factor, the session has timed out, or the session has been tampered with), and the single-sign-on attempt failed.',
    message: {
      en: `A technical error has occurred.
Please try again.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.`
    }
  },
  {
    code: 'AUTH010',
    cause: 'The user answered an OTP challenge that was not the latest issued. The user was probably trying to use the device in several sessions at once.',
    message: {
      en: `A technical error has occurred.
Please try again, and ensure that only one NemID login is running.`,
      da: `Der er opstået en teknisk fejl.
Tjek at kun ét NemID login er aktivt og forsøg igen.`
    }
  },
  {
    code: 'AUTH011',
    cause: 'The user authenticated using a PIN code on the mobile client.',
    message: {
      en: `NemID login on mobile does not support authentication using a temporary password.
Please contact NemID support to have a new temporary password issued [https://www.nemid.nu/dken/support/contact/]
Thereafter, please log on NemID at [url to Service Provider site containing client(s)]`,
      da: `NemID på mobil understøtter ikke brug af midlertidig adgangskode.
Kontakt NemID support for at få en ny kode udstedt [https://www.nemid.nu/dkda/support/faa_hjaelp_til_nemid/kontakt/]
Log derefter på med NemID på [url til Tjenesteudbyders side med klient(er)]`
    }
  },
  {
    code: 'AUTH012',
    cause: 'The user tried to answer an expired OTP challenge.',
    message: {
      en: `A technical error has occurred.
Please try again.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.`
    }
  },
  {
    code: 'AUTH013',
    cause: 'Split 2-factor authentication is not possible',
    message: {
      en: `A technical error has occurred.
Please try again.`,
      da: `Der er opstået en teknisk fejl.
Forsøg igen.`
    }
  },
  {
    code: 'AUTH017',
    cause: 'Environment error.',
    message: {
      en: `Something in the browser environment has caused NemID to stop working. This could be because of an incompatible plugin, too restrictive privacy settings or other environment factors.
Please try deactivating plugins, resetting your browser settings or try using a different browser.`,
      da: `En teknisk fejl i browseren gør at NemID ikke kan starte.
Forsøg at slå unødige plug-ins fra, eller prøv igen med en anden browser.`
    }
  },
  {
    code: 'AUTH018',
    cause: 'Code app is revoked, i.e. the user tried to approve in a code app that was revoked. This happen is a code app is revoked (for any reason) in the time from the code app is initiated and the user approved in the app.',
    message: {
      en: 'Your code app is revoked. To use it again please reactivate it.',
      da: 'Din nøgleapp er spærret. For at bruge den igen skal den genaktiveres.'
    }
  },
  {
    code: 'AUTH019',
    cause: `Prevent OTP card is activated and the user has no other active alternatives.
I.e. the bank has enabled the prevent OTP card option, but the user has no alternative to the OTP card.`,
    message: {
      en: 'It is not possible to login with a code card, please use a code app or code token.',
      da: 'Det er ikke muligt at logge ind med nøglekort, brug anden løsning nøgleapp eller nøgleviser.'
    }
  },
  {
    code: 'AUTH020',
    cause: 'Number of allowed attempts exceeded for self-contained logins, use 2factor login.',
    message: {
      en: 'Unable to login with 1-factor, please try with 2-factor login',
      da: 'Kunne ikke logge ind med 1-faktor, prøv med 2-faktor login.'
    }
  },
  {
    code: 'SRV001',
    cause: 'The signature on the client parameters could not be verified by DanID.',
    message: {
      en: 'A technical error has occurred. Please try again.',
      da: 'Der er opstået en teknisk fejl. Forsøg igen.'
    }
  },
  {
    code: 'SRV002',
    cause: 'The authentication request could not be parsed by DanID',
    message: {
      en: 'A technical error has occurred. Please try again.',
      da: 'Der er opstået en teknisk fejl. Forsøg igen.'
    }
  },
  {
    code: 'SRV003',
    cause: 'The time stamp of the authentication request was not within the allowed time span.',
    message: {
      en: 'A technical error has occurred. Please try again.',
      da: 'Der er opstået en teknisk fejl. Forsøg igen.'
    }
  },
  {
    code: 'SRV004',
    cause: 'An unrecoverable, internal error occurred in the NemID servers.',
    message: {
      en: 'A technical error has occurred. Please contact NemID support.',
      da: 'Der er opstået en teknisk fejl. Kontakt NemID support.'
    }
  },
  {
    code: 'SRV005',
    cause: 'The service provider was not known by DanID.',
    message: {
      en: 'A technical error has occurred. Please try again.',
      da: 'Der er opstået en teknisk fejl. Forsøg igen.'
    }
  },
  {
    code: 'SRV006',
    cause: 'The server lost the session it had established with the client. This may occur if the user leaves the client open for a prolonged stretch of time without interaction. ',
    message: {
      en: 'Time limit exceeded. Please try again.',
      da: 'Tidsgrænse er overskredet. Forsøg venligst igen.'
    }
  },
  {
    code: 'SRV007',
    cause: 'The user is using an obsolete version of the CSP or the Mobile client',
    message: {
      en: 'Please update to the most recent version.',
      da: 'Opdater venligst til nyeste version.'
    }
  },
  {
    code: 'SRV008',
    cause: 'The server requires that identity protection be enabled in the SAML request. ',
    message: {
      en: 'A technical error has occurred.',
      da: 'Der er opstået en teknisk fejl.'
    }
  },
  {
    code: 'SRV010',
    cause: 'The requested client is not available to the service provider.',
    message: {
      en: 'A technical error has occurred. Please try again. Contact [Service Provider] if the problem persists.',
      da: 'Der er opstået en teknisk fejl. Forsøg igen. Kontakt [Tjenesteudbyder], hvis problemet fortsætter.'
    }
  },
  {
    code: 'SRV011',
    cause: 'The transaction context was too long. ',
    message: {
      en: 'A technical error has occurred. Contact [Service Provider].',
      da: 'Der er opstået en teknisk fejl. Kontakt [Tjenesteudbyder].'
    }
  },
  {
    code: 'CAN001',
    cause: 'The user chose to cancel a flow that was started using a temporary password, e.g. an activation pin code. This error is not transmitted if the user navigates away from the page containing the client, e.g. by closing the browser window or clicking a link.',
    message: {
      en: 'You have cancelled the activation of NemID after submitting the activation password. Your activation password is no longer valid, and you must request a new activation password before you can activate and use NemID.',
      da: 'Du har afbrudt aktiveringen efter du har brugt den midlertidige adgangskode. Din midlertidige adgangskode er ikke længere gyldig, og du skal bestille en ny midlertidig adgangskode, før du kan aktivere og bruge NemID.'
    }
  },
  {
    code: 'CAN002',
    cause: 'The user chose to cancel the operation by pressing the cancel button. This error is not transmitted if the user navigates away from the page containing the client, e.g. by closing the browser window or clicking a link.',
    message: {
      en: 'You have cancelled login.',
      da: 'Du har afbrudt login.'
    }
  },
  {
    code: 'CAN003',
    cause: 'The client has timed out due to user inactivity, and the flow has been cancelled.',
    message: {
      en: 'The connection to the application has timed out or has been interrupted by another app.',
      da: 'Forbindelsen til applikationen er timet ud eller er blevet afbrudt af en anden app.'
    }
  },
  {
    code: 'CAN004',
    cause: 'The bank app has called logout during a flow.',
    message: {
      en: 'The session is cancelled. Please try again',
      da: 'Sessionen er afbrudt. Forsøg igen.'
    }
  },
  {
    code: 'CAN005',
    cause: 'No response was received from the code app. This error is not transmitted if the user navigates away from the page containing the client, e.g. by closing the browser window or clicking a link',
    message: {
      en: 'You took too long to authenticate the request you had sent to your code app.',
      da: 'Det tog for lang tid, før du godkendte den anmodning, du havde sendt til din nøgleapp'
    }
  },
  {
    code: 'CAN006',
    cause: 'Code app enrol flow cancelled due to max limit.',
    message: {
      en: 'The maximum number of active code apps you can have at any time is ##MAXACTIVENMAS##. If you wish to activate another code app, you must first block one of your current code apps at nemid.nu or by contacting NemID Support or your bank.',
      da: 'Du kan højst have ##MAXACTIVENMAS## aktive nøgleapps ad gangen. Hvis du vil aktivere en ny nøgleapp, skal du først spærre en af dine nuværende på nemid.nu eller ved at kontakte NemID support eller din bank.'
    }
  },
  {
    code: 'CAN007',
    cause: 'The user rejected the transaction in the code app.',
    message: {
      en: 'You rejected your code app authentication request. If this was incorrect, you can submit a new request after clicking “OK” to finish.',
      da: 'Du har afvist din anmodning om godkendelse i din nøgleapp. Hvis det var en fejl, kan du sende en ny anmodning, når du har afsluttet ved at klikke på ”Ok”.'
    }
  },
  {
    code: 'CAN008',
    cause: 'The transaction has been cancelled due to overwrite of the code app notification.',
    message: {
      en: 'You sent a new authentication request to your code app overwriting an existing one.',
      da: 'Du har sendt en ny anmodning til godkendelse i din nøgleapp, som overskriver en eksisterende.'
    }
  },
  {
    code: 'OCES001',
    cause: 'The user has opted out of OCES, but is trying to log in at a service provider that requires it.',
    message: {
      en: 'You only have NemID for online banking. If you wish to use NemID for other public or private services, you must affiliate a public digital signature to your NemID.',
      da: 'Du har kun NemID til netbank. Ønsker du at bruge NemID til andre hjemmesider, skal du tilknytte en offentlig digital signatur til dit NemID. '
    }
  },
  {
    code: 'OCES002',
    cause: 'The user was not OCES-qualified, but is trying to log in at a service provider that requires it.',
    message: {
      en: 'If you wish to use NemID for other services than online banking, you have to affiliate public digital signature to your NemID.',
      da: 'Ønsker du at bruge NemID til andet end netbank, skal du først tilknytte en offentlig digital signatur.'
    }
  },
  {
    code: 'OCES003',
    cause: 'The OTP device used to log in does not have OCES, but another OTP device belonging to the user does.',
    message: {
      en: ` You have attempted to log on using a NemID with no public digital signature
      If you previously have logged on to our service using your NemID, the error can be due to having more than one NemID and having used a different NemID than normally.`,
      da: `Der er ikke tilknyttet en offentlig digital signatur til det NemID du har forsøgt at logge på med.
      Hvis du tidligere har logget ind hos os med NemID, kan fejlen skyldes, at du har flere NemID, og har brugt et andet end normalt.`
    }
  },
  {
    code: 'OCES004',
    cause: 'The user is not OCES-qualified due to not having a CPR-number, being younger than 15 years of age or having the identity type bank employee.',
    message: {
      en: 'You can only use this NemID for your online banking service.',
      da: 'Du kan kun bruge dette NemID til netbank.'
    }
  },
  {
    code: 'OCES005',
    cause: 'Returned in situations where a new certificate must be issued to complete the operation, but a technical error occurred while doing so.',
    message: {
      en: `Issuing your public digital signature failed. Please try again.
      If the problem persists contact NemID support `,
      da: `Udstedelsen af din offentlige
      digitale signatur mislykkedes. Forsøg venligst igen.
      Hvis problemet fortsætter, kontakt NemID support `
    }
  },
  {
    code: 'OCES006',
    cause: 'The user has only inaccessible or inactive OCES on all of his OTP devices or no OCES at all.',
    message: {
      en: `You currently don’t have an active public digital signature (OCES certificate) affiliated with your NemID.
      To get this, start the regular NemID order flow after witch you will be asked to affiliate a public digital signature with your current NemID.`,
      da: 'Du har ikke en aktiv offentlig digital signatur tilknyttet NemID i øjeblikket. Ved bestilling af NemID vil du blive tilbudt at knytte en signatur til dit nuværende NemID.'
    }
  }
]
NemID.errorsByCode = NemID.errors.reduce((map, e) => {
  map.set(e.code, e)

  return map
}, new Map())

module.exports = NemID
