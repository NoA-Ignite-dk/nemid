const crypto = require('crypto')
const https = require('https')
const assert = require('nanoassert')
const concat = require('secure-concat')
const xml = require('xml-core')

module.exports = class PIDCPRRequest {
  static TEST = 'pidws.pp.certifikat.dk'
  static PROD = 'pidws.certifikat.dk'

  constructor (spid, key, cert, host = PIDCPRRequest.TEST) {
    this._spid = spid
    // Hack since https.request can work with KeyObject apparently
    this._key = key.export({ type: 'pkcs1', format: 'pem' })
    this._cert = cert
    this._host = host
  }

  match (pid, cpr, cb) {
    assert(typeof pid === 'string', 'pid must be string')
    assert(typeof cpr === 'string', 'cpr must be string')
    assert(cpr.length === 10, 'cpr must be 10 digits')

    pid = pid.replace(/^PID:/i, '')
    const rid = crypto.randomBytes(16).toString('hex')

    const body = this._body(rid, this._spid, pid, cpr)
    const req = https.request({
      method: 'POST',
      hostname: this._host,
      path: '/pid_serviceprovider_server/pidxml/',
      headers: {
        'content-type': 'application/x-www-form-urlencoded'
      },
      key: this._key,
      cert: this._cert
    }, function (res) {
      if (res.statusCode !== 200) return cb(new Error('Unable to access PID/CPR service'))

      res.pipe(concat({ limit: 4096 }, function (err, res) {
        if (err) return cb(err)

        const doc = xml.Parse(res.toString())

        const result = doc.getElementById(rid)
        if (result == null) return cb(new Error('Invalid response from PID/CPR service'))

        return cb(null, result.firstChild.getAttribute('statusCode') === '0')
      }))
    })

    req.once('error', cb)
    req.end(`PID_REQUEST=${body}`)
  }

  _body (rid, spid, pid, cpr) {
    return `<?xml version="1.0" encoding="iso-8859-1"?><method name="pidCprRequest" version="1.0"><request id="${rid}"><serviceId>${spid}</serviceId><pid>${pid}</pid><cpr>${cpr}</cpr></request></method>`
  }
}
