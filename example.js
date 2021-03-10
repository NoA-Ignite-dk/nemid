const express = require('express')
const app = express()
const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
const cert = path.join(__dirname, 'cert.der')
const key = path.join(__dirname, 'test.key')
const issuer = path.join(__dirname, 'issuer.der')
const NemID = require('.')

const nemid = new NemID({
  clientKey: crypto.createPrivateKey({
    key: fs.readFileSync(key),
    format: 'pem',
    type: 'pkcs1'
  }),
  clientCert: fs.readFileSync(cert),
  serverCA: fs.readFileSync(issuer)
})

app.use(express.json())

app.get('/', function (req, res) {
  res.setHeader('X-Frame-Options', 'deny')
  // res.setHeader('Content-Security-Policy', "")
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Download-Options', 'noopen')
  res.setHeader('Strict-Transport-Security', 'max-age=5184000; includeSubDomains; preload')

  const parameters = nemid.authenticate({ origin: 'http://localhost:8000' })

  res.send(`<!DOCTYPE html>
  <html lang="en" dir="ltr">
    <head>
      <meta charset="utf-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width, initialscale=1.0, user-scalable=no">
      <title></title>
      <style>
        .nemid {
          border: 0;
          width: 320px;
          height: 480px;
        }
      </style>
      <script type="text/javascript">
        const NEMID_ORIGIN = 'https://appletk.danid.dk'

        function initNemid (parameters) {
          const elm = document.createElement('iframe')
          elm.id = 'nemid-' + Math.random().toString(32)
          elm.classList.add('nemid')
          elm.title = 'NemID'
          elm.allowfullscreen = true
          elm.src = \`\${NEMID_ORIGIN}/launcher/std/\${elm.id}\`

          window.addEventListener('message', handler)

          return { element: elm }

          function handler (ev) {
            if (ev.origin !== NEMID_ORIGIN) return
            if (ev.source !== elm.contentWindow) return

            // capture the event here
            ev.stopPropagation()

            var data = {}

            try {
              data = JSON.parse(ev.data)
            } catch (ex) {
              console.error(ev.data)
            }

            const { command, content } = data

            if (command === 'SendParameters') {
              const res = { command: 'parameters', content: JSON.stringify(parameters) }
              elm.contentWindow.postMessage(JSON.stringify(res), NEMID_ORIGIN)
              return false
            }

            if (command === 'changeResponseAndSubmit') {
              console.log('http://localhost:8000/', { content })
              // Terminal condition
              window.removeEventListener('message', handler)
              return false
            }
          }
        }
      </script>
    </head>
    <body>

      <script>
        const ctx = initNemid(${JSON.stringify(parameters)})
        document.body.appendChild(ctx.element)

        const ctx2 = initNemid(${JSON.stringify(parameters)})
        document.body.appendChild(ctx2.element)
      </script>
    </body>
  </html>`)
})

app.post('/', function (req, res) {
  nemid.verifyAuthenticate(req.body.content, console.log)
})

app.listen(8000)
