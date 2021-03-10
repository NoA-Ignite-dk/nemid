const ocsp = require('ocsp');
const path = require('path');
const fs = require('fs');
const issuer = path.join(__dirname, '../issuer.der');
const cert = path.join(__dirname, '../cert.der');

ocsp.check({
	issuer: fs.readFileSync(issuer),
	cert: fs.readFileSync(cert)
}, console.log);
