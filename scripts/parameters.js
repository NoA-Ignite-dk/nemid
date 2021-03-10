const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cert = path.join(__dirname, '../cert.der');
const key = path.join(__dirname, '../test.key');
const NemID = require('..');

const privateKey = crypto.createPrivateKey({
	key: fs.readFileSync(key),
	format: 'pem',
	type: 'pkcs1'
});

const spCert = fs.readFileSync(cert);

const params = NemID.signParameters({
	privateKey,
	spCert,
	parameters: {
		clientflow: 'OcesLogin2',
		clientmode: 'standard',
		timestamp: Buffer.from(Date.now().toString()).toString('base64'),
		ORIGIN: 'http://localhost:8000'
	}
});

console.log(JSON.stringify(params, null, 2));
