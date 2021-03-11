const express = require('express');
const app = express();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cert = path.join(__dirname, '../cert.der');
const key = path.join(__dirname, '../test.key');
const issuer = path.join(__dirname, '../issuer.der');
const { NemID } = require('@noaignite/nemid');

const nemid = new NemID({
	clientKey: crypto.createPrivateKey({
		key: fs.readFileSync(key),
		format: 'pem',
		type: 'pkcs1'
	}),
	clientCert: fs.readFileSync(cert),
	serverCA: fs.readFileSync(issuer)
});

app.use(require('cors')({
	origin: 'http://localhost:9966'
}));

app.use(express.json());

app.get('/authenticate', function (req, res) {
	const parameters = nemid.authenticate({ origin: 'http://localhost:9966' });

	res.send(parameters);
});

app.post('/authenticate/verify', function (req, res) {
	const response = req.body.content;

	nemid.verifyAuthenticate(response, function (err, userInfo) {
		if (err) {
			// err is a NemIDError
			// Log the cause of the error on the server somehow
			console.error(err);
			// And send a user message to the client
			return res.send(err.userMessage.da);
		}

		if (userInfo === false) {
			return res.send({ success: false });
		}

		// Can do stuff with userInfo now
		console.log(userInfo.serialNumber); // contains the user PID

		return res.send({ success: true });
	});
});

app.listen(8000);
