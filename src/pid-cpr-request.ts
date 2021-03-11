import crypto from 'crypto';
import https from 'https';
import assert from 'nanoassert';
import concat from 'secure-concat';
import xml from 'xml-core';

export class PIDCPRRequest {
	static TEST = 'pidws.pp.certifikat.dk'
	static PROD = 'pidws.certifikat.dk'
	private _host: string;
	private _cert: string;
	private _key: string | Buffer;
	private _spid: string;

	constructor (spid: string, key: crypto.KeyObject, cert: string, host = PIDCPRRequest.TEST) {
		this._spid = spid;
		// Hack since https.request can work with KeyObject apparently
		this._key = key.export({ type: 'pkcs1', format: 'pem' });
		this._cert = cert;
		this._host = host;
	}

	async match (pid: string, cpr: string): Promise<boolean> {
		assert(typeof pid === 'string', 'pid must be string');
		assert(typeof cpr === 'string', 'cpr must be string');
		assert(cpr.length === 10, 'cpr must be 10 digits');

		pid = pid.replace(/^PID:/i, '');
		const rid = crypto.randomBytes(16).toString('hex');

		const body = this._body(rid, this._spid, pid, cpr);

		return new Promise((resolve, reject) => {
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
				if (res.statusCode !== 200) return reject(new Error('Unable to access PID/CPR service'));
	
				res.pipe(concat({ limit: 4096 }, function (err: any, res: Buffer) {
					if (err) return reject(err);
	
					const doc = xml.Parse(res.toString());
	
					const result = doc.getElementById(rid);
					if (result == null) return reject(new Error('Invalid response from PID/CPR service'));
	
					return resolve(result.firstElementChild!.getAttribute('statusCode') === '0');
				}));
			});
	
			req.once('error', reject);
			req.end(`PID_REQUEST=${body}`);
		});
	}

	_body (rid: string, spid: string, pid: string, cpr: string) {
		return `<?xml version="1.0" encoding="iso-8859-1"?><method name="pidCprRequest" version="1.0"><request id="${rid}"><serviceId>${spid}</serviceId><pid>${pid}</pid><cpr>${cpr}</cpr></request></method>`;
	}
}
