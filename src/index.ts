import compare from 'compare';
import assert from 'nanoassert';
import crypto from 'crypto';
import WebCrypto from 'node-webcrypto-ossl';
import * as XmlDSigJs from 'xmldsigjs';
import { PIDCPRRequest } from './pid-cpr-request';
import { Code, errors, NemIDError, NemIDErrorType } from './error';
export type { getNemIDAuthContext } from './browser';

// Unfortunately a singleton
XmlDSigJs.Application.setEngine('OpenSSL', new WebCrypto() as unknown as Crypto);

function derToPem (buf: Buffer) {
	return `-----BEGIN CERTIFICATE-----
${buf.toString('base64')!.match(/.{1,64}/g)!.join('\n')}
-----END CERTIFICATE-----`;
}

interface Parameters {
	clientflow: string;
	clientmode: string;
	timestamp: string;
	ORIGIN: string;
}

export interface SignedParameters {
	clientflow: string;
	clientmode: string;
	timestamp: string;
	ORIGIN: string;
	SP_CERT: string;
	PARAMS_DIGEST: string;
	DIGEST_SIGNATURE: string;
}

export interface UserInfo {
	C: string;
	O: string;
	CN: string;
	serialNumber: string;
}

export class NemID {
	static PROD = { pid: PIDCPRRequest.PROD }
	static TEST = { pid: PIDCPRRequest.TEST }

	private _clientKey: crypto.KeyObject;
	private _clientCert: Buffer;
	private _serverCA: Buffer;
	private _lookup: PIDCPRRequest;

	constructor ({ spid, clientKey, clientCert, serverCA, env = NemID.TEST }: { spid: string, clientKey: crypto.KeyObject, clientCert: Buffer, serverCA: Buffer, env: (typeof NemID.TEST | typeof NemID.PROD ) }) {
		this._clientKey = clientKey;
		this._clientCert = clientCert;
		this._serverCA = serverCA;

		this._lookup = new PIDCPRRequest(spid, clientKey, derToPem(clientCert), env.pid);
	}

	authenticate ({ origin }: { origin: string}) {
		const parameters: Parameters = {
			clientflow: 'OcesLogin2',
			clientmode: 'standard',
			timestamp: Buffer.from(new Date().toISOString().slice(0, -5).replace('T', ' ') + '+0000').toString('base64'),
			ORIGIN: origin
		};

		return NemID.signParameters({
			parameters,
			privateKey: this._clientKey,
			spCert: this._clientCert
		});
	}

	async verifyAuthenticate (nemIdResponse: string) {
		assert(typeof nemIdResponse === 'string', 'nemIdResponse must be string');

		const responseData = Buffer.from(nemIdResponse, 'base64').toString();
		const error = NemID.errorsByCode.get(responseData as Code);
		if (error != null) throw new NemIDError(error);

		// An RSA signature is well beyond 32 bytes
		if (responseData.length < 32) {
			const err = new NemIDError(NemID.errorsByCode.get('NODE001')!);
			err.cause += '. Input: ' + responseData;

			throw err;
		}

		let doc: Document;
		let signedXml: XmlDSigJs.SignedXml;
		try {
			doc = XmlDSigJs.Parse(responseData);
			const signature = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');

			signedXml = new XmlDSigJs.SignedXml(doc);
			signedXml.LoadXml(signature[0]);
		} catch (ex) {
			const err = new NemIDError(NemID.errorsByCode.get('NODE001')!);
			err.cause += '. Exception: ' + ex;

			throw err;
		}

		const isValid  = await signedXml.Verify();

		if (isValid === false) {
			return false;
		}

		const x509 = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Data');

		const certs = Array.from(x509).flatMap(c => XmlDSigJs.KeyInfoX509Data.LoadXml(c).Certificates);

		const subjects = certs
			.map(c => c.Subject
				.split(', ')
				.reduce((o, kv) => {
					let [k, v] = kv.split('=');
					// remap this OID to the identifier name
					if (k === '2.5.4.5') k = 'serialNumber';

					o[k] = v;
					return o;
				}, {} as {[key: string]: string})
			);

		const user = subjects
			.find(c => c.serialNumber != null) as UserInfo | undefined;

		if (user == null) {
			return false;
		}

		return user;
	}

	async matchCPR (pid: string, cpr: string): Promise<boolean> {
		return this._lookup.match(pid, cpr);
	}

	static signParameters ({ parameters, privateKey, spCert }: { parameters: Parameters, privateKey: crypto.KeyObject, spCert: Buffer }): SignedParameters {
		const _keys = Object.keys(parameters).map(k => k.toLowerCase());
		assert(_keys.includes('sp_cert') === false);
		assert(_keys.includes('params_digest') === false);
		assert(_keys.includes('digest_signature') === false);

		const SP_CERT = spCert.toString('base64');
		const input = this.normalizedParameters({ ...parameters, SP_CERT});

		const signedParameters = {
			...parameters,
			SP_CERT: SP_CERT,
			PARAMS_DIGEST: crypto.createHash('sha256')
				.update(input)
				.digest('base64'),
			DIGEST_SIGNATURE: crypto.createSign('sha256')
				.update(input)
				.sign(privateKey, 'base64')
		};

		return signedParameters;
	}

	static normalizedParameters (parameters: Parameters & { SP_CERT: string }) {
		const keys = (
			Object
				.keys(parameters)
				.sort((a, b)  => compare(a.toLowerCase(), b.toLowerCase()))
		) as (keyof Parameters)[];

		return keys.reduce((sum: string, key: keyof Parameters) => {
			sum += key + parameters[key];
			return sum;
		}, '');
	}

	static NemIDError = NemIDError;
	static errorsByCode = errors.reduce((map, e) => {
		map.set(e.code, e);

		return map;
	}, new Map<Code, NemIDErrorType>())
}
