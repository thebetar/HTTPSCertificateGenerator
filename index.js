import crypto from 'crypto';
import forge from 'node-forge';

export function generateCertificateAndKey(organisationName, { altNameIPs, altNameURIs, validityDays }) {
	const keys = forge.pki.rsa.generateKeyPair(2048);
	const cert = forge.pki.createCertificate();
	cert.publicKey = keys.publicKey;

	cert.serialNumber = '01' + crypto.randomBytes(19).toString('hex'); // 1 octet = 8 bits = 1 byte = 2 hex chars
	cert.validity.notBefore = new Date();
	cert.validity.notAfter = new Date(new Date().getTime() + 1000 * 60 * 60 * 24 * (validityDays ?? 1));

	const attrs = [
		{
			name: 'countryName',
			value: 'AU',
		},
		{
			shortName: 'ST',
			value: 'Some-State',
		},
		{
			name: 'organizationName',
			value: organisationName,
		},
	];
	cert.setSubject(attrs);
	cert.setIssuer(attrs);

	// add alt names so that the browser won't complain
	cert.setExtensions([
		{
			name: 'subjectAltName',
			altNames: [
				...(altNameURIs !== undefined ? altNameURIs.map(uri => ({ type: 6, value: uri })) : []),
				...(altNameIPs !== undefined ? altNameIPs.map(uri => ({ type: 7, ip: uri })) : []),
			],
		},
	]);
	// self-sign certificate
	cert.sign(keys.privateKey);

	// convert a Forge certificate and private key to PEM
	const pem = forge.pki.certificateToPem(cert);
	const privateKey = forge.pki.privateKeyToPem(keys.privateKey);

	return {
		cert: pem,
		privateKey,
	};
}
