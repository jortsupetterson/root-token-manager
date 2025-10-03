const te = new TextEncoder();
let __accessKey: string;
async function getAccessKey(env: Env) {
	if (__accessKey) return __accessKey;
	__accessKey = await env.ACS_ACCESS_KEY.get();
	return __accessKey;
}

export const mailer = {
	async send(
		env: Env,
		body: {
			senderAddress: string;
			recipients: { to: { address: string; displayName?: string }[] };
			content: { subject: string; plainText?: string; html?: string };
			replyTo?: { address: string }[];
			userEngagementTrackingDisabled?: boolean;
		}
	) {
		const method = 'POST';
		const endpoint = env.ACS_EMAIL_ENDPOINT;
		const url = new URL(endpoint);
		const pathAndQuery = url.pathname + url.search;
		const dateRfc1123 = new Date().toUTCString();
		const keyBytes = Uint8Array.from(atob(await getAccessKey(env)), (c) => c.charCodeAt(0));
		const bodyJson = JSON.stringify(body);
		const bodyHashBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(bodyJson)));
		const bodyHashB64 = btoa(String.fromCharCode(...bodyHashBytes));
		const stringToSign = `${method}\n${pathAndQuery}\n${dateRfc1123};${url.host};${bodyHashB64}`;
		const hmacKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
		const sigBytes = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, te.encode(stringToSign)));
		const signature = btoa(String.fromCharCode(...sigBytes));
		const auth = `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`;

		const res = await fetch(endpoint, {
			method,
			headers: {
				Authorization: auth,
				'x-ms-date': dateRfc1123,
				'x-ms-content-sha256': bodyHashB64,
				'Content-Type': 'application/json',
			},
			body: bodyJson,
		});

		return {
			status: res.status,
			requestId: res.headers.get('x-ms-request-id') || null,
			operationLocation: res.headers.get('operation-location') || null,
		};
	},
};
