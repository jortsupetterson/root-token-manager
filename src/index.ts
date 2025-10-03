/// <reference path="../worker-configuration.d.ts" />
import { mailer } from './mailer';

declare const crypto: Crypto;

const LOCK_KEY = 'acct-token-rot-lock';
const LOCK_TTL = 300; // seconds

function randToken(): string {
	return crypto.randomUUID();
}

/** KV-lock helpers */
export async function acquireLock(env: Env): Promise<string | null> {
	const token = randToken();
	await env.KV_CACHE.put(LOCK_KEY, token, { expirationTtl: LOCK_TTL });
	const current = await env.KV_CACHE.get(LOCK_KEY);
	return current === token ? token : null;
}

export async function releaseLock(env: Env, token: string | null): Promise<void> {
	if (!token) return;
	try {
		const current = await env.KV_CACHE.get(LOCK_KEY);
		if (current === token) await env.KV_CACHE.delete(LOCK_KEY);
	} catch (e) {
		console.error('releaseLock error', e);
	}
}

/** Secrets Store upsert via Cloudflare API (requires secret-edit bootstrap token) */
export async function upsertSecret(env: Env, secretEditBootstrap: string, secretName: string, secretValue: string): Promise<void> {
	const accountId = (env as any).ACCOUNT_ID ?? (env as any).account_id;
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/secrets/${encodeURIComponent(secretName)}`;
	const res = await fetch(url, {
		method: 'PUT',
		headers: {
			Authorization: `Bearer ${secretEditBootstrap}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ text: secretValue }),
	});
	if (!res.ok) {
		const txt = await res.text().catch(() => '');
		throw new Error(`upsertSecret ${secretName} failed ${res.status} ${txt}`);
	}
}

/** Create account API token via Cloudflare API (creationBootstrap must have create-token rights) */
export async function createAccountToken(env: Env, creationBootstrap: string, tokenNameSuffix: string): Promise<string> {
	const accountId = (env as any).ACCOUNT_ID ?? (env as any).account_id;
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/api_tokens`;
	const expires_on = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(); // now + 2h
	const body = {
		name: `auto-rotated-${tokenNameSuffix}-${Date.now()}`,
		expires_on,
		policies: [], // adapt to minimal policies required
	};
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${creationBootstrap}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		const t = await res.text().catch(() => '');
		throw new Error(`createAccountToken failed ${res.status} ${t}`);
	}

	const payload = (await res.json()) as Record<string, any>;
	const token = payload?.result?.token as string | undefined;
	if (!token) throw new Error('createAccountToken: no token in response');
	return token;
}

/** Lightweight verify */
export async function verifyToken(token: string): Promise<boolean> {
	const res = await fetch('https://api.cloudflare.com/client/v4/user/tokens/verify', {
		method: 'GET',
		headers: { Authorization: `Bearer ${token}` },
	});
	return res.ok;
}

/** Core rotation logic (2-slot model: PRIMARY <-> SECONDARY) */
export async function rotateOnce(env: Env): Promise<void> {
	// read bootstrap tokens (PRIMARY creation and secret-edit)
	const [currCreation, currSecretEdit] = await Promise.all([env.PRIMARY_TOKEN_CREATION_TOKEN.get(), env.PRIMARY_SECRET_EDIT_TOKEN.get()]);

	if (!currCreation || !currSecretEdit) {
		throw new Error('rotation: missing PRIMARY bootstrap tokens (PRIMARY_TOKEN_CREATION_TOKEN or PRIMARY_SECRET_EDIT_TOKEN)');
	}

	// 1) Stage: copy current PRIMARY values into SECONDARY names (idempotent)
	await Promise.all([
		upsertSecret(env, currSecretEdit, 'SECONDARY_TOKEN_CREATION_TOKEN', currCreation),
		upsertSecret(env, currSecretEdit, 'SECONDARY_SECRET_EDIT_TOKEN', currSecretEdit),
	]);

	// 2) Create: new creation + new secret-edit tokens in parallel (both created using currCreation per your model)
	const created = await Promise.allSettled([
		createAccountToken(env, currCreation, 'creation-bootstrap'),
		createAccountToken(env, currCreation, 'secret-edit-bootstrap'),
	]);

	if (created[0].status !== 'fulfilled' || created[1].status !== 'fulfilled') {
		const reasons: string[] = [];
		if (created[0].status === 'rejected') reasons.push(String(created[0].reason));
		if (created[1].status === 'rejected') reasons.push(String(created[1].reason));
		throw new Error(`rotation: token creation failed: ${reasons.join(' | ')}`);
	}

	const newCreationToken = created[0].value as string;
	const newSecretEditToken = created[1].value as string;

	// 3) Verify both tokens
	const [v1, v2] = await Promise.all([
		verifyToken(newCreationToken).catch(() => false),
		verifyToken(newSecretEditToken).catch(() => false),
	]);
	if (!v1 || !v2) {
		throw new Error(`rotation: verification failed (creation:${v1} secret-edit:${v2})`);
	}

	// 4) Promote: overwrite PRIMARY_* bindings with new tokens
	await Promise.all([
		upsertSecret(env, currSecretEdit, 'PRIMARY_TOKEN_CREATION_TOKEN', newCreationToken),
		upsertSecret(env, currSecretEdit, 'PRIMARY_SECRET_EDIT_TOKEN', newSecretEditToken),
	]);
}

/** Default export — scheduled handler */
export default {
	async scheduled(_controller: unknown, env: Env) {
		let lockToken: string | null = null;
		try {
			lockToken = await acquireLock(env);
			if (!lockToken) {
				console.log('rotation: lock not acquired; another rotation in progress');
				return;
			}

			await rotateOnce(env);
			console.log('rotation: success; primaries promoted; secondaries contain previous values');
		} catch (err: any) {
			// single log + single mail (do not rethrow)
			try {
				const errString =
					typeof err === 'string'
						? err
						: err && (err.stack || err.message)
						? `${err.message || ''}\n${err.stack || ''}`
						: JSON.stringify(err);

				console.error('rotation: critical error', errString);

				try {
					await mailer.send(env, {
						senderAddress: 'DoNotReply@notifications.authentication.center',
						recipients: { to: [{ address: 'lehtinenjori03@gmail.com' }] },
						content: {
							subject: 'CRITICAL! ROOT-TOKEN-MANAGER FAILURE',
							plainText: `rotation failed:\n\n${errString}`,
						},
					});
				} catch (mailErr) {
					console.error('rotation: mailer failed', String(mailErr));
				}
			} catch (inner) {
				console.error('rotation: error while handling error', inner);
			}
			// intentionally NOT rethrowing to keep scheduled handler silent after alert
		} finally {
			await releaseLock(env, lockToken);
		}
	},
};
