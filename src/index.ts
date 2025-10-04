/// <reference path="../worker-configuration.d.ts" />
import { mailer } from './mailer';

declare const crypto: Crypto;

const LOCK_KEY = 'acct-token-rot-lock';
const LOCK_TTL = 300; // seconds
const SECRET_ID_KV_PREFIX = 'secretid:'; // KV key prefix for cached secret ids

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

/** Resolve accountId and storeId from env */
function resolveIds(env: Env): { accountId: string; storeId: string } {
	const accountId = (env as any).ACCOUNT_ID ?? (env as any).account_id;
	const storeId = (env as any).SECRET_STORE_ID;
	if (!accountId) throw new Error('account id not set in env (ACCOUNT_ID or account_id)');
	if (!storeId) throw new Error('SECRET_STORE_ID not set in env');
	return { accountId, storeId };
}

/**
 * Update existing secret by name
 * - Uses simple KV caching of secret_id: if cached id fails, will list store and refresh.
 * - Throws if secret not found or PATCH fails.
 */
export async function updateSecretByName(env: Env, secretEditBootstrap: string, secretName: string, secretValue: string): Promise<void> {
	const { accountId, storeId } = resolveIds(env);
	const headers = {
		Authorization: `Bearer ${secretEditBootstrap}`,
		'Content-Type': 'application/json',
	};

	// try cached id first
	const cacheKey = SECRET_ID_KV_PREFIX + secretName;
	let cachedId: string | null = null;
	try {
		cachedId = await env.KV_CACHE.get(cacheKey);
	} catch (e) {
		// KV read error -> ignore and continue to list fallback
		console.warn('KV_CACHE.get failed (ignoring):', String(e));
		cachedId = null;
	}

	async function patchById(secretId: string): Promise<void> {
		const patchUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/secrets_store/stores/${storeId}/secrets/${encodeURIComponent(
			secretId
		)}`;
		const patchRes = await fetch(patchUrl, {
			method: 'PATCH',
			headers,
			body: JSON.stringify({ text: secretValue }),
		});
		if (!patchRes.ok) {
			const t = await patchRes.text().catch(() => '<no body>');
			throw new Error(`updateSecretByName: PATCH failed for id ${secretId} ${patchRes.status} ${t}`);
		}
		// success -> update KV cache (freshen TTL to LOCK_TTL*2 to be safe)
		try {
			await env.KV_CACHE.put(cacheKey, secretId, { expirationTtl: LOCK_TTL * 2 });
		} catch (e) {
			// ignore cache write failures
			console.warn('KV_CACHE.put failed (ignoring):', String(e));
		}
	}

	// If we have cachedId, try patching directly
	if (cachedId) {
		try {
			await patchById(cachedId);
			return;
		} catch (e) {
			// If patch fails with 404 or similar, drop cache and fall through to listing
			console.warn('patchById with cachedId failed, will refresh list:', String(e));
			try {
				await env.KV_CACHE.delete(cacheKey);
			} catch (_) {}
		}
	}

	// List secrets and find the secret name
	const listUrl = `https://api.cloudflare.com/client/v4/accounts/${accountId}/secrets_store/stores/${storeId}/secrets`;
	const listRes = await fetch(listUrl, { method: 'GET', headers });
	if (!listRes.ok) {
		const t = await listRes.text().catch(() => '<no body>');
		throw new Error(`updateSecretByName: failed to list secrets for store ${storeId}: ${listRes.status} ${t}`);
	}
	const listJson = (await listRes.json()) as any;
	const items: Array<{ id: string; name: string }> = listJson.result || [];
	const found = items.find((it) => it.name === secretName);
	if (!found) {
		throw new Error(`updateSecretByName: secret "${secretName}" not found in store ${storeId}`);
	}

	// patch found secret id
	await patchById(found.id);
}

/**
 * Create an account token using the Accounts Tokens API.
 * Returns the token string (value), id and expires.
 *
 * Note: this implementation assumes the account endpoint is /accounts/{accountId}/tokens
 * and that the response contains result.value with the token secret string.
 */
export async function createAccountToken(
	env: Env,
	creationBootstrap: string,
	tokenNameSuffix: string
): Promise<{ value: string; id?: string; expires?: string }> {
	const { accountId } = resolveIds(env);
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/tokens`;
	const expires_on = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(); // now + 2h

	const body: Record<string, any> = {
		name: `auto-rotated-${tokenNameSuffix}-${Date.now()}`,
		expires_on,
		// policies: [] // keep empty or add minimal policies as you require
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

	const payload = (await res.json()) as any;
	const tokenValue = payload?.result?.value as string | undefined;
	const id = payload?.result?.id as string | undefined;
	const expires = payload?.result?.expires_on || expires_on;

	if (!tokenValue) throw new Error('createAccountToken: no token value returned (payload.result.value missing)');

	return { value: tokenValue, id, expires };
}

/** Verify account token via tokens verify endpoint */
export async function verifyToken(env: Env, token: string): Promise<boolean> {
	const { accountId } = resolveIds(env);
	const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/tokens/verify`;
	const res = await fetch(url, { method: 'GET', headers: { Authorization: `Bearer ${token}` } });
	return res.ok;
}

/** Core rotation logic (2-slot model: PRIMARY <-> SECONDARY) */
export async function rotateOnce(env: Env): Promise<void> {
	// Read bootstrap tokens (PRIMARY creation + PRIMARY secret-edit) from Secrets Store bindings
	const [currCreation, currSecretEdit] = await Promise.all([env.PRIMARY_TOKEN_CREATION_TOKEN.get(), env.PRIMARY_SECRET_EDIT_TOKEN.get()]);

	if (!currCreation || !currSecretEdit) {
		throw new Error('rotation: missing PRIMARY bootstrap tokens (PRIMARY_TOKEN_CREATION_TOKEN or PRIMARY_SECRET_EDIT_TOKEN)');
	}

	// 1) Stage: copy current PRIMARY values into SECONDARY names (idempotent)
	await Promise.all([
		updateSecretByName(env, currSecretEdit, 'SECONDARY_TOKEN_CREATION_TOKEN', currCreation),
		updateSecretByName(env, currSecretEdit, 'SECONDARY_SECRET_EDIT_TOKEN', currSecretEdit),
	]);

	// 2) Create new account tokens in parallel using currCreation bootstrap
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

	const newCreation = created[0].value as { value: string; id?: string; expires?: string };
	const newSecretEdit = created[1].value as { value: string; id?: string; expires?: string };

	// 3) Verify new tokens
	const [ok1, ok2] = await Promise.all([
		verifyToken(env, newCreation.value).catch(() => false),
		verifyToken(env, newSecretEdit.value).catch(() => false),
	]);
	if (!ok1 || !ok2) {
		throw new Error(`rotation: verification failed (creation:${ok1} secret-edit:${ok2})`);
	}

	// 4) Promote: overwrite PRIMARY_* names with new token values (use currSecretEdit bootstrap to write)
	await Promise.all([
		updateSecretByName(env, currSecretEdit, 'PRIMARY_TOKEN_CREATION_TOKEN', newCreation.value),
		updateSecretByName(env, currSecretEdit, 'PRIMARY_SECRET_EDIT_TOKEN', newSecretEdit.value),
	]);

	// done
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
			// intentionally not rethrowing
		} finally {
			await releaseLock(env, lockToken);
		}
	},
};
