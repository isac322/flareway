// Repository link and build-time star count, shared by the landing and docs
// headers. The count is fetched once per build from the public GitHub API; any
// failure (offline build, rate limit, timeout) yields `undefined` and callers
// render no number. Never hard-code or estimate a count.

export const REPO_URL = 'https://github.com/isac322/flareway';

const API_URL = 'https://api.github.com/repos/isac322/flareway';

let pending: Promise<number | undefined> | undefined;

async function fetchStars(): Promise<number | undefined> {
	try {
		const headers: Record<string, string> = { Accept: 'application/vnd.github+json' };
		const token = process.env.GITHUB_TOKEN;
		if (token) headers.Authorization = `Bearer ${token}`;
		const response = await fetch(API_URL, { headers, signal: AbortSignal.timeout(4000) });
		if (!response.ok) return undefined;
		const body: unknown = await response.json();
		const count = (body as { stargazers_count?: unknown }).stargazers_count;
		return typeof count === 'number' && Number.isInteger(count) && count >= 0 ? count : undefined;
	} catch {
		return undefined;
	}
}

/** Below this, no count is shown at all: no number reads better than a tiny one. */
const MIN_SHOWN_STARS = 100;

/**
 * Stargazer count fetched at build time, or `undefined` when unavailable or
 * below MIN_SHOWN_STARS. Every caller (labels included) therefore shows either
 * a plural count or nothing.
 */
export function getStars(): Promise<number | undefined> {
	pending ??= fetchStars().then((count) => (count !== undefined && count >= MIN_SHOWN_STARS ? count : undefined));
	return pending;
}

/** Compact display form: 999 → "999", 1234 → "1.2k", 12345 → "12k". */
export function formatStars(count: number): string {
	if (count < 1000) return String(count);
	const thousands = count / 1000;
	return `${thousands < 10 ? thousands.toFixed(1).replace(/\.0$/, '') : Math.round(thousands)}k`;
}
