import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

/** Error codes the server can return, derived from the published contract. */
export type SignetErrorCode = components["schemas"]["ApiError"]["error"];

/** An error response decoded into a typed exception. */
export class SignetApiError extends Error {
	constructor(
		readonly code: SignetErrorCode,
		message: string,
		readonly status: number,
	) {
		super(message);
		this.name = "SignetApiError";
	}
}

type RequestBody<P extends keyof paths, M extends keyof paths[P]> =
	paths[P][M] extends { requestBody: { content: { "application/json": infer B } } } ? B : never;

type SuccessBody<P extends keyof paths, M extends keyof paths[P], S extends number> =
	paths[P][M] extends { responses: Record<S, infer R> }
		? R extends { content: { "application/json": infer B } } ? B : void
		: void;

type ApiError = components["schemas"]["ApiError"];

type Result<T> = { data?: T; error?: ApiError; response: Response };

async function unwrap<T>(result: Result<T>): Promise<T> {
	if (result.error) {
		throw new SignetApiError(result.error.error, result.error.message, result.response.status);
	}
	if (result.data === undefined) {
		return undefined as T;
	}
	return result.data;
}

export interface SignetClientOptions {
	/** Backend origin, e.g. https://api.example.com */
	baseURL: string;
	/** Optional custom fetch implementation (useful for tests). */
	fetch?: (input: Request) => Promise<Response>;
	/** Pre-obtained CSRF token; otherwise fetched lazily from /csrf-token. */
	csrfToken?: string;
}

/** A type-safe client for Signet's HTTP endpoints. */
export function createSignetClient(options: SignetClientOptions) {
	const api = createClient<paths>({
		baseUrl: options.baseURL,
		credentials: "include",
		fetch: options.fetch,
	});
	let csrfToken = options.csrfToken;

	async function csrfHeaders(): Promise<Record<string, string>> {
		if (!csrfToken) {
			const result = await api.GET("/csrf-token");
			if (result.error || !result.data) {
				const code = result.error?.error ?? "internal_error";
				const message = result.error?.message ?? "could not obtain CSRF token";
				throw new SignetApiError(code, message, result.response.status);
			}
			csrfToken = result.data.token;
		}
		return { "X-CSRF-Token": csrfToken };
	}

	return {
		/** Force a fresh CSRF token on the next state-changing request. */
		clearCsrfToken(): void {
			csrfToken = undefined;
		},

		async signUp(body: RequestBody<"/signup", "post">): Promise<SuccessBody<"/signup", "post", 201>> {
			return unwrap(await api.POST("/signup", { body, headers: await csrfHeaders() }));
		},

		async signIn(body: RequestBody<"/signin", "post">): Promise<SuccessBody<"/signin", "post", 200>> {
			const result = await api.POST("/signin", { body, headers: await csrfHeaders() });
			const data = await unwrap(result);
			csrfToken = data.csrf_token;
			return data;
		},

		async sendMagicLink(
			body: RequestBody<"/send-magic-link", "post">,
		): Promise<SuccessBody<"/send-magic-link", "post", 200>> {
			return unwrap(await api.POST("/send-magic-link", { body }));
		},

		async verifyMagicLink(
			params: paths["/verify-magic-link"]["get"]["parameters"]["query"],
		): Promise<SuccessBody<"/verify-magic-link", "get", 200>> {
			return unwrap(await api.GET("/verify-magic-link", { params: { query: params } }));
		},

		async sendOtp(body: RequestBody<"/send-otp", "post">): Promise<SuccessBody<"/send-otp", "post", 200>> {
			return unwrap(await api.POST("/send-otp", { body }));
		},

		async verifyOtp(body: RequestBody<"/verify-otp", "post">): Promise<SuccessBody<"/verify-otp", "post", 200>> {
			return unwrap(await api.POST("/verify-otp", { body }));
		},

		async signOut(body: RequestBody<"/signout", "post">): Promise<SuccessBody<"/signout", "post", 204>> {
			return unwrap(await api.POST("/signout", { body, headers: await csrfHeaders() }));
		},

		async listSessions(): Promise<SuccessBody<"/sessions", "get", 200>> {
			return unwrap(await api.GET("/sessions"));
		},

		async revokeAllSessions(): Promise<SuccessBody<"/sessions", "delete", 204>> {
			return unwrap(await api.DELETE("/sessions", { headers: await csrfHeaders() }));
		},

		async revokeSession(): Promise<SuccessBody<"/session", "delete", 204>> {
			return unwrap(await api.DELETE("/session", { headers: await csrfHeaders() }));
		},

		async exchangeToken(body: RequestBody<"/token", "post">): Promise<SuccessBody<"/token", "post", 200>> {
			return unwrap(await api.POST("/token", { body, headers: await csrfHeaders() }));
		},

		async sendVerification(
			body: RequestBody<"/send-verification", "post">,
		): Promise<SuccessBody<"/send-verification", "post", 200>> {
			return unwrap(await api.POST("/send-verification", { body, headers: await csrfHeaders() }));
		},

		async verifyEmail(body: RequestBody<"/verify-email", "post">): Promise<SuccessBody<"/verify-email", "post", 200>> {
			return unwrap(await api.POST("/verify-email", { body, headers: await csrfHeaders() }));
		},

		async sendPasswordReset(
			body: RequestBody<"/send-password-reset", "post">,
		): Promise<SuccessBody<"/send-password-reset", "post", 200>> {
			return unwrap(await api.POST("/send-password-reset", { body, headers: await csrfHeaders() }));
		},

		async resetPassword(
			body: RequestBody<"/reset-password", "post">,
		): Promise<SuccessBody<"/reset-password", "post", 200>> {
			return unwrap(await api.POST("/reset-password", { body, headers: await csrfHeaders() }));
		},

		async changePassword(
			body: RequestBody<"/change-password", "post">,
		): Promise<SuccessBody<"/change-password", "post", 200>> {
			return unwrap(await api.POST("/change-password", { body, headers: await csrfHeaders() }));
		},

		async oauthStart(body: RequestBody<"/oauth/start", "post">): Promise<SuccessBody<"/oauth/start", "post", 200>> {
			return unwrap(await api.POST("/oauth/start", { body, headers: await csrfHeaders() }));
		},

		async oauthCallback(code: string, state: string): Promise<SuccessBody<"/oauth/callback", "get", 302>> {
			return unwrap(await api.GET("/oauth/callback", { params: { query: { code, state } } }));
		},

		async csrfToken(): Promise<SuccessBody<"/csrf-token", "get", 200>> {
			return unwrap(await api.GET("/csrf-token"));
		},

		async lastSignInMethod(): Promise<SuccessBody<"/last-sign-in-method", "get", 200>> {
			return unwrap(await api.GET("/last-sign-in-method"));
		},
	};
}

export type SignetClient = ReturnType<typeof createSignetClient>;
