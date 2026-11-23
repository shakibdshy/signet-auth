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

	function clearCsrfToken(): void {
		csrfToken = undefined;
	}

	return {
		/** Force a fresh CSRF token on the next state-changing request. */
		clearCsrfToken,

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

		// --- Passkeys ---

		async beginPasskeyRegistration(
			body: RequestBody<"/passkeys/register-begin", "post">,
		): Promise<SuccessBody<"/passkeys/register-begin", "post", 200>> {
			return unwrap(await api.POST("/passkeys/register-begin", { body, headers: await csrfHeaders() }));
		},

		async finishPasskeyRegistration(
			body: RequestBody<"/passkeys/register-finish", "post">,
		): Promise<SuccessBody<"/passkeys/register-finish", "post", 200>> {
			return unwrap(await api.POST("/passkeys/register-finish", { body, headers: await csrfHeaders() }));
		},

		async beginPasskeySignIn(): Promise<SuccessBody<"/passkeys/signin-begin", "post", 200>> {
			return unwrap(await api.POST("/passkeys/signin-begin"));
		},

		async finishPasskeySignIn(
			body: RequestBody<"/passkeys/signin-finish", "post">,
		): Promise<SuccessBody<"/passkeys/signin-finish", "post", 200>> {
			const result = await unwrap(await api.POST("/passkeys/signin-finish", { body }));
			clearCsrfToken();
			return result;
		},

		async listPasskeys(): Promise<SuccessBody<"/passkeys", "get", 200>> {
			return unwrap(await api.GET("/passkeys"));
		},

		async deletePasskey(
			body: RequestBody<"/passkeys/delete", "post">,
		): Promise<SuccessBody<"/passkeys/delete", "post", 200>> {
			return unwrap(await api.POST("/passkeys/delete", { body, headers: await csrfHeaders() }));
		},

		// --- API keys ---

		async createApiKey(
			body: RequestBody<"/api-keys", "post">,
		): Promise<SuccessBody<"/api-keys", "post", 201>> {
			return unwrap(await api.POST("/api-keys", { body, headers: await csrfHeaders() }));
		},

		async listApiKeys(): Promise<SuccessBody<"/api-keys", "get", 200>> {
			return unwrap(await api.GET("/api-keys"));
		},

		async verifyApiKey(
			key: string,
		): Promise<SuccessBody<"/verify-api-key", "post", 200>> {
			return unwrap(await api.POST("/verify-api-key", {
				params: { header: { "X-API-Key": key } },
			}));
		},

		async revokeApiKey(
			body: RequestBody<"/revoke-api-key", "post">,
		): Promise<SuccessBody<"/revoke-api-key", "post", 200>> {
			return unwrap(await api.POST("/revoke-api-key", { body, headers: await csrfHeaders() }));
		},

		// --- Organizations ---

		async createOrganization(
			body: RequestBody<"/organizations", "post">,
		): Promise<SuccessBody<"/organizations", "post", 201>> {
			return unwrap(await api.POST("/organizations", { body, headers: await csrfHeaders() }));
		},

		async listOrganizations(): Promise<SuccessBody<"/organizations", "get", 200>> {
			return unwrap(await api.GET("/organizations"));
		},

		async listOrganizationMembers(
			organizationId: string,
		): Promise<SuccessBody<"/organization-members", "get", 200>> {
			return unwrap(await api.GET("/organization-members", {
				params: { query: { organization_id: organizationId } },
			}));
		},

		async addOrganizationMember(
			body: RequestBody<"/organization-members/add", "post">,
		): Promise<SuccessBody<"/organization-members/add", "post", 200>> {
			return unwrap(await api.POST("/organization-members/add", { body, headers: await csrfHeaders() }));
		},

		async removeOrganizationMember(
			body: RequestBody<"/organization-members/remove", "post">,
		): Promise<SuccessBody<"/organization-members/remove", "post", 200>> {
			return unwrap(await api.POST("/organization-members/remove", { body, headers: await csrfHeaders() }));
		},

		async setOrganizationMemberRole(
			body: RequestBody<"/organization-members/role", "post">,
		): Promise<SuccessBody<"/organization-members/role", "post", 200>> {
			return unwrap(await api.POST("/organization-members/role", { body, headers: await csrfHeaders() }));
		},

		async setActiveOrganization(
			body: RequestBody<"/set-active-organization", "post">,
		): Promise<SuccessBody<"/set-active-organization", "post", 200>> {
			return unwrap(await api.POST("/set-active-organization", { body, headers: await csrfHeaders() }));
		},

		async activeOrganization(): Promise<SuccessBody<"/active-organization", "get", 200>> {
			return unwrap(await api.GET("/active-organization"));
		},

		async clearActiveOrganization(): Promise<SuccessBody<"/clear-active-organization", "post", 200>> {
			return unwrap(await api.POST("/clear-active-organization", { headers: await csrfHeaders() }));
		},

		// --- Admin management ---

		async adminListUsers(): Promise<SuccessBody<"/admin-users", "get", 200>> {
			return unwrap(await api.GET("/admin-users"));
		},

		async adminSetUserRole(
			body: RequestBody<"/admin-users/role", "post">,
		): Promise<SuccessBody<"/admin-users/role", "post", 200>> {
			return unwrap(await api.POST("/admin-users/role", { body, headers: await csrfHeaders() }));
		},

		async adminBanUser(
			body: RequestBody<"/admin-users/ban", "post">,
		): Promise<SuccessBody<"/admin-users/ban", "post", 200>> {
			return unwrap(await api.POST("/admin-users/ban", { body, headers: await csrfHeaders() }));
		},

		async adminUnbanUser(
			body: RequestBody<"/admin-users/unban", "post">,
		): Promise<SuccessBody<"/admin-users/unban", "post", 200>> {
			return unwrap(await api.POST("/admin-users/unban", { body, headers: await csrfHeaders() }));
		},

		async adminListUserSessions(
			userId: string,
		): Promise<SuccessBody<"/admin-user-sessions", "get", 200>> {
			return unwrap(await api.GET("/admin-user-sessions", {
				params: { query: { user_id: userId } },
			}));
		},

		async adminRevokeUserSession(
			body: RequestBody<"/admin-user-sessions/revoke", "post">,
		): Promise<SuccessBody<"/admin-user-sessions/revoke", "post", 200>> {
			return unwrap(await api.POST("/admin-user-sessions/revoke", { body, headers: await csrfHeaders() }));
		},

		async impersonate(
			body: RequestBody<"/impersonate", "post">,
		): Promise<SuccessBody<"/impersonate", "post", 200>> {
			const data = await unwrap(await api.POST("/impersonate", { body, headers: await csrfHeaders() }));
			clearCsrfToken();
			return data;
		},

		async stopImpersonating(
			token: string,
		): Promise<SuccessBody<"/stop-impersonating", "post", 200>> {
			const data = await unwrap(await api.POST("/stop-impersonating", {
				body: { token },
				headers: await csrfHeaders(),
			}));
			clearCsrfToken();
			return data;
		},
	};
}

export type SignetClient = ReturnType<typeof createSignetClient>;
