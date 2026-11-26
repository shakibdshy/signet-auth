// Compile-time contract checks. These never run; `npm run typecheck` is the test.
import { createSignetClient } from "./index";

const client = createSignetClient({ baseURL: "https://api.example.com" });

void client.signUp({ email: "user@example.com", password: "correct horse", name: "Ada" });
void client.signIn({ email: "user@example.com", password: "correct horse" });
void client.signOut({});
void client.exchangeToken({ email: "user@example.com", password: "correct horse" });
void client.sendVerification({ email: "user@example.com" });
void client.verifyEmail({ token: "proof" });
void client.listSessions();
void client.revokeAllSessions();
void client.revokeSession();
void client.csrfToken();
void client.lastSignInMethod();

// Username-only sign-in is expressible: the contract makes email optional.
void client.signIn({ username: "ada", password: "correct horse" });

// @ts-expect-error password is required by the published contract
void client.signUp({ email: "user@example.com", name: "Ada" });

// @ts-expect-error email must be a string
void client.signIn({ email: 42, password: "correct horse" });

// @ts-expect-error unknown method must not exist
void client.deleteEverything();

void client.sendMagicLink({
	email: "user@example.com",
	callback_url: "https://app.example.com/welcome",
});
void client.verifyMagicLink({ token: "proof", callback_url: "https://app.example.com/welcome" });
void client.sendOtp({ email: "user@example.com" });
void client.verifyOtp({ email: "user@example.com", code: "123456" });

// @ts-expect-error code is required by the published contract
void client.verifyOtp({ email: "user@example.com" });

void client.changePassword({ current_password: "old", new_password: "new" });

// @ts-expect-error new_password is required by the published contract
void client.changePassword({ current_password: "old" });

void client.changeEmail({ new_email: "ada@example.com", current_password: "correct horse" });
void client.verifyChangeEmail({ token: "proof" });
void client.listAccounts();
void client.unlinkAccount({ account_id: "acc_1" });
void client.enableTwoFactor({ password: "correct horse" });
void client.verifyTwoFactor({ challenge: "proof", code: "123456" });
void client.disableTwoFactor({ password: "correct horse" });
void client.regenerateBackupCodes({ password: "correct horse" });
void client.requestAccountDeletion();
void client.confirmAccountDeletion({ token: "proof" });

// @ts-expect-error code is required by the published contract
void client.verifyTwoFactor({ challenge: "proof" });

// @ts-expect-error current_password is required by the published contract
void client.changeEmail({ new_email: "ada@example.com" });

// Shape checks for the Phase 13 fields: the compile errors ARE the test.
type Assert<T extends true> = T;
type MeResult = Awaited<ReturnType<typeof client.me>>;
type SessionsResult = Awaited<ReturnType<typeof client.listSessions>>;
type SignInResult = Awaited<ReturnType<typeof client.signIn>>;
type VerifyOtpResult = Awaited<ReturnType<typeof client.verifyOtp>>;
type SessionRow = SessionsResult["sessions"][number];

// GET /me returns the full profile.
type _meVerification = Assert<MeResult extends { email_verified: boolean } ? true : false>;
type _meUsername = Assert<MeResult extends { username: string } ? true : false>;
type _meTimestamps = Assert<MeResult extends { created_at: string; updated_at: string } ? true : false>;

// Each listed Session names the Sign-in client that started it.
type _sessionUserAgent = Assert<SessionRow extends { user_agent: string } ? true : false>;

// Sign-in responses report the canonical method; required where a Session
// always results, optional where a challenge branch can omit it.
type _otpMethodRequired = Assert<VerifyOtpResult extends { last_sign_in_method: string } ? true : false>;
type _signInMethodOptional = Assert<SignInResult extends { last_sign_in_method?: string } ? true : false>;
