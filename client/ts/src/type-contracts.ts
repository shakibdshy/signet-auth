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
