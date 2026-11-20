// Compile-time contract checks. These never run; `npm run typecheck` is the test.
import { createSignetClient } from "./index";

const client = createSignetClient({ baseURL: "https://api.example.com" });

void client.signUp({ email: "user@example.com", password: "correct horse", name: "Ada" });
void client.signIn({ email: "user@example.com", password: "correct horse" });
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
