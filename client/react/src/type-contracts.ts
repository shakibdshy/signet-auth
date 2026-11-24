// Compile-time surface checks; `npm run typecheck` is the test.
import type { SessionState, SessionUser, SessionStatus } from "./index";
import { sessionGuard } from "./index";

type Assert<T extends true> = T;
type _status = Assert<SessionStatus extends "loading" | "authenticated" | "anonymous" ? true : false>;
type _refresh = Assert<SessionState extends { refresh: () => Promise<void> } ? true : false>;
type _signIn = Assert<SessionState extends { signIn: (input: never) => Promise<void> } ? true : false>;
type _signOut = Assert<SessionState extends { signOut: () => Promise<void> } ? true : false>;
type _error = Assert<SessionState extends { error: unknown } ? true : false>;
type _guard = Assert<typeof sessionGuard extends (url: string, cookies: string) => Promise<boolean> ? true : false>;
type _user = Assert<SessionUser extends { id: string } ? true : false>;
