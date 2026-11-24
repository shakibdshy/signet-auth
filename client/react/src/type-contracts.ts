// Compile-time surface checks; `npm run typecheck` is the test.
import type { SessionState, SessionUser, SessionStatus } from "./index";

type Assert<T extends true> = T;
type _status = Assert<SessionStatus extends "loading" | "authenticated" | "anonymous" ? true : false>;
type _state = Assert<SessionState extends { refresh: () => Promise<void> } ? true : false>;
type _user = Assert<SessionUser extends { id: string } ? true : false>;
