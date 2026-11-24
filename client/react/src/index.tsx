import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  SignetApiError,
  type SignetClient,
} from "@shakibdshy/signet-client";

export type SessionStatus = "loading" | "authenticated" | "anonymous";
export type SessionUser = Awaited<ReturnType<SignetClient["me"]>>;

export interface SessionState {
  status: SessionStatus;
  user: SessionUser | null;
  error: SignetApiError | null;
  refresh: () => Promise<void>;
  signIn: (input: Parameters<SignetClient["signIn"]>[0]) => Promise<void>;
  signOut: () => Promise<void>;
}

const SignetContext = createContext<SignetClient | null>(null);

export function SignetProvider({
  client,
  children,
}: {
  client: SignetClient;
  children: ReactNode;
}) {
  return <SignetContext.Provider value={client}>{children}</SignetContext.Provider>;
}

export function useSession(): SessionState {
  const client = useContext(SignetContext);
  if (!client) {
    throw new Error("useSession requires <SignetProvider client={...}>");
  }

  const [status, setStatus] = useState<SessionStatus>("loading");
  const [user, setUser] = useState<SessionUser | null>(null);
  const [error, setError] = useState<SignetApiError | null>(null);

  const refresh = useCallback(async () => {
    try {
      const current = await client.me();
      setUser(current ?? null);
      setStatus(current ? "authenticated" : "anonymous");
      setError(null);
    } catch (err) {
      setUser(null);
      setStatus("anonymous");
      setError(err instanceof SignetApiError ? err : null);
    }
  }, [client]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signIn = useCallback(
    async (input: Parameters<SignetClient["signIn"]>[0]) => {
      await client.signIn(input);
      await refresh();
    },
    [client, refresh],
  );

  const signOut = useCallback(async () => {
    await client.signOut({});
    setUser(null);
    setStatus("anonymous");
  }, [client]);

  return useMemo(
    () => ({ status, user, error, refresh, signIn, signOut }),
    [status, user, error, refresh, signIn, signOut],
  );
}

/** Session check for server middleware (e.g. Next.js), given the request cookies. */
export async function sessionGuard(
  authURL: string,
  cookieHeader: string,
): Promise<boolean> {
  const response = await fetch(new URL("/me", authURL), {
    headers: { cookie: cookieHeader },
  });
  return response.ok;
}
