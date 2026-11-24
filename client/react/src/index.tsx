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

interface ContextValue {
  client: SignetClient;
  state: Omit<SessionState, "refresh" | "signIn" | "signOut">;
  setState: React.Dispatch<
    React.SetStateAction<Omit<SessionState, "refresh" | "signIn" | "signOut">>
  >;
}

const SignetContext = createContext<ContextValue | null>(null);

export function SignetProvider({
  client,
  children,
}: {
  client: SignetClient;
  children: ReactNode;
}) {
  const [state, setState] = useState<ContextValue["state"]>({
    status: "loading",
    user: null,
    error: null,
  });

  useEffect(() => {
    let active = true;
    client
      .me()
      .then((user) => {
        if (!active) return;
        setState({
          status: user ? "authenticated" : "anonymous",
          user: user ?? null,
          error: null,
        });
      })
      .catch((error: unknown) => {
        if (!active) return;
        setState({
          status: "anonymous",
          user: null,
          error: error instanceof SignetApiError ? error : new SignetApiError("internal_error", "session check failed", 0),
        });
      });
    return () => {
      active = false;
    };
  }, [client]);

  const value = useMemo(() => ({ client, state, setState }), [client, state]);
  return <SignetContext.Provider value={value}>{children}</SignetContext.Provider>;
}

export function useSession(): SessionState {
  const context = useContext(SignetContext);
  if (!context) {
    throw new Error("useSession requires <SignetProvider client={...}>");
  }
  const { client, state, setState } = context;

  const refresh = useCallback(async () => {
    try {
      const user = await client.me();
      setState({
        status: user ? "authenticated" : "anonymous",
        user: user ?? null,
        error: null,
      });
    } catch (error) {
      setState({
        status: "anonymous",
        user: null,
        error:
          error instanceof SignetApiError
            ? error
            : new SignetApiError("internal_error", "session check failed", 0),
      });
    }
  }, [client, setState]);

  const signIn = useCallback(
    async (input: Parameters<SignetClient["signIn"]>[0]) => {
      await client.signIn(input);
      await refresh();
    },
    [client, refresh],
  );

  const signOut = useCallback(async () => {
    await client.signOut({ session_token: "" });
    client.clearCsrfToken();
    setState({ status: "anonymous", user: null, error: null });
  }, [client, setState]);

  return useMemo(
    () => ({ ...state, refresh, signIn, signOut }),
    [state, refresh, signIn, signOut],
  );
}

/** Session check for server middleware (e.g. Next.js), given the request cookies. */
export async function sessionGuard(
  authURL: string,
  cookieHeader: string,
): Promise<boolean> {
  const url = new URL(authURL);
  url.pathname = url.pathname.replace(/\/$/, "") + "/me";
  const response = await fetch(url, { headers: { cookie: cookieHeader } });
  return response.ok;
}
