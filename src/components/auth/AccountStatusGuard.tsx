import { useEffect, useRef } from "react";
import { useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { useAppStore } from "@/stores/app-store";
import { signOut } from "@/lib/auth-client";

/**
 * Real-time account status enforcement.
 *
 * Forces the current device to sign out immediately when:
 *  - the user's profile row is deleted or soft-deleted (`deleted_at` set)
 *  - a new active row appears in `user_bans` for the user
 *  - a periodic `supabase.auth.getUser()` probe reports the auth row is gone
 *    (covers permanent_delete where the JWT is still valid client-side)
 *
 * The user lands on /login with a friendly explanation. No page refresh
 * is required.
 */
export function AccountStatusGuard() {
  const user = useAppStore((s) => s.user);
  const navigate = useNavigate();
  const kickedRef = useRef(false);

  useEffect(() => {
    if (!user?.id) {
      kickedRef.current = false;
      return;
    }
    const uid = user.id;
    let stopped = false;

    const forceLogout = async (
      reason: "deleted" | "banned" | "missing",
    ) => {
      if (kickedRef.current || stopped) return;
      kickedRef.current = true;
      try {
        await signOut();
      } catch {
        /* noop */
      }
      const message =
        reason === "banned"
          ? "Your account has been banned by an administrator."
          : reason === "deleted"
            ? "Your account has been removed by an administrator."
            : "Your session is no longer valid. Please sign in again.";
      toast.error(message, { duration: 8000 });
      try {
        navigate({ to: "/login", replace: true });
      } catch {
        if (typeof window !== "undefined") window.location.replace("/login");
      }
    };

    const channel = supabase
      .channel(`account-status-${uid}`)
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "profiles", filter: `id=eq.${uid}` },
        (payload) => {
          const next = payload.new as { deleted_at?: string | null; status?: string | null } | null;
          if (!next) return;
          if (next.deleted_at) void forceLogout("deleted");
          else if (next.status === "suspended") void forceLogout("banned");
        },
      )
      .on(
        "postgres_changes",
        { event: "DELETE", schema: "public", table: "profiles", filter: `id=eq.${uid}` },
        () => void forceLogout("deleted"),
      )
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "user_bans", filter: `user_id=eq.${uid}` },
        () => void forceLogout("banned"),
      )
      .subscribe();

    // Periodic probe: catches permanent_delete (auth row gone) and any case
    // where the realtime channel was missed (offline → online).
    const probe = async () => {
      if (stopped || kickedRef.current) return;
      try {
        const { data, error } = await supabase.auth.getUser();
        if (error || !data?.user) {
          const msg = (error?.message ?? "").toLowerCase();
          if (msg.includes("user_not_found") || msg.includes("not found")) {
            void forceLogout("deleted");
            return;
          }
          // Other auth errors (e.g. expired token) → let the auth listener handle it.
          return;
        }
        // Check ban status via SECURITY DEFINER RPC. Fails open on error.
        const { data: banned } = await (supabase as unknown as {
          rpc: (name: string, args: Record<string, unknown>) => Promise<{ data: boolean | null; error: unknown }>;
        }).rpc("is_user_banned", { _user_id: uid });
        if (banned === true) void forceLogout("banned");
      } catch {
        /* network blip — try again next tick */
      }
    };

    const interval = window.setInterval(probe, 30_000);
    const onFocus = () => void probe();
    const onOnline = () => void probe();
    window.addEventListener("focus", onFocus);
    window.addEventListener("online", onOnline);
    const initial = window.setTimeout(() => void probe(), 4_000);

    return () => {
      stopped = true;
      window.clearTimeout(initial);
      window.clearInterval(interval);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("online", onOnline);
      void supabase.removeChannel(channel);
    };
  }, [user?.id, navigate]);

  return null;
}
