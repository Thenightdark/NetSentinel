"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username, password);
      const requested = new URLSearchParams(window.location.search).get("returnTo");
      const destination = requested?.startsWith("/") && !requested.startsWith("//")
        ? requested
        : "/";
      router.replace(destination);
      router.refresh();
    } catch {
      setError("The username or password was not accepted.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand">
          <span className="brand-mark" aria-hidden="true"><i /></span>
          <span><strong>NetSentinel</strong><small>Network defense</small></span>
        </div>
        <p className="kicker">SECURE CONSOLE</p>
        <h1 id="login-title">Sign in to your dashboard</h1>
        <p className="login-intro">Access passive network telemetry, observed hosts, and defensive security alerts.</p>
        <form className="login-form" onSubmit={submit}>
          <label>
            <span>Username</span>
            <input autoComplete="username" autoFocus maxLength={64} onChange={(event) => setUsername(event.target.value)} required value={username} />
          </label>
          <label>
            <span>Password</span>
            <input autoComplete="current-password" maxLength={128} minLength={8} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} />
          </label>
          {error ? <p className="login-error" role="alert">{error}</p> : null}
          <button className="button login-button" disabled={submitting} type="submit">
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <p className="login-note"><span className="status-dot" /> Credentials are sent only to the NetSentinel API.</p>
      </section>
    </main>
  );
}
