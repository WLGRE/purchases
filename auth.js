// Shared sign-in for every page.
// startAuth(sb, onSignedIn) shows the sign-in screen until there is a Supabase session, then calls
// onSignedIn(user) once. Database rules limit every query to the signed-in user's own rows, so pages
// query as normal after that.
(function () {
  const CSS = `
    .auth-gate { position: fixed; inset: 0; z-index: 10000; background: var(--bg); display: flex; align-items: center; justify-content: center; padding: 16px; overflow-y: auto; }
    .auth-gate[hidden] { display: none; }
    .auth-card { width: 100%; max-width: 380px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.1)); padding: 28px 24px; }
    .auth-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; }
    .auth-logo { width: 40px; height: 40px; background: var(--accent); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .auth-logo svg { width: 22px; height: 22px; fill: none; stroke: #fff; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
    .auth-brand h1 { font-size: 17px; font-weight: 600; margin: 0; }
    .auth-brand p { font-size: 13px; color: var(--text2); margin: 2px 0 0; }
    .auth-card h2 { font-size: 15px; font-weight: 600; margin: 0 0 14px; }
    .auth-field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 12px; }
    .auth-field[hidden] { display: none; }
    .auth-field label { font-size: 12px; font-weight: 600; color: var(--text2); letter-spacing: 0.03em; }
    .auth-field input { width: 100%; font-family: "DM Sans", sans-serif; font-size: 16px; padding: 10px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface); color: var(--text); outline: none; }
    .auth-field input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(42,92,69,0.12); }
    .auth-hint { font-size: 11px; color: var(--text3); }
    .auth-msg { font-size: 13px; margin: 0 0 12px; padding: 9px 12px; border-radius: var(--radius-sm); }
    .auth-msg[hidden] { display: none; }
    .auth-msg.error { background: var(--danger-light); color: var(--danger); }
    .auth-msg.info { background: var(--accent-light); color: var(--accent-text); }
    .auth-submit { width: 100%; margin-top: 4px; padding: 11px 16px; border: none; border-radius: var(--radius-sm); background: var(--accent); color: #fff; font-family: "DM Sans", sans-serif; font-size: 14px; font-weight: 600; cursor: pointer; }
    .auth-submit:disabled { opacity: 0.6; cursor: default; }
    .auth-links { margin-top: 16px; display: flex; flex-direction: column; gap: 8px; align-items: center; font-size: 13px; color: var(--text2); }
    .auth-links button { background: none; border: none; color: var(--accent); font: inherit; font-weight: 500; cursor: pointer; padding: 2px; }
    .auth-user { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text2); }
    .auth-user span { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  `;

  const HTML = `
    <div class="auth-card">
      <div class="auth-brand">
        <div class="auth-logo"><svg viewBox="0 0 24 24"><path d="M6 2h12l4 6-10 14L2 8z"/><path d="M2 8h20M12 22V8"/></svg></div>
        <div><h1>Business Purchase Log</h1><p>Track and manage your business expenses</p></div>
      </div>
      <h2 id="auth-title"></h2>
      <form id="auth-form" novalidate>
        <div class="auth-field" id="auth-email-field">
          <label for="auth-email">Email</label>
          <input type="email" id="auth-email" autocomplete="email" inputmode="email" autocapitalize="off" spellcheck="false" />
        </div>
        <div class="auth-field" id="auth-pass-field">
          <label for="auth-pass">Password</label>
          <input type="password" id="auth-pass" />
          <span class="auth-hint" id="auth-pass-hint" hidden>At least 8 characters</span>
        </div>
        <p class="auth-msg" id="auth-msg" hidden></p>
        <button class="auth-submit" id="auth-submit" type="submit"></button>
      </form>
      <div class="auth-links" id="auth-links"></div>
    </div>
  `;

  // email/password: which fields each screen shows. links: [label, screen to switch to].
  const MODES = {
    signin:   { title: "Sign in", submit: "Sign in", email: true, password: "current-password",
                links: [["Forgot password?", "forgot"], ["New here? Create an account", "signup"]] },
    signup:   { title: "Create your account", submit: "Create account", email: true, password: "new-password",
                links: [["Already have an account? Sign in", "signin"]] },
    forgot:   { title: "Reset your password", submit: "Send reset link", email: true, password: null,
                links: [["Back to sign in", "signin"]] },
    recovery: { title: "Choose a new password", submit: "Save new password", email: false, password: "new-password",
                links: [] },
  };
  const MIN_PASSWORD = 8;

  let sb, onSignedIn, gate, mode = "signin", started = false;
  const $ = (id) => document.getElementById(id);

  function setMode(next, message, kind) {
    mode = next;
    const m = MODES[mode];
    $("auth-title").textContent = m.title;
    $("auth-submit").textContent = m.submit;
    $("auth-email-field").hidden = !m.email;
    $("auth-pass-field").hidden = !m.password;
    $("auth-pass").autocomplete = m.password || "off";
    $("auth-pass").value = "";
    $("auth-pass-hint").hidden = m.password !== "new-password";
    $("auth-links").innerHTML = "";
    for (const [label, target] of m.links) {
      const b = document.createElement("button");
      b.type = "button"; b.textContent = label;
      b.onclick = () => setMode(target);
      $("auth-links").appendChild(b);
    }
    showMsg(message, kind);
  }

  function showMsg(text, kind) {
    const el = $("auth-msg");
    el.hidden = !text;
    el.textContent = text || "";
    el.className = "auth-msg " + (kind || "error");
  }

  function friendly(err) {
    const msg = (err && err.message) || String(err);
    if (/invalid login credentials/i.test(msg)) return "Wrong email or password.";
    if (/email not confirmed/i.test(msg)) return "Confirm your email first. Check your inbox for the link we sent.";
    if (/rate limit|too many/i.test(msg)) return "Too many attempts. Wait a few minutes and try again.";
    return msg;
  }

  async function submit(e) {
    e.preventDefault();
    const m = MODES[mode];
    const email = $("auth-email").value.trim();
    const password = $("auth-pass").value;
    if (m.email && !/^\S+@\S+\.\S+$/.test(email)) return showMsg("Enter a valid email address.");
    if (m.password && !password) return showMsg("Enter your password.");
    if (m.password === "new-password" && password.length < MIN_PASSWORD) return showMsg("Use at least " + MIN_PASSWORD + " characters.");

    const btn = $("auth-submit");
    btn.disabled = true; showMsg("");
    const back = location.origin + "/";
    try {
      if (mode === "signin") {
        const { error } = await sb.auth.signInWithPassword({ email, password });
        if (error) throw error;
      } else if (mode === "signup") {
        const { data, error } = await sb.auth.signUp({ email, password, options: { emailRedirectTo: back } });
        if (error) throw error;
        // With email confirmation on, an already-registered email comes back with no identities.
        if (data.user && data.user.identities && data.user.identities.length === 0) {
          setMode("signin", "That email already has an account. Sign in instead.", "info");
        } else if (!data.session) {
          setMode("signin", "Check " + email + " for a confirmation link. Open it, then sign in here.", "info");
        }
      } else if (mode === "forgot") {
        const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: back });
        if (error) throw error;
        setMode("signin", "If " + email + " has an account, a reset link is on its way.", "info");
      } else if (mode === "recovery") {
        const { data, error } = await sb.auth.updateUser({ password });
        if (error) throw error;
        history.replaceState(null, "", location.pathname);
        mode = "signin";
        enterApp(data.user);
      }
    } catch (err) {
      showMsg(friendly(err));
    } finally {
      btn.disabled = false;
    }
  }

  function addHeaderUser(user) {
    const right = document.querySelector("header .header-right");
    if (!right || !user) return;
    const box = document.createElement("div");
    box.className = "auth-user";
    const name = document.createElement("span");
    name.textContent = user.email; name.title = user.email;
    const out = document.createElement("button");
    out.className = "btn btn-ghost btn-sm"; out.type = "button"; out.textContent = "Sign out";
    out.onclick = window.authSignOut;
    box.append(name, out);
    right.prepend(box);
  }

  function enterApp(user) {
    gate.hidden = true;
    if (started) return;
    started = true;
    addHeaderUser(user);
    onSignedIn(user);
  }

  window.startAuth = async function (client, callback) {
    sb = client; onSignedIn = callback;
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);
    gate = document.createElement("div");
    gate.className = "auth-gate"; gate.id = "auth-gate"; gate.hidden = true;
    gate.innerHTML = HTML;
    document.body.appendChild(gate);
    $("auth-form").addEventListener("submit", submit);

    // Read this before supabase-js tidies the URL: a reset-password link lands here with type=recovery.
    const recovering = /type=recovery/.test(location.hash);
    const showGate = (m, msg, kind) => { setMode(m, msg, kind); gate.hidden = false; };

    sb.auth.onAuthStateChange((event, session) => {
      // Defer: calling Supabase from inside this callback can deadlock the client.
      setTimeout(() => {
        if (event === "PASSWORD_RECOVERY") showGate("recovery");
        else if (event === "SIGNED_OUT") location.reload();
        else if (event === "SIGNED_IN" && session && mode !== "recovery") enterApp(session.user);
      }, 0);
    });

    if (recovering) return showGate("recovery");
    const { data: { session } } = await sb.auth.getSession();
    if (session) enterApp(session.user);
    else showGate("signin");
  };

  window.authSignOut = async function () {
    await sb.auth.signOut();
    location.reload();
  };
})();
