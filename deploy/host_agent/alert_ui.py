#!/usr/bin/env python3
"""
Modern HTML security alert dialog for the Host IDS/IPS Agent.

Uses pywebview for a native frameless window with embedded HTML/CSS/JS.
Called as a subprocess by host_agent.py so webview runs on the main thread.

Exit codes:
    0 = Admin authenticated (agent should reset prevention)
    1 = User acknowledged / window closed (no admin action)
"""

import sys
import os
import argparse

# ──────────────────────────────────────────────────────────────
# HTML Template — dark cybersecurity theme, frameless design
# ──────────────────────────────────────────────────────────────

ALERT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  :root {
    --bg: #0B1121;
    --bg2: #0F172A;
    --red: #EF4444;
    --red-dim: rgba(239, 68, 68, 0.12);
    --red-glow: rgba(239, 68, 68, 0.25);
    --green: #22C55E;
    --text: #F1F5F9;
    --muted: #94A3B8;
    --dim: #475569;
    --border: rgba(239, 68, 68, 0.15);
    --input-bg: rgba(15, 23, 42, 0.7);
    --input-border: rgba(100, 116, 139, 0.3);
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Segoe UI Variable Display', 'Segoe UI', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    height: 100vh;
    overflow: hidden;
    -webkit-font-smoothing: antialiased;
    border: 1px solid rgba(239, 68, 68, 0.08);
  }

  /* ── Animated grid background ── */
  .bg-grid {
    position: fixed; inset: 0;
    background:
      linear-gradient(rgba(239,68,68,0.018) 1px, transparent 1px),
      linear-gradient(90deg, rgba(239,68,68,0.018) 1px, transparent 1px);
    background-size: 28px 28px;
    animation: drift 40s linear infinite;
    pointer-events: none;
  }
  @keyframes drift { to { transform: translate(28px, 28px); } }

  /* ── Scanning line ── */
  .scan-line {
    position: fixed; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent 8%, var(--red) 50%, transparent 92%);
    opacity: 0.5;
    animation: scan 4.5s cubic-bezier(0.4, 0, 0.2, 1) infinite;
    pointer-events: none; z-index: 100;
  }
  @keyframes scan {
    0%   { top: -1px; opacity: 0; }
    6%   { opacity: 0.5; }
    94%  { opacity: 0.5; }
    100% { top: 100%; opacity: 0; }
  }

  /* ── Custom Title Bar ── */
  .title-bar {
    height: 38px;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 14px;
    background: rgba(8, 12, 28, 0.97);
    border-bottom: 1px solid var(--border);
    user-select: none;
  }
  .title-bar-left {
    display: flex; align-items: center; gap: 9px;
    font-size: 11.5px; color: var(--muted);
    font-family: 'Cascadia Code', 'Consolas', monospace;
    letter-spacing: 0.3px;
  }
  .title-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--red);
    box-shadow: 0 0 8px var(--red-glow);
    animation: blink 1.8s ease-in-out infinite;
  }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.25; } }

  .close-btn {
    width: 30px; height: 30px;
    display: none;  /* HIDDEN — user cannot close without password */
    align-items: center; justify-content: center;
    border: none; background: transparent;
    color: var(--dim); font-size: 15px; cursor: pointer;
    border-radius: 6px; transition: all 0.2s;
  }
  .close-btn:hover { background: rgba(239,68,68,0.15); color: var(--red); }

  /* ── Main Content ── */
  .content {
    display: flex; flex-direction: column; align-items: center;
    padding: 22px 32px 18px;
    height: calc(100vh - 38px);
  }

  /* Shield icon */
  .icon-wrap { position: relative; margin-bottom: 14px; }
  .icon-ring {
    width: 64px; height: 64px; border-radius: 50%;
    background: radial-gradient(circle, var(--red-dim), transparent 70%);
    display: flex; align-items: center; justify-content: center;
    animation: pulse-ring 2.8s ease-in-out infinite;
  }
  @keyframes pulse-ring {
    0%,100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.2); }
    50%     { box-shadow: 0 0 0 14px rgba(239,68,68,0); }
  }
  .icon-inner {
    width: 46px; height: 46px; border-radius: 50%;
    background: var(--red-dim);
    border: 1.5px solid rgba(239,68,68,0.25);
    display: flex; align-items: center; justify-content: center;
  }
  .icon-inner svg { width: 24px; height: 24px; fill: var(--red); }

  /* Badge */
  .badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 12px; border-radius: 100px;
    background: var(--red-dim);
    border: 1px solid rgba(239,68,68,0.2);
    font-size: 9.5px; font-weight: 700;
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--red); margin-bottom: 14px;
  }

  h1 {
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 18px; font-weight: 700;
    color: var(--red); letter-spacing: 3.5px;
    text-transform: uppercase;
    margin-bottom: 10px; text-align: center;
  }

  .reason-text {
    font-size: 12.5px; color: var(--text); text-align: center;
    line-height: 1.5; margin-bottom: 4px; font-weight: 500;
  }
  .sub-text {
    font-size: 11px; color: var(--muted);
    text-align: center; line-height: 1.55; margin-bottom: 16px;
  }

  /* Divider */
  .divider {
    width: 100%; height: 1px;
    background: linear-gradient(90deg, transparent, var(--border), transparent);
    margin: 2px 0 16px;
  }

  /* Input */
  .field { width: 100%; margin-bottom: 4px; }
  .field label {
    display: block; font-size: 9.5px; font-weight: 600;
    color: var(--dim); text-transform: uppercase;
    letter-spacing: 1.5px; margin-bottom: 7px;
  }
  .field input {
    width: 100%; padding: 10px 14px;
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: 8px; color: var(--text);
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 13px; outline: none;
    transition: border 0.25s, box-shadow 0.25s;
  }
  .field input::placeholder {
    color: var(--dim);
    font-family: 'Segoe UI', sans-serif;
    font-size: 11.5px;
  }
  .field input:focus {
    border-color: var(--red);
    box-shadow: 0 0 0 3px rgba(239,68,68,0.08);
  }

  .status-msg {
    font-size: 11.5px; text-align: center;
    min-height: 18px; margin: 6px 0 10px;
    font-weight: 500; transition: color 0.2s;
  }
  .status-msg.error  { color: var(--red); }
  .status-msg.success { color: var(--green); }

  /* Buttons */
  .btn-row { display: flex; gap: 10px; width: 100%; }
  .btn {
    flex: 1; padding: 10px 14px;
    border: none; border-radius: 8px;
    font-family: 'Segoe UI', sans-serif;
    font-size: 11.5px; font-weight: 600;
    cursor: pointer; transition: all 0.25s;
    text-transform: uppercase; letter-spacing: 0.8px;
  }
  .btn-ghost {
    background: rgba(100,116,139,0.1);
    color: var(--muted);
    border: 1px solid rgba(100,116,139,0.18);
  }
  .btn-ghost:hover { background: rgba(100,116,139,0.18); color: var(--text); }

  .btn-danger {
    background: linear-gradient(135deg, #DC2626, #EF4444);
    color: #fff;
    box-shadow: 0 4px 16px rgba(239,68,68,0.2);
  }
  .btn-danger:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 22px rgba(239,68,68,0.3);
  }
  .btn-danger:active { transform: translateY(0); }
  .btn-danger:disabled {
    opacity: 0.7; cursor: default; transform: none;
    box-shadow: none;
  }
  .btn-danger.success-state {
    background: linear-gradient(135deg, #16A34A, #22C55E);
    box-shadow: 0 4px 16px rgba(34,197,94,0.2);
  }

  .footer {
    margin-top: auto; padding-top: 12px;
    font-size: 9.5px; color: var(--dim);
    font-family: 'Cascadia Code', 'Consolas', monospace;
    letter-spacing: 0.5px;
  }

  /* Entry animation */
  .content > * {
    animation: fadeUp 0.45s ease-out both;
  }
  .content > *:nth-child(1)  { animation-delay: 0.04s; }
  .content > *:nth-child(2)  { animation-delay: 0.08s; }
  .content > *:nth-child(3)  { animation-delay: 0.12s; }
  .content > *:nth-child(4)  { animation-delay: 0.16s; }
  .content > *:nth-child(5)  { animation-delay: 0.20s; }
  .content > *:nth-child(6)  { animation-delay: 0.24s; }
  .content > *:nth-child(7)  { animation-delay: 0.28s; }
  .content > *:nth-child(8)  { animation-delay: 0.32s; }
  .content > *:nth-child(9)  { animation-delay: 0.36s; }
  .content > *:nth-child(10) { animation-delay: 0.40s; }
  .content > *:nth-child(11) { animation-delay: 0.44s; }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
  }
</style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="scan-line"></div>

  <div class="title-bar pywebview-drag-region">
    <div class="title-bar-left">
      <div class="title-dot"></div>
      <span>IDS/IPS &bull; THREAT ALERT</span>
    </div>
    <button class="close-btn" onclick="doClose()">&times;</button>
  </div>

  <div class="content">
    <div class="icon-wrap">
      <div class="icon-ring">
        <div class="icon-inner">
          <svg viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12
                     5.16-1.26 9-6.45 9-12V5l-9-4zm1 15h-2v-2h2v2zm0-4h-2V7h2v5z"/>
          </svg>
        </div>
      </div>
    </div>

    <span class="badge">&#9888; active threat</span>

    <h1>Threat Detected</h1>

    <p class="reason-text" id="reason">{{REASON}}</p>
    <p class="sub-text">
      Your system activity has been flagged as suspicious.<br>
      This screen is <strong style="color:var(--red)">LOCKED</strong> until admin authentication.<br>
      Contact your IT administrator immediately.
    </p>

    <div class="divider"></div>

    <div class="field">
      <label>Admin / IT Password</label>
      <input type="password" id="pw"
             placeholder="Enter password to override..."
             autocomplete="off" spellcheck="false">
    </div>

    <p class="status-msg" id="status"></p>

    <div class="btn-row">
      <button class="btn btn-danger" id="dismissBtn" onclick="doDismiss()" style="flex:1">
        Admin Override
      </button>
    </div>

    <p class="footer">AI-Based IDS/IPS &bull; Threat Response System</p>
  </div>

<script>
  var apiReady = false;

  window.addEventListener('pywebviewready', function() {
    apiReady = true;
    /* auto-focus password field after API is ready */
    document.getElementById('pw').focus();
  });

  document.getElementById('pw').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') doDismiss();
  });

  function withApi(fn) {
    if (apiReady && window.pywebview && window.pywebview.api) {
      fn();
    } else {
      setTimeout(function() { withApi(fn); }, 80);
    }
  }

  function doClose() {
    /* Blocked — user must enter admin password */
    var stat = document.getElementById('status');
    stat.className = 'status-msg error';
    stat.textContent = '\u26D4 Enter admin password to dismiss this alert';
    document.getElementById('pw').focus();
  }

  function doDismiss() {
    var pw    = document.getElementById('pw').value;
    var stat  = document.getElementById('status');
    var btn   = document.getElementById('dismissBtn');

    if (!pw) {
      stat.className = 'status-msg error';
      stat.textContent = 'Please enter the admin password';
      document.getElementById('pw').focus();
      return;
    }

    btn.textContent = 'Verifying\u2026';
    btn.disabled = true;

    withApi(function() {
      window.pywebview.api.try_dismiss(pw).then(function(ok) {
        if (ok) {
          stat.className = 'status-msg success';
          stat.textContent = '\u2713 Authenticated \u2014 resetting prevention';
          btn.textContent = '\u2713 Verified';
          btn.classList.add('success-state');
          setTimeout(function() {
            window.pywebview.api.close_dialog();
          }, 850);
        } else {
          stat.className = 'status-msg error';
          stat.textContent = '\u2717 Incorrect password \u2014 try again';
          btn.textContent = 'Admin Override';
          btn.disabled = false;
          document.getElementById('pw').value = '';
          document.getElementById('pw').focus();
        }
      });
    });
  }
</script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────
# Main — runs as subprocess, shows dialog, returns exit code
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDS/IPS Alert Dialog")
    parser.add_argument("--reason", default="Threat detected", help="Alert reason")
    args = parser.parse_args()

    admin_pw = os.environ.get("_IDS_ADMIN_PW", "")

    try:
        import webview
    except ImportError:
        print("[alert_ui] pywebview not installed")
        sys.exit(2)

    # Play Windows warning sound
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception:
        pass

    class Api:
        def __init__(self):
            self.authenticated = False
            self._window = None

        def try_dismiss(self, entered_pw):
            if entered_pw == admin_pw:
                self.authenticated = True
                return True
            return False

        def close_dialog(self):
            if self._window:
                self._window.destroy()

    api = Api()

    reason_safe = (
        args.reason
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
    html = ALERT_HTML.replace("{{REASON}}", reason_safe)

    # Get screen dimensions for centering
    try:
        import ctypes
        user32 = ctypes.windll.user32
        screen_w = user32.GetSystemMetrics(0)
        screen_h = user32.GetSystemMetrics(1)
    except Exception:
        screen_w, screen_h = 1920, 1080

    win_w, win_h = 480, 560
    x = (screen_w - win_w) // 2
    y = (screen_h - win_h) // 2

    def block_close():
        """Prevent window from being closed without admin password."""
        if api.authenticated:
            return True  # allow close after auth
        # Play error sound when they try to close
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass
        return False  # block close

    window = webview.create_window(
        title="IDS/IPS — Threat Detected",
        html=html,
        width=win_w,
        height=win_h,
        x=x,
        y=y,
        resizable=False,
        on_top=True,
        frameless=True,
        js_api=api,
    )
    window.events.closing += block_close
    api._window = window

    webview.start()

    sys.exit(0 if api.authenticated else 1)


if __name__ == "__main__":
    main()
