/**
 * auth.js — Client-side authentication UI + backend integration
 *
 * Wires registration and login forms to the Flask backend via fetch().
 * Uses the CSRF token injected into each page by Jinja2.
 * Handles JSON responses and shows toast notifications for all outcomes.
 */

'use strict';

/* ─── Utility: Toast Notifications ─── */
const ToastManager = {
  container: null,

  init() {
    this.container = document.getElementById('toastContainer');
    this._renderFlashMessages();
  },

  show(type, title, message, duration = 4000) {
    if (!this.container) return;

    const icons = {
      success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                  <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>`,
      error:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>`,
      info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="16" x2="12" y2="12"/>
                  <line x1="12" y1="8" x2="12.01" y2="8"/>
                </svg>`,
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-content">
        <p class="toast-title">${title}</p>
        <p class="toast-msg">${message}</p>
      </div>
    `;
    this.container.appendChild(toast);

    const removeAfter = Math.max(duration, 2000);
    setTimeout(() => {
      toast.classList.add('removing');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    }, removeAfter);
  },

  /**
   * Read Flask flash messages injected as JSON in #flashMessages
   * and display them as toasts on page load.
   */
  _renderFlashMessages() {
    const el = document.getElementById('flashMessages');
    if (!el) return;
    try {
      const messages = JSON.parse(el.dataset.messages || '[]');
      messages.forEach(([category, text]) => {
        const type = category === 'error' ? 'error' : category === 'success' ? 'success' : 'info';
        this.show(type, text, '', 4000);
      });
    } catch (_) { /* ignore parse errors */ }
  },
};

/* ─── Utility: Field Validation ─── */
const Validator = {
  validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  },
  validateUsername(username) {
    return /^[a-zA-Z0-9_]{3,20}$/.test(username.trim());
  },
  validatePassword(password) {
    return password.length >= 8;
  },
  setError(inputEl, errorEl) {
    inputEl?.classList.add('is-invalid');
    inputEl?.classList.remove('is-valid');
    if (errorEl) errorEl.style.display = 'block';
  },
  setValid(inputEl, errorEl) {
    inputEl?.classList.remove('is-invalid');
    inputEl?.classList.add('is-valid');
    if (errorEl) errorEl.style.display = 'none';
  },
  clearState(inputEl, errorEl) {
    inputEl?.classList.remove('is-invalid', 'is-valid');
    if (errorEl) errorEl.style.display = 'none';
  },
};

/* ─── Password Toggle ─── */
function setupPasswordToggle(toggleBtnId, inputId, iconId) {
  const btn   = document.getElementById(toggleBtnId);
  const input = document.getElementById(inputId);
  const icon  = document.getElementById(iconId);
  if (!btn || !input) return;

  const eyeOpen   = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  const eyeClosed = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

  btn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    if (icon) icon.innerHTML = isPassword ? eyeClosed : eyeOpen;
    btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  });
}

/* ─── Password Strength Meter ─── */
function setupStrengthMeter(inputId) {
  const input    = document.getElementById(inputId);
  const bar      = document.getElementById('strengthBar');
  const label    = document.getElementById('strengthLabel');
  if (!input || !bar) return;

  const segments = bar.querySelectorAll('.strength-segment');

  function getStrength(pwd) {
    let score = 0;
    if (pwd.length >= 8)  score++;
    if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    return Math.min(score, 4);
  }

  const levels = [
    { label: 'Very weak',   cls: 'active-weak'   },
    { label: 'Weak',        cls: 'active-weak'   },
    { label: 'Fair',        cls: 'active-fair'   },
    { label: 'Strong',      cls: 'active-strong' },
    { label: 'Very strong', cls: 'active-strong' },
  ];

  input.addEventListener('input', () => {
    const pwd = input.value;
    if (!pwd) {
      segments.forEach(s => { s.className = 'strength-segment'; });
      label.textContent = 'Password strength';
      label.style.color = '';
      return;
    }
    const score = getStrength(pwd);
    segments.forEach((s, i) => {
      s.className = 'strength-segment';
      if (i < score) s.classList.add(levels[score - 1].cls);
    });
    const lvl = levels[Math.max(0, score - 1)];
    label.textContent = lvl.label;
    label.style.color =
      lvl.cls === 'active-strong' ? 'var(--success)' :
      lvl.cls === 'active-fair'   ? 'var(--warning)' : 'var(--danger)';
  });
}

/* ─── Loading State ─── */
function setLoading(btn, state) {
  btn.classList.toggle('loading', state);
  btn.disabled = state;
}

/* ─── CSRF token helper ─── */
function getCsrfToken() {
  return document.getElementById('csrf_token')?.value ?? '';
}

/* ─── Backend POST (JSON) ─── */
async function postJSON(url, payload) {
  const response = await fetch(url, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'X-CSRFToken':   getCsrfToken(),
    },
    body: JSON.stringify(payload),
    credentials: 'same-origin',
  });

  let data = {};
  try { data = await response.json(); } catch (_) {}
  return { status: response.status, data };
}

/* ═══════════════════════════════════════
   REGISTER PAGE
   ═══════════════════════════════════════ */
function initRegisterPage() {
  ToastManager.init();
  setupPasswordToggle('togglePassword', 'password',        'eyeIconPwd');
  setupPasswordToggle('toggleConfirm',  'confirmPassword', 'eyeIconConf');
  setupStrengthMeter('password');

  const form     = document.getElementById('registerForm');
  const userInp  = document.getElementById('username');
  const emailInp = document.getElementById('email');
  const pwdInp   = document.getElementById('password');
  const confInp  = document.getElementById('confirmPassword');
  const btn      = document.getElementById('registerBtn');
  if (!form) return;

  /* Live blur validation */
  userInp?.addEventListener('blur', () => {
    Validator.validateUsername(userInp.value)
      ? Validator.setValid(userInp, document.getElementById('usernameError'))
      : Validator.setError(userInp, document.getElementById('usernameError'));
  });
  emailInp?.addEventListener('blur', () => {
    Validator.validateEmail(emailInp.value)
      ? Validator.setValid(emailInp, document.getElementById('emailError'))
      : Validator.setError(emailInp, document.getElementById('emailError'));
  });
  pwdInp?.addEventListener('blur', () => {
    Validator.validatePassword(pwdInp.value)
      ? Validator.setValid(pwdInp, document.getElementById('passwordError'))
      : Validator.setError(pwdInp, document.getElementById('passwordError'));
  });
  confInp?.addEventListener('blur', () => {
    confInp.value === pwdInp.value
      ? Validator.setValid(confInp, document.getElementById('confirmError'))
      : Validator.setError(confInp, document.getElementById('confirmError'));
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let valid = true;

    if (!Validator.validateUsername(userInp.value)) {
      Validator.setError(userInp, document.getElementById('usernameError'));
      valid = false;
    }
    if (!Validator.validateEmail(emailInp.value)) {
      Validator.setError(emailInp, document.getElementById('emailError'));
      valid = false;
    }
    if (!Validator.validatePassword(pwdInp.value)) {
      Validator.setError(pwdInp, document.getElementById('passwordError'));
      valid = false;
    }
    if (confInp.value !== pwdInp.value) {
      Validator.setError(confInp, document.getElementById('confirmError'));
      valid = false;
    }
    if (!valid) return;

    setLoading(btn, true);

    try {
      const { status, data } = await postJSON('/register', {
        username:        userInp.value.trim(),
        email:           emailInp.value.trim(),
        password:        pwdInp.value,
        confirmPassword: confInp.value,
      });

      if (status === 201 && data.ok) {
        ToastManager.show('success', 'Account Created!', data.message ?? 'Redirecting to login…');
        setTimeout(() => { window.location.href = '/login'; }, 2000);
      } else {
        const msg = data.error ?? 'Registration failed. Please try again.';
        ToastManager.show('error', 'Registration Error', msg);
        setLoading(btn, false);
      }
    } catch (err) {
      ToastManager.show('error', 'Network Error', 'Could not reach the server. Please try again.');
      setLoading(btn, false);
    }
  });
}

/* ═══════════════════════════════════════
   LOGIN PAGE
   ═══════════════════════════════════════ */
function initLoginPage() {
  ToastManager.init();
  setupPasswordToggle('toggleLoginPwd', 'loginPassword', 'eyeIconLogin');

  const form        = document.getElementById('loginForm');
  const emailInp    = document.getElementById('loginEmail');
  const pwdInp      = document.getElementById('loginPassword');
  const btn         = document.getElementById('loginBtn');
  const forgotLink  = document.getElementById('forgotLink');
  const forgotModal = document.getElementById('forgotModal');
  const closeModal  = document.getElementById('closeForgotModal');
  const sendResetBtn= document.getElementById('sendResetBtn');
  if (!form) return;

  /* Forgot Password Modal */
  forgotLink?.addEventListener('click', (e) => {
    e.preventDefault();
    forgotModal?.classList.add('active');
    document.getElementById('resetEmail')?.focus();
  });
  closeModal?.addEventListener('click',  () => forgotModal?.classList.remove('active'));
  forgotModal?.addEventListener('click', (e) => {
    if (e.target === forgotModal) forgotModal.classList.remove('active');
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') forgotModal?.classList.remove('active');
  });

  sendResetBtn?.addEventListener('click', async () => {
    const email = document.getElementById('resetEmail')?.value ?? '';
    if (!Validator.validateEmail(email)) {
      ToastManager.show('error', 'Invalid Email', 'Please enter a valid email address.');
      return;
    }
    setLoading(sendResetBtn, true);
    /* Password reset will be implemented in a later phase */
    await new Promise(r => setTimeout(r, 1200));
    setLoading(sendResetBtn, false);
    forgotModal?.classList.remove('active');
    ToastManager.show('info', 'Coming Soon', 'Password reset will be available in the next phase.');
  });

  /* Live blur validation */
  emailInp?.addEventListener('blur', () => {
    Validator.validateEmail(emailInp.value)
      ? Validator.setValid(emailInp, document.getElementById('loginEmailError'))
      : Validator.setError(emailInp, document.getElementById('loginEmailError'));
  });
  pwdInp?.addEventListener('blur', () => {
    pwdInp.value.length > 0
      ? Validator.setValid(pwdInp, document.getElementById('loginPasswordError'))
      : Validator.setError(pwdInp, document.getElementById('loginPasswordError'));
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let valid = true;

    if (!Validator.validateEmail(emailInp.value)) {
      Validator.setError(emailInp, document.getElementById('loginEmailError'));
      valid = false;
    }
    if (!pwdInp.value) {
      Validator.setError(pwdInp, document.getElementById('loginPasswordError'));
      valid = false;
    }
    if (!valid) return;

    setLoading(btn, true);

    try {
      const { status, data } = await postJSON('/login', {
        email:    emailInp.value.trim(),
        password: pwdInp.value,
      });

      if (data.ok) {
        ToastManager.show('success', 'Welcome back!', data.message ?? 'Loading your workspace…');
        setTimeout(() => {
          window.location.href = data.redirect ?? '/chat';
        }, 1200);
      } else {
        const msg = data.error ?? 'Invalid email or password.';
        ToastManager.show('error', 'Login Failed', msg);
        /* Shake the form card */
        document.querySelector('.auth-card')?.classList.add('shake');
        setTimeout(() => document.querySelector('.auth-card')?.classList.remove('shake'), 500);
        setLoading(btn, false);
      }
    } catch (err) {
      ToastManager.show('error', 'Network Error', 'Could not reach the server. Please try again.');
      setLoading(btn, false);
    }
  });
}

/* ─── Auto-detect and init correct page ─── */
document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('registerForm')) initRegisterPage();
  if (document.getElementById('loginForm'))    initLoginPage();
});
