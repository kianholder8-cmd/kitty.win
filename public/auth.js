const isSignin = location.pathname.replace(/\/+$/, '') === '/signin';

const copy = isSignin
  ? {
      documentTitle: 'Sign in | kitty.win',
      eyebrow: 'Sign in',
      heading: 'Welcome back',
      sub: 'Sign in to your kitty.win account.',
      submit: 'Sign in',
      busy: 'Signing in...',
      endpoint: '/api/signin',
      passwordPlaceholder: 'Your password',
      passwordAutocomplete: 'current-password',
      switchHtml: 'New here? <a href="/signup">Create an account</a>',
    }
  : {
      documentTitle: 'Sign up | kitty.win',
      eyebrow: 'Sign up',
      heading: 'Create your account',
      sub: 'One account for kitty.win. Takes about a minute.',
      submit: 'Create account',
      busy: 'Creating account...',
      endpoint: '/api/signup',
      passwordPlaceholder: 'At least 8 characters',
      passwordAutocomplete: 'new-password',
      switchHtml: 'Already have an account? <a href="/signin">Sign in</a>',
    };

const form = document.getElementById('form');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const submitButton = document.getElementById('submit');
const errorBox = document.getElementById('error');

document.title = copy.documentTitle;
document.getElementById('eyebrow').textContent = copy.eyebrow;
document.getElementById('heading').textContent = copy.heading;
document.getElementById('sub').textContent = copy.sub;
document.getElementById('switch').innerHTML = copy.switchHtml;
submitButton.textContent = copy.submit;
passwordInput.placeholder = copy.passwordPlaceholder;
passwordInput.autocomplete = copy.passwordAutocomplete;

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  errorBox.textContent = '';
  errorBox.hidden = true;
}

function setBusy(busy) {
  submitButton.disabled = busy;
  submitButton.textContent = busy ? copy.busy : copy.submit;
  form.setAttribute('aria-busy', busy ? 'true' : 'false');
}

const googleErrors = {
  google_not_configured: 'Google sign-in is not set up on this server yet.',
  google_state: 'That sign-in attempt expired. Please try again.',
  google_email: 'Google did not share a verified email address.',
  google_failed: 'Google sign-in did not work. Try again or use email.',
};

const errorCode = new URLSearchParams(location.search).get('error');
if (errorCode) {
  showError(googleErrors[errorCode] || 'That sign-in attempt did not work. Try again.');
  history.replaceState({}, '', location.pathname);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError();

  const email = emailInput.value.trim().toLowerCase();
  const password = passwordInput.value;

  if (!email) {
    showError('Enter your email address.');
    emailInput.focus();
    return;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    showError('That email address does not look right.');
    emailInput.focus();
    return;
  }

  if (!password) {
    showError('Enter your password.');
    passwordInput.focus();
    return;
  }

  if (!isSignin && password.length < 8) {
    showError('Password must be at least 8 characters.');
    passwordInput.focus();
    return;
  }

  setBusy(true);

  try {
    const response = await fetch(copy.endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      setBusy(false);
      showError(data.error || 'Something went wrong. Try again.');
      return;
    }

    location.assign('/welcome');
  } catch {
    setBusy(false);
    showError('Could not reach the server. Check your connection and try again.');
  }
});
