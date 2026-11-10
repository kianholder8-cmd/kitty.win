const emailElement = document.getElementById('email');
const signoutButton = document.getElementById('signout');

fetch('/api/me', { headers: { accept: 'application/json' } })
  .then((response) => {
    if (!response.ok) throw new Error('not signed in');
    return response.json();
  })
  .then((me) => {
    emailElement.textContent = me.email;
  })
  .catch(() => {
    location.replace('/signup');
  });

signoutButton.addEventListener('click', async () => {
  signoutButton.disabled = true;
  try {
    await fetch('/api/signout', { method: 'POST' });
  } catch {
    // Signing out locally is still fine if the request fails.
  }
  location.assign('/signup');
});
