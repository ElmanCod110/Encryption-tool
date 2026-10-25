'use strict';

const form = document.getElementById('authForm');
if (form) {
  const message = document.getElementById('authMessage');
  const submit = form.querySelector('button[type="submit"]');
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    message.classList.remove('success');
    submit.disabled = true;
    const mode = form.dataset.mode === 'register' ? 'register' : 'login';
    try {
      const response = await fetch(`api.php?action=${mode}`, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfMeta?.content || '',
        },
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.ok === false) throw new Error(data.error || 'Unable to complete account request.');
      if (csrfMeta && data.csrf) csrfMeta.content = data.csrf;
      document.getElementById('password').value = '';
      message.textContent = mode === 'register' ? 'Account created. Opening your profile…' : 'Signed in. Opening your profile…';
      message.classList.add('success');
      window.location.replace('profile.php');
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : 'Unable to complete account request.';
    } finally {
      submit.disabled = false;
    }
  });
}
