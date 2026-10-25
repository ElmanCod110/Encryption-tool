'use strict';

const logoutButton = document.getElementById('logoutButton');
const message = document.getElementById('profileMessage');
const csrfMeta = document.querySelector('meta[name="csrf-token"]');

logoutButton?.addEventListener('click', async () => {
  logoutButton.disabled = true;
  message.textContent = '';
  message.classList.remove('success');
  try {
    const response = await fetch('api.php?action=logout', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfMeta?.content || '',
      },
      body: '{}',
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) throw new Error(data.error || 'Unable to sign out.');
    window.location.replace('login.php');
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : 'Unable to sign out.';
    logoutButton.disabled = false;
  }
});
