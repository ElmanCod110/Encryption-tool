<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

use SecurePackage\Security\WebSecurity;

WebSecurity::startSession();
WebSecurity::applyHeaders(true);
$csrf = WebSecurity::csrfToken();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<meta name="description" content="Secure Package V14 — high-assurance encrypted project packages with authenticated integrity and recovery. ">
<title>Secure Package V14</title>
<link rel="stylesheet" href="assets/app.css">
</head>
<body>
<div class="app-shell">
<header class="topbar glass">
  <a class="brand" href="./" aria-label="Secure Package home">
    <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 32 32"><path d="M16 3 26 7v7c0 7-4.2 11.6-10 15-5.8-3.4-10-8-10-15V7l10-4Z"/><path d="m11.5 16 3 3 6-7"/></svg></span>
    <span><b>Secure Package</b><small>High-assurance encrypted package platform</small></span>
  </a>
  <div class="top-actions">
    <span class="version-pill">V14</span>
    <a class="ghost-button" href="client-vault.html">Browser Vault V13</a>
    <button class="ghost-button" id="authButton" type="button">Sign in</button>
  </div>
</header>

<main>
<section class="hero">
  <div class="hero-copy">
    <span class="eyebrow"><span class="status-dot"></span> V14 cryptographic package engine</span>
    <h1>Encrypt the project. Authenticate the package. Restore safely.</h1>
    <p>V14 separates credential wrapping from the package root key, authenticates metadata and ciphertext, verifies the complete blob inventory and Merkle root, and refuses unsafe restore paths.</p>
    <div class="hero-badges">
      <span>Argon2id13</span><span>XChaCha20-Poly1305</span><span>Secretstream</span><span>HKDF key separation</span><span>Pre-write integrity</span>
    </div>
  </div>
  <div class="hero-orbit glass" aria-hidden="true">
    <div class="orbit-ring ring-1"></div><div class="orbit-ring ring-2"></div>
    <div class="core-shield"><svg viewBox="0 0 48 48"><path d="M24 4 39 10v10c0 10.2-6.1 17-15 23-8.9-6-15-12.8-15-23V10L24 4Z"/><path d="m17 24 5 5 10-12"/></svg></div>
  </div>
</section>

<section class="workspace-grid">
  <article class="panel glass span-2">
    <div class="panel-heading">
      <div><span class="step-index">01</span><h2>Create a V14 encrypted package</h2><p>Upload a ZIP, process protected archives, then build an authenticated package.</p></div>
      <span class="mini-state" id="createState">Ready</span>
    </div>
    <div class="dropzone" id="dropzone">
      <input id="archive" type="file" accept=".zip,application/zip" hidden>
      <div class="upload-icon"><svg viewBox="0 0 32 32"><path d="M16 22V6"/><path d="m10 12 6-6 6 6"/><path d="M7 18v7h18v-7"/></svg></div>
      <h3>Drop a ZIP archive here</h3>
      <p>or <button class="inline-link" id="browseBtn" type="button">browse from your computer</button></p>
      <small>Resumable ciphertext upload • protected ZIPs • staged extraction</small>
      <div class="upload-progress hidden" id="uploadProgress">
        <div class="progress-line"><span id="uploadProgressBar"></span></div>
        <div class="progress-meta"><span id="uploadProgressText">0%</span><span id="uploadProgressSize">0 / 0</span></div>
      </div>
    </div>

    <div class="flow-grid hidden" id="createFlow">
      <div class="field-card">
        <span>Archive status</span><strong id="archiveNotice">No archive pending</strong>
        <button class="small-button" id="stepBtn" type="button">Enter archive password</button>
        <input class="text-input hidden" id="archivePassword" type="password" autocomplete="off" placeholder="Archive password">
      </div>
      <div class="field-card">
        <span>Unique package name</span><strong>Reserved permanently</strong>
        <input class="text-input" id="projectName" maxlength="100" placeholder="e.g. Research Vault 01">
      </div>
      <div class="field-card">
        <span>Encryption password</span><strong>Argon2id credential wrapping</strong>
        <div class="secret-row"><input class="text-input" id="password" type="password" autocomplete="new-password" placeholder="Strong password"><button class="icon-button" id="showPassword" type="button" aria-label="Show password">◉</button></div>
        <div class="strength"><span id="passwordStrength"></span></div>
      </div>
      <div class="field-card">
        <span>Encryption pattern</span><strong>Independent Argon2id input</strong>
        <div class="secret-row"><input class="text-input" id="pattern" type="password" autocomplete="new-password" placeholder="High-entropy pattern"><button class="icon-button" id="showPattern" type="button" aria-label="Show pattern">◉</button></div>
        <div class="strength"><span id="patternStrength"></span></div>
      </div>
      <div class="field-card full-card">
        <span>Recovery policy</span><strong>Independent random recovery key</strong>
        <label class="check"><input id="createRecovery" type="checkbox" checked> Create a 256-bit recovery key in a separate authenticated key slot.</label>
        <small class="helper">The recovery key is displayed once after successful creation. Store it offline; it is not recoverable from the package.</small>
      </div>
    </div>

    <div class="panel-footer hidden" id="buildFooter">
      <div><span class="security-note">Secrets are never written to the encrypted package. V14 verifies package integrity before restore output begins.</span></div>
      <button class="primary-button" id="buildBtn" type="button"><span>Build V14 package</span><svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></button>
    </div>

    <div class="result-card hidden" id="recoveryCard">
      <div><span class="result-kicker">Recovery key · shown once</span><strong id="recoveryKey">—</strong><small>Save this value offline before leaving the page. It grants package restore without the password/pattern.</small></div>
      <button class="small-button" id="copyRecovery" type="button">Copy key</button>
    </div>
  </article>

  <article class="panel glass">
    <div class="panel-heading"><div><span class="step-index">02</span><h2>Open a package</h2><p>Use the primary credentials or the independent V14 recovery key.</p></div></div>
    <div class="stack-fields">
      <label>Package ID<input class="text-input" id="packageId" maxlength="48" placeholder="48-character package ID"></label>
      <label>Password<input class="text-input" id="decryptPassword" type="password" autocomplete="off" placeholder="Package password"></label>
      <label>Pattern<input class="text-input" id="decryptPattern" type="password" autocomplete="off" placeholder="Package pattern"></label>
      <label>Recovery key <span class="muted-label">optional</span><input class="text-input" id="recoveryKeyInput" maxlength="43" autocomplete="off" spellcheck="false" placeholder="V14 recovery key (43 chars)"></label>
    </div>
    <button class="primary-button full" id="decryptBtn" type="button">Open package <svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></button>
    <div class="callout"><span class="callout-icon">i</span><p>Credential failures remain generic. Restore is fail-closed and never overwrites an existing destination.</p></div>
  </article>

  <article class="panel glass">
    <div class="panel-heading"><div><span class="step-index">03</span><h2>Your packages</h2><p>Management is tied to your current identity.</p></div><button class="refresh-button" id="refreshPackages" type="button">Refresh</button></div>
    <div id="packageList" class="package-list empty"><div class="empty-icon"><svg viewBox="0 0 32 32"><path d="M5 9h8l2 3h12v13H5z"/><path d="M5 9V7h9l2 2"/></svg></div><strong>No packages loaded</strong><span>Sign in or create a package to see managed items.</span></div>
  </article>
</section>

<section class="bottom-grid">
  <div class="status-panel glass">
    <div class="status-title"><span class="live-dot"></span><strong id="statusPill">System ready</strong><span class="status-caption">CSRF • ownership • replay/rate controls • ciphertext-only transport</span></div>
    <pre id="log">V14 package engine ready.</pre>
  </div>
  <div class="architecture-panel glass">
    <div class="architecture-title"><strong>V14 security pipeline</strong><span>SECURE-PKG-V14</span></div>
    <div class="pipeline"><span>CREDENTIALS</span><i></i><span>Argon2id</span><i></i><span>KEY WRAP</span><i></i><span>AEAD</span><i></i><span>STREAM</span><i></i><span>MERKLE</span></div>
    <p>V14 protects the package root key separately, authenticates the header binding and manifest, hashes every ciphertext blob, then verifies the complete Merkle root before restore.</p>
  </div>
</section>
</main>

<footer><span>Secure Package · Author: ElmanCod110</span><span>V14 server package engine · Browser Vault V13 remains a separate compatibility boundary.</span></footer>
</div>

<div class="modal hidden" id="authModal">
  <div class="modal-card glass">
    <button class="modal-close" id="closeAuth" type="button">×</button>
    <div class="modal-logo"><svg viewBox="0 0 40 40"><path d="M20 4 33 9v9c0 8.8-5.3 14.7-13 19-7.7-4.3-13-10.2-13-19V9L20 4Z"/><path d="m14 20 4 4 8-9"/></svg></div>
    <h2 id="authTitle">Sign in</h2><p id="authSubtitle">Manage packages and revoke access from one identity.</p>
    <div class="auth-tabs"><button class="active" id="loginTab" type="button">Sign in</button><button id="registerTab" type="button">Create account</button></div>
    <label>Username<input class="text-input" id="authUsername" autocomplete="username"></label>
    <label>Password<input class="text-input" id="authPassword" type="password" autocomplete="current-password"></label>
    <button class="primary-button full" id="authSubmit" type="button">Sign in</button>
    <button class="text-button" id="logoutButton" type="button">Sign out current session</button>
  </div>
</div>

<script src="assets/app.js" defer></script>
</body>
</html>
