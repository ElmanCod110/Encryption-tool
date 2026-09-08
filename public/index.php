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
<title>Secure Package</title>
<link rel="stylesheet" href="assets/app.css">
</head>
<body>
<div class="ambient ambient-a"></div>
<div class="ambient ambient-b"></div>
<div class="app-shell">
<header class="topbar glass">
  <a class="brand" href="./">
    <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 32 32"><path d="M16 3 26 7v7c0 7-4.2 11.6-10 15-5.8-3.4-10-8-10-15V7l10-4Z"/><path d="m11.5 16 3 3 6-7"/></svg></span>
    <span><b>Secure Package</b><small>Open-source encrypted package platform</small></span>
  </a>
  <div class="top-actions">
    <span class="version-pill">V4</span>
    <button class="ghost-button" id="authButton">Sign in</button>
  </div>
</header>

<main>
<section class="hero">
  <div class="hero-copy">
    <span class="eyebrow"><span class="status-dot"></span> Privacy-first package workflow</span>
    <h1>Protect complete projects, not just files.</h1>
    <p>Build opaque encrypted packages from ZIP archives, keep filenames and directory relationships private, and restore only after authenticated credentials succeed.</p>
    <div class="hero-badges">
      <span>Argon2id</span><span>XChaCha20-Poly1305</span><span>Encrypted manifest</span><span>Resumable upload</span>
    </div>
  </div>
  <div class="hero-orbit glass" aria-hidden="true">
    <div class="orbit-ring ring-1"></div><div class="orbit-ring ring-2"></div>
    <div class="core-shield"><svg viewBox="0 0 48 48"><path d="M24 4 39 10v10c0 10.2-6.1 17-15 23-8.9-6-15-12.8-15-23V10L24 4Z"/><path d="m17 24 5 5 10-12"/></svg></div>
  </div>
</section>

<section class="workspace-grid">
  <article class="panel glass span-2">
    <div class="panel-heading"><div><span class="step-index">01</span><h2>Create an encrypted package</h2><p>Upload a ZIP and process protected archives stage by stage.</p></div><span class="mini-state" id="createState">Ready</span></div>
    <div class="dropzone" id="dropzone">
      <input id="archive" type="file" accept=".zip,application/zip" hidden>
      <div class="upload-icon"><svg viewBox="0 0 32 32"><path d="M16 22V6"/><path d="m10 12 6-6 6 6"/><path d="M7 18v7h18v-7"/></svg></div>
      <h3>Drop a ZIP archive here</h3>
      <p>or <button class="inline-link" id="browseBtn" type="button">browse from your computer</button></p>
      <small>Resumable uploads • protected ZIPs supported • staged extraction</small>
      <div class="upload-progress hidden" id="uploadProgress"><div class="progress-line"><span id="uploadProgressBar"></span></div><div class="progress-meta"><span id="uploadProgressText">0%</span><span id="uploadProgressSize">0 / 0</span></div></div>
    </div>
    <div class="flow-grid hidden" id="createFlow">
      <div class="field-card"><span>Archive status</span><strong id="archiveNotice">No archive pending</strong><button class="small-button" id="stepBtn" type="button">Enter archive password</button><input class="text-input hidden" id="archivePassword" type="password" autocomplete="off" placeholder="Archive password"></div>
      <div class="field-card"><span>Unique package name</span><strong>Reserved permanently</strong><input class="text-input" id="projectName" maxlength="100" placeholder="e.g. Research Vault 01"></div>
      <div class="field-card"><span>Encryption password</span><strong>Argon2id derived</strong><div class="secret-row"><input class="text-input" id="password" type="password" autocomplete="new-password" placeholder="Strong password"><button class="icon-button" id="showPassword" type="button" aria-label="Show password">◉</button></div><div class="strength"><span id="passwordStrength"></span></div></div>
      <div class="field-card"><span>Encryption pattern</span><strong>High-entropy key input</strong><div class="secret-row"><input class="text-input" id="pattern" type="password" autocomplete="new-password" placeholder="High-entropy pattern"><button class="icon-button" id="showPattern" type="button" aria-label="Show pattern">◉</button></div><div class="strength"><span id="patternStrength"></span></div></div>
    </div>
    <div class="panel-footer hidden" id="buildFooter"><div><span class="security-note">Credentials are never written to the package.</span></div><button class="primary-button" id="buildBtn" type="button"><span>Build encrypted package</span><svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></button></div>
  </article>

  <article class="panel glass">
    <div class="panel-heading"><div><span class="step-index">02</span><h2>Open a package</h2><p>Decrypt a package using its identifier and both secrets.</p></div></div>
    <div class="stack-fields">
      <label>Package ID<input class="text-input" id="packageId" maxlength="48" placeholder="48-character package ID"></label>
      <label>Password<input class="text-input" id="decryptPassword" type="password" autocomplete="off" placeholder="Package password"></label>
      <label>Pattern<input class="text-input" id="decryptPattern" type="password" autocomplete="off" placeholder="Package pattern"></label>
    </div>
    <button class="primary-button full" id="decryptBtn" type="button">Open package <svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></button>
    <div class="callout"><span class="callout-icon">i</span><p>Credential failures are deliberately generic. The service does not reveal which secret failed.</p></div>
  </article>

  <article class="panel glass">
    <div class="panel-heading"><div><span class="step-index">03</span><h2>Your packages</h2><p>Management is tied to your current identity.</p></div><button class="refresh-button" id="refreshPackages" type="button">Refresh</button></div>
    <div id="packageList" class="package-list empty"><div class="empty-icon"><svg viewBox="0 0 32 32"><path d="M5 9h8l2 3h12v13H5z"/><path d="M5 9V7h9l2 2"/></svg></div><strong>No packages loaded</strong><span>Sign in or create a package to see managed items.</span></div>
  </article>
</section>

<section class="bottom-grid">
  <div class="status-panel glass"><div class="status-title"><span class="live-dot"></span><strong id="statusPill">System ready</strong></div><pre id="log">Upload a ZIP to begin.</pre></div>
  <div class="architecture-panel glass"><div class="architecture-title"><strong>Security pipeline</strong><span>V4</span></div><div class="pipeline"><span>ZIP</span><i></i><span>Staging</span><i></i><span>Argon2id</span><i></i><span>AEAD</span><i></i><span>.spkg</span></div><p>Source paths are normalized before encryption. Package manifests and file blobs are authenticated independently.</p></div>
</section>
</main>

<footer><span>Secure Package · Author: ElmanCod110</span><span>Open source · Security should not depend on source-code secrecy.</span></footer>
</div>

<div class="modal hidden" id="authModal"><div class="modal-card glass"><button class="modal-close" id="closeAuth" type="button">×</button><div class="modal-logo"><svg viewBox="0 0 40 40"><path d="M20 4 33 9v9c0 8.8-5.3 14.7-13 19-7.7-4.3-13-10.2-13-19V9L20 4Z"/><path d="m14 20 4 4 8-9"/></svg></div><h2 id="authTitle">Sign in</h2><p id="authSubtitle">Manage packages and revoke access from one identity.</p><div class="auth-tabs"><button class="active" id="loginTab">Sign in</button><button id="registerTab">Create account</button></div><label>Username<input class="text-input" id="authUsername" autocomplete="username"></label><label>Password<input class="text-input" id="authPassword" type="password" autocomplete="current-password"></label><button class="primary-button full" id="authSubmit">Sign in</button><button class="text-button" id="logoutButton" type="button">Sign out current session</button></div></div>

<script src="assets/app.js" defer></script>
</body>
</html>
