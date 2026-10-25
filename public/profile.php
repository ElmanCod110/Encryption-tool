<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
$config = require dirname(__DIR__) . '/config/config.php';
\SecurePackage\Security\WebSecurity::startSession();
\SecurePackage\Security\WebSecurity::applyHeaders(true);
if (!\SecurePackage\Security\AccessContext::isAuthenticated()) {
    header('Location: login.php', true, 303);
    exit;
}
$csrf = \SecurePackage\Security\WebSecurity::csrfToken();
$accountId = \SecurePackage\Security\AccessContext::accountId();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<meta name="description" content="Manage your account and encrypted packages stored by Secure Package.">
<meta name="robots" content="noindex,nofollow">
<title>Account dashboard · Secure Package</title>
<link rel="stylesheet" href="assets/app.css?v=2"><link rel="stylesheet" href="assets/auth.css?v=3">
</head>
<body class="auth-page profile-page">
<main class="profile-shell">
<header class="profile-topbar">
  <a class="auth-brand" href="./">Secure Package</a>
  <nav aria-label="Account navigation"><a class="ghost-button" href="./">Package workspace</a><button class="ghost-button" id="logoutButton" type="button">Sign out</button></nav>
</header>
<section class="profile-welcome">
  <div><p class="auth-eyebrow">ACCOUNT CONTROL CENTER</p><h1>Your dashboard</h1><p class="auth-intro">Manage encrypted packages stored in your account, review storage usage, and control download access.</p></div>
  <span class="profile-status-badge"><span aria-hidden="true"></span> Authenticated session</span>
</section>
<section class="profile-stats" aria-label="Package statistics">
  <article class="profile-stat"><span>Stored packages</span><strong id="statPackages">—</strong><small>Encrypted server packages</small></article>
  <article class="profile-stat"><span>Storage used</span><strong id="statStorage">—</strong><small>Current encrypted archive sizes</small></article>
  <article class="profile-stat"><span>Active</span><strong id="statActive">—</strong><small>Not revoked or expired</small></article>
  <article class="profile-stat"><span>Revoked</span><strong id="statRevoked">—</strong><small>Download access disabled</small></article>
</section>
<section class="profile-panel">
  <div class="profile-panel-heading">
    <div><p class="auth-eyebrow">YOUR SERVER VAULT</p><h2>Encrypted packages</h2><p>Every package stored under your account appears here. Original filenames inside encrypted packages are not exposed by this inventory.</p></div>
    <button class="ghost-button" id="refreshPackages" type="button">Refresh list</button>
  </div>
  <div class="profile-toolbar">
    <label class="profile-search-label" for="packageSearch">Search packages</label>
    <input class="text-input" id="packageSearch" type="search" placeholder="Search by package ID…" autocomplete="off">
    <label class="profile-filter-label" for="packageFilter">Show</label>
    <select class="text-input" id="packageFilter"><option value="all">All packages</option><option value="active">Active</option><option value="revoked">Revoked</option><option value="expired">Expired</option><option value="missing">Missing archive</option></select>
  </div>
  <p class="auth-message" id="profileMessage" role="status" aria-live="polite"></p>
  <div id="packageList" class="profile-package-list" aria-live="polite"><div class="profile-empty">Loading your encrypted package inventory…</div></div>
</section>
<section class="profile-panel profile-account-panel">
  <div><p class="auth-eyebrow">ACCOUNT DETAILS</p><h2>Account and security</h2></div>
  <dl class="profile-account-details">
    <div><dt>Account ID</dt><dd><code><?= htmlspecialchars((string) $accountId, ENT_QUOTES, 'UTF-8') ?></code></dd></div>
    <div><dt>Session</dt><dd class="profile-status">Signed in</dd></div>
    <div><dt>Application version</dt><dd><?= htmlspecialchars($config['app']['version_string'], ENT_QUOTES, 'UTF-8') ?></dd></div>
    <div><dt>Default package format</dt><dd><?= htmlspecialchars($config['app']['format'], ENT_QUOTES, 'UTF-8') ?> · legacy V14 readable</dd></div>
  </dl>
</section>
<footer class="profile-footer"><span>Secure Package · Account dashboard</span><span>Package actions are checked against server-side ownership.</span></footer>
</main>
<script src="assets/profile-page.js?v=3" defer></script>
</body></html>
