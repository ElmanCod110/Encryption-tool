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
<meta name="description" content="Your Secure Package account profile and session controls.">
<title>Your profile · Secure Package</title>
<link rel="stylesheet" href="assets/app.css?v=2"><link rel="stylesheet" href="assets/auth.css">
</head>
<body class="auth-page">
<main class="auth-card glass">
<a class="auth-brand" href="./">Secure Package</a>
<p class="auth-eyebrow">YOUR ACCOUNT</p><h1>Profile</h1><p class="auth-intro">Review your account identifier and manage your current session.</p>
<section class="profile-details" aria-label="Account details">
<div><span>Account ID</span><code><?= htmlspecialchars((string) $accountId, ENT_QUOTES, 'UTF-8') ?></code></div>
<div><span>Session status</span><strong class="profile-status">Signed in</strong></div>
<div><span>Application version</span><strong><?= htmlspecialchars($config['app']['version_string'], ENT_QUOTES, 'UTF-8') ?></strong></div>
</section>
<p class="auth-message" id="profileMessage" role="status" aria-live="polite"></p>
<a class="primary-button full auth-primary-link" href="./">Open package workspace</a>
<button class="ghost-button full" id="logoutButton" type="button">Sign out</button>
<a class="auth-back" href="profile.php">Refresh profile</a>
</main>
<script src="assets/profile-page.js" defer></script>
</body></html>
