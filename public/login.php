<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';
$config = require dirname(__DIR__) . '/config/config.php';
\SecurePackage\Security\WebSecurity::startSession();
\SecurePackage\Security\WebSecurity::applyHeaders(true);
if (\SecurePackage\Security\AccessContext::isAuthenticated()) {
    header('Location: profile.php', true, 303);
    exit;
}
$csrf = \SecurePackage\Security\WebSecurity::csrfToken();
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<meta name="description" content="Sign in to manage your Secure Package encrypted projects.">
<title>Sign in · Secure Package</title>
<link rel="stylesheet" href="assets/app.css?v=2"><link rel="stylesheet" href="assets/auth.css">
</head>
<body class="auth-page">
<main class="auth-card glass">
<a class="auth-brand" href="./">Secure Package</a>
<p class="auth-eyebrow">ACCOUNT ACCESS</p><h1>Sign in</h1><p class="auth-intro">Sign in to manage your encrypted packages and access links.</p>
<form id="authForm" data-mode="login">
<label for="username">Username</label><input class="text-input" id="username" name="username" autocomplete="username" minlength="3" maxlength="80" required>
<label for="password">Password</label><input class="text-input" id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required>
<button class="primary-button full" type="submit">Sign in</button>
<p id="authMessage" class="auth-message" role="status" aria-live="polite"></p>
</form>
<p class="auth-switch">New here? <a href="register.php">Create an account</a></p>
<a class="auth-back" href="./">← Back to package workspace</a>
</main>
<script src="assets/auth-page.js" defer></script>
</body></html>
