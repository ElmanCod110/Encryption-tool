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
<meta name="description" content="Create a Secure Package account to manage encrypted projects.">
<title>Create account · Secure Package</title>
<link rel="stylesheet" href="assets/app.css?v=2"><link rel="stylesheet" href="assets/auth.css">
</head>
<body class="auth-page">
<main class="auth-card glass">
<a class="auth-brand" href="./">Secure Package</a>
<p class="auth-eyebrow">ACCOUNT ACCESS</p><h1>Create account</h1><p class="auth-intro">Create an account to manage your encrypted packages.</p>
<form id="authForm" data-mode="register" novalidate>
<label for="username">Username</label><input class="text-input" id="username" name="username" autocomplete="username" minlength="3" maxlength="80" required>
<label for="password">Password</label><input class="text-input" id="password" name="password" type="password" autocomplete="new-password" required>
<button class="primary-button full" type="submit">Create account</button>
<p id="authMessage" class="auth-message" role="status" aria-live="polite"></p>
</form>
<p class="auth-switch">Already have an account? <a href="login.php">Sign in</a></p>
<a class="auth-back" href="./">← Back to package workspace</a>
</main>
<script src="assets/auth-page.js" defer></script>
</body></html>
