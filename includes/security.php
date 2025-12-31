<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Encrypt Data
 */
function ftp_uploader_encrypt($data)
{
    if (empty($data)) {
        return $data;
    }
    // Simple encryption using a constant/salt.
    // In a real world scenario, use a generated key stored securely.
    // For this, we'll use wp_salt() if available or a fallback.
    $key = defined('LOGGED_IN_KEY') ? LOGGED_IN_KEY : 'ftp_uploader_secret_key';
    $iv_length = openssl_cipher_iv_length('AES-256-CBC');
    $iv = openssl_random_pseudo_bytes($iv_length);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

/**
 * Decrypt Data
 */
function ftp_uploader_decrypt($data)
{
    if (empty($data)) {
        return $data;
    }
    $key = defined('LOGGED_IN_KEY') ? LOGGED_IN_KEY : 'ftp_uploader_secret_key';
    $data = base64_decode($data);
    $iv_length = openssl_cipher_iv_length('AES-256-CBC');
    $iv = substr($data, 0, $iv_length);
    $encrypted = substr($data, $iv_length);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}
