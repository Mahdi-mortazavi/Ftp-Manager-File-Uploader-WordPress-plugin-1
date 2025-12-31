<?php
/**
 * Plugin Name: FTP Manager & Uploader
 * Plugin URI:  https://t.me/ageek
 * Description: FTP Manager with upload from URL and device. you can manage your files and folders on your FTP server (Download Host). 
 * Version:     1.7.0
 * Author:      Aref Solaimani & Mahdi Mortezavi
 * Author URI:  https://t.me/ageek
 * License:     GPLv2 or later
 * Text Domain: ftp-uploader-manager
 */

if (!defined('ABSPATH')) {
    exit;
}

define('FTP_UPLOADER_VERSION', '1.1.0');
define('FTP_UPLOADER_PATH', plugin_dir_path(__FILE__));
define('FTP_UPLOADER_URL', plugin_dir_url(__FILE__));
define('FTP_UPLOADER_TABLE', 'ftpuploader_logs');

// Includes
require_once FTP_UPLOADER_PATH . 'includes/security.php';
require_once FTP_UPLOADER_PATH . 'includes/db-functions.php';
require_once FTP_UPLOADER_PATH . 'includes/cron-handler.php';

if (is_admin()) {
    require_once FTP_UPLOADER_PATH . 'includes/admin-page.php';
}

/**
 * Activation Hook
 */
function ftp_uploader_activate()
{
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        source_url varchar(2083) NOT NULL,
        remote_filename varchar(255) NOT NULL,
        status varchar(50) DEFAULT 'pending' NOT NULL,
        message text,
        retry_count smallint(3) DEFAULT 0 NOT NULL,
        created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}
register_activation_hook(__FILE__, 'ftp_uploader_activate');

/**
 * Deactivation Hook
 */
function ftp_uploader_deactivate()
{
    wp_clear_scheduled_hook('ftp_uploader_process_file_node');
    wp_clear_scheduled_hook('ftp_uploader_process_device_file_node');
}
register_deactivation_hook(__FILE__, 'ftp_uploader_deactivate');

/**
 * Initialize Plugin
 */
function ftp_uploader_init()
{
    // Handle Upload Form Submission (from URL)
    if (isset($_POST['ftp_uploader_action']) && $_POST['ftp_uploader_action'] === 'upload_file') {
        // Verify nonce before processing
        if (isset($_POST['ftp_uploader_nonce']) && wp_verify_nonce($_POST['ftp_uploader_nonce'], 'ftp_uploader_upload')) {
            if (function_exists('ftp_uploader_handle_upload_submission')) {
                ftp_uploader_handle_upload_submission();
            }
        }
    }
    
    // Handle Device Upload Form Submission
    if (isset($_POST['ftp_uploader_action']) && $_POST['ftp_uploader_action'] === 'upload_device_file') {
        // Verify nonce before processing
        if (isset($_POST['ftp_uploader_device_nonce']) && wp_verify_nonce($_POST['ftp_uploader_device_nonce'], 'ftp_uploader_device_upload')) {
            if (function_exists('ftp_uploader_handle_device_upload_submission')) {
                ftp_uploader_handle_device_upload_submission();
            }
        }
    }
}
add_action('plugins_loaded', 'ftp_uploader_init');
