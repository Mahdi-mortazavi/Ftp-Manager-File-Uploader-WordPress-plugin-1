<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Background Process (Cron) Handler
 */
function ftp_uploader_process_file_handler($log_id)
{
    global $wpdb;

    // Increase Memory Limit
    ini_set('memory_limit', '512M');
    set_time_limit(300); // 5 minutes

    // Get Log
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $log = $wpdb->get_row($wpdb->prepare("SELECT * FROM " . esc_sql($table_name) . " WHERE id = %d", $log_id));

    if (!$log || ($log->status !== 'pending' && $log->status !== 'retrying')) {
        return; // Already processed or not found
    }

    // Get Settings
    $options = get_option('ftp_uploader_settings');
    $ftp_host = isset($options['ftp_host']) ? $options['ftp_host'] : '';
    $ftp_user = isset($options['ftp_user']) ? $options['ftp_user'] : '';
    $ftp_pass_encrypted = isset($options['ftp_pass']) ? $options['ftp_pass'] : '';
    $remote_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '';

    // Decrypt Password
    $ftp_pass = ftp_uploader_decrypt($ftp_pass_encrypted);

    if (empty($ftp_host) || empty($ftp_user) || empty($ftp_pass)) {
        ftp_uploader_update_log_status($log_id, 'failed', 'Missing configuration or decryption failed');
        return;
    }

    // Update status to uploading
    ftp_uploader_update_log_status($log_id, 'uploading', 'Starting upload...');

    // Check if this is a device upload or URL upload
    $is_device_upload = (strpos($log->source_url, 'device://') === 0);
    
    if ($is_device_upload) {
        // Device upload: use the file path directly
        $file_path = substr($log->source_url, 9); // Remove "device://" prefix
        
        if (!file_exists($file_path)) {
            ftp_uploader_handle_failure($log, 'Uploaded file not found in queue directory');
            return;
        }
        
        $tmp_file = $file_path;
    } else {
        // URL upload: download the file first
        if (!function_exists('download_url')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $tmp_file = download_url($log->source_url);

        if (is_wp_error($tmp_file)) {
            ftp_uploader_handle_failure($log, 'Download failed: ' . $tmp_file->get_error_message());
            return;
        }
    }

    // 2. Connect to FTP
    $conn_id = @ftp_connect($ftp_host);
    if (!$conn_id) {
        ftp_uploader_handle_failure($log, 'Could not connect to FTP host');
        wp_delete_file($tmp_file);
        return;
    }

    $login_result = @ftp_login($conn_id, $ftp_user, $ftp_pass);
    if (!$login_result) {
        ftp_uploader_handle_failure($log, 'FTP Login failed');
        ftp_close($conn_id);
        wp_delete_file($tmp_file);
        return;
    }

    ftp_pasv($conn_id, true);

    // 3. Upload File
    $destination = $remote_path . $log->remote_filename;
    
    // Check if file path includes a folder and create it if needed
    $destination_dir = dirname($destination);
    if ($destination_dir !== '.' && $destination_dir !== $remote_path) {
        // Create directory structure if it doesn't exist
        $dirs = explode('/', trim(str_replace($remote_path, '', $destination_dir), '/'));
        $current_path = $remote_path;
        foreach ($dirs as $dir) {
            if (!empty($dir)) {
                $current_path = rtrim($current_path, '/') . '/' . $dir;
                // Try to change to directory, if it fails, create it
                if (!@ftp_chdir($conn_id, $current_path)) {
                    @ftp_mkdir($conn_id, $current_path);
                    @ftp_chdir($conn_id, $current_path);
                }
            }
        }
    }

    if (@ftp_put($conn_id, $destination, $tmp_file, FTP_BINARY)) {
        ftp_uploader_update_log_status($log_id, 'success', 'File uploaded successfully');
    } else {
        $last_error = error_get_last();
        $error_msg = 'FTP Upload failed';
        if ($last_error && isset($last_error['message'])) {
            $error_msg .= ': ' . $last_error['message'];
        }
        ftp_uploader_handle_failure($log, $error_msg);
    }

    // 4. Cleanup
    ftp_close($conn_id);
    
    // Only delete temp file if it was downloaded from URL
    // Device uploads are in queue directory and should be cleaned up
    if (!$is_device_upload) {
        wp_delete_file($tmp_file);
    } else {
        // Clean up device upload file from queue directory
        wp_delete_file($tmp_file);
    }
}
add_action('ftp_uploader_process_file_node', 'ftp_uploader_process_file_handler');

/**
 * Process Device File Handler (alias for compatibility)
 */
function ftp_uploader_process_device_file_handler($log_id)
{
    // Use the same handler, it checks for device:// prefix
    ftp_uploader_process_file_handler($log_id);
}
add_action('ftp_uploader_process_device_file_node', 'ftp_uploader_process_device_file_handler');

/**
 * Handle Failure / Retry
 */
function ftp_uploader_handle_failure($log, $message)
{
    // Check retry count (Max 3)
    if ((int) $log->retry_count < 3) {
        ftp_uploader_increment_retry($log->id);
        ftp_uploader_update_log_status($log->id, 'retrying', $message . ' (Retrying...)');

        // Schedule retry (in 2 minutes)
        wp_schedule_single_event(time() + 120, 'ftp_uploader_process_file_node', array($log->id));
    } else {
        ftp_uploader_update_log_status($log->id, 'failed', $message);
    }
}
