<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Add Log
 */
function ftp_uploader_add_log($url, $remote_filename)
{
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $wpdb->insert(
        $table_name,
        array(
            'source_url' => $url,
            'remote_filename' => $remote_filename,
            'status' => 'pending',
            'created_at' => current_time('mysql'),
            'retry_count' => 0
        )
    );
    
    // Clear cache
    wp_cache_delete('ftp_uploader_logs');
    wp_cache_delete('ftp_uploader_active_count');
    
    return $wpdb->insert_id;
}

/**
 * Get Logs
 */
function ftp_uploader_get_logs()
{
    $cache_key = 'ftp_uploader_logs';
    $logs = wp_cache_get($cache_key);
    
    if (false === $logs) {
        global $wpdb;
        $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
        $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM " . esc_sql($table_name) . " ORDER BY created_at DESC LIMIT 50"));
        wp_cache_set($cache_key, $logs, '', 300); // Cache for 5 minutes
    }
    
    return $logs;
}

/**
 * Update Log Status
 */
function ftp_uploader_update_log_status($id, $status, $message = '')
{
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $wpdb->update(
        $table_name,
        array(
            'status' => $status,
            'message' => $message
        ),
        array('id' => $id)
    );
    
    // Clear cache
    wp_cache_delete('ftp_uploader_logs');
    wp_cache_delete('ftp_uploader_active_count');
}

/**
 * Increment Retry Count
 */
function ftp_uploader_increment_retry($id)
{
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $wpdb->query($wpdb->prepare("UPDATE " . esc_sql($table_name) . " SET retry_count = retry_count + 1 WHERE id = %d", $id));
    
    // Clear cache
    wp_cache_delete('ftp_uploader_logs');
    wp_cache_delete('ftp_uploader_active_count');
}

/**
 * Add Log for Device Upload
 */
function ftp_uploader_add_log_device($file_path, $remote_filename, $original_filename)
{
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    // Use special prefix to indicate device upload
    $source_url = 'device://' . $file_path;
    $wpdb->insert(
        $table_name,
        array(
            'source_url' => $source_url,
            'remote_filename' => $remote_filename,
            'status' => 'pending',
            'created_at' => current_time('mysql'),
            'retry_count' => 0
        )
    );
    
    // Clear cache
    wp_cache_delete('ftp_uploader_logs');
    wp_cache_delete('ftp_uploader_active_count');
    
    return $wpdb->insert_id;
}
