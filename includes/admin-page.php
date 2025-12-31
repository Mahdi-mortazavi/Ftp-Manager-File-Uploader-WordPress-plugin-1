<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Register Settings & Menu
 */
function ftp_uploader_register_settings()
{
    register_setting('ftp_uploader_options', 'ftp_uploader_settings', 'ftp_uploader_sanitize_settings');

    add_settings_section('ftp_uploader_section_developers', 'FTP Configuration', 'ftp_uploader_section_developers_cb', 'ftp_uploader');

    add_settings_field('ftp_host', 'FTP Host', 'ftp_uploader_field_host_cb', 'ftp_uploader', 'ftp_uploader_section_developers');
    add_settings_field('ftp_user', 'FTP Username', 'ftp_uploader_field_user_cb', 'ftp_uploader', 'ftp_uploader_section_developers');
    add_settings_field('ftp_pass', 'FTP Password', 'ftp_uploader_field_pass_cb', 'ftp_uploader', 'ftp_uploader_section_developers');
    add_settings_field('base_url', 'Base URL (for public links)', 'ftp_uploader_field_baseurl_cb', 'ftp_uploader', 'ftp_uploader_section_developers');
    add_settings_field('remote_path', 'Remote Folder Path', 'ftp_uploader_field_remotepath_cb', 'ftp_uploader', 'ftp_uploader_section_developers');
}
add_action('admin_init', 'ftp_uploader_register_settings');

function ftp_uploader_sanitize_settings($input)
{
    $new_input = array();
    $new_input['ftp_host'] = sanitize_text_field($input['ftp_host']);
    $new_input['ftp_user'] = sanitize_text_field($input['ftp_user']);

    // Handle Password Encryption
    if (!empty($input['ftp_pass'])) {
        // Did it change?
        $old_options = get_option('ftp_uploader_settings');
        $old_pass = isset($old_options['ftp_pass']) ? $old_options['ftp_pass'] : '';

        // If the user entered a new password (not the encrypted string shown in input), encrypt it
        // Or we can just always encrypt. But if we show placeholders it's safer.
        // Let's assume if it looks like our IV/Encrypted base64, we keep it, else encrypt.
        // But simpler: just always encrypt what comes in, BUT show empty in the field? 
        // Best UX: Show placeholder "********" and only update if not empty.

        // Wait, standard Settings API will autofill value.
        // Let's use a workaround: The input value in the form will be empty, if user types something, we encrypt it.
        // If empty, we keep the old one.
        // BUT register_setting callback gets the SUBMITTED array.

        // BETTER APPROACH: In the field callback, value is decrypted (or empty). 
        // No, we shouldn't show decrypted password.

        // Let's do:
        // 1. If input is empty, and we have an old pass, keep old pass.
        // 2. If input is not empty, encrypt it.
        // The issue is standard WP settings form sends the value.
    }

    // Actually, let's look at how I implemented the form field.
    // I can put `value=""` placeholder="Enter new password to change".
    // If user sends a value, encrypt it.

    // However, I need to check what $input['ftp_pass'] contains.
    // Let's make the field empty in the form.

    // For now, let's assume we encrypt whatever is passed, 
    // AND in the field display, we don't show the encrypted string.

    $new_input['base_url'] = esc_url_raw($input['base_url']);
    $new_input['remote_path'] = sanitize_text_field($input['remote_path']);

    // Password Logic
    if (!empty($input['ftp_pass'])) {
        $new_input['ftp_pass'] = ftp_uploader_encrypt($input['ftp_pass']);
    } else {
        // Keep old password if exists
        $old = get_option('ftp_uploader_settings');
        if (isset($old['ftp_pass'])) {
            $new_input['ftp_pass'] = $old['ftp_pass'];
        }
    }

    // --- FTP Connection Verification ---
    $test_host = $new_input['ftp_host'];
    $test_user = $new_input['ftp_user'];

    // Decrypt password for testing connection
    $test_pass = '';
    if (!empty($input['ftp_pass'])) {
        // User entered a new raw password
        $test_pass = $input['ftp_pass'];
    } elseif (isset($new_input['ftp_pass'])) {
        // Using existing encrypted password
        $test_pass = ftp_uploader_decrypt($new_input['ftp_pass']);
    }

    if (!empty($test_host) && !empty($test_user) && !empty($test_pass)) {
        $conn_id = @ftp_connect($test_host);
        if ($conn_id) {
            $login_result = @ftp_login($conn_id, $test_user, $test_pass);
            if ($login_result) {
                ftp_close($conn_id);
                // Connection successful, allow saving.
            } else {
                ftp_close($conn_id);
                add_settings_error('ftp_uploader_settings', 'ftp_login_failed', 'FTP Login Failed: Invalid username or password.', 'error');
                // Return old settings to avoid saving bad data, or just the old valid credentials?
                // Returning $old_options would be safest if available, but we might not have it loaded fully here.
                // Let's return the old options if possible.
                $old_options = get_option('ftp_uploader_settings');
                return $old_options;
            }
        } else {
            add_settings_error('ftp_uploader_settings', 'ftp_connect_failed', 'Could not connect to FTP Host.', 'error');
            $old_options = get_option('ftp_uploader_settings');
            return $old_options;
        }
    }

    return $new_input;
}

function ftp_uploader_section_developers_cb()
{
    echo '<p>Enter your FTP credentials.</p>';
}
function ftp_uploader_field_host_cb()
{
    $options = get_option('ftp_uploader_settings');
    echo '<input type="text" name="ftp_uploader_settings[ftp_host]" value="' . esc_attr(isset($options['ftp_host']) ? $options['ftp_host'] : '') . '" class="regular-text" required />';
}
function ftp_uploader_field_user_cb()
{
    $options = get_option('ftp_uploader_settings');
    echo '<input type="text" name="ftp_uploader_settings[ftp_user]" value="' . esc_attr(isset($options['ftp_user']) ? $options['ftp_user'] : '') . '" class="regular-text" required />';
}
function ftp_uploader_field_pass_cb()
{
    // Do NOT echo the password value.
    $options = get_option('ftp_uploader_settings');
    $placeholder = !empty($options['ftp_pass']) ? 'Password set (enter new to change)' : 'Enter Password';
    echo '<input type="password" name="ftp_uploader_settings[ftp_pass]" value="" placeholder="' . esc_attr($placeholder) . '" class="regular-text" />';
}
function ftp_uploader_field_baseurl_cb()
{
    $options = get_option('ftp_uploader_settings');
    echo '<input type="url" name="ftp_uploader_settings[base_url]" value="' . esc_attr(isset($options['base_url']) ? $options['base_url'] : '') . '" class="regular-text" placeholder="https://..." />';
}
function ftp_uploader_field_remotepath_cb()
{
    $options = get_option('ftp_uploader_settings');
    echo '<input type="text" name="ftp_uploader_settings[remote_path]" value="' . esc_attr(isset($options['remote_path']) ? $options['remote_path'] : '') . '" class="regular-text" placeholder="/" />';
}

function ftp_uploader_menu()
{
    add_menu_page('FTP Manager & Uploader', 'FTP Manager & Uploader', 'manage_options', 'ftp-uploader', 'ftp_uploader_options_page', 'dashicons-cloud-upload');
}
add_action('admin_menu', 'ftp_uploader_menu');

/**
 * Check if FTP connection is valid
 */
function ftp_uploader_check_connection()
{
    $options = get_option('ftp_uploader_settings');
    if (empty($options['ftp_host']) || empty($options['ftp_user']) || empty($options['ftp_pass'])) {
        return false;
    }

    $ftp_host = $options['ftp_host'];
    $ftp_user = $options['ftp_user'];
    $ftp_pass_encrypted = $options['ftp_pass'];
    $ftp_pass = ftp_uploader_decrypt($ftp_pass_encrypted);

    if (empty($ftp_pass)) {
        return false;
    }

    $conn_id = @ftp_connect($ftp_host);
    if (!$conn_id) {
        return false;
    }

    $login_result = @ftp_login($conn_id, $ftp_user, $ftp_pass);
    ftp_close($conn_id);

    return $login_result;
}

function ftp_uploader_options_page()
{
    if (!current_user_can('manage_options'))
        return;

    $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'upload-url';
    $options = get_option('ftp_uploader_settings');
    $is_configured = !empty($options['ftp_host']); // Simple check
    $is_logged_in = $is_configured && ftp_uploader_check_connection();
    $show_edit_form = isset($_GET['edit']) && $_GET['edit'] == '1';
    
    // If settings were just saved successfully and user is logged in, redirect to remove edit parameter
    if (isset($_GET['settings-updated']) && $_GET['settings-updated'] == 'true' && $is_logged_in && $show_edit_form) {
        wp_safe_redirect(admin_url('admin.php?page=ftp-uploader&tab=settings&settings-updated=true'));
        exit;
    }

    if (!$is_configured)
        $active_tab = 'settings';
    ?>
    <div class="wrap">
        <h1>FTP Manager & Uploader</h1>
        <h2 class="nav-tab-wrapper">
            <a href="?page=ftp-uploader&tab=upload-url"
                class="nav-tab <?php echo $active_tab == 'upload-url' ? 'nav-tab-active' : ''; ?>">Upload from URL</a>
            <a href="?page=ftp-uploader&tab=upload-device"
                class="nav-tab <?php echo $active_tab == 'upload-device' ? 'nav-tab-active' : ''; ?>">Upload from your device</a>
            <a href="?page=ftp-uploader&tab=file-manager"
                class="nav-tab <?php echo $active_tab == 'file-manager' ? 'nav-tab-active' : ''; ?>">File Manager</a>
            <a href="?page=ftp-uploader&tab=settings"
                class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
        </h2>
        <?php if ($active_tab == 'settings') {
            settings_errors('ftp_uploader_settings');
            
            // Show logged in badge and edit button if logged in and not editing
            if ($is_logged_in && !$show_edit_form) {
                ?>
                <div style="background: #fff; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0, 0, 0, .04); padding: 20px; margin-top: 20px; max-width: 800px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="display: inline-block; padding: 6px 12px; background: #00a32a; color: #fff; border-radius: 4px; font-weight: 600; font-size: 14px;">
                                <span class="dashicons dashicons-yes-alt" style="font-size: 16px; width: 16px; height: 16px; vertical-align: middle; margin-right: 5px;"></span>
                                Logged In
                            </span>
                        </div>
                        <a href="?page=ftp-uploader&tab=settings&edit=1" class="button button-primary">
                            <span class="dashicons dashicons-edit" style="font-size: 16px; width: 16px; height: 16px; vertical-align: middle; margin-right: 5px;"></span>
                            Edit
                        </a>
                    </div>
                    <p style="color: #646970; margin: 0;">Your FTP credentials are configured and verified. Click "Edit" to modify your settings.</p>
                </div>
                <?php
            } else {
                // Show edit button if logged in but in edit mode
                if ($is_logged_in && $show_edit_form) {
                    ?>
                    <div style="margin-bottom: 15px;">
                        <a href="?page=ftp-uploader&tab=settings" class="button">
                            <span class="dashicons dashicons-arrow-left-alt" style="font-size: 16px; width: 16px; height: 16px; vertical-align: middle; margin-right: 5px;"></span>
                            Cancel Edit
                        </a>
                    </div>
                    <?php
                }
                ?>
                <form action="options.php" method="post" id="ftp-settings-form">
                    <?php settings_fields('ftp_uploader_options');
                    do_settings_sections('ftp_uploader');
                    submit_button('Save Settings'); ?>
                </form>
                <?php
            }
        } else {
            if (!$is_configured) {
                echo '<div class="notice notice-warning"><p>Please configure settings first.</p></div>';
            } else {
                if ($active_tab == 'upload-url') {
                    do_action('ftp_uploader_render_upload_page');
                } elseif ($active_tab == 'upload-device') {
                    do_action('ftp_uploader_render_device_upload_page');
                } elseif ($active_tab == 'file-manager') {
                    do_action('ftp_uploader_render_file_manager_page');
                }
            }
        } ?>
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccd0d4; text-align: center; color: #646970; font-size: 13px;">
            made with 🧠🩸❤️ by <a href="https://t.me/ageek" target="_blank" style="text-decoration: none; color: #2271b1;">Aref</a> & mahdi
        </div>
    </div>
    <?php
}

/**
 * Handle Upload Form Submission (from URL)
 */
function ftp_uploader_handle_upload_submission()
{
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    // Verify nonce
    if (!isset($_POST['ftp_uploader_nonce']) || !wp_verify_nonce($_POST['ftp_uploader_nonce'], 'ftp_uploader_upload')) {
        wp_die('Security check failed');
    }

    if (!isset($_POST['file_url']) || empty($_POST['file_url'])) {
        add_settings_error('ftp_uploader_upload', 'no_url', 'Please provide a file URL.', 'error');
        return;
    }

    $file_url = esc_url_raw($_POST['file_url']);
    
    // Validate URL
    if (!filter_var($file_url, FILTER_VALIDATE_URL)) {
        add_settings_error('ftp_uploader_upload', 'invalid_url', 'Invalid URL provided.', 'error');
        return;
    }

    // Use custom filename if provided, otherwise generate from URL
    if (!empty($_POST['remote_filename'])) {
        $remote_filename = sanitize_file_name($_POST['remote_filename']);
    } else {
        $remote_filename = basename(wp_parse_url($file_url, PHP_URL_PATH));
        if (empty($remote_filename)) {
            $remote_filename = 'file_' . time() . '.zip';
        }
    }

    // Get selected folder path
    $upload_folder = isset($_POST['upload_folder']) ? sanitize_text_field($_POST['upload_folder']) : '';
    
    // If folder is selected, prepend it to the filename
    if (!empty($upload_folder)) {
        $upload_folder = trim($upload_folder, '/');
        $remote_filename = $upload_folder . '/' . $remote_filename;
    }

    // Add to queue
    $log_id = ftp_uploader_add_log($file_url, $remote_filename);

    if ($log_id) {
        // Schedule immediate processing (WordPress cron)
        wp_schedule_single_event(time(), 'ftp_uploader_process_file_node', array($log_id));
        
        // Trigger cron safely via HTTP request (non-blocking)
        ftp_uploader_trigger_cron_safe();
        
        // Redirect to show success message
        wp_safe_redirect(add_query_arg(array('uploaded' => '1'), admin_url('admin.php?page=ftp-uploader&tab=upload-url')));
        exit;
    } else {
        // Redirect to show error message
        wp_safe_redirect(add_query_arg(array('error' => urlencode('Failed to add file to queue.')), admin_url('admin.php?page=ftp-uploader&tab=upload-url')));
        exit;
    }
}

/**
 * Handle Device Upload Form Submission
 */
function ftp_uploader_handle_device_upload_submission()
{
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    // Verify nonce
    if (!isset($_POST['ftp_uploader_device_nonce']) || !wp_verify_nonce($_POST['ftp_uploader_device_nonce'], 'ftp_uploader_device_upload')) {
        wp_die('Security check failed');
    }

    if (!isset($_FILES['file_upload']) || $_FILES['file_upload']['error'] !== UPLOAD_ERR_OK) {
        $error_msg = 'Please select a file to upload.';
        if (isset($_FILES['file_upload']['error']) && $_FILES['file_upload']['error'] !== UPLOAD_ERR_OK) {
            switch ($_FILES['file_upload']['error']) {
                case UPLOAD_ERR_INI_SIZE:
                case UPLOAD_ERR_FORM_SIZE:
                    $error_msg = 'File is too large.';
                    break;
                case UPLOAD_ERR_PARTIAL:
                    $error_msg = 'File was only partially uploaded.';
                    break;
                case UPLOAD_ERR_NO_FILE:
                    $error_msg = 'No file was uploaded.';
                    break;
                default:
                    $error_msg = 'Upload error occurred.';
            }
        }
        wp_safe_redirect(add_query_arg(array('error' => urlencode($error_msg)), admin_url('admin.php?page=ftp-uploader&tab=upload-device')));
        exit;
    }

    $uploaded_file = $_FILES['file_upload'];
    $tmp_file = $uploaded_file['tmp_name'];
    $original_filename = sanitize_file_name($uploaded_file['name']);
    
    // Use custom filename if provided, otherwise use original
    $remote_filename = !empty($_POST['remote_filename']) ? sanitize_file_name($_POST['remote_filename']) : $original_filename;
    
    if (empty($remote_filename)) {
        $remote_filename = 'file_' . time() . '.zip';
    }

    // Get selected folder path
    $upload_folder = isset($_POST['upload_folder']) ? sanitize_text_field($_POST['upload_folder']) : '';
    
    // If folder is selected, prepend it to the filename
    if (!empty($upload_folder)) {
        $upload_folder = trim($upload_folder, '/');
        $remote_filename = $upload_folder . '/' . $remote_filename;
    }

    // Move uploaded file to WordPress uploads directory for processing
    if (!function_exists('wp_upload_dir')) {
        require_once(ABSPATH . 'wp-admin/includes/file.php');
    }
    
    $upload_dir = wp_upload_dir();
    $ftp_upload_dir = $upload_dir['basedir'] . '/ftp-uploader-queue';
    
    // Create directory if it doesn't exist
    if (!file_exists($ftp_upload_dir)) {
        wp_mkdir_p($ftp_upload_dir);
    }
    
    // Generate unique filename for queue
    $queue_filename = 'device_' . time() . '_' . wp_generate_password(8, false) . '_' . $original_filename;
    $queue_file_path = $ftp_upload_dir . '/' . $queue_filename;
    
    // Copy file to queue directory
    if (!copy($tmp_file, $queue_file_path)) {
        wp_safe_redirect(add_query_arg(array('error' => urlencode('Failed to save uploaded file.')), admin_url('admin.php?page=ftp-uploader&tab=upload-device')));
        exit;
    }
    
    // Remove temporary uploaded file
    wp_delete_file($tmp_file);

    // Add to queue with special marker for device upload
    $log_id = ftp_uploader_add_log_device($queue_file_path, $remote_filename, $original_filename);

    if ($log_id) {
        // Schedule immediate processing (WordPress cron)
        wp_schedule_single_event(time(), 'ftp_uploader_process_device_file_node', array($log_id));
        
        // Trigger cron safely via HTTP request (non-blocking)
        ftp_uploader_trigger_cron_safe();
        
        // Redirect to show success message
        wp_safe_redirect(add_query_arg(array('uploaded' => '1'), admin_url('admin.php?page=ftp-uploader&tab=upload-device')));
        exit;
    } else {
        // Redirect to show error message
        wp_safe_redirect(add_query_arg(array('error' => urlencode('Failed to add file to queue.')), admin_url('admin.php?page=ftp-uploader&tab=upload-device')));
        exit;
    }
}

/**
 * AJAX Handler to get Logs
 */
function ftp_uploader_ajax_get_logs()
{
    if (!current_user_can('manage_options'))
        wp_die();
    
    // Verify nonce
    check_ajax_referer('ftp_uploader_upload', 'nonce');

    $logs = ftp_uploader_get_logs();
    $settings = get_option('ftp_uploader_settings');
    $base_url = isset($settings['base_url']) ? trailingslashit($settings['base_url']) : '';

    if ($logs) {
        foreach ($logs as $log) {
            $link = '';
            $link_display = '';
            if ($log->status === 'success' && $base_url) {
                $full_link = $base_url . $log->remote_filename;
                $link_display = '<div style="margin-bottom: 8px;"><a href="' . esc_url($full_link) . '" target="_blank" style="word-break: break-all; color: #2271b1; text-decoration: none;" title="Right-click to copy link">' . esc_html($full_link) . '</a></div>';
                $link = '<button type="button" class="button copy-link-btn" data-link="' . esc_attr($full_link) . '"><span class="dashicons dashicons-admin-links"></span> Copy Link</button>';
            }
            echo '<tr>';
            echo '<td>' . esc_html($log->id) . '</td>';
            // Check if this is a device upload
            $is_device_upload = (strpos($log->source_url, 'device://') === 0);
            if ($is_device_upload) {
                $file_path = substr($log->source_url, 9);
                $display_name = basename($file_path);
                // Remove the device_ prefix and timestamp for cleaner display
                $display_name = preg_replace('/^device_\d+_[a-zA-Z0-9]+_/', '', $display_name);
                echo '<td><span class="file-link" title="' . esc_attr($display_name) . '">' . esc_html($display_name) . '</span> <span style="color: #666; font-size: 11px;">(from device)</span></td>';
            } else {
                echo '<td><a href="' . esc_url($log->source_url) . '" target="_blank" class="file-link" title="' . esc_attr($log->source_url) . '">' . esc_html(basename($log->source_url)) . '</a></td>';
            }
            echo '<td>' . esc_html($log->remote_filename) . '</td>';
            echo '<td>';
            if ($log->status == 'pending')
                echo '<span class="status-pill status-pending"><span class="dashicons dashicons-clock"></span> Pending</span>';
            elseif ($log->status == 'uploading')
                echo '<span class="status-pill status-uploading"><span class="dashicons dashicons-update"></span> Uploading...</span>';
            elseif ($log->status == 'retrying')
                echo '<span class="status-pill status-retrying"><span class="dashicons dashicons-update"></span> Retrying</span>' . (!empty($log->message) ? '<div class="error-message">' . esc_html($log->message) . '</div>' : '');
            elseif ($log->status == 'success')
                echo '<span class="status-pill status-success"><span class="dashicons dashicons-yes-alt"></span> Success</span>';
            else
                echo '<span class="status-pill status-failed"><span class="dashicons dashicons-warning"></span> Failed</span>' . (!empty($log->message) ? '<div class="error-message">' . esc_html($log->message) . '</div>' : '');
            echo '</td>';
            echo '<td>' . wp_kses_post($link_display . $link) . '</td>';
            echo '</tr>';
        }
    } else {
        echo '<tr><td colspan="5">No uploads yet.</td></tr>';
    }
    wp_die();
}
add_action('wp_ajax_ftp_uploader_get_logs', 'ftp_uploader_ajax_get_logs');

/**
 * Safely trigger WordPress cron via HTTP request
 */
function ftp_uploader_trigger_cron_safe()
{
    // Only trigger if WP_CRON is not disabled
    if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
        return;
    }
    
    // Get the cron URL
    $cron_url = site_url('wp-cron.php');
    
    // Trigger cron via non-blocking HTTP request
    $args = array(
        'timeout' => 0.01,
        'blocking' => false,
        'sslverify' => apply_filters('https_local_ssl_verify', false),
    );
    
    wp_remote_post($cron_url, $args);
}

/**
 * AJAX Handler to trigger cron manually
 */
function ftp_uploader_ajax_trigger_cron()
{
    if (!current_user_can('manage_options'))
        wp_die();
    
    // Verify nonce
    check_ajax_referer('ftp_uploader_upload', 'nonce');

    // Process pending files immediately
    global $wpdb;
    $table_name = $wpdb->prefix . FTP_UPLOADER_TABLE;
    $pending_files = $wpdb->get_results("SELECT id, source_url FROM " . esc_sql($table_name) . " WHERE status IN ('pending', 'retrying') ORDER BY created_at ASC LIMIT 5");
    
    foreach ($pending_files as $file) {
        // Check if device upload or URL upload
        $is_device_upload = (strpos($file->source_url, 'device://') === 0);
        $action = $is_device_upload ? 'ftp_uploader_process_device_file_node' : 'ftp_uploader_process_file_node';
        // Schedule immediate processing
        wp_schedule_single_event(time(), $action, array($file->id));
    }
    
    // Trigger cron safely
    ftp_uploader_trigger_cron_safe();
    
    // Also process one file directly if possible (for immediate feedback)
    if (!empty($pending_files)) {
        $first_file = reset($pending_files);
        // Check if device upload or URL upload
        $is_device_upload = (strpos($first_file->source_url, 'device://') === 0);
        $action = $is_device_upload ? 'ftp_uploader_process_device_file_node' : 'ftp_uploader_process_file_node';
        // Process directly in background
        do_action($action, $first_file->id);
    }
    
    wp_send_json_success(array('message' => 'Queue processing triggered'));
}
add_action('wp_ajax_ftp_uploader_trigger_cron', 'ftp_uploader_ajax_trigger_cron');


/**
 * Render Upload Page Callback
 */
function ftp_uploader_render_upload_page_cb()
{
    ?>
    <style>
        .ftp-card {
            background: #fff;
            border: 1px solid #ccd0d4;
            box-shadow: 0 1px 1px rgba(0, 0, 0, .04);
            padding: 20px;
            margin-top: 20px;
            max-width: 800px;
        }

        .status-pill {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 500;
            font-size: 12px;
        }

        .status-pending {
            background: #f0f0f1;
            color: #50575e;
        }

        .status-success {
            background: #d4edda;
            color: #155724;
        }

        .status-failed {
            background: #f8d7da;
            color: #721c24;
            cursor: help;
        }

        .status-retrying {
            background: #fff3cd;
            color: #856404;
        }

        .status-uploading {
            background: #fff3cd;
            color: #856404;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .error-message {
            color: #d63638;
            display: block;
            font-size: 11px;
            margin-top: 5px;
            padding: 4px 8px;
            background: #f8d7da;
            border-radius: 4px;
            border-left: 3px solid #d63638;
        }

        .file-link {
            text-decoration: none;
            font-weight: 500;
        }

        .dashicons {
            font-size: 16px;
            width: 16px;
            height: 16px;
            vertical-align: middle;
            margin-right: 3px;
        }

        /* Toast */
        #ftp-toast {
            visibility: hidden;
            min-width: 250px;
            margin-left: -125px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 4px;
            padding: 16px;
            position: fixed;
            z-index: 1000;
            left: 50%;
            bottom: 30px;
            font-size: 14px;
        }

        #ftp-toast.show {
            visibility: visible;
            -webkit-animation: fadein 0.5s, fadeout 0.5s 2.5s;
            animation: fadein 0.5s, fadeout 0.5s 2.5s;
        }

        @-webkit-keyframes fadein {
            from {
                bottom: 0;
                opacity: 0;
            }

            to {
                bottom: 30px;
                opacity: 1;
            }
        }

        @keyframes fadein {
            from {
                bottom: 0;
                opacity: 0;
            }

            to {
                bottom: 30px;
                opacity: 1;
            }
        }

        @-webkit-keyframes fadeout {
            from {
                bottom: 30px;
                opacity: 1;
            }

            to {
                bottom: 0;
                opacity: 0;
            }
        }

        @keyframes fadeout {
            from {
                bottom: 30px;
                opacity: 1;
            }

            to {
                bottom: 0;
                opacity: 0;
            }
        }
    </style>

    <div class="ftp-card">
        <h2><span class="dashicons dashicons-upload"></span> Upload New File</h2>
        <?php
        // Show form submission messages
        if (isset($_GET['uploaded']) && $_GET['uploaded'] == '1') {
            echo '<div class="notice notice-success is-dismissible"><p>File added to upload queue successfully!</p></div>';
        }
        if (isset($_GET['error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html(urldecode($_GET['error'])) . '</p></div>';
        }
        ?>
        <form method="post" action="">
            <?php wp_nonce_field('ftp_uploader_upload', 'ftp_uploader_nonce'); ?>
            <input type="hidden" name="ftp_uploader_action" value="upload_file">
            <p>
                <label for="file_url" style="font-weight: 600; display: block; margin-bottom: 5px;">File Direct Link
                    URL:</label>
                <input type="url" name="file_url" id="file_url" class="large-text"
                    placeholder="https://example.com/archive.zip" required style="padding: 10px;">
            <p class="description">Enter the direct URL to the file you want to upload to your FTP server.</p>
            </p>
            <p style="margin-top: 15px;">
                <label for="remote_filename" style="font-weight: 600; display: block; margin-bottom: 5px;">Remote Filename (optional):</label>
                <input type="text" name="remote_filename" id="remote_filename" class="regular-text" placeholder="Leave empty to use original filename">
            <p class="description">Customize the filename on the FTP server. If left empty, the original filename will be used.</p>
            </p>
            <p style="margin-top: 15px;">
                <label for="upload_folder" style="font-weight: 600; display: block; margin-bottom: 5px;">Select Folder (optional):</label>
                <select name="upload_folder" id="upload_folder" class="regular-text" style="padding: 8px;">
                    <option value="">Loading folders...</option>
                </select>
            <p class="description">Select a folder to upload the file to. If not selected, the file will be uploaded to the root directory.</p>
            </p>
            <p style="margin-top: 15px;">
                <input type="submit" class="button button-primary button-hero" value="Start Background Upload">
            </p>
        </form>
        <p class="description" style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffb900; color: #856404;">
            <strong>Note:</strong> Files are uploaded in the background using WordPress cron. Processing starts automatically when your site receives traffic, or you can use the "Process Queue Now" button for immediate processing.
        </p>
    </div>

    <script>
        // Load folders into dropdown for upload-url page
        jQuery(document).ready(function ($) {
            if ($('#upload_folder').length > 0) {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_get_folders',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function (response) {
                        var $select = $('#upload_folder');
                        $select.empty();
                        
                        if (response.success && response.data.folders) {
                            $.each(response.data.folders, function(index, folder) {
                                $select.append($('<option>', {
                                    value: folder.path,
                                    text: folder.display
                                }));
                            });
                        } else {
                            $select.append($('<option>', {
                                value: '',
                                text: 'Root (Default)'
                            }));
                        }
                    },
                    error: function(xhr, status, error) {
                        var $select = $('#upload_folder');
                        $select.empty();
                        $select.append($('<option>', {
                            value: '',
                            text: 'Root (Default)'
                        }));
                    }
                });
            }
        });
    </script>

    <div style="margin-top: 30px; max-width: 1000px;">
        <h3>
            Upload History
            <span id="ftp-loading-indicator"
                style="display:none; margin-left:10px; font-size:12px; font-weight:normal; color:#666;">
                <span class="dashicons dashicons-update" style="animation: spin 2s linear infinite;"></span> Updating...
            </span>
            <button type="button" class="button" id="trigger-cron" style="float: right; font-size: 12px; margin-top: -5px;">
                <span class="dashicons dashicons-controls-play"></span> Process Queue Now
            </button>
        </h3>
        <?php
        // Show active uploads count
        $active_count = ftp_uploader_get_active_count();
        if ($active_count > 0) {
            echo '<p style="color: #856404; margin-top: 10px;"><span class="dashicons dashicons-info"></span> ' . esc_html($active_count) . ' file(s) currently in queue or uploading.</p>';
        }
        ?>
        <style>
            @keyframes spin {
                100% {
                    -webkit-transform: rotate(360deg);
                    transform: rotate(360deg);
                }
            }
        </style>

        <table class="wp-list-table widefat fixed striped" id="ftp-history-table"
            style="box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <thead>
                <tr>
                    <th style="width: 50px;">ID</th>
                    <th>Source File</th>
                    <th>Remote Filename</th>
                    <th style="width: 200px;">Status</th>
                    <th style="width: 120px;">Action</th>
                </tr>
            </thead>
            <tbody id="ftp-history-body">
                <tr>
                    <td colspan="5" style="padding: 20px; text-align: center; color: #666;">Loading logs...</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div id="ftp-toast">Link Copied to Clipboard!</div>

    <!-- Debug Log Section -->
    <div class="ftp-card" id="ftp-debug-log" style="margin-top: 30px; max-width: 1000px;">
        <h3>
            <span class="dashicons dashicons-code-standards"></span> Debug Log
            <button type="button" class="button" id="toggle-log" style="float: right; font-size: 12px;">
                <span class="dashicons dashicons-arrow-up-alt2"></span> Hide
            </button>
        </h3>
        <div id="log-content" style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; max-height: 300px; overflow-y: auto; margin-top: 10px;">
            <div id="log-entries"></div>
        </div>
        <p style="margin-top: 10px;">
            <button type="button" class="button" id="clear-log">Clear Log</button>
            <span style="color: #666; font-size: 12px; margin-left: 10px;">This log helps debug upload issues during development.</span>
        </p>
    </div>

    <script>
        jQuery(document).ready(function ($) {

            // Track previous states to avoid duplicate log entries
            var previousStates = {};

            function fetchLogs() {
                $('#ftp-loading-indicator').show();
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_get_logs',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function (response) {
                        var $oldBody = $('#ftp-history-body');
                        var oldContent = $oldBody.html();
                        $oldBody.html(response);
                        $('#ftp-loading-indicator').fadeOut();
                        
                        // Check for status changes and log them
                        $(response).find('tr').each(function() {
                            var $row = $(this);
                            var id = $row.find('td:first').text().trim();
                            var status = $row.find('.status-pill').text().trim();
                            var filename = $row.find('.file-link').text().trim() || $row.find('td:nth-child(2)').text().trim();
                            
                            if (!id || id === 'No uploads yet.') return;
                            
                            var currentState = status;
                            var previousState = previousStates[id];
                            
                            // Only log if state changed
                            if (previousState !== currentState) {
                                previousStates[id] = currentState;
                                
                                if (status.indexOf('Failed') !== -1) {
                                    var errorMsg = $row.find('.error-message').text().trim();
                                    addLogEntry('Upload failed: ' + filename + (errorMsg ? ' - ' + errorMsg : ''), 'error');
                                } else if (status.indexOf('Success') !== -1) {
                                    addLogEntry('Upload successful: ' + filename, 'success');
                                } else if (status.indexOf('Uploading') !== -1) {
                                    addLogEntry('Upload started: ' + filename, 'warning');
                                } else if (status.indexOf('Retrying') !== -1) {
                                    var retryMsg = $row.find('.error-message').text().trim();
                                    addLogEntry('Retrying upload: ' + filename + (retryMsg ? ' - ' + retryMsg : ''), 'warning');
                                } else if (status.indexOf('Pending') !== -1 && previousState) {
                                    addLogEntry('Upload queued: ' + filename, 'info');
                                }
                            }
                        });
                    },
                    error: function (xhr, status, error) {
                        $('#ftp-loading-indicator').hide();
                        addLogEntry('Error fetching logs: ' + error, 'error');
                    }
                });
            }

            // Initial fetch
            fetchLogs();

            // Polling every 5 seconds
            setInterval(fetchLogs, 5000);

            // Copy Link with fallback method
            function copyToClipboard(text) {
                // Try modern clipboard API first
                if (navigator.clipboard && window.isSecureContext) {
                    return navigator.clipboard.writeText(text).then(function () {
                        return true;
                    }).catch(function (err) {
                        console.error('Clipboard API failed:', err);
                        return fallbackCopyToClipboard(text);
                    });
                } else {
                    // Use fallback method
                    return fallbackCopyToClipboard(text);
                }
            }

            function fallbackCopyToClipboard(text) {
                return new Promise(function (resolve, reject) {
                    var textArea = document.createElement("textarea");
                    textArea.value = text;
                    textArea.style.position = "fixed";
                    textArea.style.left = "-999999px";
                    textArea.style.top = "-999999px";
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    
                    try {
                        var successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        if (successful) {
                            resolve(true);
                        } else {
                            reject(new Error('Fallback copy command failed'));
                        }
                    } catch (err) {
                        document.body.removeChild(textArea);
                        reject(err);
                    }
                });
            }

            $(document).on('click', '.copy-link-btn', function (e) {
                e.preventDefault();
                var $btn = $(this);
                var link = $btn.data('link');
                
                if (!link) {
                    console.error('No link data found');
                    return;
                }

                // Disable button temporarily to prevent double-clicks
                $btn.prop('disabled', true);
                
                copyToClipboard(link).then(function () {
                    // Show success toast
                    var x = document.getElementById("ftp-toast");
                    x.className = "show";
                    setTimeout(function () { 
                        x.className = x.className.replace("show", ""); 
                    }, 3000);
                    
                    // Re-enable button
                    $btn.prop('disabled', false);
                }).catch(function (err) {
                    console.error('Failed to copy:', err);
                    alert('Failed to copy link. Please right-click on the link and select "Copy link address".');
                    $btn.prop('disabled', false);
                });
            });

            // Debug Log Functions
            function addLogEntry(message, type) {
                type = type || 'info';
                var timestamp = new Date().toLocaleTimeString();
                var icon = 'info';
                var color = '#d4d4d4';
                
                if (type === 'error') {
                    icon = 'warning';
                    color = '#f48771';
                } else if (type === 'success') {
                    icon = 'yes-alt';
                    color = '#4ec9b0';
                } else if (type === 'warning') {
                    icon = 'warning';
                    color = '#dcdcaa';
                }
                
                var entry = '<div style="margin-bottom: 5px; color: ' + color + ';">' +
                    '<span style="color: #858585;">[' + timestamp + ']</span> ' +
                    '<span class="dashicons dashicons-' + icon + '" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span> ' +
                    escapeHtml(message) +
                    '</div>';
                
                $('#log-entries').append(entry);
                var logContent = document.getElementById('log-content');
                logContent.scrollTop = logContent.scrollHeight;
            }

            function escapeHtml(text) {
                var map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, function(m) { return map[m]; });
            }

            // Toggle log visibility
            $('#toggle-log').on('click', function() {
                var $content = $('#log-content');
                var $btn = $(this);
                if ($content.is(':visible')) {
                    $content.slideUp();
                    $btn.html('<span class="dashicons dashicons-arrow-down-alt2"></span> Show');
                } else {
                    $content.slideDown();
                    $btn.html('<span class="dashicons dashicons-arrow-up-alt2"></span> Hide');
                }
            });

            // Clear log
            $('#clear-log').on('click', function() {
                $('#log-entries').empty();
                addLogEntry('Log cleared', 'info');
            });

            // Trigger cron manually
            $('#trigger-cron').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true).html('<span class="dashicons dashicons-update" style="animation: spin 1s linear infinite;"></span> Processing...');
                addLogEntry('Manually triggering queue processing...', 'info');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_trigger_cron',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function(response) {
                        addLogEntry('Queue processing triggered', 'success');
                        setTimeout(function() {
                            $btn.prop('disabled', false).html('<span class="dashicons dashicons-controls-play"></span> Process Queue Now');
                        }, 2000);
                    },
                    error: function() {
                        addLogEntry('Failed to trigger queue processing', 'error');
                        $btn.prop('disabled', false).html('<span class="dashicons dashicons-controls-play"></span> Process Queue Now');
                    }
                });
            });

            // Initial log entry
            addLogEntry('FTP Uploader initialized', 'info');
            addLogEntry('Polling logs every 5 seconds...', 'info');
            addLogEntry('Note: WordPress cron processes uploads when the site receives traffic. Use "Process Queue Now" for immediate processing.', 'info');
        });
    </script>
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccd0d4; text-align: center; color: #646970; font-size: 13px;">
        made with 🧠🩸❤️ by <a href="https://t.me/ageek" target="_blank" style="text-decoration: none; color: #2271b1;">Aref</a> & mahdi
    </div>
    <?php
}
add_action('ftp_uploader_render_upload_page', 'ftp_uploader_render_upload_page_cb');

/**
 * Render Device Upload Page Callback
 */
function ftp_uploader_render_device_upload_page_cb()
{
    ?>
    <style>
        .ftp-card {
            background: #fff;
            border: 1px solid #ccd0d4;
            box-shadow: 0 1px 1px rgba(0, 0, 0, .04);
            padding: 20px;
            margin-top: 20px;
            max-width: 800px;
        }

        .status-pill {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-weight: 500;
            font-size: 12px;
        }

        .status-pending {
            background: #f0f0f1;
            color: #50575e;
        }

        .status-success {
            background: #d4edda;
            color: #155724;
        }

        .status-failed {
            background: #f8d7da;
            color: #721c24;
            cursor: help;
        }

        .status-retrying {
            background: #fff3cd;
            color: #856404;
        }

        .status-uploading {
            background: #fff3cd;
            color: #856404;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .error-message {
            color: #d63638;
            display: block;
            font-size: 11px;
            margin-top: 5px;
            padding: 4px 8px;
            background: #f8d7da;
            border-radius: 4px;
            border-left: 3px solid #d63638;
        }

        .file-link {
            text-decoration: none;
            font-weight: 500;
        }

        .dashicons {
            font-size: 16px;
            width: 16px;
            height: 16px;
            vertical-align: middle;
            margin-right: 3px;
        }

        /* Toast */
        #ftp-toast {
            visibility: hidden;
            min-width: 250px;
            margin-left: -125px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 4px;
            padding: 16px;
            position: fixed;
            z-index: 1000;
            left: 50%;
            bottom: 30px;
            font-size: 14px;
        }

        #ftp-toast.show {
            visibility: visible;
            -webkit-animation: fadein 0.5s, fadeout 0.5s 2.5s;
            animation: fadein 0.5s, fadeout 0.5s 2.5s;
        }

        @-webkit-keyframes fadein {
            from {
                bottom: 0;
                opacity: 0;
            }

            to {
                bottom: 30px;
                opacity: 1;
            }
        }

        @keyframes fadein {
            from {
                bottom: 0;
                opacity: 0;
            }

            to {
                bottom: 30px;
                opacity: 1;
            }
        }

        @-webkit-keyframes fadeout {
            from {
                bottom: 30px;
                opacity: 1;
            }

            to {
                bottom: 0;
                opacity: 0;
            }
        }

        @keyframes fadeout {
            from {
                bottom: 30px;
                opacity: 1;
            }

            to {
                bottom: 0;
                opacity: 0;
            }
        }
    </style>

    <div class="ftp-card">
        <h2><span class="dashicons dashicons-upload"></span> Upload from your device</h2>
        <?php
        // Show form submission messages
        if (isset($_GET['uploaded']) && $_GET['uploaded'] == '1') {
            echo '<div class="notice notice-success is-dismissible"><p>File added to upload queue successfully!</p></div>';
        }
        if (isset($_GET['error'])) {
            echo '<div class="notice notice-error is-dismissible"><p>' . esc_html(urldecode($_GET['error'])) . '</p></div>';
        }
        ?>
        <form method="post" action="" enctype="multipart/form-data">
            <?php wp_nonce_field('ftp_uploader_device_upload', 'ftp_uploader_device_nonce'); ?>
            <input type="hidden" name="ftp_uploader_action" value="upload_device_file">
            <p>
                <label for="file_upload" style="font-weight: 600; display: block; margin-bottom: 5px;">Select File:</label>
                <input type="file" name="file_upload" id="file_upload" required style="padding: 10px;">
            <p class="description">Select a file from your device to upload to your FTP server.</p>
            </p>
            <p style="margin-top: 15px;">
                <label for="remote_filename" style="font-weight: 600; display: block; margin-bottom: 5px;">Remote Filename (optional):</label>
                <input type="text" name="remote_filename" id="remote_filename_device" class="regular-text" placeholder="Leave empty to use original filename">
            <p class="description">Customize the filename on the FTP server. If left empty, the original filename will be used.</p>
            </p>
            <p style="margin-top: 15px;">
                <label for="upload_folder_device" style="font-weight: 600; display: block; margin-bottom: 5px;">Select Folder (optional):</label>
                <select name="upload_folder" id="upload_folder_device" class="regular-text" style="padding: 8px;">
                    <option value="">Loading folders...</option>
                </select>
            <p class="description">Select a folder to upload the file to. If not selected, the file will be uploaded to the root directory.</p>
            </p>
            <p style="margin-top: 15px;">
                <input type="submit" class="button button-primary button-hero" value="Start Background Upload">
            </p>
        </form>
        <p class="description" style="margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffb900; color: #856404;">
            <strong>Note:</strong> Files are uploaded in the background using WordPress cron. Processing starts automatically when your site receives traffic, or you can use the "Process Queue Now" button for immediate processing.
        </p>
    </div>

    <script>
        // Load folders into dropdown for upload-device page
        jQuery(document).ready(function ($) {
            if ($('#upload_folder_device').length > 0) {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_get_folders',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function (response) {
                        var $select = $('#upload_folder_device');
                        $select.empty();
                        
                        if (response.success && response.data.folders) {
                            $.each(response.data.folders, function(index, folder) {
                                $select.append($('<option>', {
                                    value: folder.path,
                                    text: folder.display
                                }));
                            });
                        } else {
                            $select.append($('<option>', {
                                value: '',
                                text: 'Root (Default)'
                            }));
                        }
                    },
                    error: function(xhr, status, error) {
                        var $select = $('#upload_folder_device');
                        $select.empty();
                        $select.append($('<option>', {
                            value: '',
                            text: 'Root (Default)'
                        }));
                    }
                });
            }
        });
    </script>

    <div style="margin-top: 30px; max-width: 1000px;">
        <h3>
            Upload History
            <span id="ftp-loading-indicator"
                style="display:none; margin-left:10px; font-size:12px; font-weight:normal; color:#666;">
                <span class="dashicons dashicons-update" style="animation: spin 2s linear infinite;"></span> Updating...
            </span>
            <button type="button" class="button" id="trigger-cron" style="float: right; font-size: 12px; margin-top: -5px;">
                <span class="dashicons dashicons-controls-play"></span> Process Queue Now
            </button>
        </h3>
        <?php
        // Show active uploads count
        $active_count = ftp_uploader_get_active_count();
        if ($active_count > 0) {
            echo '<p style="color: #856404; margin-top: 10px;"><span class="dashicons dashicons-info"></span> ' . esc_html($active_count) . ' file(s) currently in queue or uploading.</p>';
        }
        ?>
        <style>
            @keyframes spin {
                100% {
                    -webkit-transform: rotate(360deg);
                    transform: rotate(360deg);
                }
            }
        </style>

        <table class="wp-list-table widefat fixed striped" id="ftp-history-table"
            style="box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <thead>
                <tr>
                    <th style="width: 50px;">ID</th>
                    <th>Source File</th>
                    <th>Remote Filename</th>
                    <th style="width: 200px;">Status</th>
                    <th style="width: 120px;">Action</th>
                </tr>
            </thead>
            <tbody id="ftp-history-body">
                <tr>
                    <td colspan="5" style="padding: 20px; text-align: center; color: #666;">Loading logs...</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div id="ftp-toast">Link Copied to Clipboard!</div>

    <!-- Debug Log Section -->
    <div class="ftp-card" id="ftp-debug-log" style="margin-top: 30px; max-width: 1000px;">
        <h3>
            <span class="dashicons dashicons-code-standards"></span> Debug Log
            <button type="button" class="button" id="toggle-log" style="float: right; font-size: 12px;">
                <span class="dashicons dashicons-arrow-up-alt2"></span> Hide
            </button>
        </h3>
        <div id="log-content" style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; max-height: 300px; overflow-y: auto; margin-top: 10px;">
            <div id="log-entries"></div>
        </div>
        <p style="margin-top: 10px;">
            <button type="button" class="button" id="clear-log">Clear Log</button>
            <span style="color: #666; font-size: 12px; margin-left: 10px;">This log helps debug upload issues during development.</span>
        </p>
    </div>

    <script>
        jQuery(document).ready(function ($) {

            // Track previous states to avoid duplicate log entries
            var previousStates = {};

            function fetchLogs() {
                $('#ftp-loading-indicator').show();
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_get_logs',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function (response) {
                        var $oldBody = $('#ftp-history-body');
                        var oldContent = $oldBody.html();
                        $oldBody.html(response);
                        $('#ftp-loading-indicator').fadeOut();
                        
                        // Check for status changes and log them
                        $(response).find('tr').each(function() {
                            var $row = $(this);
                            var id = $row.find('td:first').text().trim();
                            var status = $row.find('.status-pill').text().trim();
                            var filename = $row.find('.file-link').text().trim() || $row.find('td:nth-child(2)').text().trim();
                            
                            if (!id || id === 'No uploads yet.') return;
                            
                            var currentState = status;
                            var previousState = previousStates[id];
                            
                            // Only log if state changed
                            if (previousState !== currentState) {
                                previousStates[id] = currentState;
                                
                                if (status.indexOf('Failed') !== -1) {
                                    var errorMsg = $row.find('.error-message').text().trim();
                                    addLogEntry('Upload failed: ' + filename + (errorMsg ? ' - ' + errorMsg : ''), 'error');
                                } else if (status.indexOf('Success') !== -1) {
                                    addLogEntry('Upload successful: ' + filename, 'success');
                                } else if (status.indexOf('Uploading') !== -1) {
                                    addLogEntry('Upload started: ' + filename, 'warning');
                                } else if (status.indexOf('Retrying') !== -1) {
                                    var retryMsg = $row.find('.error-message').text().trim();
                                    addLogEntry('Retrying upload: ' + filename + (retryMsg ? ' - ' + retryMsg : ''), 'warning');
                                } else if (status.indexOf('Pending') !== -1 && previousState) {
                                    addLogEntry('Upload queued: ' + filename, 'info');
                                }
                            }
                        });
                    },
                    error: function (xhr, status, error) {
                        $('#ftp-loading-indicator').hide();
                        addLogEntry('Error fetching logs: ' + error, 'error');
                    }
                });
            }

            // Initial fetch
            fetchLogs();

            // Polling every 5 seconds
            setInterval(fetchLogs, 5000);

            // Copy Link with fallback method
            function copyToClipboard(text) {
                // Try modern clipboard API first
                if (navigator.clipboard && window.isSecureContext) {
                    return navigator.clipboard.writeText(text).then(function () {
                        return true;
                    }).catch(function (err) {
                        console.error('Clipboard API failed:', err);
                        return fallbackCopyToClipboard(text);
                    });
                } else {
                    // Use fallback method
                    return fallbackCopyToClipboard(text);
                }
            }

            function fallbackCopyToClipboard(text) {
                return new Promise(function (resolve, reject) {
                    var textArea = document.createElement("textarea");
                    textArea.value = text;
                    textArea.style.position = "fixed";
                    textArea.style.left = "-999999px";
                    textArea.style.top = "-999999px";
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    
                    try {
                        var successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        if (successful) {
                            resolve(true);
                        } else {
                            reject(new Error('Fallback copy command failed'));
                        }
                    } catch (err) {
                        document.body.removeChild(textArea);
                        reject(err);
                    }
                });
            }

            $(document).on('click', '.copy-link-btn', function (e) {
                e.preventDefault();
                var $btn = $(this);
                var link = $btn.data('link');
                
                if (!link) {
                    console.error('No link data found');
                    return;
                }

                // Disable button temporarily to prevent double-clicks
                $btn.prop('disabled', true);
                
                copyToClipboard(link).then(function () {
                    // Show success toast
                    var x = document.getElementById("ftp-toast");
                    x.className = "show";
                    setTimeout(function () { 
                        x.className = x.className.replace("show", ""); 
                    }, 3000);
                    
                    // Re-enable button
                    $btn.prop('disabled', false);
                }).catch(function (err) {
                    console.error('Failed to copy:', err);
                    alert('Failed to copy link. Please right-click on the link and select "Copy link address".');
                    $btn.prop('disabled', false);
                });
            });

            // Debug Log Functions
            function addLogEntry(message, type) {
                type = type || 'info';
                var timestamp = new Date().toLocaleTimeString();
                var icon = 'info';
                var color = '#d4d4d4';
                
                if (type === 'error') {
                    icon = 'warning';
                    color = '#f48771';
                } else if (type === 'success') {
                    icon = 'yes-alt';
                    color = '#4ec9b0';
                } else if (type === 'warning') {
                    icon = 'warning';
                    color = '#dcdcaa';
                }
                
                var entry = '<div style="margin-bottom: 5px; color: ' + color + ';">' +
                    '<span style="color: #858585;">[' + timestamp + ']</span> ' +
                    '<span class="dashicons dashicons-' + icon + '" style="font-size: 14px; width: 14px; height: 14px; vertical-align: middle;"></span> ' +
                    escapeHtml(message) +
                    '</div>';
                
                $('#log-entries').append(entry);
                var logContent = document.getElementById('log-content');
                logContent.scrollTop = logContent.scrollHeight;
            }

            function escapeHtml(text) {
                var map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, function(m) { return map[m]; });
            }

            // Toggle log visibility
            $('#toggle-log').on('click', function() {
                var $content = $('#log-content');
                var $btn = $(this);
                if ($content.is(':visible')) {
                    $content.slideUp();
                    $btn.html('<span class="dashicons dashicons-arrow-down-alt2"></span> Show');
                } else {
                    $content.slideDown();
                    $btn.html('<span class="dashicons dashicons-arrow-up-alt2"></span> Hide');
                }
            });

            // Clear log
            $('#clear-log').on('click', function() {
                $('#log-entries').empty();
                addLogEntry('Log cleared', 'info');
            });

            // Trigger cron manually
            $('#trigger-cron').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true).html('<span class="dashicons dashicons-update" style="animation: spin 1s linear infinite;"></span> Processing...');
                addLogEntry('Manually triggering queue processing...', 'info');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_trigger_cron',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_uploader_upload')); ?>'
                    },
                    success: function(response) {
                        addLogEntry('Queue processing triggered', 'success');
                        setTimeout(function() {
                            $btn.prop('disabled', false).html('<span class="dashicons dashicons-controls-play"></span> Process Queue Now');
                        }, 2000);
                    },
                    error: function() {
                        addLogEntry('Failed to trigger queue processing', 'error');
                        $btn.prop('disabled', false).html('<span class="dashicons dashicons-controls-play"></span> Process Queue Now');
                    }
                });
            });

            // Initial log entry
            addLogEntry('FTP Uploader initialized', 'info');
            addLogEntry('Polling logs every 5 seconds...', 'info');
            addLogEntry('Note: WordPress cron processes uploads when the site receives traffic. Use "Process Queue Now" for immediate processing.', 'info');
        });
    </script>
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccd0d4; text-align: center; color: #646970; font-size: 13px;">
        made with 🧠🩸❤️ by <a href="https://t.me/ageek" target="_blank" style="text-decoration: none; color: #2271b1;">Aref</a> & mahdi
    </div>
    <?php
}
add_action('ftp_uploader_render_device_upload_page', 'ftp_uploader_render_device_upload_page_cb');

/**
 * Get FTP Connection
 */
function ftp_uploader_get_connection()
{
    $options = get_option('ftp_uploader_settings');
    if (empty($options['ftp_host']) || empty($options['ftp_user']) || empty($options['ftp_pass'])) {
        return false;
    }

    $ftp_host = $options['ftp_host'];
    $ftp_user = $options['ftp_user'];
    $ftp_pass_encrypted = $options['ftp_pass'];
    $ftp_pass = ftp_uploader_decrypt($ftp_pass_encrypted);

    if (empty($ftp_pass)) {
        return false;
    }

    $conn_id = @ftp_connect($ftp_host);
    if (!$conn_id) {
        return false;
    }

    $login_result = @ftp_login($conn_id, $ftp_user, $ftp_pass);
    if (!$login_result) {
        ftp_close($conn_id);
        return false;
    }

    ftp_pasv($conn_id, true);
    return $conn_id;
}

/**
 * AJAX Handler: List Files and Directories
 */
function ftp_uploader_ajax_list_files()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $current_path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : '';
    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    // Combine base path with current path
    $full_path = rtrim($base_path . ltrim($current_path, '/'), '/');
    if (empty($full_path)) {
        $full_path = '/';
    }

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Change to the directory
    if (!@ftp_chdir($conn_id, $full_path)) {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Could not access directory: ' . $full_path));
    }

    // Get file list
    $files = @ftp_nlist($conn_id, '.');
    $detailed_files = @ftp_rawlist($conn_id, '.');

    if ($files === false) {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Could not list files'));
    }

    $items = array();
    
    // Process detailed list to get file types
    $file_details = array();
    if (is_array($detailed_files)) {
        foreach ($detailed_files as $line) {
            if (preg_match('/^([-d])([rwx-]+)\s+\d+\s+\w+\s+\w+\s+(\d+)\s+(\w+\s+\d+\s+[\d:]+)\s+(.+)$/', $line, $matches)) {
                $type = $matches[1];
                $size = $matches[3];
                $name = trim($matches[6]);
                $file_details[$name] = array(
                    'type' => $type === 'd' ? 'directory' : 'file',
                    'size' => $size
                );
            }
        }
    }

    foreach ($files as $file) {
        $basename = basename($file);
        if ($basename === '.' || $basename === '..') {
            continue;
        }

        $full_file_path = rtrim($full_path, '/') . '/' . $basename;
        $relative_path = ltrim(str_replace($base_path, '', $full_file_path), '/');
        
        $is_dir = false;
        $file_size = 0;
        
        if (isset($file_details[$basename])) {
            $is_dir = $file_details[$basename]['type'] === 'directory';
            $file_size = $file_details[$basename]['size'];
        } else {
            // Fallback: try to determine if it's a directory
            $old_dir = @ftp_pwd($conn_id);
            if (@ftp_chdir($conn_id, $full_file_path)) {
                $is_dir = true;
                @ftp_chdir($conn_id, $old_dir);
            } else {
                $file_size = @ftp_size($conn_id, $basename);
            }
        }

        $items[] = array(
            'name' => $basename,
            'path' => $relative_path,
            'full_path' => $full_file_path,
            'is_directory' => $is_dir,
            'size' => $file_size,
            'size_formatted' => $is_dir ? '-' : size_format($file_size, 2)
        );
    }

    // Sort: directories first, then files
    usort($items, function($a, $b) {
        if ($a['is_directory'] && !$b['is_directory']) return -1;
        if (!$a['is_directory'] && $b['is_directory']) return 1;
        return strcasecmp($a['name'], $b['name']);
    });

    ftp_close($conn_id);

    wp_send_json_success(array(
        'items' => $items,
        'current_path' => $current_path,
        'base_path' => $base_path
    ));
}
add_action('wp_ajax_ftp_uploader_list_files', 'ftp_uploader_ajax_list_files');

/**
 * AJAX Handler: Get Folders (Directories Only)
 */
function ftp_uploader_ajax_get_folders()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_uploader_upload', 'nonce');

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    // Get folders recursively from base path
    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    $folders = array();
    
    // Function to recursively get folders (limited depth for performance)
    function ftp_uploader_get_folders_recursive($conn, $base_path, $current_path, &$folders, $base_path_original, $depth = 0, $max_depth = 2) {
        if ($depth > $max_depth) {
            return; // Limit recursion depth
        }
        
        $full_path = rtrim($base_path . ltrim($current_path, '/'), '/');
        if (empty($full_path)) {
            $full_path = '/';
        }
        
        // Change to the directory
        if (!@ftp_chdir($conn, $full_path)) {
            return;
        }
        
        // Get file list
        $files = @ftp_nlist($conn, '.');
        $detailed_files = @ftp_rawlist($conn, '.');
        
        if ($files === false) {
            return;
        }
        
        // Process detailed list to get file types
        $file_details = array();
        if (is_array($detailed_files)) {
            foreach ($detailed_files as $line) {
                if (preg_match('/^([-d])([rwx-]+)\s+\d+\s+\w+\s+\w+\s+(\d+)\s+(\w+\s+\d+\s+[\d:]+)\s+(.+)$/', $line, $matches)) {
                    $type = $matches[1];
                    $name = trim($matches[6]);
                    if ($type === 'd') {
                        $file_details[$name] = 'directory';
                    }
                }
            }
        }
        
        foreach ($files as $file) {
            $basename = basename($file);
            if ($basename === '.' || $basename === '..') {
                continue;
            }
            
            $is_dir = false;
            if (isset($file_details[$basename])) {
                $is_dir = true;
            } else {
                // Fallback: try to determine if it's a directory
                $old_dir = @ftp_pwd($conn);
                $full_file_path = rtrim($full_path, '/') . '/' . $basename;
                if (@ftp_chdir($conn, $full_file_path)) {
                    $is_dir = true;
                    @ftp_chdir($conn, $old_dir);
                }
            }
            
            if ($is_dir) {
                $relative_path = ltrim(str_replace($base_path_original, '', rtrim($full_path, '/') . '/' . $basename), '/');
                $folders[] = array(
                    'name' => $basename,
                    'path' => $relative_path,
                    'display' => $relative_path ? $relative_path : $basename
                );
                
                // Recursively get subfolders (limited depth)
                if ($depth < $max_depth) {
                    ftp_uploader_get_folders_recursive($conn, $base_path, $relative_path, $folders, $base_path_original, $depth + 1, $max_depth);
                }
            }
        }
    }
    
    // Add root option
    $folders[] = array(
        'name' => 'Root',
        'path' => '',
        'display' => 'Root (Default)'
    );
    
    // Get all folders
    ftp_uploader_get_folders_recursive($conn_id, $base_path, '', $folders, $base_path);
    
    ftp_close($conn_id);
    
    // Sort folders by path
    usort($folders, function($a, $b) {
        return strcasecmp($a['path'], $b['path']);
    });
    
    wp_send_json_success(array('folders' => $folders));
}
add_action('wp_ajax_ftp_uploader_get_folders', 'ftp_uploader_ajax_get_folders');

/**
 * AJAX Handler: Create Directory
 */
function ftp_uploader_ajax_create_directory()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $dir_name = isset($_POST['dir_name']) ? sanitize_file_name($_POST['dir_name']) : '';
    $current_path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : '';
    
    if (empty($dir_name)) {
        wp_send_json_error(array('message' => 'Directory name is required'));
    }

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    $full_path = rtrim($base_path . ltrim($current_path, '/'), '/');
    if (empty($full_path)) {
        $full_path = '/';
    }
    
    $new_dir_path = rtrim($full_path, '/') . '/' . $dir_name;

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Change to parent directory
    if (!empty($full_path) && $full_path !== '/') {
        if (!@ftp_chdir($conn_id, $full_path)) {
            ftp_close($conn_id);
            wp_send_json_error(array('message' => 'Could not access parent directory'));
        }
    }

    // Create directory
    if (@ftp_mkdir($conn_id, $dir_name)) {
        ftp_close($conn_id);
        wp_send_json_success(array('message' => 'Directory created successfully'));
    } else {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Failed to create directory'));
    }
}
add_action('wp_ajax_ftp_uploader_create_directory', 'ftp_uploader_ajax_create_directory');

/**
 * AJAX Handler: Delete File
 */
function ftp_uploader_ajax_delete_file()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $file_path = isset($_POST['file_path']) ? sanitize_text_field($_POST['file_path']) : '';
    
    if (empty($file_path)) {
        wp_send_json_error(array('message' => 'File path is required'));
    }

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    $full_path = rtrim($base_path . ltrim($file_path, '/'), '/');

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Delete file
    if (@ftp_delete($conn_id, $full_path)) {
        ftp_close($conn_id);
        wp_send_json_success(array('message' => 'File deleted successfully'));
    } else {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Failed to delete file'));
    }
}
add_action('wp_ajax_ftp_uploader_delete_file', 'ftp_uploader_ajax_delete_file');

/**
 * AJAX Handler: Delete Directory
 */
function ftp_uploader_ajax_delete_directory()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $dir_path = isset($_POST['dir_path']) ? sanitize_text_field($_POST['dir_path']) : '';
    
    if (empty($dir_path)) {
        wp_send_json_error(array('message' => 'Directory path is required'));
    }

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    $full_path = rtrim($base_path . ltrim($dir_path, '/'), '/');

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Recursively delete directory
    function ftp_uploader_delete_directory_recursive($conn, $dir) {
        // Change to the directory
        $old_dir = @ftp_pwd($conn);
        if (!@ftp_chdir($conn, $dir)) {
            return false;
        }
        
        $files = @ftp_nlist($conn, '.');
        if ($files === false) {
            @ftp_chdir($conn, $old_dir);
            return false;
        }
        
        foreach ($files as $file) {
            $basename = basename($file);
            if ($basename === '.' || $basename === '..') {
                continue;
            }
            
            // Check if it's a directory
            $current_dir = @ftp_pwd($conn);
            if (@ftp_chdir($conn, $basename)) {
                @ftp_chdir($conn, $current_dir);
                // It's a directory, recurse
                $sub_dir = rtrim($dir, '/') . '/' . $basename;
                if (!ftp_uploader_delete_directory_recursive($conn, $sub_dir)) {
                    @ftp_chdir($conn, $old_dir);
                    return false;
                }
            } else {
                // It's a file
                if (!@ftp_delete($conn, $basename)) {
                    @ftp_chdir($conn, $old_dir);
                    return false;
                }
            }
        }
        
        // Go back to parent directory
        @ftp_chdir($conn, $old_dir);
        
        // Remove the directory itself
        if (!@ftp_rmdir($conn, $dir)) {
            return false;
        }
        
        return true;
    }

    // Delete directory recursively
    if (ftp_uploader_delete_directory_recursive($conn_id, $full_path)) {
        ftp_close($conn_id);
        wp_send_json_success(array('message' => 'Directory deleted successfully'));
    } else {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Failed to delete directory'));
    }
}
add_action('wp_ajax_ftp_uploader_delete_directory', 'ftp_uploader_ajax_delete_directory');

/**
 * AJAX Handler: Move File or Directory
 */
function ftp_uploader_ajax_move_item()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $source_path = isset($_POST['source_path']) ? sanitize_text_field(wp_unslash($_POST['source_path'])) : '';
    $destination_path = isset($_POST['destination_path']) ? sanitize_text_field(wp_unslash($_POST['destination_path'])) : '';
    
    if (empty($source_path)) {
        wp_send_json_error(array('message' => 'Source path is required'));
    }
    
    if (empty($destination_path)) {
        wp_send_json_error(array('message' => 'Destination path is required'));
    }

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    $full_source = rtrim($base_path . ltrim($source_path, '/'), '/');
    $full_destination = rtrim($base_path . ltrim($destination_path, '/'), '/');

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Check if destination already exists
    $dest_name = basename($full_source);
    $full_dest_path = rtrim($full_destination, '/') . '/' . $dest_name;
    
    // Check if destination exists
    $old_dir = @ftp_pwd($conn_id);
    if (@ftp_chdir($conn_id, $full_dest_path)) {
        @ftp_chdir($conn_id, $old_dir);
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Destination already exists'));
    }

    // Recursively move directory or file
    function ftp_uploader_move_recursive($conn, $source, $dest_dir) {
        $old_dir = @ftp_pwd($conn);
        $item_name = basename($source);
        $full_dest = rtrim($dest_dir, '/') . '/' . $item_name;
        
        // Check if it's a directory
        if (@ftp_chdir($conn, $source)) {
            @ftp_chdir($conn, $old_dir);
            // It's a directory, create it and move contents
            if (!@ftp_mkdir($conn, $full_dest)) {
                return false;
            }
            
            $files = @ftp_nlist($conn, $source);
            if ($files === false) {
                return false;
            }
            
            foreach ($files as $file) {
                $basename = basename($file);
                if ($basename === '.' || $basename === '..') {
                    continue;
                }
                
                $sub_source = rtrim($source, '/') . '/' . $basename;
                if (!ftp_uploader_move_recursive($conn, $sub_source, $full_dest)) {
                    return false;
                }
            }
            
            // Remove source directory
            if (!ftp_uploader_delete_directory_recursive($conn, $source)) {
                return false;
            }
        } else {
            // It's a file
            $temp_file = tempnam(sys_get_temp_dir(), 'ftp_move_');
            if (!@ftp_get($conn, $temp_file, $source, FTP_BINARY)) {
                return false;
            }
            
            if (!@ftp_put($conn, $full_dest, $temp_file, FTP_BINARY)) {
                wp_delete_file($temp_file);
                return false;
            }
            
            wp_delete_file($temp_file);
            
            // Delete source file
            if (!@ftp_delete($conn, $source)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Helper function for recursive delete (reuse from delete_directory)
    function ftp_uploader_delete_directory_recursive($conn, $dir) {
        $old_dir = @ftp_pwd($conn);
        if (!@ftp_chdir($conn, $dir)) {
            return false;
        }
        
        $files = @ftp_nlist($conn, '.');
        if ($files === false) {
            @ftp_chdir($conn, $old_dir);
            return false;
        }
        
        foreach ($files as $file) {
            $basename = basename($file);
            if ($basename === '.' || $basename === '..') {
                continue;
            }
            
            $current_dir = @ftp_pwd($conn);
            if (@ftp_chdir($conn, $basename)) {
                @ftp_chdir($conn, $current_dir);
                $sub_dir = rtrim($dir, '/') . '/' . $basename;
                if (!ftp_uploader_delete_directory_recursive($conn, $sub_dir)) {
                    @ftp_chdir($conn, $old_dir);
                    return false;
                }
            } else {
                if (!@ftp_delete($conn, $basename)) {
                    @ftp_chdir($conn, $old_dir);
                    return false;
                }
            }
        }
        
        @ftp_chdir($conn, $old_dir);
        
        if (!@ftp_rmdir($conn, $dir)) {
            return false;
        }
        
        return true;
    }

    // Ensure destination directory exists
    $dest_parts = explode('/', trim($full_destination, '/'));
    $current_path = '';
    foreach ($dest_parts as $part) {
        if (empty($part)) continue;
        $current_path .= '/' . $part;
        if (!@ftp_chdir($conn_id, $current_path)) {
            if (!@ftp_mkdir($conn_id, $current_path)) {
                ftp_close($conn_id);
                wp_send_json_error(array('message' => 'Failed to create destination directory'));
            }
        }
    }

    // Move the item
    if (ftp_uploader_move_recursive($conn_id, $full_source, $full_destination)) {
        ftp_close($conn_id);
        wp_send_json_success(array('message' => 'Item moved successfully'));
    } else {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Failed to move item'));
    }
}
add_action('wp_ajax_ftp_uploader_move_item', 'ftp_uploader_ajax_move_item');

/**
 * AJAX Handler: Copy File or Directory
 */
function ftp_uploader_ajax_copy_item()
{
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('message' => 'Unauthorized'));
    }

    check_ajax_referer('ftp_file_manager_nonce', 'nonce');

    $source_path = isset($_POST['source_path']) ? sanitize_text_field(wp_unslash($_POST['source_path'])) : '';
    $destination_path = isset($_POST['destination_path']) ? sanitize_text_field(wp_unslash($_POST['destination_path'])) : '';
    
    if (empty($source_path)) {
        wp_send_json_error(array('message' => 'Source path is required'));
    }
    
    if (empty($destination_path)) {
        wp_send_json_error(array('message' => 'Destination path is required'));
    }

    $options = get_option('ftp_uploader_settings');
    $base_path = isset($options['remote_path']) ? trailingslashit($options['remote_path']) : '/';
    
    $full_source = rtrim($base_path . ltrim($source_path, '/'), '/');
    $full_destination = rtrim($base_path . ltrim($destination_path, '/'), '/');

    $conn_id = ftp_uploader_get_connection();
    if (!$conn_id) {
        wp_send_json_error(array('message' => 'Could not connect to FTP server'));
    }

    // Check if destination already exists
    $dest_name = basename($full_source);
    $full_dest_path = rtrim($full_destination, '/') . '/' . $dest_name;
    
    $old_dir = @ftp_pwd($conn_id);
    if (@ftp_chdir($conn_id, $full_dest_path)) {
        @ftp_chdir($conn_id, $old_dir);
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Destination already exists'));
    }

    // Recursively copy directory or file
    function ftp_uploader_copy_recursive($conn, $source, $dest_dir) {
        $old_dir = @ftp_pwd($conn);
        $item_name = basename($source);
        $full_dest = rtrim($dest_dir, '/') . '/' . $item_name;
        
        // Check if it's a directory
        if (@ftp_chdir($conn, $source)) {
            @ftp_chdir($conn, $old_dir);
            // It's a directory, create it and copy contents
            if (!@ftp_mkdir($conn, $full_dest)) {
                return false;
            }
            
            $files = @ftp_nlist($conn, $source);
            if ($files === false) {
                return false;
            }
            
            foreach ($files as $file) {
                $basename = basename($file);
                if ($basename === '.' || $basename === '..') {
                    continue;
                }
                
                $sub_source = rtrim($source, '/') . '/' . $basename;
                if (!ftp_uploader_copy_recursive($conn, $sub_source, $full_dest)) {
                    return false;
                }
            }
        } else {
            // It's a file
            $temp_file = tempnam(sys_get_temp_dir(), 'ftp_copy_');
            if (!@ftp_get($conn, $temp_file, $source, FTP_BINARY)) {
                return false;
            }
            
            if (!@ftp_put($conn, $full_dest, $temp_file, FTP_BINARY)) {
                wp_delete_file($temp_file);
                return false;
            }
            
            wp_delete_file($temp_file);
        }
        
        return true;
    }

    // Ensure destination directory exists
    $dest_parts = explode('/', trim($full_destination, '/'));
    $current_path = '';
    foreach ($dest_parts as $part) {
        if (empty($part)) continue;
        $current_path .= '/' . $part;
        if (!@ftp_chdir($conn_id, $current_path)) {
            if (!@ftp_mkdir($conn_id, $current_path)) {
                ftp_close($conn_id);
                wp_send_json_error(array('message' => 'Failed to create destination directory'));
            }
        }
    }

    // Copy the item
    if (ftp_uploader_copy_recursive($conn_id, $full_source, $full_destination)) {
        ftp_close($conn_id);
        wp_send_json_success(array('message' => 'Item copied successfully'));
    } else {
        ftp_close($conn_id);
        wp_send_json_error(array('message' => 'Failed to copy item'));
    }
}
add_action('wp_ajax_ftp_uploader_copy_item', 'ftp_uploader_ajax_copy_item');

/**
 * Render File Manager Page Callback
 */
function ftp_uploader_render_file_manager_page_cb()
{
    ?>
    <style>
        .ftp-file-manager {
            background: #fff;
            border: 1px solid #ccd0d4;
            box-shadow: 0 1px 1px rgba(0, 0, 0, .04);
            padding: 20px;
            margin-top: 20px;
            max-width: 1200px;
        }

        .file-manager-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e5e5e5;
        }

        .file-manager-breadcrumb {
            display: flex;
            align-items: center;
            gap: 5px;
            flex: 1;
            flex-wrap: wrap;
        }

        .file-manager-breadcrumb a {
            color: #2271b1;
            text-decoration: none;
            padding: 5px 10px;
            border-radius: 3px;
        }

        .file-manager-breadcrumb a:hover {
            background: #f0f0f1;
        }

        .file-manager-breadcrumb span {
            color: #646970;
            margin: 0 5px;
        }

        .file-manager-actions {
            display: flex;
            gap: 10px;
        }

        .file-manager-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .file-manager-table th {
            background: #f6f7f7;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 1px solid #dcdcde;
        }

        .file-manager-table td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f1;
        }

        .file-manager-table tr:hover {
            background: #f6f7f7;
        }

        .file-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .file-icon {
            font-size: 20px;
            width: 24px;
            height: 24px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .file-name {
            font-weight: 500;
            color: #2271b1;
            cursor: pointer;
            text-decoration: none;
        }

        .file-name:hover {
            text-decoration: underline;
        }

        .file-actions {
            display: flex;
            gap: 5px;
        }

        .file-actions .button {
            padding: 4px 8px;
            font-size: 12px;
            height: auto;
            line-height: 1.5;
        }

        .loading-overlay {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0.9);
            align-items: center;
            justify-content: center;
            z-index: 100;
        }

        .loading-overlay.active {
            display: flex;
        }

        .file-manager-container {
            position: relative;
            min-height: 300px;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #646970;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }

        .modal-content {
            background-color: #fff;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #ccd0d4;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e5e5e5;
        }

        .modal-close {
            color: #646970;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            border: none;
            background: none;
        }

        .modal-close:hover {
            color: #000;
        }
    </style>

    <div class="ftp-file-manager">
        <h2><span class="dashicons dashicons-media-code"></span> FTP File Manager</h2>
        
        <div id="ftp-file-manager-message" style="display: none; margin-bottom: 15px;"></div>

        <div class="file-manager-container">
            <div class="loading-overlay" id="file-manager-loading">
                <div style="text-align: center;">
                    <span class="dashicons dashicons-update" style="font-size: 32px; animation: spin 2s linear infinite;"></span>
                    <p>Loading...</p>
                </div>
            </div>

            <div class="file-manager-toolbar">
                <div class="file-manager-breadcrumb" id="file-manager-breadcrumb">
                    <a href="#" data-path="">Root</a>
                </div>
                <div class="file-manager-actions">
                    <button type="button" class="button button-primary" id="create-folder-btn">
                        <span class="dashicons dashicons-plus-alt"></span> New Folder
                    </button>
                    <button type="button" class="button" id="refresh-btn">
                        <span class="dashicons dashicons-update"></span> Refresh
                    </button>
                </div>
            </div>

            <table class="file-manager-table">
                <thead>
                    <tr>
                        <th style="width: 50px;">Type</th>
                        <th>Name</th>
                        <th style="width: 150px;">Size</th>
                        <th style="width: 350px;">Actions</th>
                    </tr>
                </thead>
                <tbody id="file-manager-list">
                    <tr>
                        <td colspan="4" class="empty-state">Loading...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Create Folder Modal -->
    <div id="create-folder-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Create New Folder</h3>
                <button class="modal-close" id="close-create-modal">&times;</button>
            </div>
            <form id="create-folder-form">
                <p>
                    <label for="folder-name" style="font-weight: 600; display: block; margin-bottom: 5px;">Folder Name:</label>
                    <input type="text" id="folder-name" class="regular-text" required style="width: 100%;">
                </p>
                <p style="margin-top: 15px;">
                    <button type="submit" class="button button-primary">Create</button>
                    <button type="button" class="button" id="cancel-create-folder">Cancel</button>
                </p>
            </form>
        </div>
    </div>

    <!-- Move/Copy Destination Modal -->
    <div id="destination-modal" class="modal">
        <div class="modal-content" style="max-width: 600px;">
            <div class="modal-header">
                <h3 id="destination-modal-title">Select Destination</h3>
                <button class="modal-close" id="close-destination-modal">&times;</button>
            </div>
            <div style="margin-bottom: 15px;">
                <div class="file-manager-breadcrumb" id="destination-breadcrumb">
                    <a href="#" data-path="">Root</a>
                </div>
            </div>
            <div style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 10px;">
                <div id="destination-list">Loading...</div>
            </div>
            <p style="margin-top: 15px;">
                <button type="button" class="button button-primary" id="confirm-destination-btn">Confirm</button>
                <button type="button" class="button" id="cancel-destination-btn">Cancel</button>
            </p>
        </div>
    </div>

    <script>
        jQuery(document).ready(function ($) {
            var currentPath = '';
            var basePath = '';

            // Show message
            function showMessage(message, type) {
                var $msg = $('#ftp-file-manager-message');
                $msg.removeClass('notice notice-success notice-error')
                    .addClass('notice notice-' + (type === 'success' ? 'success' : 'error'))
                    .html('<p>' + message + '</p>')
                    .fadeIn();
                
                setTimeout(function() {
                    $msg.fadeOut();
                }, 3000);
            }

            // Show loading
            function showLoading() {
                $('#file-manager-loading').addClass('active');
            }

            // Hide loading
            function hideLoading() {
                $('#file-manager-loading').removeClass('active');
            }

            // Load files
            function loadFiles(path) {
                showLoading();
                currentPath = path || '';

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_list_files',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        path: currentPath
                    },
                    success: function(response) {
                        hideLoading();
                        if (response.success) {
                            basePath = response.data.base_path;
                            renderFiles(response.data.items);
                            renderBreadcrumb(response.data.current_path);
                        } else {
                            showMessage(response.data.message || 'Error loading files', 'error');
                            $('#file-manager-list').html('<tr><td colspan="4" class="empty-state">' + (response.data.message || 'Error loading files') + '</td></tr>');
                        }
                    },
                    error: function() {
                        hideLoading();
                        showMessage('Network error occurred', 'error');
                        $('#file-manager-list').html('<tr><td colspan="4" class="empty-state">Network error occurred</td></tr>');
                    }
                });
            }

            // Render files
            function renderFiles(items) {
                var $tbody = $('#file-manager-list');
                
                if (items.length === 0) {
                    $tbody.html('<tr><td colspan="4" class="empty-state">This directory is empty</td></tr>');
                    return;
                }

                var html = '';
                items.forEach(function(item) {
                    var icon = item.is_directory ? 'dashicons-portfolio' : 'dashicons-media-default';
                    var size = item.is_directory ? '-' : item.size_formatted;
                    
                    html += '<tr>';
                    html += '<td><span class="dashicons ' + icon + ' file-icon"></span></td>';
                    html += '<td>';
                    if (item.is_directory) {
                        html += '<a href="#" class="file-name" data-path="' + escapeHtml(item.path) + '">' + escapeHtml(item.name) + '</a>';
                    } else {
                        html += '<span class="file-name">' + escapeHtml(item.name) + '</span>';
                    }
                    html += '</td>';
                    html += '<td>' + size + '</td>';
                    html += '<td class="file-actions">';
                    if (item.is_directory) {
                        html += '<button type="button" class="button button-small move-item-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '" data-type="directory">';
                        html += '<span class="dashicons dashicons-move"></span> Move</button>';
                        html += '<button type="button" class="button button-small copy-item-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '" data-type="directory">';
                        html += '<span class="dashicons dashicons-admin-page"></span> Copy</button>';
                        html += '<button type="button" class="button button-small delete-dir-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '">';
                        html += '<span class="dashicons dashicons-trash"></span> Delete</button>';
                    } else {
                        html += '<button type="button" class="button button-small move-item-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '" data-type="file">';
                        html += '<span class="dashicons dashicons-move"></span> Move</button>';
                        html += '<button type="button" class="button button-small copy-item-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '" data-type="file">';
                        html += '<span class="dashicons dashicons-admin-page"></span> Copy</button>';
                        html += '<button type="button" class="button button-small delete-file-btn" data-path="' + escapeHtml(item.path) + '" data-name="' + escapeHtml(item.name) + '">';
                        html += '<span class="dashicons dashicons-trash"></span> Delete</button>';
                    }
                    html += '</td>';
                    html += '</tr>';
                });
                
                $tbody.html(html);
            }

            // Render breadcrumb
            function renderBreadcrumb(path) {
                var $breadcrumb = $('#file-manager-breadcrumb');
                var parts = path ? path.split('/').filter(function(p) { return p; }) : [];
                
                var html = '<a href="#" data-path="">Root</a>';
                var current = '';
                
                parts.forEach(function(part) {
                    current += (current ? '/' : '') + part;
                    html += ' <span>/</span> <a href="#" data-path="' + escapeHtml(current) + '">' + escapeHtml(part) + '</a>';
                });
                
                $breadcrumb.html(html);
            }

            // Escape HTML
            function escapeHtml(text) {
                var map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, function(m) { return map[m]; });
            }

            // Navigate to directory
            $(document).on('click', '.file-name[data-path]', function(e) {
                e.preventDefault();
                var path = $(this).data('path');
                loadFiles(path);
            });

            // Breadcrumb navigation
            $(document).on('click', '.file-manager-breadcrumb a', function(e) {
                e.preventDefault();
                var path = $(this).data('path') || '';
                loadFiles(path);
            });

            // Create folder
            $('#create-folder-btn').on('click', function() {
                $('#create-folder-modal').fadeIn();
                $('#folder-name').focus();
            });

            $('#close-create-modal, #cancel-create-folder').on('click', function() {
                $('#create-folder-modal').fadeOut();
                $('#folder-name').val('');
            });

            $('#create-folder-form').on('submit', function(e) {
                e.preventDefault();
                var folderName = $('#folder-name').val().trim();
                
                if (!folderName) {
                    showMessage('Please enter a folder name', 'error');
                    return;
                }

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_create_directory',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        dir_name: folderName,
                        path: currentPath
                    },
                    success: function(response) {
                        if (response.success) {
                            showMessage('Folder created successfully', 'success');
                            $('#create-folder-modal').fadeOut();
                            $('#folder-name').val('');
                            loadFiles(currentPath);
                        } else {
                            showMessage(response.data.message || 'Failed to create folder', 'error');
                        }
                    },
                    error: function() {
                        showMessage('Network error occurred', 'error');
                    }
                });
            });

            // Delete file
            $(document).on('click', '.delete-file-btn', function() {
                var $btn = $(this);
                var filePath = $btn.data('path');
                var fileName = $btn.data('name');
                
                if (!confirm('Are you sure you want to delete "' + fileName + '"? This action cannot be undone.')) {
                    return;
                }

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_delete_file',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        file_path: filePath
                    },
                    success: function(response) {
                        if (response.success) {
                            showMessage('File deleted successfully', 'success');
                            loadFiles(currentPath);
                        } else {
                            showMessage(response.data.message || 'Failed to delete file', 'error');
                        }
                    },
                    error: function() {
                        showMessage('Network error occurred', 'error');
                    }
                });
            });

            // Delete directory
            $(document).on('click', '.delete-dir-btn', function() {
                var $btn = $(this);
                var dirPath = $btn.data('path');
                var dirName = $btn.data('name');
                
                if (!confirm('Are you sure you want to delete the folder "' + dirName + '" and all its contents? This action cannot be undone.')) {
                    return;
                }

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_delete_directory',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        dir_path: dirPath
                    },
                    success: function(response) {
                        if (response.success) {
                            showMessage('Directory deleted successfully', 'success');
                            loadFiles(currentPath);
                        } else {
                            showMessage(response.data.message || 'Failed to delete directory', 'error');
                        }
                    },
                    error: function() {
                        showMessage('Network error occurred', 'error');
                    }
                });
            });

            // Move/Copy item variables
            var pendingAction = null; // 'move' or 'copy'
            var pendingSourcePath = null;
            var pendingSourceName = null;
            var destinationPath = '';

            // Load destination directory list
            function loadDestinationList(path) {
                destinationPath = path || '';
                showLoading();
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'ftp_uploader_list_files',
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        path: destinationPath
                    },
                    success: function(response) {
                        hideLoading();
                        if (response.success) {
                            renderDestinationFiles(response.data.items);
                            renderDestinationBreadcrumb(response.data.current_path);
                        } else {
                            $('#destination-list').html('<div class="empty-state">' + (response.data.message || 'Error loading files') + '</div>');
                        }
                    },
                    error: function() {
                        hideLoading();
                        $('#destination-list').html('<div class="empty-state">Network error occurred</div>');
                    }
                });
            }

            // Render destination files (only directories)
            function renderDestinationFiles(items) {
                var $list = $('#destination-list');
                
                var html = '<div style="margin-bottom: 10px;"><a href="#" class="destination-dir" data-path="' + escapeHtml(destinationPath ? destinationPath.split('/').slice(0, -1).join('/') : '') + '">';
                html += '<span class="dashicons dashicons-arrow-up-alt"></span> .. (Parent Directory)</a></div>';
                
                var dirs = items.filter(function(item) { return item.is_directory; });
                
                if (dirs.length === 0) {
                    html += '<div class="empty-state">No subdirectories found</div>';
                } else {
                    dirs.forEach(function(item) {
                        html += '<div style="margin-bottom: 8px; padding: 8px; border: 1px solid #e5e5e5; cursor: pointer;" class="destination-dir-item">';
                        html += '<a href="#" class="destination-dir" data-path="' + escapeHtml(item.path) + '" style="display: flex; align-items: center; text-decoration: none;">';
                        html += '<span class="dashicons dashicons-portfolio" style="margin-right: 8px;"></span>';
                        html += '<span>' + escapeHtml(item.name) + '</span>';
                        html += '</a></div>';
                    });
                }
                
                $list.html(html);
            }

            // Render destination breadcrumb
            function renderDestinationBreadcrumb(path) {
                var $breadcrumb = $('#destination-breadcrumb');
                var parts = path ? path.split('/').filter(function(p) { return p; }) : [];
                
                var html = '<a href="#" class="destination-breadcrumb-link" data-path="">Root</a>';
                var current = '';
                
                parts.forEach(function(part) {
                    current += (current ? '/' : '') + part;
                    html += ' <span>/</span> <a href="#" class="destination-breadcrumb-link" data-path="' + escapeHtml(current) + '">' + escapeHtml(part) + '</a>';
                });
                
                $breadcrumb.html(html);
            }

            // Move item button
            $(document).on('click', '.move-item-btn', function() {
                var $btn = $(this);
                pendingAction = 'move';
                pendingSourcePath = $btn.data('path');
                pendingSourceName = $btn.data('name');
                $('#destination-modal-title').text('Move "' + escapeHtml(pendingSourceName) + '" to:');
                $('#destination-modal').fadeIn();
                loadDestinationList('');
            });

            // Copy item button
            $(document).on('click', '.copy-item-btn', function() {
                var $btn = $(this);
                pendingAction = 'copy';
                pendingSourcePath = $btn.data('path');
                pendingSourceName = $btn.data('name');
                $('#destination-modal-title').text('Copy "' + escapeHtml(pendingSourceName) + '" to:');
                $('#destination-modal').fadeIn();
                loadDestinationList('');
            });

            // Destination directory navigation
            $(document).on('click', '.destination-dir', function(e) {
                e.preventDefault();
                var path = $(this).data('path') || '';
                loadDestinationList(path);
            });

            // Destination breadcrumb navigation
            $(document).on('click', '.destination-breadcrumb-link', function(e) {
                e.preventDefault();
                var path = $(this).data('path') || '';
                loadDestinationList(path);
            });

            // Confirm destination
            $('#confirm-destination-btn').on('click', function() {
                if (!pendingAction || !pendingSourcePath) {
                    return;
                }

                var action = pendingAction === 'move' ? 'ftp_uploader_move_item' : 'ftp_uploader_copy_item';
                var actionText = pendingAction === 'move' ? 'move' : 'copy';

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: action,
                        nonce: '<?php echo esc_js(wp_create_nonce('ftp_file_manager_nonce')); ?>',
                        source_path: pendingSourcePath,
                        destination_path: destinationPath
                    },
                    success: function(response) {
                        if (response.success) {
                            showMessage('Item ' + actionText + 'ed successfully', 'success');
                            $('#destination-modal').fadeOut();
                            loadFiles(currentPath);
                            pendingAction = null;
                            pendingSourcePath = null;
                            pendingSourceName = null;
                            destinationPath = '';
                        } else {
                            showMessage(response.data.message || 'Failed to ' + actionText + ' item', 'error');
                        }
                    },
                    error: function() {
                        showMessage('Network error occurred', 'error');
                    }
                });
            });

            // Close destination modal
            $('#close-destination-modal, #cancel-destination-btn').on('click', function() {
                $('#destination-modal').fadeOut();
                pendingAction = null;
                pendingSourcePath = null;
                pendingSourceName = null;
                destinationPath = '';
            });

            // Refresh
            $('#refresh-btn').on('click', function() {
                loadFiles(currentPath);
            });

            // Initial load
            loadFiles('');
        });
    </script>
    <?php
}
add_action('ftp_uploader_render_file_manager_page', 'ftp_uploader_render_file_manager_page_cb');
