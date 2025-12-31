# FTP Manager & Uploader 
Contributors: Aref solaimani & Mahdi mortazavi
Tags: ftp, uploader, file manager, ftp manager, file browser, url uploader
Requires at least: 5.0
Tested up to: 6.9
Stable tag: 1.7.0
License: GPLv2 or later

Complete FTP management solution with background uploads from URL and device, plus full file manager capabilities.

### Description

FTP Manager & Uploader is a comprehensive WordPress plugin that provides a complete FTP management solution. Upload files from URLs or directly from your device, and manage your entire FTP server structure through an intuitive file manager interface—all from your WordPress admin panel.

**Key Features:**

*   **Dual Upload Methods:**
    *   Upload from URL: Transfer files directly from any public URL to your FTP server
    *   Upload from Device: Upload files directly from your computer to FTP

*   **Background Processing:** All uploads run asynchronously using WordPress Cron, preventing server timeouts even with large files. You can close the page immediately after starting an upload.

*   **Full-Featured File Manager:**
    *   Browse files and folders on your FTP server
    *   Create new directories
    *   Delete files and folders (with recursive deletion support)
    *   Move files and folders to different locations
    *   Copy files and folders
    *   Navigate with breadcrumb navigation
    *   View file details (size, date)

*   **Enterprise-Grade Security:** Your FTP password is encrypted using AES-256-CBC encryption before storage in the database.

*   **Smart Retry System:** Automatic retry mechanism attempts to re-upload failed files up to 3 times with intelligent error handling.

*   **Public Link Generation:** Configure a "Base URL" to automatically generate and copy public links for your uploaded files.

*   **Real-Time Status Updates:** Live AJAX-powered status updates show upload progress without page refresh.

*   **Connection Testing:** Built-in FTP connection tester to verify your credentials before uploading.

*   **Upload History:** Track all upload attempts with detailed status information, retry counts, and error messages.

### Installation

1.  Download zip & Upload the zip to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.
3.  Navigate to **FTP Uploader > Settings** tab.
4.  Enter your FTP Host, Username, Password, Base URL (optional), and Remote Path (optional).
5.  Click **Save Settings**. The plugin will automatically test your FTP connection.
6.  Once configured, you can start uploading files or managing your FTP server.

### Usage

**Uploading from URL:**

1.  Go to **FTP Uploader > Upload from URL** tab.
2.  Paste the direct URL of the file you want to transfer (e.g., `https://example.com/large-archive.zip`).
3.  Optionally select a destination folder from the dropdown.
4.  Click **Start Background Upload**.
5.  The file will appear in the "Upload History" list with a "Pending" status.
6.  The list auto-refreshes. Once status shows "Success", click **Copy Link** to get the public URL.

**Uploading from Device:**

1.  Go to **FTP Uploader > Upload from your device** tab.
2.  Click **Choose File** and select a file from your computer.
3.  Optionally select a destination folder from the dropdown.
4.  Click **Start Background Upload**.
5.  Monitor the upload status in the history table below.

**File Manager:**

1.  Go to **FTP Uploader > File Manager** tab.
2.  Browse your FTP server structure by clicking on folders.
3.  Use the toolbar buttons to:
    *   **Create Folder:** Create new directories
    *   **Refresh:** Reload the current directory
4.  For each file/folder, you can:
    *   **Click the name:** Navigate into folders or view file details
    *   **Move:** Move items to a different location
    *   **Copy:** Copy items to a different location
    *   **Delete:** Remove files or folders (folders are deleted recursively)

### Frequently Asked Questions

= Does it support SFTP? =
Currently, the plugin supports standard FTP. SFTP support is planned for future updates.

= What happens if the upload fails? =
The plugin will automatically retry up to 3 times. If it still fails after all retries, the status will show "Failed" and you can hover over the status to see the detailed error message.

= Can I close the page after clicking upload? =
Yes! Since the process runs in the background using WordPress Cron, you can close the page or navigate away immediately after clicking upload. The upload will continue processing.

= What file sizes are supported? =
There are no hard limits, but very large files may take longer to process. The plugin sets memory limit to 512MB and execution time to 5 minutes per upload attempt.

= Can I manage existing files on my FTP server? =
Yes! The File Manager tab allows you to browse, create, delete, move, and copy files and folders on your FTP server, just like a desktop FTP client.

= Is my FTP password secure? =
Yes. Your FTP password is encrypted using AES-256-CBC encryption before being stored in the WordPress database. The encryption key is based on WordPress security salts.

= Can I upload to subdirectories? =
Yes! Both upload methods support selecting a destination folder. The plugin will automatically create the directory structure if it doesn't exist.

### Changelog

= 1.7.0 =
*   Added complete File Manager with browse, create, delete, move, and copy functionality
*   Added upload from device feature
*   Enhanced upload interface with folder selection
*   Improved error handling and user feedback
*   Added breadcrumb navigation in File Manager
*   Added recursive directory operations support

= 1.1.0 =
*   Refactored code structure for better performance
*   Added military-grade encryption for stored passwords
*   Implemented automatic retry logic for failed uploads
*   Added AJAX auto-refresh for the history table

= 1.0.0 =
*   Initial release with URL upload functionality

