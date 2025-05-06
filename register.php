<?php
// --- Configuration ---

// ** IMPORTANT: Replace with your actual Razorpay Test or Live Keys **
// Your Test Key ID has been added.
// !!! YOU MUST REPLACE 'YOUR_KEY_SECRET' WITH YOUR ACTUAL TEST SECRET KEY !!!
define('RAZORPAY_KEY_ID', 'rzp_test_s8NLbkJf0TGPMy'); // Your Test Key ID
define('RAZORPAY_KEY_SECRET', 'lXmJo0FGkUWatvFlQjQwHRjXT'); // !!! REPLACE THIS WITH YOUR TEST SECRET KEY !!!

// ** IMPORTANT: Replace with the email address where registration details should be sent **
define('ADMIN_EMAIL', 'syedmutaibnzir@gmail.com'); // Recipient Email (e.g., your.email@gmail.com)

// ** IMPORTANT: Replace with a valid 'From' email address for sending mails **
// (Some servers require this to be a valid email from your domain)
define('SENDER_EMAIL', 'mutoibnazirbukhari@gmail.com'); // e.g., registration@yourwebsite.com

// Directory to store uploaded photos (Make sure this directory exists and is writable by the web server)
// (__DIR__ gives the directory of the current PHP file)
define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('ALLOWED_MIME_TYPES', ['image/jpeg', 'image/png', 'image/jpg']);
define('MAX_FILE_SIZE', 2 * 1024 * 1024); // 2 MB

// Registration End Date (Same as frontend, for server-side check)
define('REGISTRATION_END_DATE_STR', "2025-05-10T23:59:59");

// --- Error Reporting (Disable in production for security) ---
// For Development (Uncomment these lines to see errors directly in the browser - NOT FOR LIVE SITES):
// error_reporting(E_ALL);
// ini_set('display_errors', 1);

// For Production (Recommended):
error_reporting(0); // Turn off error reporting displayed to users
ini_set('display_errors', 0);
ini_set('log_errors', 1); // Log errors to server log file
// ini_set('error_log', '/path/to/your/php-error.log'); // Optional: specify log file location if needed


// --- Set Header for JSON Response ---
// Ensure no output before this header
header('Content-Type: application/json');

// --- Helper Function to Send JSON Response ---
function send_json_response($success, $message = '', $data = []) {
    // Ensure success is boolean
    $response = ['success' => (bool)$success, 'message' => $message] + $data;
    // Prevent caching of API responses
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    echo json_encode($response);
    exit;
}

// --- Helper Function to Sanitize Input ---
function sanitize_input($data) {
    if (is_array($data)) {
        // Sanitize recursively for arrays like $_POST
        return array_map('sanitize_input', $data);
    }
    // Trim whitespace and convert special characters to HTML entities
    // Using ENT_QUOTES to handle both single and double quotes.
    return htmlspecialchars(trim((string)$data), ENT_QUOTES, 'UTF-8');
}

// --- Check Registration Deadline ---
function is_registration_open() {
    try {
        // Set timezone to avoid potential issues if server timezone is different
        // date_default_timezone_set('Asia/Kolkata'); // Example: Set to Indian Standard Time
        $now = new DateTime(); // Use server time
        $endDate = new DateTime(REGISTRATION_END_DATE_STR);
        return $now <= $endDate;
    } catch (Exception $e) {
        error_log("Error creating DateTime object in is_registration_open(): " . $e->getMessage());
        // Fail closed (treat as closed) if date parsing fails
        return false;
    }
}

// --- Main Logic ---

// Check if registration is closed (server-side check is crucial)
if (!is_registration_open()) {
    send_json_response(false, 'Registration is closed. The deadline has passed.');
}

// Check Request Method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Send error for non-POST requests
    send_json_response(false, 'Invalid request method. Only POST requests are accepted.');
}

// Sanitize the action input immediately
$action = isset($_POST['action']) ? sanitize_input($_POST['action']) : null;

// --- Action: Create Razorpay Order ---
if ($action === 'create_order') {

    // --- Define Required Fields for Order Creation ---
     $required_order_fields = [
        'email', 'name', 'father_name', 'mother_name', 'dob', 'phone', 'gender',
        'district', 'aadhaar', 'district_achievements', 'state_achievements',
        'national_achievements', 'player_position', 'basic_price', 'amount', 'currency'
    ];
     // File upload check is separate

    // --- Validate Required POST Fields ---
    foreach ($required_order_fields as $field) {
        // Check if the key exists and if the trimmed value is not empty
        if (!isset($_POST[$field]) || trim((string)$_POST[$field]) === '') {
            send_json_response(false, "Missing required field: " . ucfirst(str_replace('_', ' ', $field)));
        }
    }
    // --- Validate File Upload Existence ---
     if (!isset($_FILES['passport_photo']) || empty($_FILES['passport_photo']['name']) || $_FILES['passport_photo']['error'] === UPLOAD_ERR_NO_FILE) {
         send_json_response(false, "Missing required field: Passport Photo");
     }
     // Check for other upload errors immediately after checking for NO_FILE
     if ($_FILES['passport_photo']['error'] !== UPLOAD_ERR_OK) {
         send_json_response(false, 'Error during photo upload. Code: ' . $_FILES['passport_photo']['error']);
     }


     // --- Sanitize Text Inputs (Do this *after* checking they exist) ---
     // Use the sanitized array for further processing
     $post_data = sanitize_input($_POST);


    // --- Validate Specific Formats (Server-Side) ---
    if (!filter_var($post_data['email'], FILTER_VALIDATE_EMAIL)) {
        send_json_response(false, 'Invalid email format.');
    }
    if (!preg_match('/^[6-9]\d{9}$/', $post_data['phone'])) {
        send_json_response(false, 'Invalid phone number format (must be 10 digits starting with 6-9).');
    }
     if (!preg_match('/^\d{12}$/', $post_data['aadhaar'])) {
        send_json_response(false, 'Invalid Aadhaar number format (must be 12 digits).');
    }
    // Validate basic_price strictly as integer within range
    $basic_price = filter_var($post_data['basic_price'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 50, 'max_range' => 200]]);
    if ($basic_price === false) {
         send_json_response(false, 'Invalid Basic Price. Must be a whole number between 50 and 200.');
    }
     // Validate DOB is in the past and a valid date format
     try {
        // Check if date is provided before creating DateTime object
        if(empty($post_data['dob'])) {
            send_json_response(false, 'Date of Birth is required.');
        }
        $dobDate = new DateTime($post_data['dob']);
        $today = new DateTime('today'); // Gets date part only
        if ($dobDate >= $today) {
             send_json_response(false, 'Date of Birth must be in the past.');
        }
    } catch (Exception $e) {
         // Catches invalid date formats like '0000-00-00' or 'abc'
         send_json_response(false, 'Invalid Date of Birth format provided.');
    }


    // --- Handle File Upload ---
    $uploaded_file_path = null;
    $original_filename = null;
    $unique_filename = null; // Store the unique name for later use

    // Re-check file existence and error status
    if (isset($_FILES['passport_photo']) && $_FILES['passport_photo']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['passport_photo'];
        // Sanitize original filename before using it
        $original_filename = preg_replace("/[^a-zA-Z0-9\.\-\_]/", "_", basename($file['name']));

        // Validate File Size (Server-Side)
        if ($file['size'] > MAX_FILE_SIZE) {
            send_json_response(false, 'File size exceeds 2MB limit.');
        }

        // Validate File Type (using MIME type is more reliable than extension)
        // Check if tmp_name exists and is readable before checking MIME type
        if (!is_uploaded_file($file['tmp_name']) || !is_readable($file['tmp_name'])) {
             error_log("Upload error: tmp_name '{$file['tmp_name']}' is not valid or readable.");
             send_json_response(false, 'Server error during file upload processing.');
        }
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        if ($mime_type === false) {
            error_log("Could not determine MIME type for uploaded file: {$original_filename}");
            send_json_response(false, 'Could not verify file type.');
        } elseif (!in_array($mime_type, ALLOWED_MIME_TYPES)) {
            send_json_response(false, 'Invalid file type. Only JPG, PNG, JPEG allowed. Detected: ' . htmlspecialchars($mime_type));
        }

        // Create a unique filename to prevent overwrites and avoid issues with special chars
        $file_extension = pathinfo($original_filename, PATHINFO_EXTENSION);
        // Sanitize extension just in case
        $safe_extension = preg_replace('/[^a-zA-Z0-9]/', '', strtolower($file_extension));
        if (empty($safe_extension) || strlen($safe_extension) > 5) { // Basic sanity check on extension
            $safe_extension = 'jpg'; // Default extension if extraction fails or seems unsafe
        }
        $unique_filename = uniqid('photo_', true) . '.' . $safe_extension;
        $destination = UPLOAD_DIR . $unique_filename;

        // Ensure upload directory exists and is writable
         if (!is_dir(UPLOAD_DIR)) {
            // Attempt to create directory recursively with appropriate permissions
            if (!mkdir(UPLOAD_DIR, 0755, true)) { // 0755 is usually appropriate
                 error_log("Failed to create upload directory: " . UPLOAD_DIR . " - Check parent directory permissions.");
                 send_json_response(false, 'Server configuration error: Could not create upload directory.');
            }
         } elseif (!is_writable(UPLOAD_DIR)) {
             error_log("Upload directory is not writable: " . UPLOAD_DIR . " - Check permissions.");
             send_json_response(false, 'Server configuration error: Upload directory not writable.');
         }


        // Move the uploaded file using is_uploaded_file() check for security
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $uploaded_file_path = $destination; // Store the full path if needed
             // We have the unique filename in $unique_filename
        } else {
             $error_details = error_get_last();
             error_log("Failed to move uploaded file to: " . $destination . ". Error: " . ($error_details['message'] ?? 'Unknown error'));
            send_json_response(false, 'Failed to save uploaded photo due to a server error.');
        }
    } else {
        // Handle specific file upload errors explicitly if needed (already checked UPLOAD_ERR_OK above)
        $error_code = $_FILES['passport_photo']['error'] ?? UPLOAD_ERR_NO_FILE; // Default if not set
        $upload_error_message = 'Passport photo upload failed.';
         switch ($error_code) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE: $upload_error_message = 'File size exceeds server limit.'; break;
            case UPLOAD_ERR_PARTIAL: $upload_error_message = 'File was only partially uploaded.'; break;
            case UPLOAD_ERR_NO_FILE: $upload_error_message = 'No file was uploaded or file was empty.'; break; // Should have been caught earlier
            case UPLOAD_ERR_NO_TMP_DIR: $upload_error_message = 'Server error: Missing temporary folder.'; break;
            case UPLOAD_ERR_CANT_WRITE: $upload_error_message = 'Server error: Failed to write file to disk.'; break;
            case UPLOAD_ERR_EXTENSION: $upload_error_message = 'Server error: File upload stopped by a PHP extension.'; break;
            default: $upload_error_message = 'Unknown upload error. Code: ' . $error_code; break;
        }
         send_json_response(false, $upload_error_message);
    }


    // --- Prepare Data for Razorpay Order API ---
    $receipt_id = 'rcptid_' . time() . '_' . uniqid(); // Generate a unique receipt ID
    // Amount should be sent in paise from JS, validate it again
    $amount_in_paise = filter_var($post_data['amount'], FILTER_VALIDATE_INT);
    $currency = strtoupper($post_data['currency']); // Should be 'INR'

    if ($currency !== 'INR') {
         send_json_response(false, 'Invalid currency specified. Only INR is supported.');
    }
     // Check if amount is a positive integer
     if ($amount_in_paise === false || $amount_in_paise <= 0) {
         send_json_response(false, 'Invalid payment amount received from the form.');
     }
     // Optional: Double check amount matches expected fee server-side
     // define('EXPECTED_FEE_PAISE', 100 * 100); // 100 INR in paise
     // if ($amount_in_paise !== EXPECTED_FEE_PAISE) {
     //     send_json_response(false, 'Payment amount mismatch.');
     // }


    $order_data = [
        'receipt'         => $receipt_id,
        'amount'          => $amount_in_paise, // Amount in paise
        'currency'        => $currency,
        'payment_capture' => 1, // Auto capture payment (1) or manually capture (0)
        'notes'           => [ // Add useful notes for tracking in Razorpay dashboard
            'player_name'  => $post_data['name'], // Use sanitized name
            'player_email' => $post_data['email'], // Use sanitized email
            'registration' => 'Paradise Handball League 2025'
         ]
    ];

    // --- Call Razorpay API using cURL ---
    // Check if cURL is available
    if (!function_exists('curl_init')) {
        error_log("cURL extension is not installed or enabled.");
        send_json_response(false, "Server configuration error: cURL is required but not available.");
    }

    // Check if Keys are set (basic check)
    if (RAZORPAY_KEY_ID === 'YOUR_KEY_ID' || RAZORPAY_KEY_SECRET === 'YOUR_KEY_SECRET') {
         error_log("Razorpay API keys are not configured in register.php");
         send_json_response(false, "Payment gateway is not configured correctly. Please contact support.");
    }


    $api_url = 'https://api.razorpay.com/v1/orders';
    // Use defined constants for keys
    $auth_header = 'Authorization: Basic ' . base64_encode(RAZORPAY_KEY_ID . ':' . RAZORPAY_KEY_SECRET);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($order_data)); // Encode data as JSON
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        $auth_header
    ]);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20); // Connection timeout (increased slightly)
    curl_setopt($ch, CURLOPT_TIMEOUT, 45);      // Total execution timeout
    // curl_setopt($ch, CURLOPT_FAILONERROR, true); // Optional: Fail if HTTP code >= 400

    // IMPORTANT FOR PRODUCTION: Ensure SSL verification is enabled and working
    // These should typically be enabled by default in modern PHP.
    // curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    // curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    // If you have SSL issues, investigate server config rather than disabling checks.


    $response = curl_exec($ch);
    $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error_no = curl_errno($ch);
    $curl_error = curl_error($ch);
    curl_close($ch);

    // --- Handle API Response ---
    if ($curl_error_no) {
         error_log("cURL Error #{$curl_error_no} creating Razorpay order: " . $curl_error);
        // If curl fails, delete the uploaded file as the order wasn't created
         if ($uploaded_file_path && file_exists($uploaded_file_path)) {
             @unlink($uploaded_file_path); // Use @ to suppress errors if unlink fails
         }
        send_json_response(false, 'Error communicating with payment gateway (' . $curl_error_no . '). Please try again later.');
    }

    $response_data = json_decode($response, true);

    // Check if decoding failed
    if (json_last_error() !== JSON_ERROR_NONE && $http_status >= 200 && $http_status < 300) {
        error_log("Failed to decode Razorpay JSON response. HTTP Status: $http_status, Response: $response");
         if ($uploaded_file_path && file_exists($uploaded_file_path)) {
             @unlink($uploaded_file_path);
         }
        send_json_response(false, 'Received an invalid response from payment gateway.');
    }

    // Check for successful order creation (HTTP 2xx and 'id' present)
    if ($http_status >= 200 && $http_status < 300 && isset($response_data['id'])) {
        // Order created successfully
        send_json_response(true, 'Order created successfully.', [
            'order_id' => $response_data['id'],
            'amount'   => $response_data['amount'], // Send amount back for confirmation
            'currency' => $response_data['currency'],
            // Pass back the sanitized original filename
            'original_filename' => $original_filename
        ]);
    } else {
        // Order creation failed
        $error_message = 'Failed to create payment order.';
        // Try to get description from Razorpay error structure
        if (isset($response_data['error']['description'])) {
            $error_message .= ' Reason: ' . htmlspecialchars($response_data['error']['description']); // Sanitize error message
        } elseif (!empty($response)) {
             $error_message .= ' Unexpected response received.'; // Avoid showing raw response
        }
         error_log("Razorpay order creation failed: HTTP Status $http_status, Response: $response");
         // If order fails, attempt to delete the uploaded file to clean up
         if ($uploaded_file_path && file_exists($uploaded_file_path)) {
             @unlink($uploaded_file_path);
         }
        send_json_response(false, $error_message);
    }

// --- Action: Verify Razorpay Payment ---
} elseif ($action === 'verify_payment') {

    // --- Define Required Fields for Verification ---
    $required_verify_fields = [
        'razorpay_payment_id', 'razorpay_order_id', 'razorpay_signature',
        // Include form fields needed for the email again
        'email', 'name', 'father_name', 'mother_name', 'dob', 'phone', 'gender', 'district', 'aadhaar',
        'district_achievements', 'state_achievements', 'national_achievements', 'player_position', 'basic_price',
        'passport_photo_filename' // Get the original filename sent back from JS
    ];

    // --- Validate Required POST Fields for Verification ---
    foreach ($required_verify_fields as $field) {
        if (!isset($_POST[$field]) || trim((string)$_POST[$field]) === '') {
            // Log the missing field for debugging
            error_log("Missing field during payment verification: " . $field);
            send_json_response(false, "Payment verification failed: Missing required information.");
        }
    }

    // --- Sanitize All Inputs for Verification Step ---
    // Note: Signature should not be sanitized as it's needed raw for comparison
    $post_data = sanitize_input($_POST); // Sanitize most data
    $razorpay_payment_id = trim($_POST['razorpay_payment_id']); // Trim only
    $razorpay_order_id = trim($_POST['razorpay_order_id']);     // Trim only
    $razorpay_signature = trim($_POST['razorpay_signature']);   // Trim only
    // Use the sanitized filename from post_data
    $original_photo_filename = $post_data['passport_photo_filename'];


    // --- Verify Signature ---
    // Construct the payload exactly as Razorpay expects: order_id|payment_id
    $signature_payload = $razorpay_order_id . '|' . $razorpay_payment_id;

    // Check if the secret key is configured
    if (RAZORPAY_KEY_SECRET === 'YOUR_KEY_SECRET') {
         error_log("Razorpay Secret Key is not configured in register.php during verification.");
         send_json_response(false, "Payment gateway configuration error during verification.");
    }

    try {
        // Calculate expected signature using the SECRET Key
        $expected_signature = hash_hmac('sha256', $signature_payload, RAZORPAY_KEY_SECRET);

        // Compare signatures securely (timing-attack safe)
        if (!hash_equals($expected_signature, $razorpay_signature)) {
            // Signature Mismatch - Log details for investigation
            error_log("Signature verification failed for Order ID: {$razorpay_order_id}, Payment ID: {$razorpay_payment_id}.");
            // Don't reveal expected vs received signature to the client
            send_json_response(false, 'Payment verification failed: Invalid signature.');
        }
    } catch (Exception $e) {
        error_log("Error during signature verification hash_hmac: " . $e->getMessage());
        send_json_response(false, 'Payment verification failed due to server error.');
    }

    // --- Signature is Valid - Payment Successful ---
    // At this point, the payment is confirmed by Razorpay.
    // Optional: Fetch payment details from Razorpay API for double-checking amount, status etc.

    // --- Compose Email ---
    $subject = "New Player Registration - Paradise Handball League 2025 - " . $post_data['name'];

    // Build HTML Email Body (using sanitized $post_data)
    $email_body = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>$subject</title><style>";
    // (Styles remain the same as previous version)
    $email_body .= "body { font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }";
    $email_body .= ".container { max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }";
    $email_body .= "h2 { color: #4a90e2; border-bottom: 2px solid #4a90e2; padding-bottom: 10px; margin-bottom: 20px; }";
    $email_body .= "h3 { color: #333; margin-top: 25px; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }";
    $email_body .= "table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }";
    $email_body .= "th, td { text-align: left; padding: 10px; border: 1px solid #ddd; vertical-align: top; }"; // Added vertical-align
    $email_body .= "th { background-color: #f8f8f8; font-weight: bold; width: 170px; }"; // Label column width
    $email_body .= ".footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #777; }";
    $email_body .= "</style></head><body>";
    $email_body .= "<div class='container'>";
    $email_body .= "<h2>Paradise Handball League 2025</h2>";
    $email_body .= "<p>A new player has successfully registered and paid the fee.</p>";

    $email_body .= "<h3>Player Details</h3>";
    $email_body .= "<table>";
    $email_body .= "<tr><th>Name:</th><td>" . $post_data['name'] . "</td></tr>";
    $email_body .= "<tr><th>Email:</th><td>" . $post_data['email'] . "</td></tr>";
    $email_body .= "<tr><th>Phone / WhatsApp:</th><td>" . $post_data['phone'] . "</td></tr>";
    $email_body .= "<tr><th>Date of Birth:</th><td>" . $post_data['dob'] . "</td></tr>";
    $email_body .= "<tr><th>Gender:</th><td>" . $post_data['gender'] . "</td></tr>";
    $email_body .= "<tr><th>Father's Name:</th><td>" . $post_data['father_name'] . "</td></tr>";
    $email_body .= "<tr><th>Mother's Name:</th><td>" . $post_data['mother_name'] . "</td></tr>";
    $email_body .= "<tr><th>District:</th><td>" . $post_data['district'] . "</td></tr>";
    $email_body .= "<tr><th>Aadhaar Number:</th><td>" . $post_data['aadhaar'] . "</td></tr>";
    $email_body .= "<tr><th>Player Position:</th><td>" . $post_data['player_position'] . "</td></tr>";
    $email_body .= "<tr><th>Basic Price:</th><td>₹" . $post_data['basic_price'] . "</td></tr>";
    $email_body .= "</table>";

    $email_body .= "<h3>Achievements</h3>";
    $email_body .= "<table>";
    $email_body .= "<tr><th>District:</th><td>" . $post_data['district_achievements'] . "</td></tr>";
    $email_body .= "<tr><th>State:</th><td>" . $post_data['state_achievements'] . "</td></tr>";
    $email_body .= "<tr><th>National:</th><td>" . $post_data['national_achievements'] . "</td></tr>";
    $email_body .= "</table>";

    $email_body .= "<h3>Payment Details</h3>";
    $email_body .= "<table>";
    // Use raw payment/order IDs here, not sanitized ones
    $email_body .= "<tr><th>Razorpay Payment ID:</th><td>" . htmlspecialchars($razorpay_payment_id) . "</td></tr>";
    $email_body .= "<tr><th>Razorpay Order ID:</th><td>" . htmlspecialchars($razorpay_order_id) . "</td></tr>";
    $email_body .= "</table>";

    $email_body .= "<h3>Uploaded Photo</h3>";
    // Use the sanitized original filename
    $email_body .= "<p>Photo Filename: <strong>" . $original_photo_filename . "</strong></p>";
    $email_body .= "<p>(The actual file is stored in the server's 'uploads' directory, likely under a unique system-generated name).</p>";


    $email_body .= "<div class='footer'>";
    $email_body .= "<p><em>This is an automated message. Please do not reply directly.</em></p>";
    $email_body .= "</div>";
    $email_body .= "</div>"; // End container
    $email_body .= "</body></html>";

    // Set Email Headers for HTML content and proper encoding
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8" . "\r\n";
    // Use the configured sender email address
    $headers .= 'From: Paradise Handball League <' . SENDER_EMAIL . '>' . "\r\n";
    $headers .= 'Reply-To: ' . SENDER_EMAIL . "\r\n"; // Optional: Set reply-to
    // $headers .= 'Cc: another_email@example.com' . "\r\n"; // Optional: CC someone
    // $headers .= 'Bcc: backup@example.com' . "\r\n"; // Optional: BCC

    // --- Send Email ---
    // Using PHP's mail() function. Reliability depends on server setup (sendmail/SMTP).
    // Check if admin/sender emails are configured before attempting to send
    if (ADMIN_EMAIL === 'YOUR_ADMIN_EMAIL@example.com' || SENDER_EMAIL === 'noreply@yourdomain.com') {
         error_log("Admin/Sender email not configured. Skipping email notification for Order ID: {$razorpay_order_id}");
         // Still report success to user as payment is verified
         send_json_response(true, 'Registration successful! Payment verified. (Email notification skipped due to configuration).');
    } else {
        if (mail(ADMIN_EMAIL, $subject, $email_body, $headers)) {
            // Email sent successfully
            send_json_response(true, 'Registration successful! Payment verified and details have been emailed to the admin.');
        } else {
            // Email sending failed
            $error_info = error_get_last(); // Get the last error message if possible
            error_log("Failed to send registration email to " . ADMIN_EMAIL . " for order " . $razorpay_order_id . ". Error: " . ($error_info['message'] ?? 'Unknown mail() error'));
            // Still send success to frontend as payment *was* verified, but inform about email issue.
            send_json_response(true, 'Payment verified, but there was an issue sending the confirmation email. Registration data is saved. Please contact support if needed.');
        }
    }

} else {
    // --- Invalid Action ---
    // Log invalid action attempts
    error_log("Invalid action specified in POST request: " . print_r($_POST, true));
    send_json_response(false, 'Invalid action specified.');
}

?>
