<?php
// Allow requests ONLY from your Vercel app domain
// IMPORTANT: Make sure this is the VERY FIRST THING in the script, before any output or other code.
header("Access-Control-Allow-Origin: https://paradise-handball-league.vercel.app");
// Allow methods (POST for submitting data, OPTIONS for preflight checks)
header("Access-Control-Allow-Methods: POST, OPTIONS");
// Allow necessary headers (Content-Type is sent with FormData, Accept for JSON response expectation)
header("Access-Control-Allow-Headers: Content-Type, Accept");
// Allow credentials if needed in future (e.g., cookies), though not used here
// header("Access-Control-Allow-Credentials: true");
// Max age for preflight request caching (optional, in seconds)
// header("Access-Control-Max-Age: 86400"); // 1 day

// Handle the browser's preflight OPTIONS request
// This request is sent by the browser before the actual POST request to check CORS permissions.
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    // Send OK status for preflight request and exit.
    http_response_code(200);
    // Optionally add allowed headers/methods again if needed by specific browsers
    // header("Access-Control-Allow-Methods: POST, OPTIONS");
    // header("Access-Control-Allow-Headers: Content-Type, Accept");
    exit; // Stop script execution, browser only needs headers for OPTIONS
}


// --- Configuration ---

// ** IMPORTANT: Replace with your actual Razorpay Test or Live Keys **
define('RAZORPAY_KEY_ID', 'rzp_test_K6OGVKTAf7Pnle'); // Your Test Key ID
define('RAZORPAY_KEY_SECRET', 'YOUR_TEST_SECRET_KEY'); // !!! REPLACE THIS WITH YOUR TEST (or Live) SECRET KEY !!!

// ** IMPORTANT: Replace with the email address where registration details should be sent **
define('ADMIN_EMAIL', 'your_email@example.com'); // !!! REPLACE THIS !!! Recipient Email

// ** IMPORTANT: Replace with a valid 'From' email address for sending mails **
// (Some servers require this to be a valid email from your domain)
define('SENDER_EMAIL', 'registration@yourdomain.com'); // !!! REPLACE THIS !!! (Use a valid sender)

// Directory to store uploaded photos (Make sure this directory exists and is writable by the web server)
// (__DIR__ gives the directory of the current PHP file)
define('UPLOAD_DIR', __DIR__ . '/uploads/'); // Ensure trailing slash
define('ALLOWED_MIME_TYPES', ['image/jpeg', 'image/png', 'image/jpg']);
define('MAX_FILE_SIZE', 2 * 1024 * 1024); // 2 MB

// Registration End Date (Same as frontend, for server-side check)
define('REGISTRATION_END_DATE_STR', "2025-05-10T23:59:59");

// --- Error Reporting ---
// Recommended for Production: Log errors, don't display them
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
// Ensure PHP can write to its error log file. Check server config if errors aren't logged.
// ini_set('error_log', '/path/to/your/php-error.log'); // Optional: specify log file location

// --- Set Header for JSON Response ---
// This should come after CORS headers and before any JSON output
header('Content-Type: application/json');

// --- Helper Function to Send JSON Response ---
function send_json_response($success, $message = '', $data = []) {
    // Ensure success is boolean
    $response = ['success' => (bool)$success, 'message' => $message] + $data;
    // Prevent caching of API responses
    header('Cache-Control: no-cache, must-revalidate');
    header('Expires: Mon, 26 Jul 1997 05:00:00 GMT'); // Date in the past
    // Make sure Content-Type is set before echoing
    if (!headers_sent()) {
         header('Content-Type: application/json');
    }
    echo json_encode($response);
    exit; // Stop script execution after sending response
}

// --- Helper Function to Sanitize Input ---
function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    return htmlspecialchars(trim((string)$data), ENT_QUOTES, 'UTF-8');
}

// --- Check Registration Deadline ---
function is_registration_open() {
    try {
        // Consider setting default timezone if server's default is uncertain
        // date_default_timezone_set('Asia/Kolkata');
        $now = new DateTime();
        $endDate = new DateTime(REGISTRATION_END_DATE_STR);
        return $now <= $endDate;
    } catch (Exception $e) {
        error_log("Error creating DateTime object in is_registration_open(): " . $e->getMessage());
        return false; // Fail closed
    }
}

// --- Main Logic ---

// Check if registration is closed (server-side check is crucial)
if (!is_registration_open()) {
    send_json_response(false, 'Registration is closed. The deadline has passed.');
}

// Check Request Method (Should be POST, OPTIONS was handled earlier)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_json_response(false, 'Invalid request method.');
}

// Basic check for keys configuration
if (RAZORPAY_KEY_ID === 'YOUR_KEY_ID' || RAZORPAY_KEY_SECRET === 'YOUR_KEY_SECRET' || RAZORPAY_KEY_SECRET === '') {
     error_log("Razorpay API keys are not configured in register.php");
     send_json_response(false, "Payment gateway is not configured correctly. Please contact support.");
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
        if (!isset($_POST[$field]) || trim((string)$_POST[$field]) === '') {
            send_json_response(false, "Missing required field: " . ucfirst(str_replace('_', ' ', $field)));
        }
    }
    // --- Validate File Upload Existence ---
     if (!isset($_FILES['passport_photo']) || empty($_FILES['passport_photo']['name']) || $_FILES['passport_photo']['error'] === UPLOAD_ERR_NO_FILE) {
         send_json_response(false, "Missing required field: Passport Photo");
     }
     if ($_FILES['passport_photo']['error'] !== UPLOAD_ERR_OK) {
         send_json_response(false, 'Error during photo upload. Code: ' . $_FILES['passport_photo']['error']);
     }


     // --- Sanitize Text Inputs ---
     $post_data = sanitize_input($_POST);


    // --- Validate Specific Formats (Server-Side) ---
    if (!filter_var($post_data['email'], FILTER_VALIDATE_EMAIL)) { send_json_response(false, 'Invalid email format.'); }
    if (!preg_match('/^[6-9]\d{9}$/', $post_data['phone'])) { send_json_response(false, 'Invalid phone number format (must be 10 digits starting with 6-9).'); }
    if (!preg_match('/^\d{12}$/', $post_data['aadhaar'])) { send_json_response(false, 'Invalid Aadhaar number format (must be 12 digits).'); }
    $basic_price = filter_var($post_data['basic_price'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 50, 'max_range' => 200]]);
    if ($basic_price === false || ($basic_price % 10 !== 0)) { send_json_response(false, 'Invalid Basic Price. Must be a whole number between 50 and 200, in steps of 10.'); }
    try {
        if(empty($post_data['dob'])) { send_json_response(false, 'Date of Birth is required.'); }
        $dobDate = new DateTime($post_data['dob']);
        $today = new DateTime('today');
        if ($dobDate >= $today) { send_json_response(false, 'Date of Birth must be in the past.'); }
    } catch (Exception $e) { send_json_response(false, 'Invalid Date of Birth format provided.'); }


    // --- Handle File Upload ---
    $uploaded_file_path = null;
    $original_filename = null;
    $unique_filename = null;

    if (isset($_FILES['passport_photo']) && $_FILES['passport_photo']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['passport_photo'];
        $original_filename = preg_replace("/[^a-zA-Z0-9\.\-\_]/", "_", basename($file['name']));

        if ($file['size'] > MAX_FILE_SIZE) { send_json_response(false, 'File size exceeds 2MB limit.'); }

        if (!is_uploaded_file($file['tmp_name']) || !is_readable($file['tmp_name'])) {
             error_log("Upload error: tmp_name '{$file['tmp_name']}' is not valid or readable for {$original_filename}.");
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

        $file_extension = pathinfo($original_filename, PATHINFO_EXTENSION);
        $safe_extension = preg_replace('/[^a-zA-Z0-9]/', '', strtolower($file_extension));
        if (empty($safe_extension) || strlen($safe_extension) > 5) { $safe_extension = 'jpg'; }
        $unique_filename = uniqid('photo_', true) . '.' . $safe_extension;
        $destination = rtrim(UPLOAD_DIR, '/') . '/' . $unique_filename; // Ensure single slash

        if (!is_dir(UPLOAD_DIR)) {
            if (!mkdir(UPLOAD_DIR, 0755, true)) {
                 error_log("Failed to create upload directory: " . UPLOAD_DIR . " - Check parent directory permissions.");
                 send_json_response(false, 'Server configuration error: Could not create upload directory.');
            }
        } elseif (!is_writable(UPLOAD_DIR)) {
             error_log("Upload directory is not writable: " . UPLOAD_DIR . " - Check permissions.");
             send_json_response(false, 'Server configuration error: Upload directory not writable.');
        }

        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $uploaded_file_path = $destination;
        } else {
             $error_details = error_get_last();
             error_log("Failed to move uploaded file '{$original_filename}' to: " . $destination . ". Error: " . ($error_details['message'] ?? 'Unknown error'));
            send_json_response(false, 'Failed to save uploaded photo due to a server error.');
        }
    } else {
        // Handle specific file upload errors explicitly
        $error_code = $_FILES['passport_photo']['error'] ?? UPLOAD_ERR_NO_FILE;
        $upload_error_message = 'Passport photo upload failed.';
         switch ($error_code) { /* Cases as before */
            case UPLOAD_ERR_INI_SIZE: case UPLOAD_ERR_FORM_SIZE: $upload_error_message = 'File size exceeds server limit.'; break;
            case UPLOAD_ERR_PARTIAL: $upload_error_message = 'File was only partially uploaded.'; break;
            case UPLOAD_ERR_NO_FILE: $upload_error_message = 'No file was uploaded or file was empty.'; break;
            case UPLOAD_ERR_NO_TMP_DIR: $upload_error_message = 'Server error: Missing temporary folder.'; break;
            case UPLOAD_ERR_CANT_WRITE: $upload_error_message = 'Server error: Failed to write file to disk.'; break;
            case UPLOAD_ERR_EXTENSION: $upload_error_message = 'Server error: File upload stopped by a PHP extension.'; break;
            default: $upload_error_message = 'Unknown upload error. Code: ' . $error_code; break;
         }
         send_json_response(false, $upload_error_message);
    }


    // --- Prepare Data for Razorpay Order API ---
    $receipt_id = 'rcptid_' . time() . '_' . uniqid();
    $amount_in_paise = filter_var($post_data['amount'], FILTER_VALIDATE_INT);
    $currency = strtoupper($post_data['currency']);

    if ($currency !== 'INR') { send_json_response(false, 'Invalid currency specified. Only INR is supported.'); }
    if ($amount_in_paise === false || $amount_in_paise <= 0) { send_json_response(false, 'Invalid payment amount received from the form.'); }
    // Optional: Server-side amount check
    // define('EXPECTED_FEE_PAISE', 100 * 100);
    // if ($amount_in_paise !== EXPECTED_FEE_PAISE) { send_json_response(false, 'Payment amount mismatch.'); }


    $order_data = [
        'receipt'         => $receipt_id,
        'amount'          => $amount_in_paise,
        'currency'        => $currency,
        'payment_capture' => 1,
        'notes'           => [
            'player_name'  => $post_data['name'],
            'player_email' => $post_data['email'],
            'registration' => 'Paradise Handball League 2025'
         ]
    ];

    // --- Call Razorpay API using cURL ---
    if (!function_exists('curl_init')) {
        error_log("cURL extension is not installed or enabled.");
        send_json_response(false, "Server configuration error: cURL is required but not available.");
    }

    $api_url = 'https://api.razorpay.com/v1/orders';
    $auth_header = 'Authorization: Basic ' . base64_encode(RAZORPAY_KEY_ID . ':' . RAZORPAY_KEY_SECRET);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $api_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($order_data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', $auth_header]);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
    curl_setopt($ch, CURLOPT_TIMEOUT, 45);
    // curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); // Should be true in production
    // curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);   // Should be 2 in production

    $response = curl_exec($ch);
    $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error_no = curl_errno($ch);
    $curl_error = curl_error($ch);
    curl_close($ch);

    // --- Handle API Response ---
    if ($curl_error_no) {
         error_log("cURL Error #{$curl_error_no} creating Razorpay order: " . $curl_error);
         if ($uploaded_file_path && file_exists($uploaded_file_path)) { @unlink($uploaded_file_path); }
        send_json_response(false, 'Error communicating with payment gateway (' . $curl_error_no . '). Please try again later.');
    }

    $response_data = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE && $http_status >= 200 && $http_status < 300) {
        error_log("Failed to decode Razorpay JSON response. HTTP Status: $http_status, Response: $response");
         if ($uploaded_file_path && file_exists($uploaded_file_path)) { @unlink($uploaded_file_path); }
        send_json_response(false, 'Received an invalid response from payment gateway.');
    }

    if ($http_status >= 200 && $http_status < 300 && isset($response_data['id'])) {
        send_json_response(true, 'Order created successfully.', [
            'order_id' => $response_data['id'],
            'amount'   => $response_data['amount'],
            'currency' => $response_data['currency'],
            'original_filename' => $original_filename // Send sanitized original filename back
        ]);
    } else {
        $error_message = 'Failed to create payment order.';
        if (isset($response_data['error']['description'])) {
            $error_message .= ' Reason: ' . htmlspecialchars($response_data['error']['description']);
        } elseif (!empty($response)) {
             $error_message .= ' Unexpected response received.';
        }
         error_log("Razorpay order creation failed: HTTP Status $http_status, Response: $response");
         if ($uploaded_file_path && file_exists($uploaded_file_path)) { @unlink($uploaded_file_path); }
        send_json_response(false, $error_message);
    }

// --- Action: Verify Razorpay Payment ---
} elseif ($action === 'verify_payment') {

    // --- Define Required Fields for Verification ---
    $required_verify_fields = [
        'razorpay_payment_id', 'razorpay_order_id', 'razorpay_signature',
        'email', 'name', 'father_name', 'mother_name', 'dob', 'phone', 'gender', 'district', 'aadhaar',
        'district_achievements', 'state_achievements', 'national_achievements', 'player_position', 'basic_price',
        'passport_photo_filename'
    ];

    // --- Validate Required POST Fields for Verification ---
    foreach ($required_verify_fields as $field) {
        if (!isset($_POST[$field]) || trim((string)$_POST[$field]) === '') {
            error_log("Missing field during payment verification: " . $field);
            send_json_response(false, "Payment verification failed: Missing required information.");
        }
    }

    // --- Sanitize All Inputs for Verification Step ---
    $post_data = sanitize_input($_POST); // Sanitize most data
    // Get raw signature details directly from $_POST before sanitization
    $razorpay_payment_id = trim($_POST['razorpay_payment_id']);
    $razorpay_order_id = trim($_POST['razorpay_order_id']);
    $razorpay_signature = trim($_POST['razorpay_signature']);
    // Use the sanitized filename from post_data
    $original_photo_filename = $post_data['passport_photo_filename'];


    // --- Verify Signature ---
    $signature_payload = $razorpay_order_id . '|' . $razorpay_payment_id;

    if (RAZORPAY_KEY_SECRET === 'YOUR_KEY_SECRET' || RAZORPAY_KEY_SECRET === '') {
         error_log("Razorpay Secret Key is not configured in register.php during verification.");
         send_json_response(false, "Payment gateway configuration error during verification.");
    }

    try {
        $expected_signature = hash_hmac('sha256', $signature_payload, RAZORPAY_KEY_SECRET);
        if (!hash_equals($expected_signature, $razorpay_signature)) {
            error_log("Signature verification failed for Order ID: {$razorpay_order_id}, Payment ID: {$razorpay_payment_id}.");
            send_json_response(false, 'Payment verification failed: Invalid signature.');
        }
    } catch (Exception $e) {
        error_log("Error during signature verification hash_hmac: " . $e->getMessage());
        send_json_response(false, 'Payment verification failed due to server error.');
    }

    // --- Signature is Valid - Payment Successful ---

    // --- Compose Email ---
    $subject = "New Player Registration - Paradise Handball League 2025 - " . $post_data['name'];
    // (HTML Email Body remains the same as previous version - using $post_data for content)
    $email_body = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>$subject</title><style>";
    $email_body .= "body { font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }";
    $email_body .= ".container { max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }";
    $email_body .= "h2 { color: #4a90e2; border-bottom: 2px solid #4a90e2; padding-bottom: 10px; margin-bottom: 20px; }";
    $email_body .= "h3 { color: #333; margin-top: 25px; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }";
    $email_body .= "table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }";
    $email_body .= "th, td { text-align: left; padding: 10px; border: 1px solid #ddd; vertical-align: top; }";
    $email_body .= "th { background-color: #f8f8f8; font-weight: bold; width: 170px; }";
    $email_body .= ".footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #777; }";
    $email_body .= "</style></head><body>";
    $email_body .= "<div class='container'>";
    $email_body .= "<h2>Paradise Handball League 2025</h2>";
    $email_body .= "<p>A new player has successfully registered and paid the fee.</p>";
    $email_body .= "<h3>Player Details</h3><table>";
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
    $email_body .= "<h3>Achievements</h3><table>";
    $email_body .= "<tr><th>District:</th><td>" . $post_data['district_achievements'] . "</td></tr>";
    $email_body .= "<tr><th>State:</th><td>" . $post_data['state_achievements'] . "</td></tr>";
    $email_body .= "<tr><th>National:</th><td>" . $post_data['national_achievements'] . "</td></tr>";
    $email_body .= "</table>";
    $email_body .= "<h3>Payment Details</h3><table>";
    $email_body .= "<tr><th>Razorpay Payment ID:</th><td>" . htmlspecialchars($razorpay_payment_id) . "</td></tr>"; // Display raw ID
    $email_body .= "<tr><th>Razorpay Order ID:</th><td>" . htmlspecialchars($razorpay_order_id) . "</td></tr>";   // Display raw ID
    $email_body .= "</table>";
    $email_body .= "<h3>Uploaded Photo</h3>";
    $email_body .= "<p>Photo Filename (as uploaded): <strong>" . $original_photo_filename . "</strong></p>";
    $email_body .= "<p>(The actual file is stored in the server's 'uploads' directory, likely under a unique system-generated name).</p>";
    $email_body .= "<div class='footer'><p><em>This is an automated message. Please do not reply directly.</em></p></div>";
    $email_body .= "</div></body></html>";


    // Set Email Headers
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8" . "\r\n";
    $headers .= 'From: Paradise Handball League <' . SENDER_EMAIL . '>' . "\r\n";
    $headers .= 'Reply-To: ' . SENDER_EMAIL . "\r\n";

    // --- Send Email ---
    if (ADMIN_EMAIL === 'syedmutaibnazir@gmail.com' || SENDER_EMAIL === 'mutoibnazirbukhari@gmail.com') {
         error_log("Admin/Sender email not configured. Skipping email notification for Order ID: {$razorpay_order_id}");
         send_json_response(true, 'Registration successful! Payment verified. (Email notification skipped due to configuration).');
    } else {
        if (mail(ADMIN_EMAIL, $subject, $email_body, $headers)) {
            send_json_response(true, 'Registration successful! Payment verified and details have been emailed to the admin.');
        } else {
            $error_info = error_get_last();
            error_log("Failed to send registration email to " . ADMIN_EMAIL . " for order " . $razorpay_order_id . ". Error: " . ($error_info['message'] ?? 'Unknown mail() error'));
            send_json_response(true, 'Payment verified, but there was an issue sending the confirmation email. Registration data is saved. Please contact support if needed.');
        }
    }

} else {
    // --- Invalid Action ---
    error_log("Invalid action specified in POST request: " . print_r($_POST, true));
    send_json_response(false, 'Invalid action specified.');
}

?>
