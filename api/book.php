<?php
// cspell:disable
header('X-Frame-Options: ' . 'DENY');
header('X-Content-Type-Options: ' . 'nosniff');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: https://kwikeylocksmith.com');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
header('Referrer-Policy: strict-origin-when-cross-origin');

/**
 * Booking Form API Endpoint
 * Handles booking form submissions with validation, reCAPTCHA, and SMTP2GO email
 */

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'errors' => ['Method not allowed']]);
    exit;
}

// Rate limiting
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
require __DIR__ . '/utils.php';

if (!isAllowed($ip)) {
    http_response_code(429);
    echo json_encode(['success' => false, 'errors' => ['Too many requests. Please try again later.']]);
    exit;
}

// Load config
$config = require __DIR__ . '/config.php';

// Parse form data
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
$data = [];

if (strpos($contentType, 'application/json') !== false) {
    $data = json_decode(file_get_contents('php://input'), true) ?? [];
} else {
    $data = $_POST;
}

// Validation
$errors = [];
$name = trim($data['name'] ?? '');
$email = trim($data['email'] ?? '');
$phone = trim($data['phone'] ?? '');
$service = trim($data['service'] ?? '');
$recaptchaToken = $data['recaptchaToken'] ?? '';

if (empty($name)) $errors[] = 'Name is required';
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email is required';
if (empty($service)) $errors[] = 'Service type is required';
if (empty($recaptchaToken)) $errors[] = 'reCAPTCHA verification failed';

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

// Verify reCAPTCHA
$ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, [
    'secret'   => $config['recaptcha_secret_key'],
    'response' => $recaptchaToken,
    'remoteip' => $ip
]);
$response = curl_exec($ch);
// curl_close() is deprecated in PHP 8.5 and unnecessary in PHP 8.0+
$recaptchaResult = json_decode($response, true);

if (!$recaptchaResult['success']) {
    http_response_code(400);
    echo json_encode(['success' => false, 'errors' => ['reCAPTCHA verification failed. Please try again.']]);
    exit;
}

// Prepare email content
$subject = "New Booking Request: $service - $name";
$html = "
    <h2>New Booking Request</h2>
    <p><strong>Name:</strong> $name</p>
    <p><strong>Email:</strong> $email</p>
    <p><strong>Phone:</strong> $phone</p>
    <p><strong>Service:</strong> $service</p>
    <p><strong>Location Info:</strong> Obtained via website form</p>
";

$result = sendSmtp2goEmail($config, $config['notification_email'], $subject, $html, $email);

if ($result['success']) {
    echo json_encode(['success' => true, 'message' => 'Booking request sent successfully']);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'errors' => [$result['error']]]);
}
