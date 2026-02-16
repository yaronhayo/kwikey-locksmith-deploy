<?php
/**
 * Shared API Utilities
 * cspell:disable
 */

/**
 * Basic IP-based rate limiting using flat files
 */
function isAllowed(string $ip, int $limit = 5, int $window = 3600): bool {
    $dir = __DIR__ . '/.rate_limit';
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0777, true)) return true; // Fail-open
    }

    // Use SHA256 for deterministic but more secure filename hashing
    $file = $dir . '/' . hash('sha256', $ip);
    $now = time();
    $data = is_file($file) ? json_decode(file_get_contents($file), true) : [];

    if (!is_array($data)) $data = [];

    // Filter out old timestamps
    $data = array_filter($data, function($ts) use ($now, $window) {
        return ($now - $ts) < $window;
    });

    if (count($data) >= $limit) return false;

    $data[] = $now;
    file_put_contents($file, json_encode(array_values($data)));
    return true;
}

/**
 * Sanitizes email to prevent header injection
 */
function sanitizeEmail(string $email): string {
    return preg_replace('/[\x00-\x1F\x7F]/', '', $email);
}

/**
 * Sends email via SMTP2GO
 */
function sendSmtp2goEmail(array $config, string $to, string $subject, string $html, string $replyTo = ''): array {
    $payload = [
        'api_key'   => $config['smtp2go_api_key'],
        'to'        => [$to],
        'sender'    => $config['sender_name'] . ' <' . $config['sender_email'] . '>',
        'subject'   => $subject,
        'html_body' => $html,
        'text_body' => strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $html)),
    ];

    if ($replyTo) {
        $payload['custom_headers'] = [['header' => 'Reply-To', 'value' => $replyTo]];
    }

    $ch = curl_init('https://api.smtp2go.com/v3/email/send');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_TIMEOUT        => 15,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    // curl_close() is deprecated in PHP 8.5 and unnecessary in PHP 8.0+
    $result = json_decode($response, true);

    if ($httpCode >= 200 && $httpCode < 300 && ($result['data']['succeeded'] ?? 0) > 0) {
        return ['success' => true, 'messageId' => $result['data']['email_id'] ?? ''];
    }

    return ['success' => false, 'error' => $result['data']['error'] ?? 'Failed to send email'];
}
