<?php
/*
Plugin Name: IP Fail Ban
Description: Blocks IP subnets after repeated failed login attempts, similar to ipfailban.
Version: 1.0
Author: Infactionfreddy
*/

class IPFailBan {
    private $failThreshold = 5;   // Number of failed attempts before blocking
    private $banTime = 3600;      // Ban duration in seconds
    private $subnetMask = 24;     // Subnet mask for ban (IPv4 only)
    private $optionAttempts = 'ipfailban_failed_attempts';
    private $optionBlocked = 'ipfailban_blocked_subnets';

    private function get_subnet($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_long = ip2long($ip);
            $mask = -1 << (32 - $this->subnetMask);
            $subnet = long2ip($ip_long & $mask) . '/' . $this->subnetMask;
            return $subnet;
        }
        // Optional: Add IPv6 support here
        return false;
    }

    public function register_failed_login($ip) {
        $subnet = $this->get_subnet($ip);
        if (!$subnet) return;
        $now = time();

        $failedAttempts = get_option($this->optionAttempts, []);
        if (!isset($failedAttempts[$subnet])) {
            $failedAttempts[$subnet] = [];
        }
        $failedAttempts[$subnet][] = $now;
        // Remove old attempts
        $failedAttempts[$subnet] = array_filter(
            $failedAttempts[$subnet],
            function($t) use ($now) { return $now - $t < $this->banTime; }
        );
        update_option($this->optionAttempts, $failedAttempts);

        // Block if threshold reached
        if (count($failedAttempts[$subnet]) >= $this->failThreshold) {
            $blockedSubnets = get_option($this->optionBlocked, []);
            $blockedSubnets[$subnet] = $now + $this->banTime;
            update_option($this->optionBlocked, $blockedSubnets);
        }
    }

    public function is_blocked($ip) {
        $subnet = $this->get_subnet($ip);
        if (!$subnet) return false;
        $blockedSubnets = get_option($this->optionBlocked, []);
        if (isset($blockedSubnets[$subnet])) {
            if (time() < $blockedSubnets[$subnet]) {
                return true;
            } else {
                // Unblock expired subnets
                unset($blockedSubnets[$subnet]);
                update_option($this->optionBlocked, $blockedSubnets);
            }
        }
        return false;
    }
}

$ipFailBan = new IPFailBan();

// On failed login event
add_action('wp_login_failed', function($username) use ($ipFailBan) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $ipFailBan->register_failed_login($ip);
});

// Block login if subnet is banned
add_filter('authenticate', function($user, $username, $password) use ($ipFailBan) {
    $ip = $_SERVER['REMOTE_ADDR'];
    if ($ipFailBan->is_blocked($ip)) {
        // Optionally log this event
        return new WP_Error('ip_banned', __('Your subnet is temporarily blocked due to repeated failed logins.'));
    }
    return $user;
}, 1, 3);
