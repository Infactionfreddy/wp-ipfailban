<?php
/*
Plugin Name: IP Fail Ban
Description: Blocks IP subnets after repeated failed login attempts, similar to ipfailban. Adds admin menu for ban management.
Version: 1.1
Author: Infactionfreddy
*/

class IPFailBan {
    private $failThreshold = 5;
    private $banTime = 3600;
    private $subnetMask = 24;
    private $optionAttempts = 'ipfailban_failed_attempts';
    private $optionBlocked = 'ipfailban_blocked_subnets';

    private function get_subnet($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_long = ip2long($ip);
            $mask = -1 << (32 - $this->subnetMask);
            $subnet = long2ip($ip_long & $mask) . '/' . $this->subnetMask;
            return $subnet;
        }
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
        $failedAttempts[$subnet] = array_filter(
            $failedAttempts[$subnet],
            function($t) use ($now) { return $now - $t < $this->banTime; }
        );
        update_option($this->optionAttempts, $failedAttempts);

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
                unset($blockedSubnets[$subnet]);
                update_option($this->optionBlocked, $blockedSubnets);
            }
        }
        return false;
    }

    // Admin: Get all banned subnets
    public function get_blocked_subnets() {
        $blockedSubnets = get_option($this->optionBlocked, []);
        $result = [];
        foreach ($blockedSubnets as $subnet => $unblockTime) {
            if (time() < $unblockTime) {
                $result[$subnet] = $unblockTime;
            }
        }
        return $result;
    }

    // Admin: Unban a subnet
    public function unban_subnet($subnet) {
        $blockedSubnets = get_option($this->optionBlocked, []);
        if (isset($blockedSubnets[$subnet])) {
            unset($blockedSubnets[$subnet]);
            update_option($this->optionBlocked, $blockedSubnets);
        }
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
        return new WP_Error('ip_banned', __('Your subnet is temporarily blocked due to repeated failed logins.'));
    }
    return $user;
}, 1, 3);

// Admin menu for banned IPs
add_action('admin_menu', function() use ($ipFailBan) {
    add_menu_page(
        'IP Fail Ban',
        'IP Fail Ban',
        'manage_options',
        'ip-failban-admin',
        function() use ($ipFailBan) {
            // Unban if requested
            if (isset($_GET['unban']) && is_admin()) {
                $subnet = sanitize_text_field($_GET['unban']);
                $ipFailBan->unban_subnet($subnet);
                echo '<div class="notice notice-success"><p>Subnet ' . esc_html($subnet) . ' wurde entbannt.</p></div>';
            }

            echo '<div class="wrap"><h1>IP Fail Ban Übersicht</h1>';
            $blocked = $ipFailBan->get_blocked_subnets();
            if (empty($blocked)) {
                echo '<p>Keine gebannten Subnets.</p>';
            } else {
                echo '<table class="widefat"><thead><tr><th>Subnet</th><th>Ban-Ende</th><th>Aktion</th></tr></thead><tbody>';
                foreach ($blocked as $subnet => $until) {
                    echo '<tr>';
                    echo '<td>' . esc_html($subnet) . '</td>';
                    echo '<td>' . esc_html(date('Y-m-d H:i:s', $until)) . '</td>';
                    echo '<td><a href="' . esc_url(admin_url('admin.php?page=ip-failban-admin&unban=' . urlencode($subnet))) . '" class="button">Entbannen</a></td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }
            echo '</div>';
        },
        'dashicons-shield-alt'
    );
});
