#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - Improved PHP Version
 * Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections
 *
 * Only works on Linux systems with access to /proc.
 * Usage: php tcp_monitor.php [--json] [--listen] [--established] [--count]
 */

// ---- Safe constant definitions (avoid redefinition warnings) ----
defined('AF_INET')  || define('AF_INET', 2);
defined('AF_INET6') || define('AF_INET6', 10);
defined('JSON_INVALID_UTF8_SUBSTITUTE') || define('JSON_INVALID_UTF8_SUBSTITUTE', 0);

// TCP state mappings (from the Linux kernel)
const TCP_STATES = [
    '01' => "ESTABLISHED",
    '02' => "SYN_SENT",
    '03' => "SYN_RECV",
    '04' => "FIN_WAIT1",
    '05' => "FIN_WAIT2",
    '06' => "TIME_WAIT",
    '07' => "CLOSE",
    '08' => "CLOSE_WAIT",
    '09' => "LAST_ACK",
    '0A' => "LISTEN",
    '0B' => "CLOSING",
    '0C' => "NEW_SYN_RECV",
];

/**
 * Convert hex IPv4/IPv6 from /proc into readable form.
 * - IPv4 is little-endian byte order (reverse bytes).
 * - IPv6 in /proc/net/tcp6 is little-endian per 32-bit chunk; reverse bytes within each 4-byte chunk.
 */
function hexToIp(string $hex, int $family) {
    if ($family === AF_INET && strlen($hex) === 8) {
        $bytes = array_reverse(str_split($hex, 2)); // reverse 4 bytes
        return implode('.', array_map('hexdec', $bytes));
    }

    if ($family === AF_INET6 && strlen($hex) === 32) {
        // Reverse bytes within each 4-byte (8-hex) chunk, keep chunk order
        $chunks = str_split($hex, 8); // 4 chunks * 8 hex = 32 hex total
        $fixed  = '';
        foreach ($chunks as $chunk) {
            $fixed .= implode('', array_reverse(str_split($chunk, 2)));
        }
        $packed = @pack('H*', $fixed);
        if ($packed === false) {
            return false;
        }
        $ip = @inet_ntop($packed);
        return $ip !== false ? $ip : false;
    }

    return false;
}

/** Convert hex port to int. */
function hexToPort(string $hex): int {
    return hexdec($hex);
}

/**
 * Read TCP connections from a /proc file for a protocol family.
 *
 * @param string $file   /proc/net/tcp or /proc/net/tcp6
 * @param int    $family AF_INET or AF_INET6
 * @return array<array<string,mixed>>
 */
function readTcpConnections(string $file, int $family): array {
    $connections = [];

    if (!file_exists($file)) {
        fwrite(STDERR, "Error: File $file does not exist.\n");
        return $connections;
    }
    if (!is_readable($file)) {
        fwrite(STDERR, "Error: File $file is not readable.\n");
        return $connections;
    }

    $handle = fopen($file, 'r');
    if ($handle === false) {
        fwrite(STDERR, "Error: Unable to open $file.\n");
        return $connections;
    }

    fgets($handle); // skip header line
    while (($line = fgets($handle)) !== false) {
        $fields = preg_split('/\s+/', trim($line));
        if (count($fields) < 4) {
            continue;
        }

        // fields[1] = local_address (IP:PORT), fields[2] = rem_address, fields[3] = state
        if (strpos($fields[1], ':') === false || strpos($fields[2], ':') === false) {
            continue;
        }
        list($localIpHex, $localPortHex)   = explode(':', $fields[1], 2);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2], 2);

        $localIp    = hexToIp($localIpHex, $family);
        $remoteIp   = hexToIp($remoteIpHex, $family);
        if ($localIp === false || $remoteIp === false) {
            continue;
        }

        $localPort  = hexToPort($localPortHex);
        $remotePort = hexToPort($remotePortHex);

        $stateCode  = strtoupper($fields[3]);
        $state      = TCP_STATES[$stateCode] ?? "UNKNOWN(0x$stateCode)";
        $proto      = ($family === AF_INET) ? 'IPv4' : 'IPv6';

        $connections[] = [
            'proto'       => $proto,
            'state'       => $state,
            'local_ip'    => $localIp,
            'local_port'  => $localPort,
            'remote_ip'   => $remoteIp,
            'remote_port' => $remotePort,
        ];
    }
    fclose($handle);
    return $connections;
}

/** Sort and pretty-print connections. */
function displayConnections(array $connections): void {
    usort($connections, function ($a, $b) {
        return strcmp($a['proto'] . $a['state'], $b['proto'] . $b['state']);
    });

    echo "\nACTIVE TCP CONNECTIONS:\n";
    printf("%-5s %-15s %-25s %-25s\n", "Proto", "State", "Local Address", "Remote Address");
    echo str_repeat("-", 75) . "\n";
    foreach ($connections as $c) {
        printf(
            "%-5s %-15s %-25s %-25s\n",
            $c['proto'],
            $c['state'],
            "{$c['local_ip']}:{$c['local_port']}",
            "{$c['remote_ip']}:{$c['remote_port']}"
        );
    }

    $ipv4 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv4'));
    $ipv6 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv6'));
    echo "\nFound " . count($connections) . " active connections ($ipv4 IPv4, $ipv6 IPv6)\n";
}

/** JSON output (safe for invalid UTF-8). */
function outputJson(array $connections): void {
    echo json_encode($connections, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
}

/**
 * Apply CLI state filters.
 * - If --listen and --established are both present, show union of both.
 */
function filterConnections(array $connections, array $options): array {
    $states = [];
    if (isset($options['listen'])) {
        $states[] = 'LISTEN';
    }
    if (isset($options['established'])) {
        $states[] = 'ESTABLISHED';
    }
    if ($states) {
        $connections = array_filter($connections, fn($c) => in_array($c['state'], $states, true));
    }
    return array_values($connections);
}

/** Main */
function main(): void {
    if (php_sapi_name() !== 'cli') {
        fwrite(STDERR, "This script must be run from the command line.\n");
        exit(1);
    }

    // OS check
    if (defined('PHP_OS_FAMILY')) {
        if (PHP_OS_FAMILY !== 'Linux') {
            fwrite(STDERR, "Error: This script is only supported on Linux systems.\n");
            exit(1);
        }
    } else {
        // Fallback for older PHP versions
        if (stripos(PHP_OS, 'Linux') !== 0) {
            fwrite(STDERR, "Error: This script is only supported on Linux systems.\n");
            exit(1);
        }
    }

    // Privilege hint (only if POSIX ext is available)
    if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
        fwrite(STDERR, "Warning: This script may require root privileges to access /proc/net/tcp*.\n");
    }

    $script = basename($_SERVER['argv'][0] ?? 'tcp_monitor.php');
    $options = getopt("j", ["json", "help", "listen", "established", "count"]);

    if (isset($options['help'])) {
        echo "Usage: php {$script} [--json] [--listen] [--established] [--count]\n";
        echo "  --json         Output connections in JSON format\n";
        echo "  --listen       Show only listening sockets\n";
        echo "  --established  Show only established connections\n";
        echo "  --count        Only show counts (IPv4/IPv6/total)\n";
        echo "  --help         Show this help message\n";
        exit(0);
    }

    // Read both IPv4 and IPv6 sockets
    $connections = array_merge(
        readTcpConnections('/proc/net/tcp', AF_INET),
        readTcpConnections('/proc/net/tcp6', AF_INET6)
    );

    // Apply filters
    $connections = filterConnections($connections, $options);

    if (empty($connections)) {
        echo "No matching TCP connections found.\n";
        exit(2);
    }

    if (isset($options['count'])) {
        $ipv4 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv4'));
        $ipv6 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv6'));
        echo "Counts: total=" . count($connections) . " IPv4={$ipv4} IPv6={$ipv6}\n";
        exit(0);
    }

    if (isset($options['j']) || isset($options['json'])) {
        outputJson($connections);
    } else {
        displayConnections($connections);
    }
}

main();
