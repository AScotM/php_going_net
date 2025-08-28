#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - Enhanced PHP Version
 * Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections
 * 
 * Only works on Linux systems with access to /proc.
 * Usage: php tcp_monitor.php [--json] [--listen] [--established] [--count] [--processes]
 */

// ---- Safe constant definitions ----
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

// Cache for process information to avoid repeated lookups
$processCache = [];

/**
 * Convert hex IPv4/IPv6 from /proc into readable form.
 */
function hexToIp(string $hex, int $family) {
    if ($family === AF_INET && strlen($hex) === 8) {
        $bytes = array_reverse(str_split($hex, 2));
        return implode('.', array_map('hexdec', $bytes));
    }

    if ($family === AF_INET6 && strlen($hex) === 32) {
        $chunks = str_split($hex, 8);
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
 * Get process name from inode number
 */
function getProcessByInode($inode) {
    global $processCache;
    
    if (isset($processCache[$inode])) {
        return $processCache[$inode];
    }
    
    $processName = "unknown";
    
    // Search through /proc/*/fd/* to find the process using this inode
    $processDirs = glob('/proc/[0-9]*', GLOB_NOSORT);
    foreach ($processDirs as $processDir) {
        $fdPath = $processDir . '/fd';
        if (!is_dir($fdPath)) continue;
        
        $fds = @scandir($fdPath);
        if ($fds === false) continue;
        
        foreach ($fds as $fd) {
            if ($fd === '.' || $fd === '..') continue;
            
            $link = @readlink($fdPath . '/' . $fd);
            if ($link && strpos($link, 'socket:[' . $inode . ']') !== false) {
                $pid = basename($processDir);
                $cmdline = @file_get_contents($processDir . '/comm');
                if ($cmdline) {
                    $processName = trim($cmdline) . " (PID: $pid)";
                } else {
                    $processName = "PID: $pid";
                }
                $processCache[$inode] = $processName;
                return $processName;
            }
        }
    }
    
    $processCache[$inode] = $processName;
    return $processName;
}

/**
 * Read TCP connections from a /proc file for a protocol family.
 */
function readTcpConnections(string $file, int $family, bool $includeProcess = false): array {
    $connections = [];

    if (!file_exists($file)) {
        fwrite(STDERR, "Error: File $file does not exist.\n");
        return $connections;
    }
    
    if (!is_readable($file)) {
        fwrite(STDERR, "Error: File $file is not readable.\n");
        return $connections;
    }

    $content = @file_get_contents($file);
    if ($content === false) {
        fwrite(STDERR, "Error: Unable to read $file.\n");
        return $connections;
    }

    $lines = explode("\n", $content);
    array_shift($lines); // skip header line
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        $fields = preg_split('/\s+/', $line);
        if (count($fields) < 10) {
            continue;
        }

        list($localIpHex, $localPortHex) = explode(':', $fields[1], 2);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2], 2);

        $localIp = hexToIp($localIpHex, $family);
        $remoteIp = hexToIp($remoteIpHex, $family);
        
        if ($localIp === false || $remoteIp === false) {
            continue;
        }

        $localPort = hexToPort($localPortHex);
        $remotePort = hexToPort($remotePortHex);

        $stateCode = strtoupper($fields[3]);
        $state = TCP_STATES[$stateCode] ?? "UNKNOWN(0x$stateCode)";
        $proto = ($family === AF_INET) ? 'IPv4' : 'IPv6';
        
        $inode = $fields[9]; // inode number
        $process = $includeProcess ? getProcessByInode($inode) : '';

        $connections[] = [
            'proto'       => $proto,
            'state'       => $state,
            'local_ip'    => $localIp,
            'local_port'  => $localPort,
            'remote_ip'   => $remoteIp,
            'remote_port' => $remotePort,
            'inode'       => $inode,
            'process'     => $process,
        ];
    }
    
    return $connections;
}

/** Sort and pretty-print connections. */
function displayConnections(array $connections, bool $showProcess = false): void {
    usort($connections, function ($a, $b) {
        return $a['local_port'] <=> $b['local_port'] ?: 
               strcmp($a['proto'], $b['proto']);
    });

    echo "\nACTIVE TCP CONNECTIONS:\n";
    if ($showProcess) {
        printf("%-5s %-15s %-25s %-25s %-30s\n", "Proto", "State", "Local Address", "Remote Address", "Process");
        echo str_repeat("-", 105) . "\n";
        foreach ($connections as $c) {
            printf(
                "%-5s %-15s %-25s %-25s %-30s\n",
                $c['proto'],
                $c['state'],
                "{$c['local_ip']}:{$c['local_port']}",
                "{$c['remote_ip']}:{$c['remote_port']}",
                substr($c['process'], 0, 30)
            );
        }
    } else {
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
    }

    $ipv4 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv4'));
    $ipv6 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv6'));
    
    $stateCounts = [];
    foreach ($connections as $c) {
        $stateCounts[$c['state']] = ($stateCounts[$c['state']] ?? 0) + 1;
    }
    
    echo "\nSummary: " . count($connections) . " total connections ($ipv4 IPv4, $ipv6 IPv6)\n";
    
    if (!empty($stateCounts)) {
        echo "By state: ";
        $stateStrings = [];
        foreach ($stateCounts as $state => $count) {
            $stateStrings[] = "$state: $count";
        }
        echo implode(", ", $stateStrings) . "\n";
    }
}

/** JSON output (safe for invalid UTF-8). */
function outputJson(array $connections): void {
    echo json_encode($connections, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
}

/**
 * Apply CLI state filters.
 */
function filterConnections(array $connections, array $options): array {
    $states = [];
    if (isset($options['listen'])) {
        $states[] = 'LISTEN';
    }
    if (isset($options['established'])) {
        $states[] = 'ESTABLISHED';
    }
    if (isset($options['timewait'])) {
        $states[] = 'TIME_WAIT';
    }
    
    if ($states) {
        $connections = array_filter($connections, fn($c) => in_array($c['state'], $states, true));
    }
    
    // Filter by port if specified
    if (isset($options['port'])) {
        $port = (int)$options['port'];
        $connections = array_filter($connections, fn($c) => 
            $c['local_port'] === $port || $c['remote_port'] === $port);
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
    if (!stristr(PHP_OS, 'Linux')) {
        fwrite(STDERR, "Error: This script is only supported on Linux systems.\n");
        exit(1);
    }

    // Privilege hint
    if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
        fwrite(STDERR, "Note: Some information may be limited without root privileges.\n");
    }

    $script = basename($_SERVER['argv'][0] ?? 'tcp_monitor.php');
    $options = getopt("jlp:", ["json", "help", "listen", "established", "count", "processes", "timewait", "port:"]);

    if (isset($options['help'])) {
        echo "Usage: php {$script} [options]\n";
        echo "Options:\n";
        echo "  --json         Output connections in JSON format\n";
        echo "  --listen       Show only listening sockets\n";
        echo "  --established  Show only established connections\n";
        echo "  --timewait     Show only TIME_WAIT connections\n";
        echo "  --count        Only show counts (IPv4/IPv6/total)\n";
        echo "  --processes    Show process information (slower)\n";
        echo "  --port <num>   Filter by port number\n";
        echo "  --help         Show this help message\n";
        exit(0);
    }

    $includeProcess = isset($options['processes']);
    
    // Read both IPv4 and IPv6 sockets
    $connections = array_merge(
        readTcpConnections('/proc/net/tcp', AF_INET, $includeProcess),
        readTcpConnections('/proc/net/tcp6', AF_INET6, $includeProcess)
    );

    // Apply filters
    $connections = filterConnections($connections, $options);

    if (empty($connections)) {
        echo "No matching TCP connections found.\n";
        exit(0);
    }

    if (isset($options['count'])) {
        $ipv4 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv4'));
        $ipv6 = count(array_filter($connections, fn($c) => $c['proto'] === 'IPv6'));
        
        $stateCounts = [];
        foreach ($connections as $c) {
            $stateCounts[$c['state']] = ($stateCounts[$c['state']] ?? 0) + 1;
        }
        
        echo "Counts: total=" . count($connections) . " IPv4={$ipv4} IPv6={$ipv6}\n";
        
        if (!empty($stateCounts)) {
            echo "By state: ";
            $stateStrings = [];
            foreach ($stateCounts as $state => $count) {
                $stateStrings[] = "$state: $count";
            }
            echo implode(", ", $stateStrings) . "\n";
        }
        
        exit(0);
    }

    if (isset($options['j']) || isset($options['json'])) {
        outputJson($connections);
    } else {
        displayConnections($connections, $includeProcess);
    }
}

// Handle script termination
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        fwrite(STDERR, "Fatal error: {$error['message']} in {$error['file']} on line {$error['line']}\n");
    }
});

main();
