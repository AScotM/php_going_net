#!/usr/bin/php
<?php
/**
 * TCP Connection Monitor - Enhanced PHP Version
 * Parses /proc/net/tcp and /proc/net/tcp6 to show active IPv4 and IPv6 connections
 * 
 * Only works on Linux systems with access to /proc.
 * Usage: php tcp_monitor.php [--json] [--listen] [--established] [--count] [--processes] [--watch] [--stats]
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
        // More robust IPv6 parsing
        $pairs = str_split($hex, 4);
        $ipv6 = '';
        foreach ($pairs as $pair) {
            $ipv6 .= str_pad(dechex(hexdec($pair)), 4, '0', STR_PAD_LEFT) . ':';
        }
        $ipv6 = rtrim($ipv6, ':');
        
        // Compress the IPv6 address
        $packed = @inet_pton($ipv6);
        if ($packed === false) {
            return false;
        }
        return @inet_ntop($packed);
    }

    return false;
}

/** Convert hex port to int. */
function hexToPort(string $hex): int {
    return hexdec($hex);
}

/**
 * More efficient process mapping by scanning /proc once
 */
function buildProcessMap(): array {
    $processMap = [];
    $processDirs = glob('/proc/[0-9]*', GLOB_NOSORT);
    
    foreach ($processDirs as $processDir) {
        $pid = basename($processDir);
        $fdPath = $processDir . '/fd';
        
        if (!is_dir($fdPath)) continue;
        
        // Get process name once per PID
        $commPath = $processDir . '/comm';
        $processName = @file_get_contents($commPath);
        $processName = $processName ? trim($processName) . " (PID: $pid)" : "PID: $pid";
        
        // Scan all file descriptors for sockets
        $fds = @scandir($fdPath);
        if ($fds === false) continue;
        
        foreach ($fds as $fd) {
            if ($fd === '.' || $fd === '..') continue;
            
            $link = @readlink($fdPath . '/' . $fd);
            if ($link && preg_match('/socket:\[(\d+)\]/', $link, $matches)) {
                $inode = $matches[1];
                $processMap[$inode] = $processName;
            }
        }
    }
    
    return $processMap;
}

/**
 * Get process name from inode number
 */
function getProcessByInode($inode, array &$processMap = null) {
    global $processCache;
    
    if (isset($processCache[$inode])) {
        return $processCache[$inode];
    }
    
    // Use pre-built map if available
    if ($processMap !== null && isset($processMap[$inode])) {
        $processCache[$inode] = $processMap[$inode];
        return $processMap[$inode];
    }
    
    // Fallback to individual lookup
    return lookupProcessByInode($inode);
}

/**
 * Fallback individual process lookup
 */
function lookupProcessByInode($inode) {
    global $processCache;
    
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
 * Stream-based reading for large /proc files
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

    $handle = @fopen($file, 'r');
    if ($handle === false) {
        fwrite(STDERR, "Error: Unable to read $file.\n");
        return $connections;
    }

    // Pre-build process map if needed (more efficient)
    $processMap = $includeProcess ? buildProcessMap() : null;
    
    // Skip header line
    fgets($handle);
    
    while (($line = fgets($handle)) !== false) {
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
        $process = $includeProcess ? getProcessByInode($inode, $processMap) : '';

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
    
    fclose($handle);
    return $connections;
}

/**
 * Get detailed connection statistics
 */
function getConnectionStats(array $connections): array {
    $stats = [
        'total' => count($connections),
        'ipv4' => 0,
        'ipv6' => 0,
        'by_state' => [],
        'by_process' => [],
        'timestamp' => date('c')
    ];
    
    foreach ($connections as $conn) {
        // Protocol counts
        if ($conn['proto'] === 'IPv4') {
            $stats['ipv4']++;
        } else {
            $stats['ipv6']++;
        }
        
        // State counts
        $stats['by_state'][$conn['state']] = ($stats['by_state'][$conn['state']] ?? 0) + 1;
        
        // Process counts (if available)
        if (!empty($conn['process'])) {
            $stats['by_process'][$conn['process']] = ($stats['by_process'][$conn['process']] ?? 0) + 1;
        }
    }
    
    return $stats;
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

    $stats = getConnectionStats($connections);
    
    echo "\nSummary: " . $stats['total'] . " total connections ({$stats['ipv4']} IPv4, {$stats['ipv6']} IPv6)\n";
    
    if (!empty($stats['by_state'])) {
        echo "By state: ";
        $stateStrings = [];
        foreach ($stats['by_state'] as $state => $count) {
            $stateStrings[] = "$state: $count";
        }
        echo implode(", ", $stateStrings) . "\n";
    }
}

/** JSON output (safe for invalid UTF-8). */
function outputJson(array $connections, bool $includeStats = false): void {
    if ($includeStats) {
        $output = [
            'connections' => $connections,
            'statistics' => getConnectionStats($connections),
            'metadata' => [
                'generated_at' => date('c'),
                'count' => count($connections)
            ]
        ];
    } else {
        $output = $connections;
    }
    
    echo json_encode($output, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
}

/**
 * Apply CLI state filters.
 */
function filterConnections(array $connections, array $options): array {
    $filtered = $connections;
    
    // State filtering
    $states = [];
    if (isset($options['listen'])) $states[] = 'LISTEN';
    if (isset($options['established'])) $states[] = 'ESTABLISHED';
    if (isset($options['timewait'])) $states[] = 'TIME_WAIT';
    
    if ($states) {
        $filtered = array_filter($filtered, fn($c) => in_array($c['state'], $states, true));
    }
    
    // Port filtering
    if (isset($options['port'])) {
        $port = (int)$options['port'];
        $filtered = array_filter($filtered, fn($c) => 
            $c['local_port'] === $port || $c['remote_port'] === $port);
    }
    
    // IP address filtering
    if (isset($options['local-ip'])) {
        $localIp = $options['local-ip'];
        $filtered = array_filter($filtered, fn($c) => 
            strpos($c['local_ip'], $localIp) !== false);
    }
    
    if (isset($options['remote-ip'])) {
        $remoteIp = $options['remote-ip'];
        $filtered = array_filter($filtered, fn($c) => 
            strpos($c['remote_ip'], $remoteIp) !== false);
    }
    
    return array_values($filtered);
}

/**
 * Watch mode for continuous monitoring
 */
function watchMode(array $options, int $interval = 2): void {
    $lastCount = 0;
    $startTime = time();
    
    echo "Watching TCP connections (refresh every {$interval}s). Press Ctrl+C to stop.\n";
    echo "Started at: " . date('Y-m-d H:i:s') . "\n\n";
    
    // Setup signal handler for graceful exit
    if (function_exists('pcntl_signal')) {
        pcntl_signal(SIGINT, function() use ($startTime) {
            $duration = time() - $startTime;
            echo "\n\nMonitoring stopped after {$duration} seconds.\n";
            exit(0);
        });
    }
    
    while (true) {
        // Clear screen (ANSI escape code)
        echo "\033[2J\033[;H";
        
        $connections = array_merge(
            readTcpConnections('/proc/net/tcp', AF_INET, $options['processes'] ?? false),
            readTcpConnections('/proc/net/tcp6', AF_INET6, $options['processes'] ?? false)
        );
        
        $connections = filterConnections($connections, $options);
        $currentCount = count($connections);
        
        // Show change indicator
        $change = $currentCount - $lastCount;
        $changeSymbol = $change > 0 ? "↑+$change" : ($change < 0 ? "↓$change" : "→");
        
        echo "[" . date('H:i:s') . "] Connections: $currentCount $changeSymbol\n";
        echo str_repeat("-", 50) . "\n";
        
        if (isset($options['json'])) {
            outputJson($connections, $options['stats'] ?? false);
        } else {
            displayConnections($connections, $options['processes'] ?? false);
        }
        
        // Handle signals in watch mode
        if (function_exists('pcntl_signal_dispatch')) {
            pcntl_signal_dispatch();
        }
        
        $lastCount = $currentCount;
        sleep($interval);
    }
}

/**
 * Display detailed statistics
 */
function displayStatistics(array $connections): void {
    $stats = getConnectionStats($connections);
    
    echo "\nDETAILED TCP CONNECTION STATISTICS\n";
    echo str_repeat("=", 50) . "\n";
    echo "Generated at: " . $stats['timestamp'] . "\n";
    echo "Total connections: " . $stats['total'] . "\n";
    echo "IPv4 connections: " . $stats['ipv4'] . "\n";
    echo "IPv6 connections: " . $stats['ipv6'] . "\n\n";
    
    echo "Connections by State:\n";
    echo str_repeat("-", 30) . "\n";
    foreach ($stats['by_state'] as $state => $count) {
        printf("%-20s: %d\n", $state, $count);
    }
    
    if (!empty($stats['by_process'])) {
        echo "\nConnections by Process (Top 10):\n";
        echo str_repeat("-", 50) . "\n";
        
        // Sort by count descending
        uasort($stats['by_process'], function($a, $b) {
            return $b <=> $a;
        });
        
        $count = 0;
        foreach ($stats['by_process'] as $process => $connCount) {
            printf("%-40s: %d\n", $process, $connCount);
            if (++$count >= 10) break;
        }
    }
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
    $options = getopt("jlp:w:", [
        "json", "help", "listen", "established", "count", "processes", 
        "timewait", "port:", "watch", "local-ip:", "remote-ip:", "stats"
    ]);

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
        echo "  --local-ip <ip>  Filter by local IP address\n";
        echo "  --remote-ip <ip> Filter by remote IP address\n";
        echo "  --watch [sec]    Refresh continuously (default: 2s)\n";
        echo "  --stats          Show detailed statistics\n";
        echo "  --help         Show this help message\n";
        exit(0);
    }

    // Handle watch mode
    if (isset($options['watch'])) {
        $interval = is_numeric($options['watch']) ? (int)$options['watch'] : 2;
        if ($interval < 1) $interval = 1;
        watchMode($options, $interval);
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
        $stats = getConnectionStats($connections);
        echo "Counts: total=" . $stats['total'] . " IPv4={$stats['ipv4']} IPv6={$stats['ipv6']}\n";
        
        if (!empty($stats['by_state'])) {
            echo "By state: ";
            $stateStrings = [];
            foreach ($stats['by_state'] as $state => $count) {
                $stateStrings[] = "$state: $count";
            }
            echo implode(", ", $stateStrings) . "\n";
        }
        
        exit(0);
    }

    if (isset($options['stats'])) {
        displayStatistics($connections);
        exit(0);
    }

    if (isset($options['j']) || isset($options['json'])) {
        outputJson($connections, $options['stats'] ?? false);
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
