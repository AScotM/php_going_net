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

// Color codes for output
const COLORS = [
    'LISTEN' => "\033[32m",      // Green
    'ESTABLISHED' => "\033[36m", // Cyan
    'TIME_WAIT' => "\033[33m",   // Yellow
    'CLOSE_WAIT' => "\033[31m",  // Red
    'FIN_WAIT1' => "\033[35m",   // Magenta
    'FIN_WAIT2' => "\033[35m",   // Magenta
    'reset' => "\033[0m"
];

// Cache for process information to avoid repeated lookups
$processCache = [];

/**
 * Performance tracking class
 */
class PerformanceTracker {
    private static $startTime;
    private static $memoryPeak = 0;
    private static $operations = 0;
    
    public static function start(): void {
        self::$startTime = microtime(true);
        self::$memoryPeak = memory_get_peak_usage(true);
    }
    
    public static function recordOperation(): void {
        self::$operations++;
        $currentMemory = memory_get_peak_usage(true);
        if ($currentMemory > self::$memoryPeak) {
            self::$memoryPeak = $currentMemory;
        }
    }
    
    public static function getMetrics(): array {
        $endTime = microtime(true);
        return [
            'execution_time' => round($endTime - self::$startTime, 4),
            'memory_peak_mb' => round(self::$memoryPeak / 1024 / 1024, 2),
            'operations' => self::$operations,
            'timestamp' => date('c')
        ];
    }
}

/**
 * Process cache with TTL
 */
class ProcessCache {
    private static $cache = [];
    private static $lastBuild = 0;
    private const CACHE_TTL = 5; // seconds
    
    public static function getProcessMap(): array {
        $now = time();
        if (empty(self::$cache) || ($now - self::$lastBuild) > self::CACHE_TTL) {
            self::$cache = self::buildProcessMap();
            self::$lastBuild = $now;
        }
        return self::$cache;
    }
    
    private static function buildProcessMap(): array {
        $processMap = [];
        $processDirs = glob('/proc/[0-9]*', GLOB_NOSORT);
        
        foreach ($processDirs as $processDir) {
            $pid = basename($processDir);
            
            // Skip if process directory disappeared
            if (!is_dir($processDir)) continue;
            
            $commPath = $processDir . '/comm';
            $processName = @file_get_contents($commPath);
            $processName = $processName ? trim($processName) . " (PID: $pid)" : "PID: $pid";
            
            $fdPath = $processDir . '/fd';
            if (!is_dir($fdPath)) continue;
            
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
}

/**
 * Convert hex IPv4/IPv6 from /proc into readable form.
 */
function hexToIp(string $hex, int $family) {
    if ($family === AF_INET && strlen($hex) === 8) {
        $bytes = array_reverse(str_split($hex, 2));
        return implode('.', array_map('hexdec', $bytes));
    }

    if ($family === AF_INET6 && strlen($hex) === 32) {
        // More direct IPv6 parsing
        $ipv6 = '';
        for ($i = 0; $i < 32; $i += 4) {
            $word = substr($hex, $i, 4);
            $ipv6 .= dechex(hexdec($word)) . ':';
        }
        $ipv6 = rtrim($ipv6, ':');
        
        // Handle compression properly
        return compressIPv6($ipv6);
    }

    return false;
}

/**
 * Compress IPv6 address by replacing longest zero sequence with ::
 */
function compressIPv6(string $ipv6): string {
    // Replace the longest sequence of zeros with ::
    $compressed = preg_replace('/(^|:)(0+:)+0+($|:)/', '::', $ipv6, 1);
    // Handle multiple compressions edge case
    return preg_replace('/::+/', '::', $compressed);
}

/** Convert hex port to int. */
function hexToPort(string $hex): int {
    return hexdec($hex);
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
 * Check if IP matches filter (supports CIDR notation)
 */
function ipMatchesFilter(string $ip, string $filter): bool {
    // Exact match
    if ($ip === $filter) {
        return true;
    }
    
    // CIDR notation match
    if (strpos($filter, '/') !== false) {
        return ipInCidr($ip, $filter);
    }
    
    // Partial match (original behavior)
    return strpos($ip, $filter) !== false;
}

/**
 * Check if IP is within CIDR range
 */
function ipInCidr(string $ip, string $cidr): bool {
    list($subnet, $mask) = explode('/', $cidr);
    $mask = (int)$mask;
    
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        
        $maskLong = -1 << (32 - $mask);
        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
    
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // For IPv6, fall back to partial matching for simplicity
        // A full IPv6 CIDR implementation would be more complex
        return strpos($ip, $subnet) === 0;
    }
    
    return false;
}

/**
 * Get color code for connection state
 */
function getStateColor(string $state): string {
    return COLORS[$state] ?? "\033[37m"; // Default to white
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
    $processMap = $includeProcess ? ProcessCache::getProcessMap() : null;
    
    // Skip header line
    fgets($handle);
    
    while (($line = fgets($handle)) !== false) {
        PerformanceTracker::recordOperation();
        
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
            $color = getStateColor($c['state']);
            $reset = COLORS['reset'];
            
            printf(
                "%-5s {$color}%-15s{$reset} %-25s %-25s %-30s\n",
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
            $color = getStateColor($c['state']);
            $reset = COLORS['reset'];
            
            printf(
                "%-5s {$color}%-15s{$reset} %-25s %-25s\n",
                $c['proto'],
                $c['state'],
                "{$c['local_ip']}:{$c['local_port']}",
                "{$c['remote_ip']}:{$c['remote_port']}"
            );
        }
    }

    $stats = getConnectionStats($connections);
    displaySummary($stats);
}

/**
 * Display connection summary with colored states
 */
function displaySummary(array $stats): void {
    echo "\nSummary: " . $stats['total'] . " total connections ({$stats['ipv4']} IPv4, {$stats['ipv6']} IPv6)\n";
    
    if (!empty($stats['by_state'])) {
        echo "By state: ";
        $stateStrings = [];
        foreach ($stats['by_state'] as $state => $count) {
            $color = getStateColor($state);
            $reset = COLORS['reset'];
            $stateStrings[] = "{$color}{$state}{$reset}: $count";
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
 * Enhanced connection filtering with CIDR support
 */
function filterConnections(array $connections, array $options): array {
    $filtered = $connections;
    
    // State filtering
    $states = [];
    if (isset($options['listen'])) $states[] = 'LISTEN';
    if (isset($options['established'])) $states[] = 'ESTABLISHED';
    if (isset($options['timewait'])) $states[] = 'TIME_WAIT';
    if (isset($options['closewait'])) $states[] = 'CLOSE_WAIT';
    if (isset($options['finwait'])) {
        $states[] = 'FIN_WAIT1';
        $states[] = 'FIN_WAIT2';
    }
    
    if ($states) {
        $filtered = array_filter($filtered, fn($c) => in_array($c['state'], $states, true));
    }
    
    // Port filtering
    if (isset($options['port'])) {
        $port = (int)$options['port'];
        $filtered = array_filter($filtered, fn($c) => 
            $c['local_port'] === $port || $c['remote_port'] === $port);
    }
    
    // IP address filtering with CIDR support
    if (isset($options['local-ip'])) {
        $localIp = $options['local-ip'];
        $filtered = array_filter($filtered, fn($c) => 
            ipMatchesFilter($c['local_ip'], $localIp));
    }
    
    if (isset($options['remote-ip'])) {
        $remoteIp = $options['remote-ip'];
        $filtered = array_filter($filtered, fn($c) => 
            ipMatchesFilter($c['remote_ip'], $remoteIp));
    }
    
    // Protocol filtering
    if (isset($options['ipv4'])) {
        $filtered = array_filter($filtered, fn($c) => $c['proto'] === 'IPv4');
    }
    
    if (isset($options['ipv6'])) {
        $filtered = array_filter($filtered, fn($c) => $c['proto'] === 'IPv6');
    }
    
    return array_values($filtered);
}

/**
 * Get connection changes between two snapshots
 */
function getConnectionChanges(array $old, array $new): array {
    $oldKeys = array_map('getConnectionKey', $old);
    $newKeys = array_map('getConnectionKey', $new);
    
    $added = array_diff($newKeys, $oldKeys);
    $removed = array_diff($oldKeys, $newKeys);
    
    return [
        'added' => $added,
        'removed' => $removed,
        'total_changes' => count($added) + count($removed)
    ];
}

/**
 * Generate unique key for connection comparison
 */
function getConnectionKey(array $conn): string {
    return "{$conn['local_ip']}:{$conn['local_port']}-{$conn['remote_ip']}:{$conn['remote_port']}-{$conn['state']}";
}

/**
 * Display connection changes in watch mode
 */
function displayChanges(array $changes, int $iteration): void {
    if ($iteration === 1) return; // Skip first iteration
    
    $totalChanges = $changes['total_changes'];
    if ($totalChanges === 0) {
        echo "No changes since last refresh\n";
        return;
    }
    
    echo "Changes: \033[32m+" . count($changes['added']) . "\033[0m \033[31m-" . count($changes['removed']) . "\033[0m\n";
    
    if (!empty($changes['added'])) {
        echo "\033[32mNew connections:\033[0m\n";
        foreach (array_slice($changes['added'], 0, 3) as $key) { // Show first 3
            echo "  + $key\n";
        }
        if (count($changes['added']) > 3) {
            echo "  ... and " . (count($changes['added']) - 3) . " more\n";
        }
    }
    
    if (!empty($changes['removed'])) {
        echo "\033[31mClosed connections:\033[0m\n";
        foreach (array_slice($changes['removed'], 0, 3) as $key) { // Show first 3
            echo "  - $key\n";
        }
        if (count($changes['removed']) > 3) {
            echo "  ... and " . (count($changes['removed']) - 3) . " more\n";
        }
    }
    
    echo "\n";
}

/**
 * Watch mode for continuous monitoring with change detection
 */
function watchMode(array $options, int $interval = 2): void {
    $lastConnections = [];
    $startTime = time();
    $iteration = 0;
    
    echo "Watching TCP connections (refresh every {$interval}s). Press Ctrl+C to stop.\n";
    echo "Started at: " . date('Y-m-d H:i:s') . "\n\n";
    
    if (function_exists('pcntl_signal')) {
        pcntl_signal(SIGINT, function() use ($startTime) {
            $duration = time() - $startTime;
            echo "\n\nMonitoring stopped after {$duration} seconds.\n";
            exit(0);
        });
    }
    
    while (true) {
        $iteration++;
        echo "\033[2J\033[;H"; // Clear screen
        
        $connections = array_merge(
            readTcpConnections('/proc/net/tcp', AF_INET, $options['processes'] ?? false),
            readTcpConnections('/proc/net/tcp6', AF_INET6, $options['processes'] ?? false)
        );
        
        $connections = filterConnections($connections, $options);
        $currentCount = count($connections);
        
        // Show changes
        $changes = getConnectionChanges($lastConnections, $connections);
        displayChanges($changes, $iteration);
        
        echo "[" . date('H:i:s') . "] Iteration: $iteration | Connections: $currentCount\n";
        echo str_repeat("-", 60) . "\n";
        
        if (isset($options['json'])) {
            outputJson($connections, $options['stats'] ?? false);
        } else {
            displayConnections($connections, $options['processes'] ?? false);
        }
        
        $lastConnections = $connections;
        
        if (function_exists('pcntl_signal_dispatch')) {
            pcntl_signal_dispatch();
        }
        
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
        $color = getStateColor($state);
        $reset = COLORS['reset'];
        printf("{$color}%-20s{$reset}: %d\n", $state, $count);
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

    // Start performance tracking
    PerformanceTracker::start();

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
    $options = getopt("jlp:w:v", [
        "json", "help", "listen", "established", "count", "processes", 
        "timewait", "closewait", "finwait", "port:", "watch", 
        "local-ip:", "remote-ip:", "stats", "ipv4", "ipv6", "verbose"
    ]);

    if (isset($options['help'])) {
        echo "Usage: php {$script} [options]\n";
        echo "Options:\n";
        echo "  --json         Output connections in JSON format\n";
        echo "  --listen       Show only listening sockets\n";
        echo "  --established  Show only established connections\n";
        echo "  --timewait     Show only TIME_WAIT connections\n";
        echo "  --closewait    Show only CLOSE_WAIT connections\n";
        echo "  --finwait      Show only FIN_WAIT1/FIN_WAIT2 connections\n";
        echo "  --count        Only show counts (IPv4/IPv6/total)\n";
        echo "  --processes    Show process information (slower)\n";
        echo "  --port <num>   Filter by port number\n";
        echo "  --local-ip <ip>  Filter by local IP address (supports CIDR)\n";
        echo "  --remote-ip <ip> Filter by remote IP address (supports CIDR)\n";
        echo "  --ipv4         Show only IPv4 connections\n";
        echo "  --ipv6         Show only IPv6 connections\n";
        echo "  --watch [sec]    Refresh continuously (default: 2s)\n";
        echo "  --stats          Show detailed statistics\n";
        echo "  --verbose, -v    Show performance metrics\n";
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
        
        // Show performance metrics if requested
        if (isset($options['verbose'])) {
            $metrics = PerformanceTracker::getMetrics();
            echo "\nPerformance Metrics:\n";
            echo "Execution time: {$metrics['execution_time']}s\n";
            echo "Memory peak: {$metrics['memory_peak_mb']} MB\n";
            echo "Operations: {$metrics['operations']}\n";
        }
        
        exit(0);
    }

    if (isset($options['count'])) {
        $stats = getConnectionStats($connections);
        echo "Counts: total=" . $stats['total'] . " IPv4={$stats['ipv4']} IPv6={$stats['ipv6']}\n";
        
        if (!empty($stats['by_state'])) {
            echo "By state: ";
            $stateStrings = [];
            foreach ($stats['by_state'] as $state => $count) {
                $color = getStateColor($state);
                $reset = COLORS['reset'];
                $stateStrings[] = "{$color}{$state}{$reset}: $count";
            }
            echo implode(", ", $stateStrings) . "\n";
        }
        
        exit(0);
    }

    if (isset($options['stats'])) {
        displayStatistics($connections);
        
        // Show performance metrics if requested
        if (isset($options['verbose'])) {
            $metrics = PerformanceTracker::getMetrics();
            echo "\nPerformance Metrics:\n";
            echo "Execution time: {$metrics['execution_time']}s\n";
            echo "Memory peak: {$metrics['memory_peak_mb']} MB\n";
            echo "Operations: {$metrics['operations']}\n";
        }
        
        exit(0);
    }

    if (isset($options['j']) || isset($options['json'])) {
        outputJson($connections, $options['stats'] ?? false);
    } else {
        displayConnections($connections, $includeProcess);
    }
    
    // Show performance metrics if requested
    if (isset($options['verbose'])) {
        $metrics = PerformanceTracker::getMetrics();
        echo "\nPerformance Metrics:\n";
        echo "Execution time: {$metrics['execution_time']}s\n";
        echo "Memory peak: {$metrics['memory_peak_mb']} MB\n";
        echo "Operations: {$metrics['operations']}\n";
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
