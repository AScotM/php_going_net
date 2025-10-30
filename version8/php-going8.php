#!/usr/bin/env php
<?php

/**
 * TCP/UDP Connection Monitor - PHP Version
 * Parses /proc/net/{tcp,udp,tcp6,udp6} to show active IPv4/IPv6 TCP/UDP connections
 * Maintains all features: IPv6 conversion, CIDR matching, UDP support, CSV/JSON outputs, alerts, config file
 */

declare(strict_types=1);

class ConnectionMonitor {
    // Color codes for output
    private const RED = "\033[31m";
    private const GREEN = "\033[32m";
    private const YELLOW = "\033[33m";
    private const BLUE = "\033[34m";
    private const MAGENTA = "\033[35m";
    private const CYAN = "\033[36m";
    private const WHITE = "\033[37m";
    private const BOLD = "\033[1m";
    private const RESET = "\033[0m";

    // TCP state mappings
    private const TCP_STATES = [
        '01' => 'ESTABLISHED',
        '02' => 'SYN_SENT',
        '03' => 'SYN_RECV',
        '04' => 'FIN_WAIT1',
        '05' => 'FIN_WAIT2',
        '06' => 'TIME_WAIT',
        '07' => 'CLOSE',
        '08' => 'CLOSE_WAIT',
        '09' => 'LAST_ACK',
        '0A' => 'LISTEN',
        '0B' => 'CLOSING',
        '0C' => 'NEW_SYN_RECV',
    ];

    // UDP states
    private const UDP_STATES = [
        '0A' => 'LISTEN',
        '07' => 'UNCONNECTED',
    ];

    // State colors
    private const STATE_COLORS = [
        'LISTEN' => self::GREEN,
        'ESTABLISHED' => self::CYAN,
        'TIME_WAIT' => self::YELLOW,
        'CLOSE_WAIT' => self::RED,
        'FIN_WAIT1' => self::MAGENTA,
        'FIN_WAIT2' => self::MAGENTA,
        'SYN_SENT' => self::BLUE,
        'SYN_RECV' => self::BLUE,
        'UNCONNECTED' => self::WHITE,
        'UNKNOWN' => self::RED,
    ];

    // Configuration defaults
    private array $config;
    private array $processCache = [];
    private array $connectionCache = [];
    private float $lastProcessScan = 0;
    private float $lastConnectionScan = 0;
    private float $scriptStartTime;
    private int $operationCount = 0;
    private const SCRIPT_VERSION = '2.0-php';

    public function __construct() {
        $this->scriptStartTime = microtime(true);
        $this->initializeConfig();
        $this->loadConfig();
    }

    private function initializeConfig(): void {
        $this->config = [
            'refresh_interval' => 2,
            'process_cache_ttl' => 5,
            'max_display_processes' => 10,
            'connection_cache_ttl' => 1,
            'show_udp' => false,
            'csv_output' => false,
            'alert_state' => '',
            'alert_threshold' => 0,
            'json_output' => false,
            'show_processes' => false,
            'show_count' => false,
            'show_stats' => false,
            'watch_mode' => false,
            'verbose' => false,
            'alert_mode' => false,
            'filter_states' => [],
            'filter_port' => '',
            'filter_local_ip' => '',
            'filter_remote_ip' => '',
            'filter_ipv4' => false,
            'filter_ipv6' => false,
            'output_file' => '',
            'include_una' => true,
            'sender_id' => 'SENDER',
            'receiver_id' => 'RECEIVER',
            'max_segment_length' => 2000,
        ];
    }

    private function loadConfig(): void {
        $configFile = getenv('HOME') . '/.tcpmonrc';
        if (is_readable($configFile)) {
            $lines = file($configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos($line, '=') !== false) {
                    [$key, $value] = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value);
                    
                    switch ($key) {
                        case 'REFRESH_INTERVAL':
                        case 'PROCESS_CACHE_TTL':
                        case 'MAX_DISPLAY_PROCESSES':
                        case 'CONNECTION_CACHE_TTL':
                        case 'ALERT_THRESHOLD':
                            if (ctype_digit($value)) {
                                $this->config[strtolower($key)] = (int)$value;
                            }
                            break;
                        case 'SHOW_UDP':
                            $this->config['show_udp'] = ($value === 'true');
                            break;
                        case 'ALERT_STATE':
                            $this->config['alert_state'] = $value;
                            break;
                    }
                }
            }
            $this->info("Loaded config from $configFile");
        }
    }

    private function die(string $message): void {
        echo self::RED . "Error: " . self::RESET . $message . PHP_EOL;
        exit(1);
    }

    private function warn(string $message): void {
        echo self::YELLOW . "Warning: " . self::RESET . $message . PHP_EOL;
    }

    private function info(string $message): void {
        if ($this->config['verbose']) {
            echo self::BLUE . "Info: " . self::RESET . $message . PHP_EOL;
        }
    }

    private function recordOperation(): void {
        $this->operationCount++;
    }

    private function getPerformanceMetrics(): string {
        $endTime = microtime(true);
        $executionTime = $endTime - $this->scriptStartTime;
        
        $memoryPeak = memory_get_peak_usage(true);
        $memoryPeakMB = round($memoryPeak / 1024 / 1024, 2);
        
        return sprintf(
            "Execution time: %.3fs\nMemory peak: %.2f MB\nOperations: %d\n",
            $executionTime,
            $memoryPeakMB,
            $this->operationCount
        );
    }

    private function validatePort(int $port): void {
        if ($port < 1 || $port > 65535) {
            $this->die("Port must be between 1 and 65535");
        }
    }

    private function validateInterval(int $interval): void {
        if ($interval < 1 || $interval > 3600) {
            $this->die("Interval must be between 1 and 3600 seconds");
        }
    }

    private function validateThreshold(int $threshold): void {
        if ($threshold < 0) {
            $this->die("Threshold must be a non-negative integer");
        }
    }

    private function validateIpCidr(string $ipCidr): void {
        if (strpos($ipCidr, '/') !== false) {
            [$ip, $mask] = explode('/', $ipCidr, 2);
            if (!ctype_digit($mask) || $mask < 0) {
                $this->die("Invalid CIDR mask: $mask");
            }
            
            // Validate IP format
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                $this->die("Invalid IP address in CIDR: $ip");
            }
            
            $maxMask = (strpos($ip, ':') !== false) ? 128 : 32;
            if ($mask > $maxMask) {
                $this->die("CIDR mask $mask exceeds maximum for IP type ($maxMask)");
            }
        } elseif (filter_var($ipCidr, FILTER_VALIDATE_IP) === false) {
            $this->die("Invalid IP or CIDR format: $ipCidr");
        }
    }

    private function ip4ToInt(string $ip): int {
        $octets = explode('.', $ip);
        return ($octets[0] << 24) + ($octets[1] << 16) + ($octets[2] << 8) + $octets[3];
    }

    private function cidr4Match(string $ip, string $network, int $mask): bool {
        $ipInt = $this->ip4ToInt($ip);
        $netInt = $this->ip4ToInt($network);
        $maskInt = (0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF;
        return ($ipInt & $maskInt) === ($netInt & $maskInt);
    }

    private function cidr6Match(string $ip, string $network, int $mask): bool {
        $prefixLen = (int)($mask / 4);
        $ipPrefix = substr($ip, 0, $prefixLen);
        $netPrefix = substr($network, 0, $prefixLen);
        return $ipPrefix === $netPrefix;
    }

    private function ipMatchesFilter(string $ip, string $filter, string $family): bool {
        if ($ip === $filter) {
            return true;
        }

        if (strpos($filter, '/') !== false) {
            [$network, $mask] = explode('/', $filter, 2);
            $mask = (int)$mask;
            
            if ($family === 'ipv4') {
                return $this->cidr4Match($ip, $network, $mask);
            } else {
                return $this->cidr6Match($ip, $network, $mask);
            }
        }

        return strpos($ip, $filter) !== false;
    }

    private function checkRequirements(): void {
        if (PHP_OS_FAMILY !== 'Linux') {
            $this->die("This script only works on Linux systems");
        }

        if (!is_dir('/proc')) {
            $this->die("/proc filesystem not available");
        }

        if ($this->config['show_processes'] && posix_geteuid() !== 0) {
            $this->warn("Some process information may be limited without root privileges");
        }
    }

    public function showHelp(): void {
        $scriptName = $this->getScriptName();
        $helpText = self::BOLD . "TCP/UDP Connection Monitor v" . self::SCRIPT_VERSION . self::RESET . "\n\n" .
                   self::BOLD . "Usage:" . self::RESET . " $scriptName [options]\n\n" .
                   self::BOLD . "Options:" . self::RESET . "\n" .
                   "  " . self::BOLD . "--json" . self::RESET . "              Output connections in JSON format\n" .
                   "  " . self::BOLD . "--csv" . self::RESET . "               Output connections in CSV format\n" .
                   "  " . self::BOLD . "--udp" . self::RESET . "               Include UDP connections\n" .
                   "  " . self::BOLD . "--listen" . self::RESET . "            Show only listening sockets\n" .
                   "  " . self::BOLD . "--established" . self::RESET . "       Show only established connections\n" .
                   "  " . self::BOLD . "--timewait" . self::RESET . "          Show only TIME_WAIT connections\n" .
                   "  " . self::BOLD . "--closewait" . self::RESET . "         Show only CLOSE_WAIT connections\n" .
                   "  " . self::BOLD . "--finwait" . self::RESET . "           Show only FIN_WAIT1/FIN_WAIT2 connections\n" .
                   "  " . self::BOLD . "--count" . self::RESET . "             Only show counts (IPv4/IPv6/total/TCP/UDP)\n" .
                   "  " . self::BOLD . "--processes" . self::RESET . "         Show process information (slower)\n" .
                   "  " . self::BOLD . "--port NUM" . self::RESET . "          Filter by port number\n" .
                   "  " . self::BOLD . "--local-ip IP" . self::RESET . "       Filter by local IP address (supports CIDR)\n" .
                   "  " . self::BOLD . "--remote-ip IP" . self::RESET . "      Filter by remote IP address (supports CIDR)\n" .
                   "  " . self::BOLD . "--ipv4" . self::RESET . "              Show only IPv4 connections\n" .
                   "  " . self::BOLD . "--ipv6" . self::RESET . "              Show only IPv6 connections\n" .
                   "  " . self::BOLD . "--watch [SEC]" . self::RESET . "       Refresh continuously (default: 2s)\n" .
                   "  " . self::BOLD . "--stats" . self::RESET . "             Show detailed statistics\n" .
                   "  " . self::BOLD . "--alert-state STATE" . self::RESET . " Enable alerts for state (e.g., CLOSE_WAIT)\n" .
                   "  " . self::BOLD . "--alert-threshold N" . self::RESET . " Alert if count > N (default: 0)\n" .
                   "  " . self::BOLD . "--output FILE" . self::RESET . "       Write output to file\n" .
                   "  " . self::BOLD . "--verbose, -v" . self::RESET . "       Show performance metrics and debug info\n" .
                   "  " . self::BOLD . "--version" . self::RESET . "           Show version\n" .
                   "  " . self::BOLD . "--help" . self::RESET . "              Show this help message\n\n" .
                   self::BOLD . "Config:" . self::RESET . " Edit ~/.tcpmonrc for defaults (e.g., REFRESH_INTERVAL=5)\n\n" .
                   self::BOLD . "Examples:" . self::RESET . "\n" .
                   "  $scriptName --listen --processes --udp\n" .
                   "  $scriptName --established --json\n" .
                   "  $scriptName --port 80 --ipv4\n" .
                   "  $scriptName --watch 5 --stats\n" .
                   "  $scriptName --local-ip \"192.168.1.0/24\" --alert-state CLOSE_WAIT --alert-threshold 50\n" .
                   "  $scriptName --csv --output connections.csv\n\n" .
                   self::BOLD . "Note:" . self::RESET . " Requires Linux and access to /proc filesystem\n";
        
        echo $helpText;
    }

    private function getScriptName(): string {
        return basename($_SERVER['argv'][0]);
    }

    public function showVersion(): void {
        echo "TCP/UDP Connection Monitor v" . self::SCRIPT_VERSION . PHP_EOL;
        exit(0);
    }

    private function hexToDec(string $hex): int {
        return intval($hex, 16);
    }

    private function hexToIpv4(string $hex): string {
        $hex = str_pad($hex, 8, '0', STR_PAD_LEFT);
        $octets = [
            $this->hexToDec(substr($hex, 0, 2)),
            $this->hexToDec(substr($hex, 2, 2)),
            $this->hexToDec(substr($hex, 4, 2)),
            $this->hexToDec(substr($hex, 6, 2))
        ];
        return implode('.', $octets);
    }

    private function hexToIpv6(string $hex): string {
        $hex = str_pad($hex, 32, '0', STR_PAD_LEFT);
        $hextets = [];
        
        for ($i = 0; $i < 32; $i += 4) {
            $hextet = substr($hex, $i, 4);
            $hextets[] = dechex(hexdec($hextet));
        }
        
        // Compress longest run of zeros
        $longestStart = 0;
        $longestLength = 0;
        $currentStart = 0;
        $currentLength = 0;
        
        foreach ($hextets as $i => $hextet) {
            if ($hextet === '0') {
                if ($currentLength === 0) {
                    $currentStart = $i;
                }
                $currentLength++;
            } else {
                if ($currentLength > $longestLength) {
                    $longestStart = $currentStart;
                    $longestLength = $currentLength;
                }
                $currentLength = 0;
            }
        }
        
        if ($currentLength > $longestLength) {
            $longestStart = $currentStart;
            $longestLength = $currentLength;
        }
        
        if ($longestLength > 1) {
            $before = array_slice($hextets, 0, $longestStart);
            $after = array_slice($hextets, $longestStart + $longestLength);
            
            if (empty($before) && empty($after)) {
                return '::';
            } elseif (empty($before)) {
                return '::' . implode(':', $after);
            } elseif (empty($after)) {
                return implode(':', $before) . '::';
            } else {
                return implode(':', $before) . '::' . implode(':', $after);
            }
        }
        
        return implode(':', $hextets);
    }

    private function buildProcessMap(): void {
        $this->info("Building process map...");
        $this->processCache = [];
        $currentTime = time();
        
        $inodes = [];
        $protoFiles = ['/proc/net/tcp', '/proc/net/tcp6', '/proc/net/udp', '/proc/net/udp6'];
        
        foreach ($protoFiles as $file) {
            if (!is_readable($file)) continue;
            
            $content = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            array_shift($content); // Skip header
            
            foreach ($content as $line) {
                if (preg_match('/\s+\d+:\s+[0-9A-F:]+\s+[0-9A-F:]+\s+[0-9A-F]+\s+[0-9A-F]+\s+[0-9A-F]+\s+[0-9A-F]+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\d+)/', $line, $matches)) {
                    $inodes[] = $matches[1];
                }
            }
        }
        
        $inodes = array_unique($inodes);
        
        foreach (glob('/proc/[0-9]*') as $pidDir) {
            $pid = basename($pidDir);
            $fdDir = "$pidDir/fd";
            
            if (!is_dir($fdDir) || !is_readable($fdDir)) continue;
            
            $processName = 'unknown';
            $commFile = "$pidDir/comm";
            if (is_readable($commFile)) {
                $processName = trim(file_get_contents($commFile)) . " (PID: $pid)";
            } else {
                $processName = "PID: $pid";
            }
            
            foreach (glob("$fdDir/*") as $fd) {
                $link = @readlink($fd);
                if ($link && preg_match('/socket:\[(\d+)\]/', $link, $matches)) {
                    $inode = $matches[1];
                    if (in_array($inode, $inodes)) {
                        $this->processCache[$inode] = $processName;
                    }
                }
            }
        }
        
        $this->lastProcessScan = $currentTime;
        $this->info("Process map built with " . count($this->processCache) . " entries");
    }

    private function getProcessByInode(string $inode): string {
        $currentTime = time();
        
        if (($currentTime - $this->lastProcessScan) >= $this->config['process_cache_ttl'] || empty($this->processCache)) {
            $this->buildProcessMap();
        }
        
        return $this->processCache[$inode] ?? 'unknown';
    }

    private function parseProtoFile(string $file, string $family, string $proto): array {
        if (!is_readable($file)) {
            $this->warn("Cannot read file: $file");
            return [];
        }
        
        $cacheKey = "{$file}_{$family}_{$proto}";
        $fileMtime = filemtime($file);
        $currentTime = time();
        
        if (($currentTime - $this->lastConnectionScan) < $this->config['connection_cache_ttl'] &&
            isset($this->connectionCache[$cacheKey]) &&
            $this->connectionCache[$cacheKey . '_mtime'] === $fileMtime) {
            $this->info("Using cached connections from $file ($proto)");
            return $this->connectionCache[$cacheKey];
        }
        
        $this->info("Parsing $file ($proto)");
        $connections = [];
        $content = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        array_shift($content); // Skip header
        
        foreach ($content as $line) {
            $this->recordOperation();
            
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 10) continue;
            
            $localAddr = $fields[1] ?? '';
            $remoteAddr = $fields[2] ?? '';
            $stateHex = $fields[3] ?? '';
            $inode = $fields[9] ?? '';
            
            if (empty($localAddr) || empty($remoteAddr) || empty($stateHex) || empty($inode)) {
                continue;
            }
            
            $localParts = explode(':', $localAddr);
            $remoteParts = explode(':', $remoteAddr);
            
            if (count($localParts) < 2 || count($remoteParts) < 2) {
                continue;
            }
            
            $localIpHex = $localParts[0];
            $localPortHex = $localParts[1];
            $remoteIpHex = $remoteParts[0];
            $remotePortHex = $remoteParts[1];
            
            $localPort = $this->hexToDec($localPortHex);
            $remotePort = $this->hexToDec($remotePortHex);
            
            if ($proto === 'tcp') {
                $state = self::TCP_STATES[$stateHex] ?? 'UNKNOWN';
            } else {
                $state = self::UDP_STATES[$stateHex] ?? 'UNCONNECTED';
            }
            
            if ($family === 'ipv4') {
                $localIp = $this->hexToIpv4($localIpHex);
                $remoteIp = $this->hexToIpv4($remoteIpHex);
            } else {
                $localIp = $this->hexToIpv6($localIpHex);
                $remoteIp = $this->hexToIpv6($remoteIpHex);
            }
            
            $process = '';
            if ($this->config['show_processes']) {
                $process = $this->getProcessByInode($inode);
            }
            
            $connections[] = [
                'proto_type' => $proto,
                'family' => $family,
                'state' => $state,
                'local_ip' => $localIp,
                'local_port' => $localPort,
                'remote_ip' => $remoteIp,
                'remote_port' => $remotePort,
                'inode' => $inode,
                'process' => $process
            ];
        }
        
        $this->connectionCache[$cacheKey] = $connections;
        $this->connectionCache[$cacheKey . '_mtime'] = $fileMtime;
        $this->lastConnectionScan = $currentTime;
        
        return $connections;
    }

    private function filterConnections(array $connections): array {
        return array_filter($connections, function($conn) {
            // State filter
            if (!empty($this->config['filter_states'])) {
                if (!in_array($conn['state'], $this->config['filter_states'])) {
                    return false;
                }
            }
            
            // Port filter
            if (!empty($this->config['filter_port'])) {
                $filterPort = (int)$this->config['filter_port'];
                if ($conn['local_port'] !== $filterPort && $conn['remote_port'] !== $filterPort) {
                    return false;
                }
            }
            
            // Local IP filter
            if (!empty($this->config['filter_local_ip'])) {
                if (!$this->ipMatchesFilter($conn['local_ip'], $this->config['filter_local_ip'], $conn['family'])) {
                    return false;
                }
            }
            
            // Remote IP filter
            if (!empty($this->config['filter_remote_ip'])) {
                if (!$this->ipMatchesFilter($conn['remote_ip'], $this->config['filter_remote_ip'], $conn['family'])) {
                    return false;
                }
            }
            
            // IP version filter
            if ($this->config['filter_ipv4'] && $conn['family'] !== 'ipv4') {
                return false;
            }
            if ($this->config['filter_ipv6'] && $conn['family'] !== 'ipv6') {
                return false;
            }
            
            return true;
        });
    }

    private function getAllConnections(): array {
        $connections = [];
        
        if ($this->config['show_udp']) {
            $connections = array_merge(
                $connections,
                $this->parseProtoFile('/proc/net/udp', 'ipv4', 'udp'),
                $this->parseProtoFile('/proc/net/udp6', 'ipv6', 'udp')
            );
        }
        
        $connections = array_merge(
            $connections,
            $this->parseProtoFile('/proc/net/tcp', 'ipv4', 'tcp'),
            $this->parseProtoFile('/proc/net/tcp6', 'ipv6', 'tcp')
        );
        
        return $this->filterConnections($connections);
    }

    private function getConnectionStats(array $connections): array {
        $stats = [
            'total' => 0,
            'tcp' => 0,
            'udp' => 0,
            'ipv4' => 0,
            'ipv6' => 0,
            'states' => [],
            'processes' => []
        ];
        
        foreach ($connections as $conn) {
            $stats['total']++;
            
            if ($conn['proto_type'] === 'tcp') {
                $stats['tcp']++;
            } else {
                $stats['udp']++;
            }
            
            if ($conn['family'] === 'ipv4') {
                $stats['ipv4']++;
            } else {
                $stats['ipv6']++;
            }
            
            $state = $conn['state'];
            $stats['states'][$state] = ($stats['states'][$state] ?? 0) + 1;
            
            $process = $conn['process'];
            if ($process && $process !== 'unknown') {
                $stats['processes'][$process] = ($stats['processes'][$process] ?? 0) + 1;
            }
        }
        
        return $stats;
    }

    private function checkAlert(array $stats, string $alertState, int $threshold): bool {
        $count = $stats['states'][$alertState] ?? 0;
        if ($count > $threshold) {
            echo self::RED . "ALERT: $alertState connections ($count) exceed threshold ($threshold)!" . self::RESET . PHP_EOL;
            return true;
        }
        return false;
    }

    private function coloredState(string $state): string {
        $color = self::STATE_COLORS[$state] ?? self::WHITE;
        return $color . $state . self::RESET;
    }

    private function displayConnectionsTable(array $connections): string {
        $output = self::BOLD . "ACTIVE CONNECTIONS (TCP/UDP)" . self::RESET . PHP_EOL . PHP_EOL;
        
        if ($this->config['show_processes']) {
            $output .= sprintf("%-6s %-6s %-15s %-25s %-25s %-30s\n", 
                "Proto", "Family", "State", "Local Address", "Remote Address", "Process");
            $output .= str_repeat('-', 120) . PHP_EOL;
        } else {
            $output .= sprintf("%-6s %-6s %-15s %-25s %-25s\n", 
                "Proto", "Family", "State", "Local Address", "Remote Address");
            $output .= str_repeat('-', 85) . PHP_EOL;
        }
        
        foreach ($connections as $conn) {
            $localAddr = $conn['local_ip'] . ':' . $conn['local_port'];
            $remoteAddr = $conn['remote_ip'] . ':' . $conn['remote_port'];
            
            if ($this->config['show_processes']) {
                $output .= sprintf("%-6s %-6s %s %-25s %-25s %-30s\n",
                    strtoupper($conn['proto_type']),
                    strtoupper($conn['family']),
                    $this->coloredState($conn['state']),
                    $localAddr,
                    $remoteAddr,
                    substr($conn['process'], 0, 30)
                );
            } else {
                $output .= sprintf("%-6s %-6s %s %-25s %-25s\n",
                    strtoupper($conn['proto_type']),
                    strtoupper($conn['family']),
                    $this->coloredState($conn['state']),
                    $localAddr,
                    $remoteAddr
                );
            }
        }
        
        return $output;
    }

    private function displaySummary(array $connections): string {
        $stats = $this->getConnectionStats($connections);
        $output = self::BOLD . "Summary:" . self::RESET . " {$stats['total']} total connections ";
        $output .= "({$stats['tcp']} TCP, {$stats['udp']} UDP; {$stats['ipv4']} IPv4, {$stats['ipv6']} IPv6)" . PHP_EOL;
        
        if (!empty($stats['states'])) {
            $output .= "By state: ";
            $stateParts = [];
            foreach ($stats['states'] as $state => $count) {
                $stateParts[] = $this->coloredState($state) . ": $count";
            }
            $output .= implode(', ', $stateParts) . PHP_EOL;
        }
        
        return $output;
    }

    private function displayConnectionsJson(array $connections): string {
        return json_encode($connections, JSON_PRETTY_PRINT);
    }

    private function displayConnectionsCsv(array $connections): string {
        $output = "Proto,Family,State,Local IP,Local Port,Remote IP,Remote Port,Inode,Process\n";
        
        foreach ($connections as $conn) {
            $escapedLocalIp = str_replace(',', '&#44;', $conn['local_ip']);
            $escapedRemoteIp = str_replace(',', '&#44;', $conn['remote_ip']);
            $escapedProcess = str_replace(',', '&#44;', $conn['process']);
            
            $output .= sprintf('"%s","%s","%s","%s",%d,"%s",%d,"%s","%s"' . PHP_EOL,
                strtoupper($conn['proto_type']),
                strtoupper($conn['family']),
                $conn['state'],
                $escapedLocalIp,
                $conn['local_port'],
                $escapedRemoteIp,
                $conn['remote_port'],
                $conn['inode'],
                $escapedProcess
            );
        }
        
        return $output;
    }

    private function displayStatistics(array $connections): string {
        $stats = $this->getConnectionStats($connections);
        $output = self::BOLD . "DETAILED CONNECTION STATISTICS" . self::RESET . PHP_EOL;
        $output .= str_repeat('=', 55) . PHP_EOL;
        
        $output .= "Generated at: " . date('c') . PHP_EOL;
        $output .= "Total connections: {$stats['total']}" . PHP_EOL;
        $output .= "TCP connections: {$stats['tcp']}" . PHP_EOL;
        $output .= "UDP connections: {$stats['udp']}" . PHP_EOL;
        $output .= "IPv4 connections: {$stats['ipv4']}" . PHP_EOL;
        $output .= "IPv6 connections: {$stats['ipv6']}" . PHP_EOL;
        
        $output .= PHP_EOL . self::BOLD . "Connections by State:" . self::RESET . PHP_EOL;
        $output .= str_repeat('-', 30) . PHP_EOL;
        
        arsort($stats['states']);
        foreach ($stats['states'] as $state => $count) {
            $output .= sprintf("%-20s: %d\n", $this->coloredState($state), $count);
        }
        
        $output .= PHP_EOL . self::BOLD . "Connections by Process (Top {$this->config['max_display_processes']}):" . self::RESET . PHP_EOL;
        $output .= str_repeat('-', 55) . PHP_EOL;
        
        arsort($stats['processes']);
        $count = 0;
        foreach ($stats['processes'] as $process => $processCount) {
            if ($count++ >= $this->config['max_display_processes']) break;
            $output .= sprintf("%-45s: %d\n", $process, $processCount);
        }
        
        return $output;
    }

    private function outputToFile(string $content, string $file): void {
        if (file_put_contents($file, $content) === false) {
            $this->die("Failed to write output to: $file");
        }
        echo "Output written to: $file" . PHP_EOL;
    }

    private function parseArguments(array $argv): void {
        $args = array_slice($argv, 1);
        
        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            
            switch ($arg) {
                case '--json':
                    $this->config['json_output'] = true;
                    break;
                case '--csv':
                    $this->config['csv_output'] = true;
                    break;
                case '--udp':
                    $this->config['show_udp'] = true;
                    break;
                case '--listen':
                    $this->config['filter_states'][] = 'LISTEN';
                    break;
                case '--established':
                    $this->config['filter_states'][] = 'ESTABLISHED';
                    break;
                case '--timewait':
                    $this->config['filter_states'][] = 'TIME_WAIT';
                    break;
                case '--closewait':
                    $this->config['filter_states'][] = 'CLOSE_WAIT';
                    break;
                case '--finwait':
                    $this->config['filter_states'] = array_merge($this->config['filter_states'], ['FIN_WAIT1', 'FIN_WAIT2']);
                    break;
                case '--count':
                    $this->config['show_count'] = true;
                    break;
                case '--processes':
                    $this->config['show_processes'] = true;
                    break;
                case '--port':
                    if (!isset($args[$i + 1])) {
                        $this->die("Port number required for --port");
                    }
                    $this->config['filter_port'] = $args[++$i];
                    $this->validatePort((int)$this->config['filter_port']);
                    break;
                case '--local-ip':
                    if (!isset($args[$i + 1])) {
                        $this->die("IP address required for --local-ip");
                    }
                    $this->config['filter_local_ip'] = $args[++$i];
                    $this->validateIpCidr($this->config['filter_local_ip']);
                    break;
                case '--remote-ip':
                    if (!isset($args[$i + 1])) {
                        $this->die("IP address required for --remote-ip");
                    }
                    $this->config['filter_remote_ip'] = $args[++$i];
                    $this->validateIpCidr($this->config['filter_remote_ip']);
                    break;
                case '--ipv4':
                    $this->config['filter_ipv4'] = true;
                    break;
                case '--ipv6':
                    $this->config['filter_ipv6'] = true;
                    break;
                case '--watch':
                    $this->config['watch_mode'] = true;
                    if (isset($args[$i + 1]) && ctype_digit($args[$i + 1])) {
                        $this->config['refresh_interval'] = (int)$args[++$i];
                        $this->validateInterval($this->config['refresh_interval']);
                    }
                    break;
                case '--stats':
                    $this->config['show_stats'] = true;
                    break;
                case '--alert-state':
                    if (!isset($args[$i + 1])) {
                        $this->die("State required for --alert-state");
                    }
                    $this->config['alert_state'] = $args[++$i];
                    $this->config['alert_mode'] = true;
                    break;
                case '--alert-threshold':
                    if (!isset($args[$i + 1])) {
                        $this->die("Threshold required for --alert-threshold");
                    }
                    $this->config['alert_threshold'] = (int)$args[++$i];
                    $this->validateThreshold($this->config['alert_threshold']);
                    break;
                case '--output':
                    if (!isset($args[$i + 1])) {
                        $this->die("Filename required for --output");
                    }
                    $this->config['output_file'] = $args[++$i];
                    break;
                case '--verbose':
                case '-v':
                    $this->config['verbose'] = true;
                    break;
                case '--version':
                    $this->showVersion();
                    break;
                case '--help':
                    $this->showHelp();
                    exit(0);
                default:
                    if ($arg) {
                        $this->die("Unknown option: $arg\nUse --help for usage information");
                    }
                    break;
            }
        }
    }

    private function watchMode(int $interval): void {
        declare(ticks=1);
        pcntl_signal(SIGINT, function() {
            echo PHP_EOL . self::YELLOW . "Monitoring stopped." . self::RESET . PHP_EOL;
            exit(0);
        });
        
        echo self::BOLD . "Watching connections" . self::RESET . " (refresh every {$interval}s). Press Ctrl+C to stop." . PHP_EOL;
        echo "Started at: " . date('Y-m-d H:i:s') . PHP_EOL . PHP_EOL;
        
        $isTty = function_exists('posix_isatty') && posix_isatty(STDOUT);
        $iteration = 0;
        
        while (true) {
            $iteration++;
            $connections = $this->getAllConnections();
            $currentCount = count($connections);
            
            if ($isTty) {
                system('clear');
            }
            
            echo self::BOLD . "[" . date('H:i:s') . "] Iteration: $iteration | Connections: $currentCount" . self::RESET . PHP_EOL;
            echo str_repeat('-', 65) . PHP_EOL . PHP_EOL;
            
            if ($this->config['json_output']) {
                echo $this->displayConnectionsJson($connections) . PHP_EOL;
            } elseif ($this->config['csv_output']) {
                echo $this->displayConnectionsCsv($connections) . PHP_EOL;
            } else {
                echo $this->displayConnectionsTable($connections);
                echo $this->displaySummary($connections) . PHP_EOL;
            }
            
            if ($this->config['show_stats']) {
                echo $this->displayStatistics($connections) . PHP_EOL;
            }
            
            if ($this->config['alert_mode'] && $this->config['alert_state'] && $this->config['alert_threshold'] > 0) {
                $stats = $this->getConnectionStats($connections);
                $this->checkAlert($stats, $this->config['alert_state'], $this->config['alert_threshold']);
            }
            
            sleep($interval);
        }
    }

    public function run(array $argv): void {
        $this->parseArguments($argv);
        $this->checkRequirements();
        
        if ($this->config['watch_mode']) {
            $this->watchMode($this->config['refresh_interval']);
            return;
        }
        
        $connections = $this->getAllConnections();
        
        if (empty($connections)) {
            echo "No matching connections found." . PHP_EOL;
            return;
        }
        
        $stats = $this->getConnectionStats($connections);
        
        if ($this->config['alert_mode'] && $this->config['alert_state'] && $this->config['alert_threshold'] > 0) {
            $this->checkAlert($stats, $this->config['alert_state'], $this->config['alert_threshold']);
        }
        
        $output = '';
        
        if ($this->config['show_count']) {
            $output = "Counts: total={$stats['total']} tcp={$stats['tcp']} udp={$stats['udp']} IPv4={$stats['ipv4']} IPv6={$stats['ipv6']}" . PHP_EOL;
            
            if (!empty($stats['states'])) {
                $output .= "By state: ";
                $stateParts = [];
                foreach ($stats['states'] as $state => $count) {
                    $stateParts[] = $this->coloredState($state) . ": $count";
                }
                $output .= implode(', ', $stateParts) . PHP_EOL;
            }
        } elseif ($this->config['show_stats']) {
            $output = $this->displayStatistics($connections);
        } elseif ($this->config['json_output']) {
            $output = $this->displayConnectionsJson($connections);
        } elseif ($this->config['csv_output']) {
            $output = $this->displayConnectionsCsv($connections);
        } else {
            $output = $this->displayConnectionsTable($connections) . $this->displaySummary($connections);
        }
        
        if ($output) {
            if ($this->config['output_file']) {
                $this->outputToFile($output, $this->config['output_file']);
            } else {
                echo $output;
            }
        }
        
        if ($this->config['verbose']) {
            echo PHP_EOL . self::BOLD . "Performance Metrics:" . self::RESET . PHP_EOL;
            echo $this->getPerformanceMetrics();
        }
    }
}

// Run the application
if (PHP_SAPI === 'cli') {
    $monitor = new ConnectionMonitor();
    $monitor->run($_SERVER['argv']);
}
