<?php
/*
author : biskuat
title: backdoor scanner
*/
echo '<style>body {background-color:#000;color:red;} body,td,th { font: 9pt Courier New;margin:0;vertical-align:top; } span,h1,a { color:#00ff00} span { font-weight: bolder; } h1 { border:1px solid #00ff00;padding: 2px 5px;font: 14pt Courier New;margin:0px; } div.content { padding: 5px;margin-left:5px;} a { text-decoration:none; } a:hover { background:#ff0000; } .ml1 { border:1px solid #444;padding:5px;margin:0;overflow: auto; } .bigarea { width:100%;height:250px; } input, textarea, select { margin:0;color:#00ff00;background-color:#000;border:1px solid #00ff00; font: 9pt Monospace,"Courier New"; } form { margin:0px; } #toolsTbl { text-align:center; } .toolsInp { width: 80%; } .main th {text-align:left;} .main tr:hover{background-color:#5e5e5e;} .main td, th{vertical-align:middle;} pre {font-family:Courier,Monospace;} #cot_tl_fixed{position:fixed;bottom:0px;font-size:12px;left:0px;padding:4px 0;clip:_top:expression(document.documentElement.scrollTop document.documentElement.clientHeight-this.clientHeight);_left:expression(document.documentElement.scrollLeft   document.documentElement.clientWidth - offsetWidth);} .style2 {color: #00FF00} .style3 {color: #009900} .style4 {color: #006600} .style5 {color: #00CC00} .style6 {color: #003300} .style8 {color: #33CC00} #footer { margin-bottom: 10px; color: #666; vertical-align: top; text-align: center; font-size: 11px; } #footer ul { margin: 0; padding: 0; list-style: none; } #footer li { display: inline-block; margin-right: 15px; border-right: 1px solid #666; vertical-align: middle; } #footer li a { margin-right: 15px; } #footer li:last-child { margin-right: 0; border-right: 0; } #footer li:last-child a { margin-right: 0; } #footer a { color: #666; } #footer a:hover { color: #858585; } #footer .footer-left { height: 20px; vertical-align: middle; line-height: 20px; } @media (min-width: 39rem) { #footer { display: flex; flex-flow: row wrap; justify-content: space-between; align-items: center; align-content: center; margin-bottom: 20px; } #footer .footer-left { align-self: flex-start; margin-right: 20px; } #footer .footer-right { align-self: flex-end; } }</style>';

set_time_limit(0);
error_reporting(0);
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
for ($i = 0; $i < ob_get_level(); $i++) { @ob_end_flush(); }
@ob_implicit_flush(true);

$path = getcwd();
if (isset($_GET['dir']) && is_string($_GET['dir']) && strlen($_GET['dir']) > 0) {
    $path = $_GET['dir'];
}

// Self delete
if (isset($_GET['kill'])) {
    @unlink(__FILE__);
}

echo "<a href='?kill'><font color='yellow'>[Self Delete]</font></a><br>";
echo '<form action="" method="get"><input type="text" name="dir" value="' . htmlspecialchars($path, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '" style="width: 548px;"> <input type="submit" value="scan"></form><br>';
echo "CURRENT DIR: <font color='yellow'>" . htmlspecialchars($path, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</font><br>";

if (isset($_GET['delete'])) {
    $to_delete = $_GET['delete'];
    if (strpos(realpath($to_delete), realpath($path)) === 0) {
        @unlink($to_delete);
        $status = "<font color='red'>FAILED</font>";
        if (!file_exists($to_delete)) {
            $status = "<font color='yellow'>Success</font>";
        }
        echo "TRY TO DELETE: " . htmlspecialchars($to_delete, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . " $status <br>";
    } else {
        echo "<font color='red'>Refused to delete outside scan path.</font><br>";
    }
    exit;
}

scanBackdoor($path);

/* ---------- helpers ---------- */

function save($fname, $value) {
    @file_put_contents($fname, $value, FILE_APPEND | LOCK_EX);
}

/**
 * Strip comments and string literals using PHP tokenizer.
 */
function strip_php_comments_and_strings(string $code): string {
    if (!function_exists('token_get_all')) {
        $code = preg_replace('/(\'(?:\\\\.|[^\'])*\'|"(?:\\\\.|[^"])*")/s', ' ', $code);
        $code = preg_replace('#/\*.*?\*/#s', ' ', $code);
        $code = preg_replace('#//.*?$#m', ' ', $code);
        return $code;
    }

    $tokens = token_get_all($code);
    $out = '';
    foreach ($tokens as $t) {
        if (is_array($t)) {
            $token_id = $t[0];
            $text = $t[1];
            if (in_array($token_id, [T_COMMENT, T_DOC_COMMENT, T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE], true)) {
                $out .= str_repeat(' ', strlen($text));
            } else {
                $out .= $text;
            }
        } else {
            $out .= $t;
        }
    }
    return $out;
}

/**
 * Check a single file for suspicious patterns.
 * Count removed — only report matches.
 */
function checkBackdoor(string $file_location) {
    global $path;

    $pattern = '#\b(?:eval|assert|preg_replace\s*/e|unserialize|system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|file_put_contents|move_uploaded_file|base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|gzdecode)\b#i';

    $contents = @file_get_contents($file_location);
    if ($contents === false || strlen($contents) === 0) {
        return;
    }

    $scan_target = strip_php_comments_and_strings($contents);
    preg_match_all($pattern, $scan_target, $matches);
    $raw_matches = $matches[0] ?? [];
    $found = array_values(array_unique(array_map('trim', array_map('strtolower', $raw_matches))));

    if (empty($found)) {
        return;
    }

    // ambil waktu modifikasi file (filemtime), jika gagal tampilkan '-'
    $mtime = @filemtime($file_location);
    $date_str = $mtime !== false ? date('Y-m-d H:i:s', $mtime) : '-';

    $safe_file = htmlspecialchars($file_location, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo "[+] Suspect file -> <a href='?delete=" . urlencode($file_location) . "&dir=" . urlencode($path) . "'><font color='yellow'>[DELETE]</font></a> <font color='white'>{$safe_file}</font> <font color='cyan'>[{$date_str}]</font><br>\n";

    // simpan path + tanggal ke log
    save("shell-found.txt", $file_location . " | " . $date_str . PHP_EOL);

    $matches_html = [];
    foreach ($found as $m) {
        $safe = htmlspecialchars($m, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        // bungkus semua match dengan warna putih
        $matches_html[] = '<span style="color:white">' . $safe . '</span>';
    }

    echo "<b>Matches:</b> " . implode(', ', $matches_html) . "<br>\n";

    echo '<textarea name="content" cols="100" rows="18">' . htmlspecialchars($contents, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</textarea><br><br>';
}

/**
 * Recursively scan directory for PHP files and check them.
 */
function scanBackdoor(string $current_dir) {
    if (!is_readable($current_dir)) {
        return;
    }

    $items = @scandir($current_dir);
    if ($items === false) return;

    foreach ($items as $file) {
        if ($file === '.' || $file === '..') continue;
        $file_location = $current_dir . DIRECTORY_SEPARATOR . $file;
        $file_location = str_replace(['//', '\\\\'], DIRECTORY_SEPARATOR, $file_location);

        if (is_dir($file_location)) {
            scanBackdoor($file_location);
            continue;
        }

        $ext = strtolower(pathinfo($file_location, PATHINFO_EXTENSION));
        if ($ext === 'php' || $ext === 'php5' || $ext === 'phtml') {
            checkBackdoor($file_location);
        }
    }
}
?>
