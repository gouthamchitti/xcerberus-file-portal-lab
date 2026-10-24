<?php
// Xcerberus File Portal — HARDENED upload handler (the fix for CWE-434).
// Drop-in replacement for app/portal.php. See README §3.
session_start();
if (!isset($_SESSION['user'])) { header('Location: /index.php'); exit; }

// Uploads live OUTSIDE the webroot and are never executed.
$STORE = '/var/lib/xcerberus-portal/uploads';          // not under the web root
@mkdir($STORE, 0750, true);

// Allow-list: real content type (magic bytes) -> safe extension. Nothing else is accepted.
$ALLOW = [
    'image/png'       => 'png',
    'image/jpeg'      => 'jpg',
    'application/pdf' => 'pdf',
    'text/plain'      => 'txt',
];
$MAX = 8 * 1024 * 1024; // 8 MB

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['doc'])) {
    $f = $_FILES['doc'];
    if ($f['error'] !== UPLOAD_ERR_OK)        { $msg = 'Upload failed.'; }
    elseif ($f['size'] <= 0 || $f['size'] > $MAX) { $msg = 'File too large.'; }
    else {
        // 1) Determine the REAL type from content, ignore the client filename entirely.
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->file($f['tmp_name']);
        if (!isset($ALLOW[$mime])) {
            // 2) Reject anything not on the allow-list (a .php web shell is rejected here).
            $msg = 'Unsupported file type. Allowed: PNG, JPG, PDF, TXT.';
        } else {
            // 3) Random server-side name + extension derived from the validated type.
            $name = bin2hex(random_bytes(16)) . '.' . $ALLOW[$mime];
            $dest = $STORE . '/' . $name;
            if (move_uploaded_file($f['tmp_name'], $dest)) {
                @chmod($dest, 0640);  // never executable
                $msg = 'Uploaded securely. Our team will review it.';
            } else {
                $msg = 'Upload failed.';
            }
        }
    }
}
// NOTE: files are served (if at all) only through a download script that streams bytes with
//   header('Content-Disposition: attachment');  header('Content-Type: application/octet-stream');
// They are NEVER reachable as an executable URL. Combined with egress filtering and
// disable_functions(system,exec,shell_exec,...), the upload path cannot yield code execution.
?>
<!doctype html><meta charset="utf-8"><title>Xcerberus File Portal — Submit a document</title>
<body style="font-family:system-ui;background:#0b1220;color:#e8eefb;padding:40px">
  <h2>Submit a support document (hardened)</h2>
  <form method="post" enctype="multipart/form-data">
    <input type="file" name="doc" required> <button>Upload</button>
  </form>
  <?php if ($msg): ?><p style="color:#9ff0d4"><?= htmlspecialchars($msg) ?></p><?php endif; ?>
</body>
