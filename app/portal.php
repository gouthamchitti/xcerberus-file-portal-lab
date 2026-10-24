<?php
// Xcerberus File Portal — support document upload
session_start();
if (!isset($_SESSION['user'])) { header('Location: /index.php'); exit; }

$msg = ''; $link = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['doc'])) {
    $dir = __DIR__ . '/uploads';
    // =====================================================================
    // VULNERABILITY (CWE-434: Unrestricted Upload of File with Dangerous Type)
    // The handler trusts the client-supplied filename and performs NO checks on
    // extension, MIME type, or content before saving into a web-served directory.
    // Because PHP's built-in server executes any .php file in the webroot, an
    // attacker can upload a .php file and have the server run it. This is the
    // flaw demonstrated and remediated in the accompanying report.
    // =====================================================================
    $name = basename($_FILES['doc']['name']);          // client-controlled, not sanitised
    $dest = $dir . '/' . $name;                         // original extension preserved
    if (move_uploaded_file($_FILES['doc']['tmp_name'], $dest)) {
        $msg = "Uploaded '" . htmlspecialchars($name) . "' successfully. Our support team will review it.";
        $link = '/uploads/' . rawurlencode($name);
    } else {
        $msg = "Upload failed. Please try again.";
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xcerberus File Portal — Submit a document</title>
<style>
  :root{--navy:#0b1220;--card:#131c2e;--line:#243249;--teal:#5eead4;--muted:#8aa0bd;--text:#e8eefb;}
  *{box-sizing:border-box}
  body{margin:0;font-family:Inter,-apple-system,Segoe UI,Roboto,sans-serif;background:
    radial-gradient(1200px 600px at 70% -10%,#16233d 0%,var(--navy) 55%);color:var(--text);min-height:100vh}
  .top{display:flex;align-items:center;justify-content:space-between;padding:16px 28px;
    border-bottom:1px solid var(--line);background:#0d1526}
  .brand{display:flex;align-items:center;gap:10px}
  .logo{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,var(--teal),#3b82f6);
    display:flex;align-items:center;justify-content:center;font-weight:800;color:#07101f}
  .who{color:var(--muted);font-size:13px}
  .wrap{max-width:680px;margin:40px auto;padding:0 20px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:30px 30px}
  h2{margin:0 0 4px}.lead{color:var(--muted);font-size:14px;margin:0 0 24px}
  .drop{border:1.5px dashed var(--line);border-radius:12px;padding:30px;text-align:center;background:#0e1627}
  input[type=file]{color:var(--muted);font-size:13px}
  button{margin-top:22px;padding:12px 20px;border:0;border-radius:10px;font-weight:700;font-size:14px;
    color:#06131f;background:linear-gradient(135deg,var(--teal),#38bdf8);cursor:pointer}
  .msg{margin-top:20px;background:#10261f;border:1px solid #1f5c48;color:#9ff0d4;
    padding:12px 14px;border-radius:9px;font-size:13px}
  .hint{color:#55688a;font-size:12px;margin-top:14px}
  a{color:var(--teal)}
</style>
</head>
<body>
  <div class="top">
    <div class="brand"><div class="logo">X</div><strong>Xcerberus File Portal</strong></div>
    <div class="who">Signed in as <?= htmlspecialchars($_SESSION['user']) ?></div>
  </div>
  <div class="wrap">
    <div class="card">
      <h2>Submit a support document</h2>
      <p class="lead">Attach a screenshot, log file, or PDF so our team can help resolve your ticket.</p>
      <form method="post" enctype="multipart/form-data">
        <div class="drop">
          <input type="file" name="doc" required>
        </div>
        <button type="submit">Upload document</button>
        <div class="hint">Accepted: images, PDF, text, and log files up to 8&nbsp;MB.</div>
      </form>
      <?php if ($msg): ?>
        <div class="msg"><?= $msg ?><?php if ($link): ?> &middot; <a href="<?= $link ?>">view</a><?php endif; ?></div>
      <?php endif; ?>
    </div>
  </div>
</body>
</html>
