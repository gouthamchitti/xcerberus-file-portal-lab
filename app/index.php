<?php
// Xcerberus File Portal — staff authentication
// Lab demo app (deliberately vulnerable) for an AUTHORISED internal RCE POC.
session_start();

// Demo credential store (lab only). In a real app this would be a hashed DB lookup.
$USERS = ['support' => 'Xcerberus@Support2026'];

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (isset($USERS[$u]) && hash_equals($USERS[$u], $p)) {
        $_SESSION['user'] = $u;
        header('Location: /portal.php');
        exit;
    }
    $error = 'Invalid credentials. Please contact IT support.';
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xcerberus File Portal — Sign in</title>
<style>
  :root{--navy:#0b1220;--card:#131c2e;--line:#243249;--teal:#5eead4;--muted:#8aa0bd;--text:#e8eefb;}
  *{box-sizing:border-box}
  body{margin:0;font-family:Inter,-apple-system,Segoe UI,Roboto,sans-serif;background:
    radial-gradient(1200px 600px at 70% -10%,#16233d 0%,var(--navy) 55%);color:var(--text);
    min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{width:380px;background:var(--card);border:1px solid var(--line);border-radius:16px;
    padding:34px 32px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
  .brand{display:flex;align-items:center;gap:10px;margin-bottom:6px}
  .logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--teal),#3b82f6);
    display:flex;align-items:center;justify-content:center;font-weight:800;color:#07101f}
  h1{font-size:19px;margin:0}
  .sub{color:var(--muted);font-size:13px;margin:4px 0 22px}
  label{display:block;font-size:12px;color:var(--muted);margin:14px 0 6px;letter-spacing:.3px}
  input{width:100%;padding:12px 13px;border-radius:10px;border:1px solid var(--line);
    background:#0e1627;color:var(--text);font-size:14px;outline:none}
  input:focus{border-color:var(--teal)}
  button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:10px;font-weight:700;
    font-size:14px;color:#06131f;background:linear-gradient(135deg,var(--teal),#38bdf8);cursor:pointer}
  .err{background:#3a1420;border:1px solid #7f2740;color:#ffb3c4;font-size:13px;
    padding:10px 12px;border-radius:9px;margin-top:16px}
  .foot{color:#55688a;font-size:11px;text-align:center;margin-top:20px}
</style>
</head>
<body>
  <form class="card" method="post" autocomplete="off">
    <div class="brand"><div class="logo">X</div><h1>Xcerberus File Portal</h1></div>
    <div class="sub">Support document intake — staff access only</div>
    <label>Username</label>
    <input name="username" placeholder="support" autofocus>
    <label>Password</label>
    <input name="password" type="password" placeholder="••••••••">
    <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <button type="submit">Sign in</button>
    <div class="foot">Xcerberus Internal · v2.3.1 · &copy; 2026</div>
  </form>
</body>
</html>
