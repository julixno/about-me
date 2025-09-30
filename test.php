<?php
// register.php
session_start();

// CSRF-Token erzeugen
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF prüfen
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Ungültiges Formular (CSRF).';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $errors[] = 'Benutzername und Passwort sind erforderlich.';
        } elseif (strlen($password) < 8) {
            $errors[] = 'Passwort muss mindestens 8 Zeichen lang sein.';
        } else {
            // Datei users.json (im selben Verzeichnis)
            $file = __DIR__ . '/users.json';
            $users = [];
            if (file_exists($file)) {
                $json = file_get_contents($file);
                $users = json_decode($json, true) ?? [];
            }

            if (isset($users[$username])) {
                $errors[] = 'Benutzer existiert bereits.';
            } else {
                // Passwort sicher hashen
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $users[$username] = [
                    'password' => $hash,
                    'created_at' => date(DATE_ATOM)
                ];
                // Datei atomar schreiben
                file_put_contents($file, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                $success = 'Benutzer erfolgreich angelegt.';
            }
        }
    }
}
?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Benutzer anlegen</title>
</head>
<body>
  <h1>Benutzer anlegen</h1>

  <?php foreach ($errors as $e): ?>
    <div style="color:red;"><?=htmlspecialchars($e)?></div>
  <?php endforeach; ?>

  <?php if ($success): ?>
    <div style="color:green;"><?=htmlspecialchars($success)?></div>
  <?php endif; ?>

  <form method="post" action="">
    <label>Benutzername: <input name="username" required></label><br>
    <label>Passwort: <input name="password" type="password" required></label><br>
    <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
    <button type="submit">Anlegen</button>
  </form>

  <p><a href="login.php">Zur Login-Seite</a></p>
</body>
</html>