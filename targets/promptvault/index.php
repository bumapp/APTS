<?php
// PromptVault — deliberately vulnerable "AI prompt library" (PHP / SQLite).
// PART OF A SECURITY TEST LAB. Every weakness is INTENTIONAL and documented in
// ../INTENDED-VULNS.md. Do not deploy anywhere real. Stack: PHP / SQLite.
$db = new PDO('sqlite:/tmp/promptvault.db');
$db->exec("CREATE TABLE IF NOT EXISTS prompts(id INTEGER PRIMARY KEY, name TEXT, body TEXT)");
if ($db->query("SELECT COUNT(*) FROM prompts")->fetchColumn() == 0) {
  $db->exec("INSERT INTO prompts(name,body) VALUES
    ('Summarizer','Summarize the following text: '),
    ('Translator','Translate to French: '),
    ('Admin secret','FLAG{promptvault-admin-only-prompt}')");
}
echo "<!doctype html><html><head><title>PromptVault</title></head><body><h1>🗝️ PromptVault</h1>";
echo '<nav><a href="/">home</a> | <a href="/?page=search">search</a> | '
   . '<a href="/?page=download">download</a> | <a href="/?page=ping">health</a></nav><hr>';
$page = $_GET['page'] ?? 'home';
if ($page == 'search') {
  $q = $_GET['q'] ?? '';
  echo '<form><input type=hidden name=page value=search><input name=q placeholder=search value="'.$q.'"><button>Go</button></form>';
  echo "<p>Query: ".$q."</p>";                         // (also reflected)
  if ($q !== '') {
    // VULN #1 — SQL injection (string concatenation into the query).
    $sql = "SELECT name,body FROM prompts WHERE name LIKE '%".$q."%'";
    try { foreach ($db->query($sql) as $r) { echo "<li><b>".$r['name']."</b>: ".$r['body']."</li>"; } }
    catch (Exception $e) { echo "<p>err: ".$e->getMessage()."</p>"; }
  }
} elseif ($page == 'download') {
  $file = $_GET['file'] ?? '';
  echo '<form><input type=hidden name=page value=download><input name=file placeholder=prompts.txt><button>Download</button></form>';
  if ($file !== '') {
    // VULN #2 — LFI / path traversal (no sanitisation): ?file=/etc/passwd
    echo "<pre>".htmlspecialchars(@file_get_contents($file))."</pre>";
  }
} elseif ($page == 'ping') {
  $host = $_GET['host'] ?? '';
  echo '<form><input type=hidden name=page value=ping><input name=host placeholder=127.0.0.1><button>Ping</button></form>';
  if ($host !== '') {
    // VULN #3 — OS command injection: ?host=127.0.0.1;id
    echo "<pre>".shell_exec("ping -c 1 ".$host." 2>&1")."</pre>";
  }
} else {
  echo "<p>A library of reusable AI prompts.</p>";
}
echo "</body></html>";
