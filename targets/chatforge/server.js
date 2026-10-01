// ChatForge — deliberately vulnerable "AI chat" app (Node / Express).
// PART OF A SECURITY TEST LAB. Every weakness is INTENTIONAL and documented in
// ../INTENDED-VULNS.md. Do not deploy anywhere real. Stack: Node / Express.
const express = require('express');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// seed data: conversation 1 is "admin" and holds a secret; 2 is the public demo.
const convos = {
  1: { owner: 'admin', msgs: [{ user: 'admin', text: 'internal: prod DB password is hunter2' }] },
  2: { owner: 'demo', msgs: [{ user: 'demo', text: 'Hi! Ask me anything.' }] },
};

const page = (b) => `<!doctype html><html><head><title>ChatForge</title></head><body>
<h1>💬 ChatForge</h1>
<nav><a href="/">home</a> | <a href="/chat">chat</a> | <a href="/summarize">summarize</a></nav><hr>${b}
</body></html>`;

app.get('/', (req, res) => res.send(page('<p>Your friendly AI chatbot.</p>')));

app.get('/chat', (req, res) => {
  // VULN #1 — stored XSS: message text rendered into the page unescaped.
  const msgs = convos[2].msgs.map((m) => `<li><b>${m.user}</b>: ${m.text}</li>`).join('');
  res.send(page(`<ul>${msgs}</ul>
    <form method="post" action="/chat"><input name="text" placeholder="message">
    <button>Send</button></form>`));
});
app.post('/chat', (req, res) => {
  convos[2].msgs.push({ user: 'you', text: req.body.text || '' });
  res.redirect('/chat');
});

app.get('/api/conversations/:id', (req, res) => {
  // VULN #2 — IDOR / broken access control: any conversation by id, no auth.
  const c = convos[req.params.id];
  if (!c) return res.status(404).json({ error: 'not found' });
  res.json(c);
});

app.get('/summarize', (req, res) => res.send(page(
  `<p>Summarize a webpage with AI:</p>
   <form method="post" action="/summarize"><input name="url" placeholder="https://...">
   <button>Summarize</button></form>`)));
app.post('/summarize', async (req, res) => {
  // VULN #3 — SSRF: fetches an arbitrary URL server-side (internal hosts, metadata).
  const url = req.body.url;
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
    const t = await r.text();
    res.json({ status: r.status, body: t.slice(0, 2000) });
  } catch (e) { res.json({ error: String(e) }); }
});

app.listen(3100, '0.0.0.0', () => console.log('ChatForge on 3100'));
