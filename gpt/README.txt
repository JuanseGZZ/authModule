auth.js (frontend helper) compatible with the FastAPI backend.

Quick start (browser):
1) <script src="auth.js"></script>
2) await AuthClient.config('http://localhost:8000', 'stateful');  // or 'stateless'
3) await AuthClient.handshake();
4) await AuthClient.registerCall('mail@example.com','emma','secret');
5) const echo = await AuthClient.echoCall({hello:'world'});

Notes:
- Uses WebCrypto + a minimal embedded TweetNaCl subset for X25519.
- No external dependencies.
- Works in modern browsers.
