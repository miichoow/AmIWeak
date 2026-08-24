// Responds with valid JSON that never carries a "score" key, to exercise the
// client's handling of a well-formed-but-unusable response.
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', function () {
  process.stdout.write(JSON.stringify({ error: 'scoring failed' }) + '\n');
});
