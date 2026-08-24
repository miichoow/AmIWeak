// Echoes back invalid JSON for every request, to exercise the client's
// json.JSONDecodeError handling.
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', function () {
  process.stdout.write('not json\n');
});
