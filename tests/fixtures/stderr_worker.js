// Writes a line to stderr on startup, then answers normally, to exercise the
// StrengthScorer's stderr-reading thread.
process.stderr.write('worker starting\n');
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', function () {
  process.stdout.write(JSON.stringify({ score: 0 }) + '\n');
});
