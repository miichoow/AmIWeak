'use strict';

const readline = require('readline');

const core = require('../static/vendor/zxcvbn-ts-core.js').zxcvbnts.core;
const common = require('../static/vendor/zxcvbn-ts-language-common.js').zxcvbnts['language-common'];
const en = require('../static/vendor/zxcvbn-ts-language-en.js').zxcvbnts['language-en'];

core.zxcvbnOptions.setOptions({
  translations: en.translations,
  graphs: common.adjacencyGraphs,
  dictionary: Object.assign({}, common.dictionary, en.dictionary)
});

// One password per stdin line, one JSON result per stdout line. Never write
// the password (or anything derived from request content) to stderr or
// anywhere else -- this is the one place in the system outside CheckRunner
// that ever sees plaintext.
const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', function (line) {
  var request;
  try {
    request = JSON.parse(line);
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: 'malformed request' }) + '\n');
    return;
  }
  try {
    var result = core.zxcvbn(String(request.password));
    process.stdout.write(JSON.stringify({ score: result.score }) + '\n');
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: 'scoring failed' }) + '\n');
  }
});
