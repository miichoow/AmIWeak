/* AmIWeak client.
 *
 * Two jobs: score the password locally with zxcvbn-ts as it is typed, and POST
 * it once when the user asks for the breach and wordlist checks.
 *
 * The password is never written to the console, to storage, to the URL, or to
 * the document title. It lives in the input element and in one local variable.
 */
(function () {
  'use strict';

  var form = document.getElementById('check-form');
  var input = document.getElementById('password');
  var reveal = document.getElementById('reveal');
  var meter = document.getElementById('meter');
  var strengthLabel = document.getElementById('strength-label');
  var strengthTime = document.getElementById('strength-time');
  var hints = document.getElementById('hints');
  var submit = document.getElementById('submit');
  var verdict = document.getElementById('verdict');
  var verdictMessage = document.getElementById('verdict-message');
  var verdictNote = document.getElementById('verdict-note');
  var breakdown = document.getElementById('breakdown');

  var SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
  var BACKEND_LABELS = {
    hibp: 'Have I Been Pwned',
    weakpass: 'weakpass wordlists'
  };

  var settings = {
    strength: { enabled: true, min_score: 3, min_length: 8 },
    messages: {}
  };

  /* ---------------------------------------------------------------- setup */

  function configureZxcvbn() {
    var core = window.zxcvbnts && window.zxcvbnts.core;
    var common = window.zxcvbnts && window.zxcvbnts['language-common'];
    var en = window.zxcvbnts && window.zxcvbnts['language-en'];
    if (!core || !common || !en) {
      return false;
    }
    core.zxcvbnOptions.setOptions({
      translations: en.translations,
      graphs: common.adjacencyGraphs,
      dictionary: Object.assign({}, common.dictionary, en.dictionary)
    });
    return true;
  }

  var zxcvbnReady = configureZxcvbn();

  fetch('/api/v1/config', { headers: { Accept: 'application/json' } })
    .then(function (response) { return response.ok ? response.json() : null; })
    .then(function (body) {
      if (body) {
        settings = body;
      }
    })
    .catch(function () {
      /* Defaults are fine; the server re-checks everything anyway. */
    });

  /* -------------------------------------------------------- live scoring */

  var debounceTimer = null;

  function onInput() {
    window.clearTimeout(debounceTimer);
    debounceTimer = window.setTimeout(score, 150);
  }

  function score() {
    var value = input.value;

    hideVerdict();

    if (!value) {
      meter.removeAttribute('data-score');
      strengthLabel.textContent = 'Waiting for input';
      strengthTime.textContent = '';
      hints.replaceChildren();
      return;
    }

    if (!zxcvbnReady) {
      zxcvbnReady = configureZxcvbn();
    }
    if (!zxcvbnReady) {
      strengthLabel.textContent = 'Local scoring unavailable';
      return;
    }

    var result = window.zxcvbnts.core.zxcvbn(value);
    meter.setAttribute('data-score', String(result.score));
    meter.setAttribute('aria-label', 'Password strength: ' + SCORE_LABELS[result.score]);
    strengthLabel.textContent = SCORE_LABELS[result.score];

    var crackTime = result.crackTimesDisplay.offlineSlowHashing1e4PerSecond;
    strengthTime.textContent = crackTime ? 'Offline cracking: ' + crackTime : '';

    var messages = [];
    if (result.feedback.warning) {
      messages.push(result.feedback.warning);
    }
    (result.feedback.suggestions || []).forEach(function (suggestion) {
      messages.push(suggestion);
    });
    if (value.length < settings.strength.min_length) {
      messages.unshift('Use at least ' + settings.strength.min_length + ' characters.');
    }

    hints.replaceChildren.apply(
      hints,
      messages.slice(0, 3).map(function (text) {
        var li = document.createElement('li');
        li.textContent = text;
        return li;
      })
    );
  }

  /* --------------------------------------------------------- the verdict */

  function hideVerdict() {
    verdict.hidden = true;
    verdict.removeAttribute('data-verdict');
  }

  function showVerdict(name, message, note) {
    verdict.hidden = false;
    verdict.setAttribute('data-verdict', name);
    verdictMessage.textContent = message;
    verdictNote.textContent = note || '';
    verdictNote.hidden = !note;
  }

  function stateOf(check) {
    if (!check.enabled) { return { key: 'off', icon: '○', detail: 'disabled' }; }
    if (check.hit === true) {
      return {
        key: 'hit',
        icon: '✕',
        detail: check.count ? 'seen ' + check.count.toLocaleString() + ' times' : 'found'
      };
    }
    if (check.hit === false) { return { key: 'clear', icon: '✓', detail: 'no match' }; }
    return { key: 'unknown', icon: '!', detail: check.error || 'unavailable' };
  }

  function renderBreakdown(checks) {
    breakdown.replaceChildren.apply(
      breakdown,
      (checks || []).map(function (check) {
        var state = stateOf(check);
        var li = document.createElement('li');

        var icon = document.createElement('span');
        icon.className = 'state';
        icon.setAttribute('data-state', state.key);
        icon.textContent = state.icon;

        var name = document.createElement('span');
        name.className = 'name';
        name.textContent = BACKEND_LABELS[check.name] || check.name;

        var detail = document.createElement('span');
        detail.className = 'detail';
        detail.textContent = state.detail;

        li.append(icon, name, detail);
        return li;
      })
    );
  }

  function busy(isBusy) {
    submit.disabled = isBusy;
    input.readOnly = isBusy;
    submit.classList.toggle('busy', isBusy);
  }

  function onSubmit(event) {
    event.preventDefault();
    var value = input.value;
    if (!value) {
      return;
    }

    // Client-side strength gate. The server still enforces its own minimum
    // length; this only saves a round trip on an obviously bad password.
    if (settings.strength.enabled && zxcvbnReady) {
      var local = window.zxcvbnts.core.zxcvbn(value);
      if (local.score < settings.strength.min_score) {
        breakdown.replaceChildren();
        showVerdict('weak', settings.messages.weak || 'This password is too easy to guess.');
        return;
      }
    }

    busy(true);

    fetch('/api/v1/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ password: value })
    })
      .then(function (response) { return response.json(); })
      .then(function (body) {
        renderBreakdown(body.checks);
        showVerdict(
          body.verdict || (body.error ? 'error' : 'safe'),
          body.errorMessage,
          body.degraded ? body.degradedMessage || settings.messages.degraded : ''
        );
      })
      .catch(function () {
        breakdown.replaceChildren();
        showVerdict('error', settings.messages.error || 'The check could not be completed.');
      })
      .finally(function () {
        busy(false);
      });
  }

  /* ---------------------------------------------------------------- wiring */

  reveal.addEventListener('click', function () {
    var shown = input.type === 'text';
    input.type = shown ? 'password' : 'text';
    reveal.setAttribute('aria-pressed', String(!shown));
    reveal.setAttribute('aria-label', shown ? 'Show password' : 'Hide password');
    input.focus();
  });

  input.addEventListener('input', onInput);
  form.addEventListener('submit', onSubmit);
})();
