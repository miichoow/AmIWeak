// Stays alive but never reads stdin or writes a response. Used to exercise
// StrengthScorer's read timeout without a 5-second real wait.
setInterval(function () {}, 1000);
