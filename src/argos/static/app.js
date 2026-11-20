// ARGOS UI helpers. No inline scripts (CSP: script-src 'self').
(function () {
  "use strict";
  var fmt = document.getElementById("fmt");
  function syncOpts() {
    if (!fmt) return;
    document.querySelectorAll(".opt").forEach(function (el) {
      el.classList.toggle("show", el.classList.contains("opt-" + fmt.value));
    });
  }
  if (fmt) { fmt.addEventListener("change", syncOpts); syncOpts(); }
  var btn = document.getElementById("explain");
  if (btn) {
    btn.addEventListener("click", function () {
      var out = document.getElementById("explain-out");
      var token = document.querySelector('meta[name="csrf-token"]').getAttribute("content");
      out.textContent = "Requesting explanation...";
      fetch(btn.getAttribute("data-url"), {method: "POST", headers: {"X-CSRF-Token": token, "Content-Type": "application/json"}, body: "{}", credentials: "same-origin"})
        .then(function (r) { return r.json(); })
        .then(function (j) { out.textContent = JSON.stringify(j, null, 2); })  // textContent: never HTML
        .catch(function (e) { out.textContent = "Error: " + e; });
    });
  }
})();
