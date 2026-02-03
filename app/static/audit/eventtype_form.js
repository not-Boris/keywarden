(function () {
  function parseSuggestions(textarea, key) {
    try {
      var raw = textarea.dataset[key];
      return raw ? JSON.parse(raw) : [];
    } catch (err) {
      return [];
    }
  }

  function splitLines(value) {
    return (value || "")
      .split(/\r?\n/)
      .map(function (line) {
        return line.trim();
      })
      .filter(function (line) {
        return line.length > 0;
      });
  }

  function appendLine(textarea, value) {
    var lines = splitLines(textarea.value);
    if (lines.indexOf(value) !== -1) {
      return;
    }
    lines.push(value);
    textarea.value = lines.join("\n");
    textarea.dispatchEvent(new Event("change", { bubbles: true }));
  }

  document.addEventListener("DOMContentLoaded", function () {
    var textarea = document.getElementById("id_endpoints_text");
    var kindSelect = document.getElementById("id_kind");
    if (!textarea || !kindSelect) {
      return;
    }

    var apiSuggestions = parseSuggestions(textarea, "apiSuggestions");
    var wsSuggestions = parseSuggestions(textarea, "wsSuggestions");

    var container = document.createElement("div");
    container.className = "audit-endpoint-suggestions";
    container.style.marginTop = "0.5rem";

    var title = document.createElement("div");
    title.style.fontWeight = "600";
    title.style.marginBottom = "0.25rem";
    title.textContent = "Suggested endpoints";
    container.appendChild(title);

    var list = document.createElement("div");
    list.style.display = "flex";
    list.style.flexWrap = "wrap";
    list.style.gap = "0.25rem";
    container.appendChild(list);

    textarea.parentNode.insertBefore(container, textarea.nextSibling);

    function currentSuggestions() {
      return kindSelect.value === "websocket" ? wsSuggestions : apiSuggestions;
    }

    function renderSuggestions() {
      var suggestions = currentSuggestions();
      list.innerHTML = "";
      if (!suggestions || suggestions.length === 0) {
        var empty = document.createElement("span");
        empty.textContent = "No endpoint suggestions were found.";
        empty.style.opacity = "0.7";
        list.appendChild(empty);
        return;
      }
      suggestions.slice(0, 40).forEach(function (suggestion) {
        var button = document.createElement("button");
        button.type = "button";
        button.textContent = suggestion;
        button.style.padding = "0.2rem 0.45rem";
        button.style.borderRadius = "999px";
        button.style.border = "1px solid #d1d5db";
        button.style.background = "#f9fafb";
        button.style.cursor = "pointer";
        button.addEventListener("click", function () {
          appendLine(textarea, suggestion);
        });
        list.appendChild(button);
      });
    }

    kindSelect.addEventListener("change", renderSuggestions);
    renderSuggestions();
  });
})();
