/* ===========================================================
   KeySense — password security helper
   Everything here runs locally in the browser.
   The password typed by the user is NEVER stored or sent:
   - no forms are submitted
   - no network requests are made
   - no localStorage / cookies are used
   =========================================================== */

(function () {
  "use strict";

  /* ---------------------------------------------------------
     Data
     --------------------------------------------------------- */

  // A short list of the most common leaked passwords.
  const COMMON_PASSWORDS = new Set([
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890", "1234", "111111",
    "000000", "123123", "654321", "666666", "121212", "112233", "123321", "7777777",
    "password", "password1", "password123", "passw0rd", "qwerty", "qwerty123", "qwertyuiop",
    "abc123", "abcd1234", "iloveyou", "admin", "admin123", "welcome", "welcome1", "login",
    "letmein", "monkey", "dragon", "football", "baseball", "cricket", "soccer", "master",
    "sunshine", "princess", "shadow", "superman", "batman", "michael", "jennifer", "jordan",
    "hunter", "hunter2", "trustno1", "starwars", "whatever", "freedom", "hello", "hello123",
    "charlie", "donald", "flower", "lovely", "loveme", "pokemon", "naruto", "ninja", "mustang",
    "access", "secret", "computer", "internet", "samsung", "google", "apple", "iphone",
    "asdfgh", "asdfghjkl", "zxcvbnm", "qazwsx", "1q2w3e4r", "1qaz2wsx", "aa123456", "q1w2e3r4",
    "zaq12wsx", "pass", "pass123", "test", "test123", "guest", "default", "root", "user",
    "changeme", "summer", "winter", "spring", "autumn", "love", "family", "friends", "money",
    "killer", "cheese", "chocolate", "banana", "orange", "purple", "pakistan", "bangladesh",
    "india", "london", "america", "liverpool", "arsenal", "chelsea", "barcelona", "realmadrid",
    "messi", "ronaldo", "blink182", "matrix", "biteme", "maggie", "ginger", "buster", "tigger",
    "robert", "thomas", "daniel", "andrew", "joshua", "ashley", "jessica", "qwerty1", "aaaaaa",
    "correcthorsebatterystaple", "p@ssw0rd", "p@ssword", "passwort", "motdepasse", "contraseña"
  ]);

  // Common dictionary-style words people build passwords from.
  const COMMON_WORDS = [
    "password", "pass", "love", "admin", "welcome", "hello", "dragon", "monkey", "master",
    "football", "soccer", "cricket", "summer", "winter", "secret", "shadow", "sunshine",
    "princess", "qwerty", "login", "letmein", "super", "angel", "baby", "happy", "money",
    "school", "student", "teacher", "computer", "google", "apple", "cookie", "pizza", "tiger",
    "lion", "eagle", "star", "king", "queen", "boss", "cool", "sweet", "honey", "lucky",
    "magic", "power", "rock", "blue", "red", "green", "black", "white", "game", "gamer"
  ];

  const KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "qazwsxedc", "!@#$%^&*()"
  ];

  const LEET_MAP = { "@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "8": "b", "9": "g" };

  // Word list for the passphrase generator (simple, easy-to-type words).
  const WORDS = [
    "acorn", "anchor", "apple", "arrow", "atlas", "autumn", "badge", "bamboo", "banjo", "barrel",
    "basket", "beacon", "berry", "bison", "blanket", "blossom", "bottle", "bramble", "breeze", "bridge",
    "bubble", "bucket", "butter", "cabin", "cactus", "camel", "candle", "canyon", "carpet", "castle",
    "cedar", "cherry", "cinder", "citrus", "cloud", "clover", "cobalt", "comet", "copper", "coral",
    "cotton", "crayon", "cricket", "crystal", "cushion", "dagger", "daisy", "desert", "dolphin", "domino",
    "dragon", "drizzle", "eagle", "echo", "ember", "falcon", "feather", "fern", "fiddle", "fig",
    "flame", "flannel", "forest", "fossil", "fountain", "galaxy", "garden", "garlic", "ginger", "glacier",
    "goblet", "granite", "gravel", "hammer", "harbor", "harvest", "hazel", "helmet", "hollow", "honey",
    "horizon", "iceberg", "igloo", "island", "ivory", "jacket", "jasmine", "jelly", "jigsaw", "jungle",
    "kayak", "kettle", "kitten", "koala", "ladder", "lagoon", "lantern", "lemon", "lettuce", "lizard",
    "lobster", "magnet", "mango", "maple", "marble", "meadow", "melon", "meteor", "mirror", "mitten",
    "monsoon", "mosaic", "muffin", "nectar", "needle", "noodle", "nutmeg", "oasis", "ocean", "olive",
    "onion", "orbit", "orchid", "otter", "paddle", "panda", "pebble", "pepper", "pickle", "pigeon",
    "pillow", "pirate", "planet", "pocket", "pollen", "popcorn", "puzzle", "quartz", "quill", "rabbit",
    "radar", "raven", "ribbon", "river", "rocket", "saddle", "salmon", "sandal", "scarf", "shadow",
    "shovel", "silver", "sketch", "socket", "spiral", "sponge", "spruce", "squid", "summit", "sunset",
    "tablet", "teapot", "thistle", "thunder", "ticket", "timber", "tomato", "topaz", "tornado", "trumpet",
    "tulip", "tunnel", "turtle", "umbrella", "valley", "velvet", "violet", "volcano", "waffle", "walnut",
    "walrus", "whistle", "willow", "window", "wizard", "yogurt", "zebra", "zephyr", "zigzag", "zipper"
  ];

  const TIPS = [
    "A 16-character password with mixed characters would take billions of years to brute-force.",
    "Most hacked accounts are caused by reused passwords, not clever hacking.",
    "Your password is only as safe as the website storing it. Use different ones everywhere.",
    "Security questions are often easy to guess. Treat their answers like extra passwords.",
    "Two-factor authentication blocks the vast majority of automated account attacks.",
    "Writing a password on paper at home is safer than reusing it, but a password manager is better.",
    "If a site limits passwords to 8 characters, take that as a hint to protect that account even more.",
    "Public Wi-Fi? Avoid logging in to important accounts unless the site uses HTTPS.",
    "Your email password is the master key: it can reset all your other passwords. Make it the strongest.",
    "Adding one random word to a passphrase makes it thousands of times harder to guess.",
    "Hackers don't guess one letter at a time; they try dictionaries, names and leaked lists first.",
    "Never type a password into a page you reached from a link in an unexpected message."
  ];

  /* ---------------------------------------------------------
     Helpers
     --------------------------------------------------------- */

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // Cryptographically secure random integer in [0, max)
  function randInt(max) {
    const limit = Math.floor(0xFFFFFFFF / max) * max;
    const buf = new Uint32Array(1);
    let x;
    do {
      crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= limit);
    return x % max;
  }

  function pick(str) { return str[randInt(str.length)]; }

  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = randInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  function escapeHTML(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => t.classList.remove("show"), 1800);
  }

  function formatTime(seconds) {
    if (!isFinite(seconds) || seconds > 1e18 * 3.15e7) return "longer than the universe has existed";
    if (seconds < 1) return "instantly";
    const units = [
      ["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]
    ];
    if (seconds >= 31557600) {
      const years = seconds / 31557600;
      if (years >= 1.4e10) return "longer than the universe has existed";
      if (years >= 1e9) return Math.round(years / 1e9) + " billion years";
      if (years >= 1e6) return Math.round(years / 1e6) + " million years";
      if (years >= 1e3) return Math.round(years / 1e3) + " thousand years";
      const y = Math.round(years);
      return y + (y === 1 ? " year" : " years");
    }
    for (const [name, size] of units) {
      if (seconds >= size) {
        const n = Math.round(seconds / size);
        return n + " " + name + (n === 1 ? "" : "s");
      }
    }
    return "instantly";
  }

  /* ---------------------------------------------------------
     Password analysis
     --------------------------------------------------------- */

  function longestRun(pw, checkStep) {
    // Longest run of characters where each step satisfies checkStep(prev, cur)
    let best = 1, cur = 1, bestStart = 0, start = 0;
    for (let i = 1; i < pw.length; i++) {
      if (checkStep(pw[i - 1], pw[i])) {
        cur++;
        if (cur > best) { best = cur; bestStart = start; }
      } else {
        cur = 1;
        start = i;
      }
    }
    return { length: pw.length ? best : 0, text: pw.substr(bestStart, best) };
  }

  function findSequence(pw) {
    const lower = pw.toLowerCase();
    const isAlnum = (c) => /[a-z0-9]/.test(c);
    const up = longestRun(lower, (a, b) => isAlnum(a) && isAlnum(b) && b.charCodeAt(0) - a.charCodeAt(0) === 1);
    const down = longestRun(lower, (a, b) => isAlnum(a) && isAlnum(b) && a.charCodeAt(0) - b.charCodeAt(0) === 1);
    return up.length >= down.length ? up : down;
  }

  function findKeyboardPattern(pw) {
    const lower = pw.toLowerCase();
    let best = "";
    for (const row of KEYBOARD_ROWS) {
      const rev = row.split("").reverse().join("");
      for (const line of [row, rev]) {
        for (let len = Math.min(line.length, lower.length); len >= 4; len--) {
          if (len <= best.length) break;
          for (let i = 0; i + len <= line.length; i++) {
            const chunk = line.substr(i, len);
            if (lower.includes(chunk)) { best = chunk; break; }
          }
          if (best.length === len) break;
        }
      }
    }
    return best;
  }

  function deLeet(pw) {
    return pw.toLowerCase().split("").map((c) => LEET_MAP[c] || c).join("");
  }

  function analyze(pw) {
    const result = {
      length: pw.length,
      has: {
        lower: /[a-z]/.test(pw),
        upper: /[A-Z]/.test(pw),
        digit: /[0-9]/.test(pw),
        symbol: /[^a-zA-Z0-9]/.test(pw)
      },
      weaknesses: [],
      positives: [],
      common: false,
      bits: 0,
      rawBits: 0,
      level: "none"
    };
    if (!pw) return result;

    const has = result.has;
    let pool = 0;
    if (has.lower) pool += 26;
    if (has.upper) pool += 26;
    if (has.digit) pool += 10;
    if (has.symbol) pool += 33;
    const perChar = Math.log2(pool);
    result.rawBits = pw.length * perChar;
    let bits = result.rawBits;

    const add = (title, detail) => result.weaknesses.push({ title, detail });
    const lower = pw.toLowerCase();

    // 1. Exact common password
    if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(deLeet(pw))) {
      result.common = true;
      bits = Math.min(bits, 8);
      add("Very common password", "This appears on lists of the most-used passwords. Attackers try these first, so it would fall almost instantly.");
    } else {
      // 2. Built on a common word / password (after removing leet and trailing digits/symbols)
      const core = deLeet(pw).replace(/[^a-z]+$/g, "").replace(/^[^a-z]+/g, "");
      const word = COMMON_WORDS.concat(Array.from(COMMON_PASSWORDS).filter((w) => /^[a-z]{4,}$/.test(w) && !/^(.)\1+$/.test(w)))
        .filter((w) => w.length >= 4 && core.includes(w))
        .sort((a, b) => b.length - a.length)[0];
      if (word && (COMMON_PASSWORDS.has(core) || word.length >= pw.length * 0.4)) {
        result.common = COMMON_PASSWORDS.has(core);
        bits -= word.length * perChar - 12;
        add("Built on a common word", `It's based on "${escapeHTML(word)}". Cracking tools combine dictionary words with numbers and swaps like @ → a.`);
      }
    }

    // 3. Keyboard patterns
    const kb = findKeyboardPattern(pw);
    if (kb) {
      bits -= kb.length * perChar * 0.8;
      add("Keyboard pattern", `Contains "${escapeHTML(kb)}", a run of neighbouring keys. These are well known to attackers.`);
    }

    // 4. Sequences like abc / 123
    const seq = findSequence(pw);
    if (seq.length >= 3 && !(kb && kb.includes(seq.text))) {
      bits -= seq.length * perChar * 0.7;
      add("Predictable sequence", `"${escapeHTML(seq.text)}" counts up or down. Sequences add very little real randomness.`);
    }

    // 5. Repeated characters
    const rep = pw.match(/(.)\1{2,}/);
    if (rep) {
      bits -= (rep[0].length - 1) * perChar * 0.8;
      add("Repeated characters", `"${escapeHTML(rep[0])}" repeats the same character. It adds length without making it harder to guess.`);
    } else {
      const chunk = pw.match(/(.{2,})\1+/);
      if (chunk && chunk[0].length >= 4) {
        bits -= (chunk[0].length - chunk[1].length) * perChar * 0.8;
        add("Repeated chunk", `"${escapeHTML(chunk[0])}" repeats the same group of characters.`);
      }
    }

    // 6. Years and dates
    const year = pw.match(/(19[5-9]\d|20[0-3]\d)/);
    const date = pw.match(/\d{1,2}[\/\-.]\d{1,2}([\/\-.]\d{2,4})?/);
    if (year) {
      bits -= Math.max(0, 4 * perChar - 7);
      add("Contains a year", `"${year[0]}" looks like a year. Birth years and graduation years are easy to find online.`);
    } else if (date) {
      bits -= Math.max(0, date[0].length * perChar - 9);
      add("Looks like a date", `"${escapeHTML(date[0])}" looks like a date, which is often personal and guessable.`);
    }

    // 7. Character variety
    const types = Object.values(has).filter(Boolean).length;
    if (/^\d+$/.test(pw)) {
      add("Numbers only", "Only digits means just 10 options per character. Add letters and symbols.");
    } else if (/^[a-zA-Z]+$/.test(pw) && pw.length < 16) {
      add("Letters only", "Add numbers or symbols, or make it much longer, to widen the search space.");
    } else if (types === 2 && pw.length < 12) {
      add("Limited variety", "Only two kinds of characters are used. Mixing in more types makes it harder to crack.");
    }

    // 8. Length
    if (pw.length < 8) {
      add("Too short", `At ${pw.length} character${pw.length === 1 ? "" : "s"}, it can be brute-forced quickly. Aim for at least 12.`);
    } else if (pw.length < 12) {
      add("Could be longer", "8–11 characters is the bare minimum. Every extra character makes it much stronger.");
    }

    // 9. Starts with capital and ends with digit/symbol (the classic "Password1!" shape)
    if (/^[A-Z][a-z]{2,}[0-9!@#$%^&*]{1,4}$/.test(pw)) {
      bits -= 6;
      add("Predictable shape", "Capital first, then lowercase, then numbers or a symbol at the end. This is the most common shape and attackers test it first.");
    }

    bits = Math.max(0, bits);
    result.bits = bits;

    // Positives
    if (pw.length >= 16) result.positives.push("Great length. Long passwords are the hardest to crack.");
    if (types === 4) result.positives.push("Uses all four character types.");

    // Level
    if (result.common || pw.length < 8 || bits < 40) result.level = "weak";
    else if (bits >= 65 && pw.length >= 12) result.level = "strong";
    else result.level = "medium";

    result.types = types;
    return result;
  }

  /* ---------------------------------------------------------
     Checker UI
     --------------------------------------------------------- */

  const pwInput = $("#pw");
  const meter = $(".meter");
  const label = $("#strength-label");
  const sub = $("#strength-sub");

  const LEVEL_TEXT = {
    weak: ["Weak", "This would be easy to crack. Check the weaknesses list for what to fix."],
    medium: ["Medium", "Not bad, but there's room to improve. Try making it longer or less predictable."],
    strong: ["Strong", "Nicely done. This would be very hard to guess or brute-force."]
  };

  function renderChecker() {
    const pw = pwInput.value;
    const r = analyze(pw);

    // meter + label
    meter.className = "meter " + (r.level !== "none" ? r.level : "");
    label.className = "strength-label " + (r.level !== "none" ? r.level : "");
    if (r.level === "none") {
      label.textContent = "Waiting for input";
      sub.textContent = "Strength appears here as you type.";
    } else {
      label.textContent = LEVEL_TEXT[r.level][0];
      sub.textContent = LEVEL_TEXT[r.level][1];
    }

    // stats
    $("#stat-length").textContent = r.length;
    $("#stat-types").textContent = (r.types || 0) + " / 4";
    $("#stat-entropy").textContent = Math.round(r.bits) + " bits";
    const seconds = pw ? Math.pow(2, r.bits) / 2 / 1e10 : NaN;
    $("#stat-time").textContent = pw ? formatTime(seconds) : "—";

    // requirements
    const reqs = {
      length: r.length >= 12,
      lower: r.has.lower,
      upper: r.has.upper,
      digit: r.has.digit,
      symbol: r.has.symbol,
      common: !r.common
    };
    $$("#req-list li").forEach((li) => {
      const key = li.dataset.req;
      li.classList.remove("ok", "fail");
      if (!pw) return;
      li.classList.add(reqs[key] ? "ok" : "fail");
    });

    // weaknesses
    const list = $("#weak-list");
    if (!pw) {
      list.innerHTML = '<li class="muted">Nothing to report yet.</li>';
      return;
    }
    let html = r.weaknesses.map((w) => `<li><strong>${w.title}</strong>${w.detail}</li>`).join("");
    if (!r.weaknesses.length) {
      html = '<li class="good"><strong>No obvious weaknesses</strong>We couldn\'t spot any common patterns. Keep it unique to one account.</li>';
    }
    html += r.positives.map((p) => `<li class="good"><strong>Good</strong>${p}</li>`).join("");
    list.innerHTML = html;
  }

  pwInput.addEventListener("input", renderChecker);

  $("#toggle-pw").addEventListener("click", () => {
    const show = pwInput.type === "password";
    pwInput.type = show ? "text" : "password";
    $("#toggle-pw").setAttribute("aria-label", show ? "Hide password" : "Show password");
    $("#toggle-pw").innerHTML = show
      ? '<svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18M10.6 6.1A9.9 9.9 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-3.1 3.8M6.6 6.6C3.7 8.4 2 12 2 12s3.5 7 10 7c1.8 0 3.3-.5 4.6-1.2M9.9 9.9a3 3 0 0 0 4.2 4.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
      : '<svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
    pwInput.focus();
  });

  $("#clear-pw").addEventListener("click", () => {
    pwInput.value = "";
    renderChecker();
    pwInput.focus();
  });

  // Make sure the browser never restores a previously typed value
  window.addEventListener("pageshow", () => { pwInput.value = ""; renderChecker(); });

  /* ---------------------------------------------------------
     Generator
     --------------------------------------------------------- */

  const SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digit: "0123456789",
    symbol: "!@#$%^&*()-_=+[]{};:,.?/~"
  };
  const AMBIGUOUS = /[l1IO0o|]/g;

  let mode = "random";
  let lastGenerated = "";

  function generateRandom() {
    const length = +$("#gen-length").value;
    const avoid = $("#opt-ambig").checked;
    const chosen = ["lower", "upper", "digit", "symbol"]
      .filter((k) => $("#opt-" + k).checked)
      .map((k) => avoid ? SETS[k].replace(AMBIGUOUS, "") : SETS[k]);

    if (!chosen.length) {
      toast("Pick at least one character type");
      return null;
    }
    const all = chosen.join("");
    // guarantee one of each chosen type, then fill the rest
    const chars = chosen.map((set) => pick(set));
    while (chars.length < length) chars.push(pick(all));
    return {
      value: shuffle(chars).join(""),
      bits: length * Math.log2(all.length)
    };
  }

  function generatePhrase() {
    const n = +$("#gen-words").value;
    const sep = $("#opt-sep").value;
    const cap = $("#opt-cap").checked;
    const num = $("#opt-num").checked;
    const words = [];
    for (let i = 0; i < n; i++) {
      let w = WORDS[randInt(WORDS.length)];
      if (cap) w = w[0].toUpperCase() + w.slice(1);
      words.push(w);
    }
    let bits = n * Math.log2(WORDS.length);
    if (num) {
      const pos = randInt(words.length);
      words[pos] = words[pos] + randInt(100);
      bits += Math.log2(100) + Math.log2(n);
    }
    return { value: words.join(sep), bits };
  }

  function generate() {
    const g = mode === "random" ? generateRandom() : generatePhrase();
    if (!g) return;
    lastGenerated = g.value;
    $("#gen-result").textContent = g.value;
    const lvl = g.bits >= 65 ? "Strong" : g.bits >= 40 ? "Medium" : "Weak";
    const secs = Math.pow(2, g.bits) / 2 / 1e10;
    $("#gen-strength").innerHTML =
      `<strong>${lvl}</strong> · about ${Math.round(g.bits)} bits of randomness · would take roughly <strong>${formatTime(secs)}</strong> to crack.`;
  }

  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      mode = tab.dataset.mode;
      $$(".tab").forEach((t) => {
        t.classList.toggle("active", t === tab);
        t.setAttribute("aria-selected", t === tab ? "true" : "false");
      });
      $("#opts-random").classList.toggle("hidden", mode !== "random");
      $("#opts-phrase").classList.toggle("hidden", mode !== "phrase");
      generate();
    });
  });

  $("#gen-length").addEventListener("input", (e) => { $("#len-val").textContent = e.target.value; generate(); });
  $("#gen-words").addEventListener("input", (e) => { $("#words-val").textContent = e.target.value; generate(); });
  $$("#opts-random input[type=checkbox], #opts-phrase input[type=checkbox], #opt-sep")
    .forEach((el) => el.addEventListener("change", generate));
  $("#gen-new").addEventListener("click", generate);

  $("#gen-copy").addEventListener("click", async () => {
    if (!lastGenerated) return;
    try {
      await navigator.clipboard.writeText(lastGenerated);
      toast("Copied to clipboard");
    } catch (e) {
      // Fallback for file:// pages where the clipboard API is blocked
      const ta = document.createElement("textarea");
      ta.value = lastGenerated;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); toast("Copied to clipboard"); }
      catch (err) { toast("Couldn't copy. Select the text manually."); }
      ta.remove();
    }
  });

  $("#gen-test").addEventListener("click", () => {
    if (!lastGenerated) return;
    pwInput.value = lastGenerated;
    renderChecker();
    $("#checker").scrollIntoView({ behavior: "smooth" });
  });

  /* ---------------------------------------------------------
     Tips
     --------------------------------------------------------- */

  let tipIndex = randInt(TIPS.length);
  function showTip() {
    $("#tip-text").textContent = TIPS[tipIndex];
  }
  $("#tip-next").addEventListener("click", () => {
    let next;
    do { next = randInt(TIPS.length); } while (next === tipIndex && TIPS.length > 1);
    tipIndex = next;
    showTip();
  });

  /* ---------------------------------------------------------
     Nav highlight
     --------------------------------------------------------- */

  const navLinks = $$(".nav a");
  if ("IntersectionObserver" in window) {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          navLinks.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + entry.target.id));
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    $$("main section[id]").forEach((s) => obs.observe(s));
  }

  /* ---------------------------------------------------------
     Init
     --------------------------------------------------------- */
  showTip();
  generate();
  renderChecker();

  // expose analyze for testing in the console
  window.KeySense = { analyze };
})();
