(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];

  // State
  let currentProject = "abc";
  let currentKey = "sk_abc_dev123";
  let email = "";
  let timer = null;

  // Elements
  const chips = $$(".project-chips .chip");
  const customKeyBox = $("#custom-key-box");
  const apiKeyInput = $("#api-key-input");
  const tabs = $$(".tab-btn");
  const panes = $$(".tab-pane");

  // Previews & Placeholders
  const otpSubjectPreview = $("#otp-subject-preview");
  const resetSubjectPreview = $("#reset-subject-preview");
  const greetingSubjectPreview = $("#greeting-subject-preview");

  function say(elId, text, kind = "") {
    const el = $(elId);
    if (!el) return;
    el.textContent = text;
    el.className = `status-msg ${kind}`;
  }

  // Network wrapper with API key injection
  async function post(path, body, customHeaders = {}) {
    try {
      const res = await fetch(path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": currentKey,
          ...customHeaders,
        },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: { error: "Cannot reach server. Check connection." } };
    }
  }

  async function get(path) {
    try {
      const res = await fetch(path, {
        headers: { "X-API-Key": currentKey },
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: {} };
    }
  }

  // ----------------------------------------------------------------------------
  // Project / Key Switching
  // ----------------------------------------------------------------------------
  function updateProject(project, key) {
    currentProject = project;
    currentKey = key;

    otpSubjectPreview.textContent = `Verification Code - ${project}`;
    resetSubjectPreview.textContent = `Reset Password - ${project}`;
    greetingSubjectPreview.textContent = `Welcome - ${project}`;

    $$(".ph-proj").forEach((el) => (el.textContent = project));
    $$(".ph-key").forEach((el) => (el.textContent = key));

    loadSubscribers();
  }

  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      chips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");

      const proj = chip.dataset.project;
      if (proj === "custom") {
        customKeyBox.hidden = false;
        apiKeyInput.focus();
        currentKey = apiKeyInput.value.trim() || "sk_custom_key";
        updateProject("custom", currentKey);
      } else {
        customKeyBox.hidden = true;
        updateProject(proj, chip.dataset.key);
      }
    });
  });

  apiKeyInput.addEventListener("input", () => {
    currentKey = apiKeyInput.value.trim() || "sk_custom_key";
    updateProject("custom", currentKey);
  });

  // ----------------------------------------------------------------------------
  // Tab Switching
  // ----------------------------------------------------------------------------
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      panes.forEach((p) => { p.hidden = true; p.classList.remove("active"); });

      tab.classList.add("active");
      const targetPane = $(`#pane-${tab.dataset.tab}`);
      if (targetPane) {
        targetPane.hidden = false;
        targetPane.classList.add("active");
      }

      if (tab.dataset.tab === "subscribers") {
        loadSubscribers();
      }
    });
  });

  // ----------------------------------------------------------------------------
  // TAB 1: OTP Verification Logic
  // ----------------------------------------------------------------------------
  const stepEmail = $("#step-email"), stepCode = $("#step-code"), stepDone = $("#step-done");
  const emailInput = $("#email"), sendBtn = $("#send-btn"), verifyBtn = $("#verify-btn");
  const resendBtn = $("#resend-btn"), changeBtn = $("#change-btn"), againBtn = $("#again-btn");
  const cellsBox = $("#cells");
  const cells = [...cellsBox.querySelectorAll("input")];

  const showStep = (el) => [stepEmail, stepCode, stepDone].forEach((s) => (s.hidden = s !== el));
  const getOtpCode = () => cells.map((c) => c.value).join("");

  function startCooldown(seconds) {
    clearInterval(timer);
    let left = seconds;
    const tick = () => {
      if (left <= 0) {
        clearInterval(timer);
        resendBtn.disabled = false;
        resendBtn.textContent = "Resend code";
        return;
      }
      resendBtn.disabled = true;
      resendBtn.textContent = `Resend code in ${left}s`;
      left -= 1;
    };
    tick();
    timer = setInterval(tick, 1000);
  }

  function openCodeStep() {
    $("#sent-to").textContent = email;
    cells.forEach((c) => (c.value = ""));
    showStep(stepCode);
    cells[0].focus();
  }

  async function sendOtp(isResend = false) {
    sendBtn.disabled = true;
    resendBtn.disabled = true;
    say("#msg-otp", "Sending code…");

    const { ok, data } = await post("/api/send-otp", { email });
    sendBtn.disabled = false;

    if (ok) {
      say("#msg-otp", `Code sent for ${data.project}! Expires in ${data.expiresInMinutes}m.`, "ok");
      if (!isResend) openCodeStep(); else cells[0].focus();
      startCooldown(data.cooldownSeconds || 60);
    } else if (data.code === "cooldown") {
      say("#msg-otp", data.error, "err");
      if (!isResend) openCodeStep();
      startCooldown(data.retryAfter || 60);
    } else {
      say("#msg-otp", data.error || "Failed to send code.", "err");
      if (isResend) resendBtn.disabled = false;
    }
  }

  stepEmail.addEventListener("submit", (e) => {
    e.preventDefault();
    email = emailInput.value.trim().toLowerCase();
    if (!emailInput.checkValidity() || !email) return say("#msg-otp", "Enter a valid email address.", "err");
    sendOtp(false);
  });

  resendBtn.addEventListener("click", () => sendOtp(true));
  changeBtn.addEventListener("click", () => { clearInterval(timer); say("#msg-otp", ""); showStep(stepEmail); emailInput.focus(); });
  againBtn.addEventListener("click", () => { emailInput.value = ""; say("#msg-otp", ""); showStep(stepEmail); emailInput.focus(); });

  stepCode.addEventListener("submit", async (e) => {
    e.preventDefault();
    const otp = getOtpCode();
    if (otp.length !== 6) return say("#msg-otp", "Enter all 6 digits.", "err");

    verifyBtn.disabled = true;
    say("#msg-otp", "Verifying code…");
    const { ok, data } = await post("/api/verify-otp", { email, otp });
    verifyBtn.disabled = false;

    if (ok) {
      clearInterval(timer);
      $("#done-email").textContent = email;
      $("#done-project").textContent = data.project || currentProject;
      say("#msg-otp", "");
      loadSubscribers();
      return showStep(stepDone);
    }

    say("#msg-otp", data.error || "Verification failed.", "err");
    cellsBox.classList.add("error");
    setTimeout(() => cellsBox.classList.remove("error"), 600);
    if (data.code === "invalid_otp") {
      cells.forEach((c) => (c.value = ""));
      cells[0].focus();
    }
  });

  cells.forEach((cell, i) => {
    cell.addEventListener("input", () => {
      cell.value = cell.value.replace(/\D/g, "").slice(-1);
      if (cell.value && i < 5) cells[i + 1].focus();
      if (getOtpCode().length === 6) stepCode.requestSubmit();
    });
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !cell.value && i > 0) cells[i - 1].focus();
      if (e.key === "ArrowLeft" && i > 0) cells[i - 1].focus();
      if (e.key === "ArrowRight" && i < 5) cells[i + 1].focus();
    });
    cell.addEventListener("paste", (e) => {
      const digits = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
      if (!digits) return;
      e.preventDefault();
      [...digits].forEach((d, k) => (cells[k].value = d));
      cells[Math.min(digits.length, 5)].focus();
      if (digits.length === 6) stepCode.requestSubmit();
    });
  });

  // ----------------------------------------------------------------------------
  // TAB 2: Broadcast Logic
  // ----------------------------------------------------------------------------
  const formBroadcast = $("#form-broadcast");
  const bcastSendBtn = $("#bcast-send-btn");

  formBroadcast.addEventListener("submit", async (e) => {
    e.preventDefault();
    const scope = $("input[name='broadcast-scope']:checked").value;
    const subject = $("#bcast-subject").value.trim();
    const title = $("#bcast-title").value.trim();
    const message = $("#bcast-message").value.trim();
    const actionUrl = $("#bcast-action-url").value.trim();
    const actionLabel = $("#bcast-action-label").value.trim();
    const customHeader = $("#bcast-header").value.trim();
    const customFooter = $("#bcast-footer").value.trim();

    if (!subject || !message) return say("#msg-broadcast", "Subject and message are required.", "err");

    bcastSendBtn.disabled = true;
    say("#msg-broadcast", "Dispatching broadcast…");

    const endpoint = scope === "all" ? "/api/broadcast/all" : "/api/broadcast";
    const { ok, data } = await post(endpoint, {
      subject,
      title: title || undefined,
      message,
      action_url: actionUrl || undefined,
      action_label: actionLabel || undefined,
      custom_header: customHeader || undefined,
      custom_footer: customFooter || undefined,
    });
    bcastSendBtn.disabled = false;

    if (ok) {
      say("#msg-broadcast", `Success: ${data.sentCount} sent (${data.totalSubscribers || data.totalRecipients || 0} active recipients).`, "ok");
    } else {
      say("#msg-broadcast", data.error || "Broadcast failed.", "err");
    }
  });

  // ----------------------------------------------------------------------------
  // TAB 3: Subscribers Viewer
  // ----------------------------------------------------------------------------
  async function loadSubscribers() {
    const tbody = $("#subs-tbody");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--muted);">Loading subscribers…</td></tr>`;

    const { ok, data } = await get("/api/subscribers");
    if (ok && data.subscribers) {
      $("#subs-count").textContent = data.subscribers.filter((s) => s.isSubscribed).length;
      if (data.subscribers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--muted);">No subscribers recorded yet for this project. Send an OTP to add one!</td></tr>`;
        return;
      }
      tbody.innerHTML = data.subscribers
        .map(
          (sub) => `
        <tr>
          <td><strong>${sub.email}</strong> ${sub.name ? `<small>(${sub.name})</small>` : ""}</td>
          <td><span class="badge-sub ${sub.isSubscribed ? "active" : "unsub"}">${sub.isSubscribed ? "Subscribed" : "Unsubscribed"}</span></td>
          <td><code>${sub.source || "auto"}</code></td>
          <td>${sub.createdAt ? new Date(sub.createdAt).toLocaleDateString() : "Recently"}</td>
        </tr>
      `
        )
        .join("");
    } else {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--err);">Could not load subscribers. Check MongoDB connection.</td></tr>`;
    }
  }

  $("#refresh-subs-btn").addEventListener("click", loadSubscribers);

  // ----------------------------------------------------------------------------
  // TAB 4 & 5: Reset Password & Greeting Form
  // ----------------------------------------------------------------------------
  const formReset = $("#form-reset");
  const resetSendBtn = $("#reset-send-btn");

  formReset.addEventListener("submit", async (e) => {
    e.preventDefault();
    const toEmail = $("#reset-email").value.trim();
    const name = $("#reset-name").value.trim();
    const resetUrl = $("#reset-url").value.trim();
    const resetCode = $("#reset-code").value.trim();

    if (!toEmail) return say("#msg-reset", "Enter recipient email address.", "err");

    resetSendBtn.disabled = true;
    say("#msg-reset", "Sending password reset email…");

    const { ok, data } = await post("/api/send-reset-password", {
      email: toEmail,
      name: name || undefined,
      reset_url: resetUrl || undefined,
      reset_code: resetCode || undefined,
    });
    resetSendBtn.disabled = false;

    if (ok) {
      say("#msg-reset", `Sent with subject: "${data.subject}"`, "ok");
      loadSubscribers();
    } else {
      say("#msg-reset", data.error || "Failed to send reset email.", "err");
    }
  });

  const formGreeting = $("#form-greeting");
  const greetingSendBtn = $("#greeting-send-btn");

  formGreeting.addEventListener("submit", async (e) => {
    e.preventDefault();
    const toEmail = $("#greet-email").value.trim();
    const name = $("#greet-name").value.trim();
    const title = $("#greet-title").value.trim();
    const message = $("#greet-message").value.trim();
    const actionUrl = $("#greet-action-url").value.trim();
    const actionLabel = $("#greet-action-label").value.trim();

    if (!toEmail) return say("#msg-greeting", "Enter recipient email address.", "err");

    greetingSendBtn.disabled = true;
    say("#msg-greeting", "Sending greeting email…");

    const { ok, data } = await post("/api/send-greeting", {
      email: toEmail,
      name: name || undefined,
      title: title || undefined,
      message: message || undefined,
      action_url: actionUrl || undefined,
      action_label: actionLabel || undefined,
    });
    greetingSendBtn.disabled = false;

    if (ok) {
      say("#msg-greeting", `Sent with subject: "${data.subject}"`, "ok");
      loadSubscribers();
    } else {
      say("#msg-greeting", data.error || "Failed to send greeting.", "err");
    }
  });

  // ----------------------------------------------------------------------------
  // TAB 6: Copy Code Snippets
  // ----------------------------------------------------------------------------
  $$(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const codeId = `code-${btn.dataset.copy}`;
      const codeEl = $(`#${codeId}`);
      if (!codeEl) return;
      navigator.clipboard.writeText(codeEl.innerText).then(() => {
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => (btn.textContent = orig), 1500);
      });
    });
  });
})();
