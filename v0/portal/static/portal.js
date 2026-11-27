"use strict";

const byId = (id) => document.getElementById(id);
const node = (element, text, css) => {
  const result = document.createElement(element);
  if (text !== undefined) result.textContent = text;
  if (css) result.className = css;
  return result;
};
const resume = document.querySelector("[data-resume]");
if (resume) location.replace(resume.href);

const page = document.body.dataset.page;
const basePath = document.body.dataset.basePath ?? "";
const taskId = document.body.dataset.id;
const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
const states = {
  evaluating: "Checking request", accepted: "Accepted", executing: "Running",
  awaiting_input: "Needs your input", cancelling: "Cancellation requested",
  completed: "Completed", rejected: "Rejected", failed: "Failed",
  cancelled: "Cancelled", indeterminate: "Outcome unconfirmed",
};
const terminal = new Set(["completed", "rejected", "failed", "cancelled", "indeterminate"]);
const timeLabel = (value) => new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const textLabel = (state) => states[state] ?? "Checking status";
const capability = (ref) => {
  const name = ref.id.split("/").pop();
  return { "task.attempt": "General task", "design.review": "Design review" }[name] ?? name;
};

async function get(path, options = {}) {
  const headers = new Headers(options.headers);
  if (options.method === "POST") {
    headers.set("X-CSRF-Token", csrf);
    if (options.body !== undefined) headers.set("Content-Type", "application/json");
  }
  const response = await fetch(basePath + path, { ...options, headers, cache: "no-store" });
  const value = await response.json().catch(() => ({}));
  if (response.status === 401) {
    location.assign(basePath + "/auth/login?next=" + encodeURIComponent(location.pathname.slice(basePath.length)));
  }
  if (!response.ok) {
    const error = new Error(value.message ?? value.problem?.message ?? "The request could not be completed.");
    error.value = value;
    error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After")) || 0;
    throw error;
  }
  return { value, etag: response.headers.get("ETag") };
}

function notice(element, message) {
  element.textContent = message;
  element.hidden = !message;
}

const conversationName = (title) => title ?? "Untitled conversation";

function recentStatus(element, status) {
  notice(element, status === "completed" ? "" : textLabel(status));
  element.classList.toggle("attention", ["awaiting_input", "indeterminate", "failed", "rejected"].includes(status));
}

function taskRow(task, { chosen = false, recent = false } = {}) {
  const row = node("li");
  const link = node("a");
  link.href = basePath + "/tasks/" + encodeURIComponent(task.task_id);
  link.dataset.taskId = task.task_id;
  if (chosen) link.setAttribute("aria-current", "page");
  link.append(node("strong", conversationName(task.title)));
  if (!recent || task.title === null) link.append(node("small", timeLabel(task.received_at)));
  if (recent) {
    const status = node("small", undefined, "recent-status");
    recentStatus(status, task.status);
    link.append(status);
  } else {
    link.append(node("small", textLabel(task.status), task.status === "awaiting_input" ? "attention" : ""));
  }
  row.append(link);
  return row;
}

function pendingRow(id) {
  const row = node("li");
  const link = node("a", "Submission unconfirmed");
  link.href = basePath + "/submissions/" + encodeURIComponent(id);
  row.append(link);
  return row;
}

function renderSidebar(body) {
  document.querySelectorAll(".recent-list").forEach((list) => {
    const focusedLink = list.contains(document.activeElement) ? document.activeElement.href : null;
    list.replaceChildren(
      ...body.pending.slice(0, 3).map(pendingRow),
      ...body.tasks.slice(0, 8).map((task) => taskRow(task, { chosen: task.task_id === taskId, recent: true }))
    );
    if (focusedLink) [...list.querySelectorAll("a")].find((item) => item.href === focusedLink)?.focus();
  });
}

function sidebar() {
  const drawer = byId("mobile-sidebar");
  const trigger = byId("open-sidebar");
  trigger.addEventListener("click", () => {
    drawer.showModal();
    trigger.setAttribute("aria-expanded", "true");
  });
  drawer.querySelector(".close-sidebar").addEventListener("click", () => drawer.close());
  drawer.addEventListener("close", () => {
    trigger.setAttribute("aria-expanded", "false");
    trigger.focus();
  });
  document.querySelectorAll(".sign-out").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await get("/auth/logout", { method: "POST" });
        location.assign(basePath + "/");
      } catch (error) {
        button.disabled = false;
        button.textContent = "Retry sign out";
      }
    });
  });
}

async function loadHistory() {
  const list = byId("history");
  const next = byId("history-next");
  let cursor = "";
  async function load() {
    next.disabled = true;
    try {
      const { value } = await get("/api/tasks" + (cursor ? "?cursor=" + encodeURIComponent(cursor) : ""));
      if (!cursor) {
        renderSidebar(value);
        list.append(...value.pending.map(pendingRow));
      }
      list.append(...value.tasks.map((task) => taskRow(task)));
      cursor = value.next_cursor;
      next.hidden = !cursor;
      notice(byId("history-status"), list.children.length ? "" : "Your tasks will appear here.");
    } catch (error) {
      notice(byId("history-status"), error.message);
    } finally {
      next.disabled = false;
    }
  }
  next.addEventListener("click", load);
  await load();
}

function growDraft(field) {
  let width;
  function fit() {
    if (!field.offsetWidth) return;
    field.style.height = "auto";
    field.style.height = field.scrollHeight + "px";
  }
  field.addEventListener("input", fit);
  new ResizeObserver(() => {
    if (width === field.offsetWidth) return;
    width = field.offsetWidth;
    fit();
  }).observe(field);
  return fit;
}

function taskOptions(panel) {
  const trigger = byId("options-toggle");
  const done = byId("options-close");
  const narrow = matchMedia("(max-width: 760px)");
  const isOpen = () => panel.open || panel.matches(":popover-open");

  function position() {
    const box = trigger.getBoundingClientRect();
    panel.style.setProperty("--options-left", box.left + "px");
    panel.style.setProperty("--options-bottom", (window.innerHeight - box.top + 6) + "px");
  }
  function reflect() {
    trigger.setAttribute("aria-expanded", String(isOpen()));
  }
  function open() {
    if (isOpen()) return;
    trigger.focus({ preventScroll: true });
    if (narrow.matches) {
      panel.removeAttribute("popover");
      panel.showModal();
    } else {
      panel.setAttribute("popover", "auto");
      position();
      panel.showPopover({ source: trigger });
    }
    done.focus({ preventScroll: true });
    reflect();
  }
  function close() {
    if (!isOpen()) return;
    if (panel.open) panel.close();
    else panel.hidePopover();
    reflect();
  }

  trigger.addEventListener("click", () => (isOpen() ? close() : open()));
  done.addEventListener("click", () => {
    close();
    trigger.focus({ preventScroll: true });
  });
  panel.addEventListener("close", reflect);
  panel.addEventListener("toggle", reflect);
  panel.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.target.matches("input") && !event.isComposing) event.preventDefault();
  });
  narrow.addEventListener("change", close);
  window.addEventListener("resize", () => {
    if (panel.matches(":popover-open")) position();
  });
  return { open, close, isOpen, trigger };
}

function composer({ recorded, refresh } = {}) {
  const form = byId("composer");
  const offer = byId("offers");
  const button = byId("submit-task");
  const errorBox = byId("form-error");
  const add = byId("add-check");
  const picker = byId("offer-picker");
  const optionsPanel = byId("follow-up-options");
  const options = optionsPanel && taskOptions(optionsPanel);
  const objective = byId("objective");
  const context = byId("context");
  const noDelegation = byId("no-delegation");
  const checkFields = byId("checks");
  const draftHint = byId("draft-hint");
  const unavailable = byId("compose-unavailable");
  const submitLabel = button.textContent;
  const fitDraft = options && growDraft(objective);
  let predecessor;
  let recordedParent;
  let offers = [];
  let pending = false;
  let retry;
  let delegationEdited = false;
  noDelegation.addEventListener("change", () => { delegationEdited = true; });

  function rememberDelegation(taskId, mode) {
    if (!delegationEdited && !pending && !retry && taskId !== recordedParent) {
      noDelegation.checked = mode === "none";
    }
  }

  function selectedOffer() {
    if (offers.length === 1) return offers[0];
    return offers.find((item) => item.offer_id === offer.value);
  }

  function processingLabel(item) {
    return item.processing.mode === "provider_domain_only"
      ? "Domain only · " + item.processing.domain
      : "Approved processing";
  }

  function choice() {
    const current = selectedOffer();
    const ready = retry ? !retry.expired : current && (!options || predecessor && objective.value.trim());
    button.disabled = form.hidden || pending || !ready;
    const drafting = options && !predecessor && unavailable.hidden && !retry;
    if (options) {
      options.trigger.textContent = offers.length > 1 && !current ? "Choose processing" : "Options";
      draftHint.hidden = !drafting;
      if (drafting) objective.setAttribute("aria-describedby", draftHint.id);
      else if (unavailable.hidden) objective.removeAttribute("aria-describedby");
      else objective.setAttribute("aria-describedby", unavailable.id);
      button.title = drafting ? "Send available after LASA releases a result" : "";
    }
    notice(byId("offer-summary"), offers.length === 1
      ? processingLabel(current) + " · Only available option"
      : "");
    if (!current) {
      notice(byId("offer-limit"), "");
      notice(byId("offer-note"), drafting ? "Processing options appear after LASA releases a result."
        : offers.length ? "Select an offer to continue." : "No general task offer is available.");
      return;
    }
    const processing = current.processing;
    notice(byId("offer-note"), processing.mode === "provider_domain_only"
      ? "Processing stays within " + processing.domain + "."
      : "LASA may use approved providers under applicable policy.");
    const bytes = Math.min(current.max_budget.input_bytes, Number(form.dataset.bodyBytes));
    notice(byId("offer-limit"), "Input limit " + new Intl.NumberFormat().format(bytes) + " bytes.");
  }

  async function loadOffers() {
    const parent = predecessor;
    if (options && !parent) return;
    button.disabled = true;
    notice(byId("offer-note"), "Loading processing offers.");
    try {
      const available = (await get("/api/offers")).value.offers;
      if (parent?.task_id !== predecessor?.task_id) return;
      offers = parent ? available.filter(({ processing }) =>
        processing.mode === parent.processing.mode && processing.domain === parent.processing.domain
      ) : available;
      offer.replaceChildren();
      picker.hidden = offers.length < 2;
      if (offers.length > 1) {
        const prompt = node("option", "Choose a processing option");
        prompt.value = "";
        prompt.disabled = true;
        offer.append(prompt);
        const labels = offers.map(processingLabel);
        offers.forEach((item, index) => {
          const label = labels[index];
          const option = node("option", labels.indexOf(label) === labels.lastIndexOf(label)
            ? label
            : label + " · " + item.offer_id);
          option.value = item.offer_id;
          offer.append(option);
        });
        offer.value = "";
      }
      choice();
    } catch (error) {
      if (parent?.task_id !== predecessor?.task_id) return;
      offers = [];
      picker.hidden = true;
      choice();
      notice(errorBox, error.message);
      notice(byId("offer-note"), "Processing offers are unavailable.");
    }
  }

  offer.addEventListener("change", choice);
  if (options) {
    objective.addEventListener("input", choice);
    objective.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" || event.shiftKey || event.isComposing
        || !matchMedia("(pointer: fine)").matches || button.disabled) return;
      event.preventDefault();
      form.requestSubmit(button);
    });
  }
  add.addEventListener("click", () => {
    const count = checkFields.querySelectorAll("input").length;
    const field = node("input");
    field.type = "text";
    field.name = "check";
    field.maxLength = 2048;
    field.required = !options;
    field.setAttribute("aria-label", "Requirement " + (count + 1));
    checkFields.append(field);
    field.focus();
    if (count + 1 === 32) add.disabled = true;
  });

  function lockFields(locked) {
    objective.readOnly = locked;
    context.readOnly = locked;
    noDelegation.disabled = locked;
    checkFields.querySelectorAll("input").forEach((field) => { field.readOnly = locked; });
    offer.disabled = locked;
    add.disabled = locked || checkFields.querySelectorAll("input").length >= 32;
    if (options) options.trigger.disabled = locked;
  }

  function show(visible, parent, message = "") {
    const eligible = parent?.task_id === recordedParent ? undefined : parent;
    const changed = predecessor?.task_id !== eligible?.task_id;
    if (!changed && visible !== form.hidden && message === unavailable.textContent) return;
    predecessor = eligible;
    if (!visible) options.close();
    form.hidden = !visible;
    notice(unavailable, message);
    if (changed) {
      offers = [];
      offer.replaceChildren();
      picker.hidden = true;
    }
    choice();
    if (visible && changed) loadOffers();
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (button.disabled || options?.isOpen()) return;
    const selected = selectedOffer();
    const parent = retry ? retry.parent : predecessor?.task_id;
    const endpoint = parent ? "/api/tasks/" + encodeURIComponent(parent) + "/follow-ups" : "/api/submissions";
    let attempt = retry;
    pending = true;
    button.disabled = true;
    notice(errorBox, "");
    button.textContent = "Submitting";
    lockFields(true);
    let navigating = false;
    try {
      if (!attempt) {
        const { value: ticket } = await get("/api/submission-ticket");
        const checks = Array.from(checkFields.querySelectorAll("input"), (field) => field.value);
        attempt = { id: ticket.id, parent, data: {
          ticket: ticket.value, objective: objective.value,
          checks: options ? checks.filter((check) => check.trim()) : checks,
          context: context.value,
          run_without_delegation: noDelegation.checked,
          selection: {
            offer_id: selected.offer_id, offer_revision: selected.revision,
            catalog_view: selected.catalog_view, contract: selected.contract,
          },
        } };
      }
      const { value } = await get(endpoint, { method: "POST", body: JSON.stringify(attempt.data) });
      if (!parent) {
        navigating = true;
        location.assign(value.task_url);
        return;
      }
      retry = undefined;
      recordedParent = parent;
      form.reset();
      noDelegation.checked = attempt.data.run_without_delegation;
      delegationEdited = false;
      checkFields.querySelectorAll("input:not(#check-1)").forEach((field) => field.remove());
      byId("context-details").open = false;
      fitDraft();
      lockFields(false);
      button.textContent = submitLabel;
      if (predecessor?.task_id === recordedParent) show(!form.hidden);
      recorded(value.task_url);
    } catch (error) {
      const code = error.value?.problem?.code ?? error.value?.code;
      const expiredRetry = retry && code === "ticket_expired";
      if (attempt && (error instanceof TypeError || expiredRetry
        || ["submission_unconfirmed", "request_in_progress"].includes(code))) {
        retry = attempt;
        retry.expired = Boolean(expiredRetry);
        const link = node("a", "Check original submission");
        link.href = error.value?.recovery_url ?? (basePath + "/submissions/" + retry.id);
        notice(errorBox, "Submission unconfirmed. ");
        errorBox.append(link);
        button.textContent = retry.expired ? submitLabel : "Retry same submission";
      } else {
        retry = undefined;
        lockFields(false);
        notice(errorBox, error.message);
        button.textContent = submitLabel;
        const field = error.value?.field;
        if (options && !form.hidden && ["checks", "context"].includes(field)) options.open();
        if (field === "context") byId("context-details").open = true;
        if (field === "checks") byId("check-1").focus();
        else if (field && byId(field)) byId(field).focus();
        if (["offer_changed", "catalog_changed"].includes(code)) await loadOffers();
        if (["task_state_conflict", "session_busy"].includes(code)) refresh?.();
      }
    } finally {
      if (!navigating) {
        pending = false;
        choice();
      }
    }
  });
  if (options) choice();
  else loadOffers();
  return { show, rememberDelegation };
}

function durationLabel(milliseconds) {
  const seconds = Math.floor(milliseconds / 1000);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(seconds / 60) % 60;
  return [hours && hours + "h", minutes && minutes + "m", seconds % 60 + "s"].filter(Boolean).join(" ");
}

function workTimer(element) {
  let interval;
  return (clock) => {
    clearInterval(interval);
    element.hidden = !clock?.running;
    if (element.hidden) return;
    const started = performance.now();
    const tick = () => { element.textContent = durationLabel(clock.elapsed_ms + performance.now() - started); };
    tick();
    interval = setInterval(tick, 250);
  };
}

function defaultCheck(check) {
  return check.id === "respond-to-follow-up" &&
    check.description === "Address the follow-up request." &&
    check.acceptance?.length === 1 &&
    check.acceptance[0] === "The response directly addresses the message and any constraints it states.";
}

function checkLabel(check) {
  const item = node("li");
  item.append(node("p", check.description, "preserve"));
  if (check.acceptance?.length && (check.acceptance.length > 1 || check.acceptance[0] !== check.description)) {
    const conditions = node("ul");
    for (const condition of check.acceptance) conditions.append(node("li", condition, "preserve"));
    item.append(conditions);
  }
  return item;
}

function artifactLinks(result, taskId) {
  const links = node("ul", undefined, "artifact-links");
  const labels = { "text/plain": "Text file", "text/markdown": "Markdown file", "application/json": "JSON file" };
  result.artifacts.forEach((artifact, index) => {
    const label = labels[artifact.media_type] ?? "File";
    const length = artifact.bytes < 1024 ? artifact.bytes + " B" : (artifact.bytes / 1024).toFixed(1) + " KB";
    const number = result.artifacts.length > 1 ? " " + (index + 1) : "";
    const link = node("a", "Download " + label.toLowerCase() + number + " · " + length);
    link.href = basePath + "/api/tasks/" + encodeURIComponent(taskId) + "/artifacts/" + encodeURIComponent(artifact.artifact_id);
    const item = node("li");
    item.append(link);
    links.append(item);
  });
  return links;
}

function reviewResult(panel, details, content, criteria) {
  const labels = new Map((criteria ?? []).map((item) => [item.id, item.description]));
  if (content.findings.length) {
    panel.append(node("h2", "Findings"));
    const findings = node("ul", undefined, "review-findings");
    const severity = { info: "Note", warning: "Warning", error: "Error" };
    for (const finding of content.findings) {
      const item = node("li");
      const label = labels.get(finding.criterion_id);
      item.append(node("strong", severity[finding.severity] + (label ? " · " + label : "")),
        node("p", finding.observation, "preserve"), node("p", finding.recommendation, "preserve"));
      findings.append(item);
    }
    panel.append(findings);
  } else {
    panel.append(node("p", "No findings for the reviewed criteria."));
  }
  const coverage = node("ul", undefined, "check-list");
  const insufficient = content.coverage.filter((item) => item.disposition === "insufficient_input");
  if (insufficient.length) {
    panel.append(node("p", "More input is needed to review " + insufficient.length
      + (insufficient.length === 1 ? " criterion." : " criteria.")));
  }
  for (const item of content.coverage) {
    const row = node("li");
    row.append(node("strong", labels.get(item.criterion_id) ?? "Review criterion"),
      node("p", item.disposition === "insufficient_input" ? "Needs more input" : "Reviewed", "check-outcome"),
      node("p", item.evidence, "preserve"));
    coverage.append(row);
  }
  details.append(node("h3", "Review coverage"), coverage);
}

function progressTimeline(taskId) {
  const limit = 25;
  const list = node("ol", undefined, "timeline");
  const feedback = node("p", undefined, "muted");
  feedback.setAttribute("role", "status");
  const more = node("button", "Load more updates", "secondary");
  more.type = "button";
  list.hidden = feedback.hidden = more.hidden = true;
  let sequence = 0;
  let through;
  let hasMore = true;
  let loading = false;
  let failed = false;

  function reflect() {
    more.hidden = !failed && !(sequence > 0 && hasMore && (through === undefined || sequence < through));
    more.disabled = loading;
    more.textContent = failed ? "Retry progress" : "Load more updates";
    if (through !== undefined) {
      list.querySelector("[aria-current]")?.removeAttribute("aria-current");
      list.querySelector(`[data-sequence="${through}"]`)?.setAttribute("aria-current", "step");
    }
  }

  async function load() {
    if (loading || !hasMore || (through !== undefined && sequence >= through)) return;
    loading = true;
    if (!sequence) notice(feedback, "Loading progress.");
    reflect();
    try {
      const path = "/api/tasks/" + encodeURIComponent(taskId) + "/events";
      const { value } = await get(path + "?limit=" + limit + "&after_sequence=" + sequence);
      for (const event of value.events) {
        const row = node("li", textLabel(event.status));
        row.dataset.sequence = event.sequence;
        list.append(row);
      }
      sequence = value.next_sequence - 1;
      hasMore = through !== undefined || value.events.length === limit;
      list.hidden = !list.children.length;
      failed = false;
      notice(feedback, list.hidden ? "No progress recorded." : "");
    } catch (error) {
      failed = true;
      if ([403, 404].includes(error.status)) {
        list.replaceChildren();
        list.hidden = true;
        sequence = 0;
      }
      notice(feedback, error.message);
    } finally {
      loading = false;
      reflect();
    }
  }

  more.addEventListener("click", load);
  return {
    elements: [list, feedback, more], load,
    follow(revision, open) {
      const changed = through !== revision;
      through = revision;
      reflect();
      if (changed && open) load();
    },
  };
}

function releasedResult(panel, turn, request) {
  const result = turn.content;
  const content = result.output;
  const checks = new Map((request?.requirements ?? []).map((check) => [check.id, check]));
  const details = node("div", undefined, "result-details");
  details.id = "result-details-" + turn.task_id;
  details.hidden = true;
  const duration = turn.work_ms === null ? null
    : turn.work_ms < 1000 ? "less than 1s" : durationLabel(turn.work_ms);
  const summary = node("button", duration === null ? "Result details" : "Worked for " + duration, "result-toggle");
  summary.type = "button";
  summary.setAttribute("aria-expanded", "false");
  summary.setAttribute("aria-controls", details.id);
  if (duration !== null) summary.setAttribute("aria-label", summary.textContent + " · Result details");
  const progress = progressTimeline(turn.task_id);
  summary.addEventListener("click", () => {
    const expanded = details.hidden;
    details.hidden = !expanded;
    summary.setAttribute("aria-expanded", String(expanded));
  });
  summary.addEventListener("click", progress.load, { once: true });
  panel.append(summary);
  if (content.disposition === "fulfilled" && Array.isArray(content.requirement_evidence)) {
    panel.append(node("h2", "LASA result", "sr-only"), node("p", content.summary, "preserve result-answer"));
    details.append(node("p", "Fulfilled", "check-outcome"));
    const evidence = node("ul", undefined, "check-list");
    for (const item of content.requirement_evidence) {
      const check = checks.get(item.id);
      const row = check ? checkLabel(check) : node("li", "Acceptance check");
      if (check && defaultCheck(check)) row.prepend(node("strong", "Default check"));
      row.append(node("p", "Met", "check-outcome"), node("p", item.evidence, "preserve"));
      evidence.append(row);
    }
    details.append(node("h3", "Acceptance checks"), evidence);
  } else if (content.disposition === "unable" && Array.isArray(content.unsatisfied_requirements)) {
    panel.append(node("h2", "Unable to fulfill"), node("p", content.reason, "preserve result-answer"));
    const unmet = content.unsatisfied_requirements.map((id) => checks.get(id));
    const unmetList = (items) => {
      const list = node("ul", undefined, "check-list");
      for (const item of items) list.append(item ? checkLabel(item) : node("li", "A requested acceptance check remains unmet."));
      return list;
    };
    if (unmet.length) panel.append(node("h3", "Still needed"), unmetList(unmet.slice(0, 1)));
    if (unmet.length > 1) details.append(node("h3", "Other unmet checks"), unmetList(unmet.slice(1)));
  } else if (result.contract.id === "https://contracts.example.net/capabilities/design.review"
    && Array.isArray(content.findings) && Array.isArray(content.coverage)) {
    panel.append(node("h2", "Design review result", "sr-only"));
    reviewResult(panel, details, content, request?.criteria);
  } else {
    panel.append(node("h2", "Result"));
    details.append(node("h3", "Result data"), node("pre", JSON.stringify(content, null, 2)));
  }
  if (result.artifacts.length) panel.append(artifactLinks(result, turn.task_id));
  const receipt = node("details", undefined, "technical-receipt");
  receipt.append(node("summary", "Technical receipt"), node("pre", JSON.stringify(result.receipt, null, 2)));
  if (result.evidence.length) {
    const checks = node("ul");
    for (const item of result.evidence) checks.append(node("li", item.criterion_id + " · " + item.disposition));
    receipt.append(checks);
  }
  details.append(node("h3", "Progress"), ...progress.elements, receipt);
  panel.append(details);
}

function conversationTurn(turn, rootId, requests) {
  const caller = turn.kind === "request" || turn.kind === "reply";
  const panel = node("li", undefined, caller ? "task-turn caller-turn" : "task-turn");
  panel.dataset.kind = turn.kind;
  const content = turn.content;
  if (turn.kind === "result") {
    releasedResult(panel, turn, requests.get(turn.task_id));
  } else if (turn.kind === "question") {
    const deadline = node("p", "Reply by " + timeLabel(content.expires_at) + ".", "muted question-deadline");
    deadline.id = "deadline-" + content.question_id;
    deadline.hidden = true;
    panel.append(node("h2", "LASA asks", "turn-speaker"), node("p", content.prompt, "preserve"), deadline);
  } else if (turn.kind === "reply") {
    panel.append(node("h2", "You replied", "sr-only"), node("p", content.answer, "preserve"));
  } else {
    panel.append(node("h2", turn.task_id === rootId ? "You requested" : "You followed up", "sr-only"));
    const details = node("details", undefined, "turn-details");
    details.append(node("summary", "Request details"));
    if (typeof content.objective === "string") {
      panel.append(node("p", content.objective, "preserve"));
      const explicit = (content.requirements ?? []).filter((item) => !defaultCheck(item));
      if (explicit.length) {
        const requirements = node("ul", undefined, "check-list");
        for (const item of explicit) requirements.append(checkLabel(item));
        details.append(node("h3", "Acceptance checks"), requirements);
      }
      if (content.context) details.append(node("h3", "Context"), node("p", content.context, "preserve"));
    } else if (typeof content.design === "string" && Array.isArray(content.criteria)) {
      panel.append(node("p", "Review this design"));
      const criteria = node("ul");
      for (const item of content.criteria) criteria.append(node("li", item.description, "preserve"));
      details.append(node("h3", "Review criteria"), criteria, node("h3", "Design"),
        node("p", content.design, "preserve"));
    } else {
      panel.append(node("p", "Task request"));
      details.append(node("pre", JSON.stringify(content, null, 2)));
    }
    if (turn.delegation === "none") details.append(node("p", "Run without delegation"));
    if (details.children.length > 1) panel.append(details);
  }
  return panel;
}

function fitTaskViewport() {
  const viewport = window.visualViewport;
  if (!viewport) return;
  const root = document.documentElement.style;
  let frame;
  function fit() {
    if (Math.abs(viewport.scale - 1) > .01) {
      root.removeProperty("--task-viewport-height");
      root.removeProperty("--task-viewport-top");
      root.removeProperty("--task-viewport-bottom");
      return;
    }
    root.setProperty("--task-viewport-height", viewport.height + "px");
    root.setProperty("--task-viewport-top", viewport.offsetTop + "px");
    root.setProperty("--task-viewport-bottom", Math.max(0, window.innerHeight - viewport.height - viewport.offsetTop) + "px");
    const field = document.activeElement;
    if (!field?.matches("input, textarea, select")) return;
    const fields = field.closest(".options-fields");
    if (!fields) return;
    const bounds = fields.getBoundingClientRect();
    const box = field.getBoundingClientRect();
    if (box.top < bounds.top || box.height >= bounds.height) {
      fields.scrollTop += box.top - bounds.top - 4;
    } else if (box.bottom > bounds.bottom) {
      fields.scrollTop += box.bottom - bounds.bottom + 4;
    }
  }
  function schedule() {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(fit);
  }
  viewport.addEventListener("resize", schedule);
  viewport.addEventListener("scroll", schedule);
  document.addEventListener("focusin", schedule);
  fit();
}

function conversationViewport(turns) {
  const scroll = byId("conversation-scroll");
  const jump = byId("jump-latest");
  let following = true;
  const atEnd = () => scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight <= 32;

  function updateJump() {
    jump.hidden = atEnd();
    if (jump.hidden && document.activeElement === jump) scroll.focus({ preventScroll: true });
  }

  function sync() {
    if (following) scroll.scrollTop = scroll.scrollHeight;
    updateJump();
  }

  function followLatest() {
    following = true;
    sync();
  }

  function track() {
    following = atEnd();
    updateJump();
  }

  scroll.addEventListener("scroll", track, { passive: true });
  turns.addEventListener("toggle", track, true);
  turns.addEventListener("click", (event) => {
    if (event.target.closest(".result-toggle")) track();
  });
  new ResizeObserver(sync).observe(scroll);
  jump.addEventListener("click", () => {
    scroll.focus({ preventScroll: true });
    followLatest();
  });
  return { sync, followLatest };
}

function taskPage() {
  const conversationPath = "/api/tasks/" + encodeURIComponent(taskId) + "/conversation";
  const path = () => "/api/tasks/" + encodeURIComponent(latestId);
  const statuses = byId("task-status");
  const dockActivity = byId("dock-activity");
  const activityStatus = byId("activity-status");
  const setTimer = workTimer(byId("task-elapsed"));
  const errorBox = byId("task-error");
  const progress = byId("progress");
  const timelinePanel = byId("live-timeline");
  const conversation = byId("conversation-turns");
  fitTaskViewport();
  const transcript = conversationViewport(conversation);
  const answerForm = byId("answer-form");
  const answer = byId("answer");
  const fitAnswer = growDraft(answer);
  const cancel = byId("cancel");
  const followUp = composer({
    recorded(url) {
      if (url !== location.pathname) window.history.replaceState(null, "", url);
      transcript.followLatest();
      refresh(true);
    },
    refresh: () => refresh(true),
  });
  let rootId = taskId;
  let latestId = taskId;
  let liveTimeline;
  let conversationRestricted = false;
  let followUpProcessing;
  let latestDelegation;
  let revision = 0;
  let timer;
  let loading = false;
  let current;
  let tag;
  let activeQuestion;
  let history = [];
  let historyRevision;
  let refreshRequested = true;
  let action;
  let delay = 2000;

  function selectedRows() {
    return document.querySelectorAll(".recent-list a[data-task-id='" + CSS.escape(rootId) + "']");
  }

  function setTitle(title) {
    const name = conversationName(title);
    byId("task-title").textContent = name;
    for (const link of selectedRows()) {
      link.setAttribute("aria-current", "page");
      link.querySelector("strong").textContent = name;
    }
  }

  function resetActivity() {
    progress.open = false;
    liveTimeline = undefined;
    timelinePanel.replaceChildren();
  }

  function setDock(status) {
    const active = Boolean(status && !terminal.has(status));
    progress.hidden = !active || status === "awaiting_input";
    cancel.hidden = !active || status === "cancelling";
    dockActivity.hidden = progress.hidden && cancel.hidden;
    if (progress.hidden) resetActivity();
    else {
      if (!liveTimeline) {
        liveTimeline = progressTimeline(latestId);
        timelinePanel.replaceChildren(...liveTimeline.elements);
      }
      activityStatus.textContent = textLabel(status);
      liveTimeline.follow(revision, progress.open);
    }
    const parent = !conversationRestricted && followUpProcessing && status === "completed"
      ? {task_id: latestId, processing: followUpProcessing} : undefined;
    const blocked = terminal.has(status) && !parent ? "Follow-ups are unavailable for this task." : "";
    followUp.show(!conversationRestricted && !activeQuestion, parent, blocked);
  }

  function showConversation(turns) {
    let unchanged = 0;
    while (unchanged < Math.min(history.length, turns.length)
      && JSON.stringify(history[unchanged]) === JSON.stringify(turns[unchanged])) unchanged++;
    if (unchanged === history.length && unchanged === turns.length) return;
    while (conversation.children.length > unchanged) conversation.lastElementChild.remove();
    const requests = new Map(turns.filter((turn) => turn.kind === "request")
      .map((turn) => [turn.task_id, turn.content]));
    for (const turn of turns.slice(unchanged)) conversation.append(conversationTurn(turn, rootId, requests));
    history = turns;
    transcript.sync();
  }

  async function readConversation() {
    historyRevision = undefined;
    const turns = [];
    let after = 0;
    let snapshot;
    do {
      const { value } = await get(conversationPath + "?after_sequence=" + after);
      snapshot = value;
      turns.push(...value.turns);
      after = value.next_after;
    } while (after !== null);
    rootId = snapshot.task_id;
    setTitle(snapshot.title);
    setTimer(snapshot.work_clock);
    followUpProcessing = snapshot.follow_up_processing;
    latestDelegation = snapshot.latest_delegation;
    followUp.rememberDelegation(snapshot.latest_task_id, latestDelegation);
    const changed = latestId !== snapshot.latest_task_id;
    if (changed) {
      latestId = snapshot.latest_task_id;
      revision = 0;
      tag = undefined;
      action = undefined;
      resetActivity();
    }
    showConversation(turns);
    historyRevision = revision;
    return changed;
  }

  function setQuestion(status) {
    const last = history.at(-1);
    const question = last?.kind === "question" && last.task_id === latestId ? last.content : undefined;
    const next = status === "awaiting_input" && question && new Date(question.expires_at) > new Date()
      ? question : undefined;
    if (next && (next.question_id !== activeQuestion?.question_id || next.revision !== activeQuestion.revision)) {
      answer.value = "";
    }
    if (activeQuestion) {
      const previousDeadline = byId("deadline-" + activeQuestion.question_id);
      if (previousDeadline) previousDeadline.hidden = true;
    }
    activeQuestion = next;
    answerForm.hidden = !next;
    if (next) {
      const deadline = byId("deadline-" + next.question_id);
      deadline.hidden = false;
      answer.setAttribute("aria-describedby", deadline.id);
      answer.minLength = next.answer_schema.minLength ?? 1;
      answer.maxLength = next.answer_schema.maxLength ?? 8192;
      fitAnswer();
    } else {
      answer.removeAttribute("aria-describedby");
    }
    const label = status === "awaiting_input" && last?.kind === "reply"
      ? "Answer received" : textLabel(status);
    if (statuses.textContent !== label) statuses.textContent = label;
  }

  function schedule() {
    clearTimeout(timer);
    if (document.hidden || (current && terminal.has(current.status) && historyRevision === revision && !refreshRequested)) return;
    timer = setTimeout(() => refresh(), refreshRequested ? 0 : delay);
  }

  async function refresh(force = false) {
    if (force) refreshRequested = true;
    if (loading) return;
    const requested = refreshRequested;
    refreshRequested = false;
    loading = true;
    try {
      const initial = requested ? await getConversation() : { changed: false, problem: "" };
      const { value, etag } = await get(path() + "?view=control");
      if (value.revision < revision) return;
      const changed = revision !== value.revision;
      current = value;
      tag = etag;
      revision = value.revision;
      byId("refresh-task").hidden = value.status !== "indeterminate";
      const update = historyRevision !== revision ? await getConversation() : initial;
      if (update !== initial && update.changed) {
        setDock();
        refreshRequested = true;
        return;
      }
      const problem = value.problem?.code === "processing_unavailable" && latestDelegation === "none"
        ? "LASA could not fulfill this task without delegation under the selected processing terms."
        : value.problem?.title;
      if (requested || changed) notice(errorBox, update.problem || problem || "");
      setQuestion(value.status);
      setDock(value.status);
      transcript.sync();
      if (changed) {
        for (const link of selectedRows()) recentStatus(link.querySelector(".recent-status"), value.status);
      }
      delay = changed ? 2000 : Math.min(delay * 1.5, 10000);
    } catch (error) {
      const denied = error.status === 403 || error.status === 404;
      if (denied) conversationRestricted = true;
      if (historyRevision !== revision || denied) {
        showConversation([]);
        setTitle(null);
        setQuestion(denied ? "rejected" : undefined);
        setDock();
        setTimer(null);
      }
      notice(errorBox, error.message);
      delay = Math.min(Math.max(delay * 2, error.retryAfter * 1000 || 0), 30000);
      if (denied) {
        current = { status: "rejected" };
        historyRevision = revision;
      }
    } finally {
      loading = false;
      schedule();
    }
  }

  async function getConversation() {
    try {
      const changed = await readConversation();
      conversationRestricted = false;
      return { changed, problem: "" };
    } catch (error) {
      if (error.status !== 403) throw error;
      showConversation([]);
      setTitle(null);
      setTimer(null);
      conversationRestricted = true;
      followUpProcessing = undefined;
      latestDelegation = undefined;
      historyRevision = revision;
      return { changed: false, problem: "The current policy restricts this conversation." };
    }
  }

  async function mutate(kind, data, control) {
    if (!tag || control.disabled) return;
    control.disabled = true;
    const etag = tag;
    const payload = JSON.stringify(data);
    if (!action || action.kind !== kind || action.etag !== etag || action.payload !== payload) {
      const id = kind + "-" + crypto.randomUUID();
      action = { id, kind, etag, payload };
    }
    const activeAction = action;
    try {
      await get(path() + "/" + kind, {
        method: "POST", headers: { "If-Match": etag, "Idempotency-Key": activeAction.id },
        body: JSON.stringify({ operation_id: activeAction.id, ...data }),
      });
      if (kind === "inputs") {
        transcript.followLatest();
        answer.value = "";
        fitAnswer();
        setQuestion();
        setDock("awaiting_input");
        statuses.textContent = "Answer received";
      }
      action = null;
      await refresh(true);
    } catch (error) {
      await refresh(true);
      notice(errorBox, error.message);
    } finally {
      control.disabled = false;
    }
  }

  byId("answer-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (!activeQuestion) return;
    mutate("inputs", {
      question_id: activeQuestion.question_id, question_revision: activeQuestion.revision,
      answer: answer.value,
    }, byId("answer-submit"));
  });
  cancel.addEventListener("click", () => mutate("cancel", {}, cancel));
  byId("refresh-task").addEventListener("click", () => refresh(true));
  progress.addEventListener("toggle", () => { if (progress.open) liveTimeline?.load(); });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTimeout(timer);
      setTimer(null);
    }
    else refresh(true);
  });
  refresh();
}

function recover() {
  let attempts = 0;
  const button = byId("check-recovery");
  async function check() {
    button.disabled = true;
    const status = byId("recovery-status");
    const note = byId("recovery-note");
    try {
      const { value } = await get("/api/submissions/" + encodeURIComponent(taskId));
      if (value.task_url) {
        status.textContent = "LASA recorded the task.";
        const link = byId("recovered-task");
        link.href = value.task_url;
        link.hidden = false;
      } else if (value.state === "rejected") {
        status.textContent = "Submission rejected.";
        note.textContent = value.problem.message;
      } else {
        status.textContent = value.state === "checking" ? "Checking submission." : "Submission unconfirmed.";
        note.textContent = "The original operation is still available for a status check.";
        if (++attempts <= 4 && !document.hidden) setTimeout(check, 2100);
      }
    } catch (error) {
      status.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }
  button.addEventListener("click", check);
  check();
}

if (page) {
  sidebar();
  if (page === "history") {
    loadHistory();
  } else {
    get("/api/tasks?limit=8").then(({ value }) => renderSidebar(value)).catch(() => {});
    if (page === "new") composer();
    if (page === "task") taskPage();
    if (page === "recovery") recover();
  }
}
