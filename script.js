(() => {
  'use strict';

  const VAULT_KEY = 'ai_quiz_vault_v1';
  const REMEMBER_KEY = 'ai_quiz_remember_v1';
  const DEVICE_KEY = 'ai_quiz_device_key_v1';

  const KDF_ITER = 250000;
  const AES_IV_BYTES = 12;
  const SALT_BYTES = 16;

  const MODEL_OPTIONS = [
    { id: 'gpt-4.1-mini', label: 'gpt-4.1-mini (default/cheap)' },
    { id: 'gpt-4o-mini', label: 'gpt-4o-mini' },
    { id: 'gpt-4.1', label: 'gpt-4.1' },
    { id: 'gpt-4o', label: 'gpt-4o' }
  ];

  const $ = (sel, el = document) => el.querySelector(sel);

  const navGenerateBtn = $('#navGenerateBtn');
  const navQuizBtn = $('#navQuizBtn');
  const openSettingsBtn = $('#openSettingsBtn');
  const openLibraryBtn = $('#openLibraryBtn');
  const lockBtn = $('#lockBtn');
  const resetBtn = $('#resetBtn');

  const drawerOverlay = $('#drawerOverlay');
  const settingsDrawer = $('#settingsDrawer');
  const libraryDrawer = $('#libraryDrawer');
  const closeSettingsBtn = $('#closeSettingsBtn');
  const closeLibraryBtn = $('#closeLibraryBtn');

  const lockScreen = $('#lockScreen');
  const lockTitle = $('#lockTitle');
  const lockHint = $('#lockHint');
  const masterPassword = $('#masterPassword');
  const masterPasswordConfirm = $('#masterPasswordConfirm');
  const confirmWrap = $('#confirmWrap');
  const rememberPassword = $('#rememberPassword');
  const forgetRememberedBtn = $('#forgetRememberedBtn');
  const unlockBtn = $('#unlockBtn');
  const lockStatus = $('#lockStatus');

  const app = $('#app');

  const viewGenerate = $('#viewGenerate');
  const viewQuiz = $('#viewQuiz');
  const goGenerateBtn = $('#goGenerateBtn');
  const openLibraryBtn2 = $('#openLibraryBtn2');
  const quizEmpty = $('#quizEmpty');

  const apiKey = $('#apiKey');
  const difficulty = $('#difficulty');
  const defaultChoices = $('#defaultChoices');
  const model = $('#model');
  const endpoint = $('#endpoint');
  const temperature = $('#temperature');
  const maxTokens = $('#maxTokens');
  const immediateFeedback = $('#immediateFeedback');
  const saveSettingsBtn = $('#saveSettingsBtn');
  const settingsStatus = $('#settingsStatus');

  const sourceText = $('#sourceText');
  const questionCount = $('#questionCount');
  const quizTitle = $('#quizTitle');
  const generateBtn = $('#generateBtn');
  const genStatus = $('#genStatus');

  const quizList = $('#quizList');
  const libraryStatus = $('#libraryStatus');

  const playerCard = $('#playerCard');
  const playerTitle = $('#playerTitle');
  const playerMeta = $('#playerMeta');
  const qProgress = $('#qProgress');
  const qText = $('#qText');
  const qChoices = $('#qChoices');
  const qExplain = $('#qExplain');
  const prevBtn = $('#prevBtn');
  const nextBtn = $('#nextBtn');
  const qMap = $('#qMap');
  const scoreBtn = $('#scoreBtn');
  const scoreBox = $('#scoreBox');
  const resultsPanel = $('#resultsPanel');
  const saveNowBtn = $('#saveNowBtn');
  const submitBtn = $('#submitBtn');
  const copyQuizBtn = $('#copyQuizBtn');

  const addCount = $('#addCount');
  const addMoreBtn = $('#addMoreBtn');
  const playerStatus = $('#playerStatus');

  const App = {
    mode: 'unlock',
    vault: null,
    password: null,
    currentQuizId: null,
    saveTimer: null
  };

  const nowISO = () => new Date().toISOString();

  function setStatus(el, msg, isError = false) {
    if (!el) return;
    el.textContent = msg || '';
    el.style.color = isError ? 'var(--danger)' : 'var(--muted)';
  }

  function uid() {
    return 'qz_' + Math.random().toString(16).slice(2) + '_' + Date.now().toString(16);
  }

  function clampInt(n, min, max, fallback) {
    const x = Number.parseInt(n, 10);
    if (!Number.isFinite(x)) return fallback;
    return Math.max(min, Math.min(max, x));
  }

  function clampNum(n, min, max, fallback) {
    const x = Number(n);
    if (!Number.isFinite(x)) return fallback;
    return Math.max(min, Math.min(max, x));
  }

  function escapeHtml(s) {
    return String(s || '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function letter(i) {
    return String.fromCharCode('A'.charCodeAt(0) + i);
  }

  function setView(which) {
    if (which === 'generate') {
      viewGenerate.hidden = false;
      viewQuiz.hidden = true;
      navGenerateBtn.classList.add('btn--primary');
      navQuizBtn.classList.remove('btn--primary');
      return;
    }
    viewGenerate.hidden = true;
    viewQuiz.hidden = false;
    navGenerateBtn.classList.remove('btn--primary');
    navQuizBtn.classList.add('btn--primary');
  }

  function openDrawer(which) {
    drawerOverlay.hidden = false;
    if (which === 'settings') {
      settingsDrawer.classList.add('open');
      settingsDrawer.setAttribute('aria-hidden', 'false');
    } else if (which === 'library') {
      libraryDrawer.classList.add('open');
      libraryDrawer.setAttribute('aria-hidden', 'false');
    }
  }

  function closeDrawers() {
    settingsDrawer.classList.remove('open');
    settingsDrawer.setAttribute('aria-hidden', 'true');
    libraryDrawer.classList.remove('open');
    libraryDrawer.setAttribute('aria-hidden', 'true');
    drawerOverlay.hidden = true;
  }

  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function b64ToBuf(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
  }

  function strToBuf(str) {
    return new TextEncoder().encode(str).buffer;
  }

  function bufToStr(buf) {
    return new TextDecoder().decode(new Uint8Array(buf));
  }

  async function deriveKey(password, salt, iterations = KDF_ITER) {
    const baseKey = await crypto.subtle.importKey('raw', strToBuf(password), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function rand(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
  }

  async function encryptVault(obj, password) {
    const salt = rand(SALT_BYTES);
    const iv = rand(AES_IV_BYTES);
    const key = await deriveKey(password, salt);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, strToBuf(JSON.stringify(obj)));
    return { v: 1, salt: bufToB64(salt), iv: bufToB64(iv), data: bufToB64(cipher) };
  }

  async function decryptVault(env, password) {
    const key = await deriveKey(password, b64ToBuf(env.salt));
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(env.iv)) },
      key,
      b64ToBuf(env.data)
    );
    return JSON.parse(bufToStr(plain));
  }

  async function deviceKey() {
    let k = localStorage.getItem(DEVICE_KEY);
    if (!k) {
      k = bufToB64(rand(32));
      localStorage.setItem(DEVICE_KEY, k);
    }
    return crypto.subtle.importKey('raw', b64ToBuf(k), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function rememberPasswordStore(pw) {
    const key = await deviceKey();
    const iv = rand(AES_IV_BYTES);
    const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, strToBuf(pw));
    localStorage.setItem(REMEMBER_KEY, JSON.stringify({ iv: bufToB64(iv), data: bufToB64(enc) }));
  }

  async function rememberPasswordLoad() {
    const raw = localStorage.getItem(REMEMBER_KEY);
    if (!raw) return null;
    try {
      const o = JSON.parse(raw);
      const key = await deviceKey();
      const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(o.iv)) },
        key,
        b64ToBuf(o.data)
      );
      return bufToStr(dec);
    } catch {
      localStorage.removeItem(REMEMBER_KEY);
      return null;
    }
  }

  function rememberPasswordClear() {
    localStorage.removeItem(REMEMBER_KEY);
  }

  function hasVault() {
    return !!localStorage.getItem(VAULT_KEY);
  }

  function defaultVault() {
    return {
      settings: {
        apiKey: '',
        difficulty: 'medium',
        defaultChoices: 4,
        model: 'gpt-4.1-mini',
        endpoint: 'https://api.openai.com/v1/responses',
        temperature: 0.7,
        maxTokens: 1800,
        immediateFeedback: false
      },
      quizzes: []
    };
  }

  async function saveVaultNow() {
    const env = await encryptVault(App.vault, App.password);
    localStorage.setItem(VAULT_KEY, JSON.stringify(env));
  }

  function scheduleSave(msg) {
    if (msg) setStatus(playerStatus, msg);
    if (App.saveTimer) clearTimeout(App.saveTimer);
    App.saveTimer = setTimeout(async () => {
      try {
        await saveVaultNow();
        if (msg) setStatus(playerStatus, 'Saved.');
      } catch (e) {
        setStatus(playerStatus, 'Save failed: ' + (e?.message || e), true);
      }
    }, 250);
  }

  function initModelDropdown() {
    model.innerHTML = '';
    for (const opt of MODEL_OPTIONS) {
      const o = document.createElement('option');
      o.value = opt.id;
      o.textContent = opt.label;
      model.appendChild(o);
    }
    model.value = 'gpt-4.1-mini';
  }

  function syncSettingsFromUI() {
    if (!App.vault) return;
    const s = App.vault.settings || (App.vault.settings = {});
    s.apiKey = (apiKey.value || '').trim();
    s.difficulty = difficulty.value || 'medium';
    s.defaultChoices = clampInt(defaultChoices.value, 4, 8, 4);
    s.model = (model.value || 'gpt-4.1-mini').trim() || 'gpt-4.1-mini';
    s.endpoint = (endpoint.value || 'https://api.openai.com/v1/responses').trim();
    s.temperature = clampNum(temperature.value, 0, 2, 0.7);
    s.maxTokens = clampInt(maxTokens.value, 256, 8000, 1800);
    s.immediateFeedback = !!immediateFeedback.checked;
  }

  function renderSettingsToUI() {
    const s = App.vault.settings;
    apiKey.value = s.apiKey || '';
    difficulty.value = s.difficulty || 'medium';
    defaultChoices.value = String(s.defaultChoices ?? 4);
    initModelDropdown();
    model.value = s.model || 'gpt-4.1-mini';
    if (!model.value) model.value = 'gpt-4.1-mini';
    endpoint.value = s.endpoint || 'https://api.openai.com/v1/responses';
    temperature.value = String(s.temperature ?? 0.7);
    maxTokens.value = String(s.maxTokens ?? 1800);
    immediateFeedback.checked = !!s.immediateFeedback;
  }

  function getQuizById(id) {
    return App.vault?.quizzes?.find(q => q.id === id) || null;
  }

  function getActiveQuiz() {
    return getQuizById(App.currentQuizId);
  }

  function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function clearAnswers(quiz) {
    quiz.questions.forEach(q => { q.user_answer_index = null; });
    quiz.submitted = false;
    quiz.submittedAt = null;
    quiz.grade = null;
    quiz.currentIndex = 0;
  }

  function difficultySpec(level) {
    if (level === 'easy') {
      return [
        'EASY SPEC:',
        '- Direct recall: one sentence/phrase.',
        '- Distractors obviously wrong (no trick).',
        '- No inference; no multi-step reasoning.',
        '- Avoid close-call options.'
      ].join('\n');
    }
    if (level === 'hard') {
      return [
        'HARD SPEC:',
        '- Requires inference or connecting multiple nearby ideas.',
        '- Distractors plausible but strictly false per text.',
        '- Exactly one correct; avoid ambiguity.',
        '- Prefer why/how/implication questions grounded in the text.'
      ].join('\n');
    }
    if (level === 'very_hard') {
      return [
        'VERY HARD SPEC:',
        '- Multi-step: connect two+ distant parts of the text.',
        '- Distractors highly plausible (same vocabulary/claims).',
        '- Still unambiguous: exactly one correct choice.',
        '- Ask about implications, motivations, contradictions, cause chains.',
        '- Explanations cite the specific clue(s) from the text.'
      ].join('\n');
    }
    return [
      'MEDIUM SPEC:',
      '- Understanding + paraphrase + cause/effect in text.',
      '- Sometimes combine two nearby ideas.',
      '- Distractors plausible but not deceptive.',
      '- Exactly one correct choice.'
    ].join('\n');
  }

  function buildSystemInstructions() {
    return [
      'You generate multiple-choice quizzes.',
      'Output ONLY valid json.',
      'No markdown. No commentary.',
      'Use ONLY the provided source text.',
      'Exactly one correct answer per question.'
    ].join(' ');
  }

  function requiredShape(choicesCount, includeTitle) {
    const base = includeTitle
      ? '{ "title": string, "questions": [ { "q": string, "choices": string[], "answer_index": number, "explanation": string } ] }'
      : '{ "questions": [ { "q": string, "choices": string[], "answer_index": number, "explanation": string } ] }';
    return base + ` (choices.length must be exactly ${choicesCount})`;
  }

  function buildGenerateUserInput({ text, count, diff, title, choicesCount }) {
    const t = (title || '').trim();
    return [
      'Output format: json',
      'Return a valid json object only.',
      '',
      difficultySpec(diff),
      '',
      `Number of questions: ${count}`,
      `Choices per question: ${choicesCount}`,
      t ? `Title preference: ${t}` : '',
      '',
      'REQUIRED JSON SHAPE:',
      requiredShape(choicesCount, true),
      '',
      'Rules:',
      '- choices must be short phrases.',
      '- explanation is 1-2 sentences.',
      '',
      'SOURCE TEXT (only allowed knowledge):',
      text.trim()
    ].filter(Boolean).join('\n');
  }

  function buildAddMoreUserInput({ existingQuestions, addCount, diff, choicesCount, sourceText }) {
    return [
      'Output format: json',
      'Return a valid json object only.',
      '',
      difficultySpec(diff),
      '',
      `Add ${addCount} NEW questions.`,
      `Choices per question: ${choicesCount}`,
      'Do NOT repeat any existing question wording or focus.',
      '',
      'EXISTING QUESTIONS (avoid duplicates):',
      existingQuestions.map((q, i) => `${i + 1}. ${q.q}`).join('\n'),
      '',
      'REQUIRED JSON SHAPE:',
      requiredShape(choicesCount, false),
      '',
      'SOURCE TEXT (only allowed knowledge):',
      sourceText.trim()
    ].join('\n');
  }

  function extractOutputText(respJson) {
    if (typeof respJson?.output_text === 'string' && respJson.output_text.trim()) return respJson.output_text;
    const out = respJson?.output;
    if (!Array.isArray(out)) return '';
    for (const item of out) {
      if (item?.type === 'message' && Array.isArray(item.content)) {
        for (const c of item.content) {
          if (c?.type === 'output_text' && typeof c.text === 'string' && c.text.trim()) return c.text;
          if (typeof c?.text === 'string' && c.text.trim()) return c.text;
        }
      }
    }
    return '';
  }

  function safeParseJson(text) {
    const t = String(text || '').trim();
    if (!t) throw new Error('Empty model output.');
    try { return JSON.parse(t); } catch {}
    const a = t.indexOf('{');
    const b = t.lastIndexOf('}');
    if (a >= 0 && b > a) return JSON.parse(t.slice(a, b + 1));
    throw new Error('Model output was not valid JSON.');
  }

  async function callOpenAI({ system, user }) {
    syncSettingsFromUI();
    const s = App.vault.settings;
    if (!s.apiKey) throw new Error('API key is blank. Paste it in Settings and Save.');

    const body = {
      model: s.model || 'gpt-4.1-mini',
      input: [
        { role: 'system', content: system },
        { role: 'user', content: user }
      ],
      temperature: s.temperature,
      max_output_tokens: s.maxTokens,
      text: { format: { type: 'json_object' } }
    };

    const res = await fetch(s.endpoint || 'https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${s.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json?.error?.message || `API error (${res.status})`);
    return safeParseJson(extractOutputText(json));
  }

  function normalizeQuestion(q, choicesCount) {
    const qq = String(q?.q || '').trim();
    const choices = Array.isArray(q?.choices) ? q.choices.map(x => String(x).trim()).filter(Boolean) : [];
    let ai = Number.isFinite(q?.answer_index) ? q.answer_index : parseInt(q?.answer_index, 10);

    if (!qq) throw new Error('Bad model output: missing question text.');
    if (choices.length !== choicesCount) throw new Error(`Bad model output: choices must be exactly ${choicesCount}.`);
    if (!Number.isFinite(ai)) ai = 0;
    ai = Math.max(0, Math.min(choices.length - 1, ai));

    return {
      id: uid(),
      q: qq,
      choices,
      answer_index: ai,
      explanation: String(q?.explanation || '').trim(),
      user_answer_index: null
    };
  }

  function normalizeQuiz(raw, { diff, title, sourceText, choicesCount }) {
    const questionsRaw = raw?.questions;
    if (!Array.isArray(questionsRaw) || questionsRaw.length === 0) throw new Error('Bad model output: missing questions array.');
    return {
      id: uid(),
      title: String(raw?.title || title || 'Quiz').trim() || 'Quiz',
      difficulty: diff,
      choicesCount,
      sourceText,
      created_at: nowISO(),
      updated_at: nowISO(),
      currentIndex: 0,
      submitted: false,
      submittedAt: null,
      grade: null,
      questions: questionsRaw.map(q => normalizeQuestion(q, choicesCount))
    };
  }

  function computeGrade(quiz) {
    const total = quiz.questions.length;
    let answered = 0;
    let correct = 0;
    const per = quiz.questions.map((q) => {
      const ua = q.user_answer_index;
      const ok = (ua !== null && ua !== undefined);
      if (ok) answered++;
      const isCorrect = ok && ua === q.answer_index;
      if (isCorrect) correct++;
      return { isAnswered: ok, isCorrect, ua, ca: q.answer_index };
    });
    const accuracyAnswered = answered ? Math.round((correct / answered) * 100) : 0;
    const accuracyTotal = total ? Math.round((correct / total) * 100) : 0;
    return { total, answered, correct, accuracyAnswered, accuracyTotal, per };
  }

  function renderResultsPanel(quiz) {
    if (!quiz.submitted || !quiz.grade) {
      resultsPanel.hidden = true;
      resultsPanel.innerHTML = '';
      return;
    }
    const g = quiz.grade;
    const lines = [];
    lines.push(`<div><strong>Answer sheet</strong></div>`);
    lines.push(`<div class="muted">Correct: ${g.correct}/${g.total} • Accuracy(total): ${g.accuracyTotal}% • Accuracy(answered): ${g.accuracyAnswered}%</div>`);
    lines.push('<ul>');
    for (let i = 0; i < quiz.questions.length; i++) {
      const q = quiz.questions[i];
      const r = g.per[i];
      const ua = r.isAnswered ? letter(r.ua) : '—';
      const ca = letter(r.ca);
      const tag = r.isCorrect ? '✅' : (r.isAnswered ? '❌' : '⏳');
      lines.push(`<li>${tag} <strong>${i + 1}</strong> • your: ${ua} • correct: ${ca} — ${escapeHtml(q.q)}</li>`);
    }
    lines.push('</ul>');
    resultsPanel.hidden = false;
    resultsPanel.innerHTML = lines.join('');
  }

  function renderQuizList() {
    quizList.innerHTML = '';
    const quizzes = App.vault?.quizzes || [];
    setStatus(libraryStatus, quizzes.length ? `${quizzes.length} quiz(es)` : 'No quizzes yet.');

    const sorted = quizzes.slice().sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));

    for (const q of sorted) {
      const answered = (q.questions || []).filter(x => x.user_answer_index !== null && x.user_answer_index !== undefined).length;

      const row = document.createElement('div');
      row.className = 'item';
      row.innerHTML = `
        <div class="item__title">${escapeHtml(q.title)}</div>
        <div class="item__meta">${q.questions.length} Q • answered ${answered} • ${escapeHtml(q.difficulty)} • ${q.submitted ? 'submitted' : 'not submitted'}</div>
        <div class="item__actions">
          <button class="btn btn--primary" data-open="${q.id}">Load</button>
          <button class="btn" data-copy="${q.id}">Copy</button>
          <button class="btn btn--danger" data-del="${q.id}">Delete</button>
        </div>
      `;
      quizList.appendChild(row);

      row.querySelector('[data-open]')?.addEventListener('click', () => {
        App.currentQuizId = q.id;
        renderPlayer();
        setView('quiz');
        closeDrawers();
      });

      row.querySelector('[data-copy]')?.addEventListener('click', () => copyQuiz(q.id));

      row.querySelector('[data-del]')?.addEventListener('click', () => {
        App.vault.quizzes = App.vault.quizzes.filter(x => x.id !== q.id);
        if (App.currentQuizId === q.id) App.currentQuizId = null;
        scheduleSave('Deleted quiz.');
        renderQuizList();
        renderPlayer();
      });
    }
  }

  function renderPlayer() {
    const quiz = getActiveQuiz();
    if (!quiz) {
      playerCard.hidden = true;
      quizEmpty.hidden = false;
      return;
    }

    quizEmpty.hidden = true;
    playerCard.hidden = false;

    const idx = clampInt(quiz.currentIndex ?? 0, 0, quiz.questions.length - 1, 0);
    quiz.currentIndex = idx;

    const q = quiz.questions[idx];
    const s = App.vault.settings;

    playerTitle.textContent = quiz.title;
    playerMeta.textContent = `${quiz.questions.length} questions • ${quiz.difficulty} • ${quiz.submitted ? 'submitted' : 'in progress'}`;

    qProgress.textContent = `${idx + 1} / ${quiz.questions.length}`;
    qText.textContent = q.q;

    submitBtn.textContent = quiz.submitted ? 'Submitted' : 'Submit';
    submitBtn.disabled = quiz.submitted;

    qChoices.innerHTML = '';
    q.choices.forEach((c, i) => {
      const btn = document.createElement('button');
      btn.type = 'button';

      const ua = q.user_answer_index;
      const isSelected = ua === i;

      btn.className = 'choice' + (isSelected ? ' selected' : '');

      const showNow = !!s.immediateFeedback;
      if (quiz.submitted || (showNow && ua !== null && ua !== undefined)) {
        if (i === q.answer_index) btn.classList.add('correct');
        if (isSelected && i !== q.answer_index) btn.classList.add('incorrect');
      }

      btn.textContent = `${letter(i)}. ${c}`;

      btn.addEventListener('click', () => {
        if (quiz.submitted) return;
        q.user_answer_index = i;
        quiz.updated_at = nowISO();
        scheduleSave('Answer saved.');
        renderPlayer();
      });

      qChoices.appendChild(btn);
    });

    const answered = q.user_answer_index !== null && q.user_answer_index !== undefined;
    const showExplainNow = quiz.submitted || (App.vault.settings.immediateFeedback && answered);

    if (!showExplainNow) {
      qExplain.hidden = true;
      qExplain.textContent = '';
    } else {
      qExplain.hidden = false;
      const ok = answered && q.user_answer_index === q.answer_index;
      const prefix = (ok ? '✅ Correct. ' : '❌ Wrong. ');
      qExplain.textContent = prefix + (q.explanation || '(No explanation provided.)');
    }

    prevBtn.disabled = idx === 0;
    nextBtn.disabled = idx === quiz.questions.length - 1;

    qMap.innerHTML = '';
    const grade = quiz.grade;
    quiz.questions.forEach((qq, i) => {
      const answered2 = qq.user_answer_index !== null && qq.user_answer_index !== undefined;
      const dot = document.createElement('div');
      dot.className = 'qdot' + (i === idx ? ' active' : '') + (answered2 ? ' answered' : '');

      if (quiz.submitted && grade?.per?.[i]) {
        dot.classList.add(grade.per[i].isCorrect ? 'good' : (grade.per[i].isAnswered ? 'bad' : ''));
      }

      dot.textContent = String(i + 1);
      dot.addEventListener('click', () => {
        quiz.currentIndex = i;
        quiz.updated_at = nowISO();
        scheduleSave();
        renderPlayer();
      });
      qMap.appendChild(dot);
    });

    renderResultsPanel(quiz);
    setStatus(playerStatus, '');
  }

  function renderScoreBox(quiz) {
    const g = quiz.grade || computeGrade(quiz);
    scoreBox.hidden = false;
    scoreBox.textContent = `Answered: ${g.answered}/${g.total} • Correct: ${g.correct} • Accuracy(total): ${g.accuracyTotal}%`;
  }

  async function generateQuiz() {
    setStatus(genStatus, 'Generating...');
    generateBtn.disabled = true;
    try {
      const s = App.vault.settings;
      const diff = (difficulty.value || s.difficulty || 'medium').trim();
      const count = clampInt(questionCount.value, 1, 100, 10);
      const choicesCount = clampInt(defaultChoices.value, 4, 8, 4);
      const title = (quizTitle.value || '').trim();
      const text = (sourceText.value || '').trim();
      if (!text) throw new Error('Source text is empty.');

      const raw = await callOpenAI({
        system: buildSystemInstructions(),
        user: buildGenerateUserInput({ text, count, diff, title, choicesCount })
      });

      const quiz = normalizeQuiz(raw, { diff, title, sourceText: text, choicesCount });
      App.vault.quizzes.push(quiz);
      App.currentQuizId = quiz.id;

      await saveVaultNow();
      renderQuizList();
      scoreBox.hidden = true;
      resultsPanel.hidden = true;
      renderPlayer();
      setView('quiz');
      setStatus(genStatus, 'Generated.');
    } catch (e) {
      setStatus(genStatus, e.message, true);
    } finally {
      generateBtn.disabled = false;
    }
  }

  async function addMoreQuestions() {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    if (quiz.submitted) {
      setStatus(playerStatus, 'Submitted. Copy quiz to retry.', true);
      return;
    }
    setStatus(playerStatus, 'Generating more...');
    addMoreBtn.disabled = true;

    try {
      const addN = clampInt(addCount.value, 1, 50, 5);
      const diff = quiz.difficulty || App.vault.settings.difficulty || 'medium';
      const choicesCount = quiz.choicesCount || 4;

      const raw = await callOpenAI({
        system: buildSystemInstructions(),
        user: buildAddMoreUserInput({
          existingQuestions: quiz.questions,
          addCount: addN,
          diff,
          choicesCount,
          sourceText: quiz.sourceText
        })
      });

      const qs = Array.isArray(raw?.questions) ? raw.questions : [];
      if (!qs.length) throw new Error('Bad model output: no questions returned.');

      const normalized = qs.map(q => normalizeQuestion(q, choicesCount));
      quiz.questions.push(...normalized);
      quiz.updated_at = nowISO();

      await saveVaultNow();
      renderQuizList();
      renderPlayer();
      setStatus(playerStatus, `Added ${normalized.length} question(s).`);
    } catch (e) {
      setStatus(playerStatus, e.message, true);
    } finally {
      addMoreBtn.disabled = false;
    }
  }

  function submitQuiz() {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    quiz.grade = computeGrade(quiz);
    quiz.submitted = true;
    quiz.submittedAt = nowISO();
    quiz.updated_at = nowISO();
    scheduleSave('Submitted.');
    renderScoreBox(quiz);
    renderPlayer();
  }

  function copyQuiz(id) {
    const orig = getQuizById(id);
    if (!orig) return;

    const clone = deepClone(orig);
    clone.id = uid();
    clone.title = (orig.title || 'Quiz') + ' (copy)';
    clone.created_at = nowISO();
    clone.updated_at = nowISO();
    clearAnswers(clone);

    App.vault.quizzes.push(clone);
    App.currentQuizId = clone.id;

    scheduleSave('Copied.');
    renderQuizList();
    renderPlayer();
    setView('quiz');
    closeDrawers();
  }

  function setLockedUI(isUnlocked) {
    navGenerateBtn.disabled = !isUnlocked;
    navQuizBtn.disabled = !isUnlocked;
    openSettingsBtn.disabled = !isUnlocked;
    openLibraryBtn.disabled = !isUnlocked;
    lockBtn.hidden = !isUnlocked;
  }

  function setLockMode() {
    if (!hasVault()) {
      App.mode = 'setup';
      lockTitle.textContent = 'Set master password';
      lockHint.textContent = 'First run. Create a master password to encrypt everything stored locally.';
      confirmWrap.hidden = false;
    } else {
      App.mode = 'unlock';
      lockTitle.textContent = 'Unlock';
      lockHint.textContent = 'Enter your master password to decrypt local data.';
      confirmWrap.hidden = true;
    }
  }

  async function unlockOrSetup(passOverride = null) {
    setStatus(lockStatus, '');
    const pw = (passOverride ?? masterPassword.value ?? '').trim();
    if (!pw) return setStatus(lockStatus, 'Password required.', true);

    try {
      unlockBtn.disabled = true;

      if (App.mode === 'setup') {
        const pw2 = (masterPasswordConfirm.value || '').trim();
        if (!pw2) return setStatus(lockStatus, 'Confirm password.', true);
        if (pw !== pw2) return setStatus(lockStatus, 'Passwords do not match.', true);

        App.vault = defaultVault();
        App.password = pw;
        await saveVaultNow();
      } else {
        const raw = localStorage.getItem(VAULT_KEY);
        if (!raw) throw new Error('Vault missing.');
        const env = JSON.parse(raw);
        App.vault = await decryptVault(env, pw);
        App.password = pw;

        const defaults = defaultVault().settings;
        if (!App.vault.settings) App.vault.settings = { ...defaults };
        App.vault.settings.temperature = (App.vault.settings.temperature ?? 0.7);
        App.vault.settings.model = (App.vault.settings.model || 'gpt-4.1-mini');
        App.vault.settings.defaultChoices = (App.vault.settings.defaultChoices || 4);
        App.vault.settings.endpoint = (App.vault.settings.endpoint || 'https://api.openai.com/v1/responses');
        App.vault.settings.immediateFeedback = !!App.vault.settings.immediateFeedback;
      }

      if (rememberPassword.checked) await rememberPasswordStore(pw);
      else rememberPasswordClear();

      lockScreen.hidden = true;
      app.hidden = false;
      closeDrawers();
      setLockedUI(true);

      renderSettingsToUI();
      renderQuizList();

      if (!App.currentQuizId && App.vault.quizzes.length) {
        const sorted = App.vault.quizzes.slice().sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
        App.currentQuizId = sorted[0].id;
      }

      renderPlayer();
      setView('generate');
      setStatus(settingsStatus, 'Unlocked.');
    } catch (e) {
      setStatus(lockStatus, e?.message || 'Wrong password.', true);
    } finally {
      unlockBtn.disabled = false;
    }
  }

  function lockApp() {
    App.password = null;
    App.vault = null;
    App.currentQuizId = null;
    closeDrawers();
    app.hidden = true;
    lockScreen.hidden = false;
    setLockedUI(false);
    masterPassword.value = '';
    masterPasswordConfirm.value = '';
    setLockMode();
  }

  async function resetAll() {
    const ok = confirm('Wipe EVERYTHING stored locally for this app? This cannot be undone.');
    if (!ok) return;
    localStorage.removeItem(VAULT_KEY);
    localStorage.removeItem(REMEMBER_KEY);
    lockApp();
    setStatus(lockStatus, 'Local data wiped.', false);
  }

  navGenerateBtn.addEventListener('click', () => setView('generate'));
  navQuizBtn.addEventListener('click', () => { setView('quiz'); renderPlayer(); });

  openSettingsBtn.addEventListener('click', () => openDrawer('settings'));
  openLibraryBtn.addEventListener('click', () => openDrawer('library'));
  closeSettingsBtn.addEventListener('click', closeDrawers);
  closeLibraryBtn.addEventListener('click', closeDrawers);
  drawerOverlay.addEventListener('click', closeDrawers);

  goGenerateBtn.addEventListener('click', () => setView('generate'));
  openLibraryBtn2.addEventListener('click', () => openDrawer('library'));

  unlockBtn.addEventListener('click', () => unlockOrSetup());
  masterPassword.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockOrSetup(); });
  masterPasswordConfirm.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockOrSetup(); });

  forgetRememberedBtn.addEventListener('click', () => {
    rememberPasswordClear();
    forgetRememberedBtn.hidden = true;
    rememberPassword.checked = false;
    setStatus(lockStatus, 'Saved password cleared.', false);
  });

  lockBtn.addEventListener('click', lockApp);
  resetBtn.addEventListener('click', () => resetAll().catch(() => {}));

  saveSettingsBtn.addEventListener('click', async () => {
    try {
      syncSettingsFromUI();
      await saveVaultNow();
      setStatus(settingsStatus, 'Settings saved.');
      renderPlayer();
    } catch (e) {
      setStatus(settingsStatus, e.message, true);
    }
  });

  generateBtn.addEventListener('click', () => generateQuiz().catch(() => {}));
  addMoreBtn.addEventListener('click', () => addMoreQuestions().catch(() => {}));

  prevBtn.addEventListener('click', () => {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    quiz.currentIndex = Math.max(0, (quiz.currentIndex || 0) - 1);
    quiz.updated_at = nowISO();
    scheduleSave();
    renderPlayer();
  });

  nextBtn.addEventListener('click', () => {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    quiz.currentIndex = Math.min(quiz.questions.length - 1, (quiz.currentIndex || 0) + 1);
    quiz.updated_at = nowISO();
    scheduleSave();
    renderPlayer();
  });

  submitBtn.addEventListener('click', submitQuiz);

  scoreBtn.addEventListener('click', () => {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    quiz.grade = quiz.grade || computeGrade(quiz);
    renderScoreBox(quiz);
  });

  saveNowBtn.addEventListener('click', async () => {
    try {
      syncSettingsFromUI();
      await saveVaultNow();
      setStatus(playerStatus, 'Saved.');
    } catch (e) {
      setStatus(playerStatus, e.message, true);
    }
  });

  copyQuizBtn.addEventListener('click', () => {
    const quiz = getActiveQuiz();
    if (!quiz) return;
    copyQuiz(quiz.id);
  });

  apiKey.addEventListener('input', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  model.addEventListener('change', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  difficulty.addEventListener('change', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  defaultChoices.addEventListener('change', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  endpoint.addEventListener('input', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  temperature.addEventListener('input', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  maxTokens.addEventListener('input', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); } });
  immediateFeedback.addEventListener('change', () => { if (App.vault) { syncSettingsFromUI(); scheduleSave(); renderPlayer(); } });

  (async () => {
    setLockedUI(false);
    closeDrawers();
    initModelDropdown();
    setLockMode();
    setView('generate');

    forgetRememberedBtn.hidden = !localStorage.getItem(REMEMBER_KEY);

    const remembered = await rememberPasswordLoad();
    if (remembered && hasVault()) {
      rememberPassword.checked = true;
      await unlockOrSetup(remembered);
      forgetRememberedBtn.hidden = !localStorage.getItem(REMEMBER_KEY);
    }
  })();

})();
