import { setupComparisonModal } from './modal.js';

let currentMode = 'otp'; // 'otp' or 'magic-link'
let generatedOtp = '';
let generatedMagicToken = '';
let timerInterval = null;
let startTime = null;
let extraDelayMs = 0;

document.addEventListener('DOMContentLoaded', () => {
  setupThemeToggle();
  setupTabs();
  setupModeSelector();
  setupFormSubmit();
  setupOtpDigitInputs();
  setupSimulatedInboxControls();
  setupComparisonModal();
});

// Setup Theme Toggle
function setupThemeToggle() {
  const themeToggleBtn = document.getElementById('theme-toggle');
  if (!themeToggleBtn) return;

  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
  }

  themeToggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const isLight = document.body.classList.contains('light-theme');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
  });
}

// Inspector Tab Navigation
function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById(`tab-${targetTab}`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

// Mode Pill Selector (OTP vs Magic Link)
function setupModeSelector() {
  const otpBtn = document.getElementById('mode-otp-btn');
  const linkBtn = document.getElementById('mode-link-btn');
  const sendBtnLabel = document.getElementById('send-btn-label');
  const otpFormSection = document.getElementById('otp-form-section');
  const magicLinkSection = document.getElementById('magic-link-section');

  otpBtn.addEventListener('click', () => {
    currentMode = 'otp';
    otpBtn.classList.add('active');
    linkBtn.classList.remove('active');
    sendBtnLabel.textContent = 'Send OTP Verification Code';
    otpFormSection.classList.remove('hidden');
    magicLinkSection.classList.add('hidden');
    resetSimulationState();
  });

  linkBtn.addEventListener('click', () => {
    currentMode = 'magic-link';
    linkBtn.classList.add('active');
    otpBtn.classList.remove('active');
    sendBtnLabel.textContent = 'Send Magic Login Link';
    magicLinkSection.classList.remove('hidden');
    otpFormSection.classList.add('hidden');
    resetSimulationState();
  });
}

// Setup Form Submission & Verification Pipeline
function setupFormSubmit() {
  const form = document.getElementById('trad-email-form');
  const emailInput = document.getElementById('trad-email');
  const sendBtn = document.getElementById('trad-send-btn');
  const sendSpinner = document.getElementById('trad-send-spinner');
  const verifyOtpBtn = document.getElementById('trad-verify-otp-btn');
  const verifySpinner = document.getElementById('trad-verify-spinner');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = emailInput.value.trim();
    if (!email) return;

    resetResults();
    setStatusBadge('verifying', 'Sending Email...');
    sendSpinner.style.display = 'inline-block';
    sendBtn.disabled = true;

    // Simulate server side email generation & SMTP dispatch
    await sleep(600 + extraDelayMs);

    sendSpinner.style.display = 'none';
    sendBtn.disabled = false;

    // Show Step 2 container
    document.getElementById('trad-step2-container').classList.remove('hidden');
    setStatusBadge('verifying', 'Waiting for User Context Switch');

    startFrictionTimer();

    if (currentMode === 'otp') {
      // Generate 6 digit code
      generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
      deliverSimulatedEmail(email, 'Your 6-Digit Verification Code', `Your single-use passcode is <strong>${generatedOtp}</strong>. It will expire in 10 minutes.`, 'otp');
      renderFrictionTrace('otp', email);
      renderSecurityLogs('otp', email);
    } else {
      // Generate Magic Link
      generatedMagicToken = btoa(Math.random().toString()).substring(0, 16);
      deliverSimulatedEmail(email, 'Sign in to EVP Verifier', `Click the button below to instantly complete your login request.`, 'magic-link');
      renderFrictionTrace('magic-link', email);
      renderSecurityLogs('magic-link', email);
    }
  });

  // Verify OTP button listener
  verifyOtpBtn.addEventListener('click', async () => {
    const enteredOtp = getEnteredOtp();
    if (enteredOtp.length < 6) {
      showError('Please enter all 6 digits of the verification code.');
      return;
    }

    verifySpinner.style.display = 'inline-block';
    verifyOtpBtn.disabled = true;

    await sleep(400); // Simulate API validation network roundtrip

    verifySpinner.style.display = 'none';
    verifyOtpBtn.disabled = false;

    if (enteredOtp === generatedOtp) {
      stopFrictionTimer();
      completeSuccess('Verified via 6-Digit OTP after manual copy & paste across context switches.');
    } else {
      showError(`Incorrect verification code. Entered: ${enteredOtp}, Expected: ${generatedOtp}`);
    }
  });
}

// Helper to handle 6-digit OTP input boxes
function setupOtpDigitInputs() {
  const digitInputs = document.querySelectorAll('.otp-digit-input');

  digitInputs.forEach((input, index) => {
    input.addEventListener('input', (e) => {
      const value = e.target.value;
      if (value.length >= 1) {
        input.value = value[0]; // Take first character only
        if (index < digitInputs.length - 1) {
          digitInputs[index + 1].focus();
        }
      }
    });

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !input.value && index > 0) {
        digitInputs[index - 1].focus();
      }
    });

    // Handle paste event across all digit inputs
    input.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
      const digits = pasteData.replace(/\D/g, '').substring(0, 6);
      
      digits.split('').forEach((d, i) => {
        if (digitInputs[i]) {
          digitInputs[i].value = d;
        }
      });

      if (digits.length > 0) {
        const lastIndex = Math.min(digits.length - 1, digitInputs.length - 1);
        digitInputs[lastIndex].focus();
      }
    });
  });
}

function getEnteredOtp() {
  const digitInputs = document.querySelectorAll('.otp-digit-input');
  let code = '';
  digitInputs.forEach(input => {
    code += input.value.trim();
  });
  return code;
}

function fillOtpDigits(code) {
  const digitInputs = document.querySelectorAll('.otp-digit-input');
  code.split('').forEach((digit, idx) => {
    if (digitInputs[idx]) {
      digitInputs[idx].value = digit;
    }
  });
}

// Live Friction Timer & Metrics Tracker
function startFrictionTimer() {
  stopFrictionTimer();
  startTime = Date.now();

  const timerEl = document.getElementById('metric-timer');
  const dropoffEl = document.getElementById('metric-dropoff');

  timerInterval = setInterval(() => {
    const elapsedMs = Date.now() - startTime + extraDelayMs;
    const totalSeconds = (elapsedMs / 1000).toFixed(1);
    
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = (totalSeconds % 60).toFixed(1);
    const formattedSec = seconds < 10 ? '0' + seconds : seconds;
    
    timerEl.textContent = `0${minutes}:${formattedSec}`;

    // Dynamic drop-off calculation model (higher latency = higher drop-off)
    const dropoffRate = Math.min(38.0, 12.0 + (totalSeconds * 0.4)).toFixed(1);
    dropoffEl.textContent = `~${dropoffRate}%`;
  }, 100);
}

function stopFrictionTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
}

// Simulated Email Inbox Controls & Delivery
function deliverSimulatedEmail(email, subject, bodyContent, mode) {
  const badge = document.getElementById('inbox-unread-badge');
  const emptyState = document.getElementById('inbox-empty-message');
  const messagesList = document.getElementById('inbox-messages-list');
  const addressLabel = document.getElementById('inbox-address-label');

  addressLabel.textContent = `mailbox: ${email}`;
  badge.textContent = '1';
  emptyState.style.display = 'none';
  messagesList.innerHTML = '';

  const timeString = new Date().toLocaleTimeString();
  const msgCard = document.createElement('div');
  msgCard.className = 'email-message-item';

  let actionButtonsHTML = '';
  if (mode === 'otp') {
    actionButtonsHTML = `
      <div class="email-action-row">
        <button type="button" class="email-act-btn primary" id="act-copy-otp">
          📋 Auto-Copy & Paste Code (${generatedOtp})
        </button>
      </div>
    `;
  } else {
    actionButtonsHTML = `
      <div class="email-action-row">
        <button type="button" class="email-act-btn primary" id="act-click-magic">
          🔗 Click Magic Link to Authenticate
        </button>
      </div>
    `;
  }

  msgCard.innerHTML = `
    <div class="email-msg-header">
      <span class="email-sender">From: auth-noreply@evp-demo.com</span>
      <span class="email-time">${timeString}</span>
    </div>
    <div class="email-subject">${escapeHtml(subject)}</div>
    <div style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.4;">
      ${bodyContent}
    </div>
    ${actionButtonsHTML}
  `;

  messagesList.appendChild(msgCard);

  // Add click handlers to simulate user action inside email app
  if (mode === 'otp') {
    document.getElementById('act-copy-otp')?.addEventListener('click', () => {
      fillOtpDigits(generatedOtp);
      badge.textContent = '0';
      logTerminal('User performed Context Switch #1: Opened Email Client app, read email, copied 6-digit OTP code.');
      logTerminal('User performed Context Switch #2: Returned to RP app tab, pasted OTP into form.');
    });
  } else {
    document.getElementById('act-click-magic')?.addEventListener('click', async () => {
      badge.textContent = '0';
      logTerminal('User clicked Magic Link inside email app.');
      logTerminal('Context Switch #1 & #2 executed: Deep-link token opened in browser callback endpoint.');
      stopFrictionTimer();
      await sleep(300);
      document.getElementById('magic-link-section')?.classList.add('hidden');
      completeSuccess('Verified via Magic Link email callback! Notice how a new browser tab/window had to be loaded.');
    });
  }
}

function setupSimulatedInboxControls() {
  const delayBtn = document.getElementById('sim-delay-btn');
  const resetBtn = document.getElementById('sim-reset-btn');

  delayBtn.addEventListener('click', () => {
    extraDelayMs += 15000;
    delayBtn.textContent = `+${extraDelayMs / 1000}s Delay Active`;
    delayBtn.style.borderColor = '#f59e0b';
    delayBtn.style.color = '#f59e0b';
    logTerminal(`[Simulation Delay] Added 15 seconds artificial SMTP delivery queue latency delay.`, 'highlight');
  });

  resetBtn.addEventListener('click', () => {
    resetSimulationState();
  });
}

function resetSimulationState() {
  stopFrictionTimer();
  extraDelayMs = 0;
  generatedOtp = '';
  generatedMagicToken = '';

  const delayBtn = document.getElementById('sim-delay-btn');
  if (delayBtn) {
    delayBtn.textContent = '+15s Latency Delay';
    delayBtn.style.borderColor = '';
    delayBtn.style.color = '';
  }

  document.getElementById('metric-timer').textContent = '00:00.0';
  document.getElementById('metric-dropoff').textContent = '~15.2%';
  document.getElementById('inbox-unread-badge').textContent = '0';
  document.getElementById('inbox-empty-message').style.display = 'block';
  document.getElementById('inbox-messages-list').innerHTML = '';
  document.getElementById('trad-step2-container').classList.add('hidden');
  
  // Clear inputs
  document.querySelectorAll('.otp-digit-input').forEach(i => i.value = '');

  resetResults();
  setStatusBadge('idle', 'Idle');
}

function completeSuccess(messageDetail) {
  setStatusBadge('verified', 'Verified');

  const banner = document.getElementById('trad-success-banner');
  const detailEl = document.getElementById('trad-success-detail');
  const timeEl = document.getElementById('trad-final-time');

  const finalSeconds = ( (Date.now() - startTime + extraDelayMs) / 1000 ).toFixed(1);
  timeEl.textContent = `${finalSeconds}s`;
  detailEl.textContent = messageDetail;
  banner.classList.remove('hidden');

  logTerminal(`AUTHENTICATION COMPLETED in ${finalSeconds}s. High friction traditional flow compared against sub-second EVP!`, 'success');
}

function showError(msg) {
  setStatusBadge('failed', 'Failed');
  const banner = document.getElementById('trad-error-banner');
  const textEl = document.getElementById('trad-error-text');
  textEl.textContent = msg;
  banner.classList.remove('hidden');
  logTerminal(`AUTH ERROR: ${msg}`, 'error');
}

function resetResults() {
  document.getElementById('trad-success-banner').classList.add('hidden');
  document.getElementById('trad-error-banner').classList.add('hidden');
  document.getElementById('trad-trace-steps-list').innerHTML = '';
}

function setStatusBadge(statusClass, text) {
  const badge = document.getElementById('trad-status-badge');
  if (badge) {
    badge.className = `status-badge ${statusClass}`;
    badge.textContent = text;
  }
}

// Render Step-by-Step Friction Trace
function renderFrictionTrace(mode, email) {
  const container = document.getElementById('trad-trace-steps-list');
  container.innerHTML = '';

  const traceSteps = [
    {
      step: 1,
      name: 'Client Email Form Submission',
      status: 'warning',
      description: `User submits email (${email}) to Relying Party (RP) backend endpoint to request verification.`,
      inputs: { email, mode },
      outputs: { status: 'Accepted', action: 'Triggering SMTP Mailer queue' }
    },
    {
      step: 2,
      name: 'RP Backend SMTP Gateway Dispatch',
      status: 'warning',
      description: 'RP server generates token/OTP in database and connects via REST API / SMTP to email dispatch provider (SendGrid / Mailgun / AWS SES).',
      inputs: { provider: 'Outbound Mailgun REST API', tokenType: mode === 'otp' ? '6-Digit Numeric OTP' : 'Magic Link JTI Token' },
      outputs: { httpStatus: 202, messageId: `<${Math.random().toString(36).substring(7)}@evp-demo.com>` }
    },
    {
      step: 3,
      name: 'MTA Relay & Spam Heuristics Queueing',
      status: 'failure',
      description: `Email traverses SMTP Mail Transfer Agents (MTAs). Subject to gray-listing, SPF/DKIM validation, and spam filters. Network Latency: 5s to 45s.`,
      inputs: { spfStatus: 'Pass', dkimStatus: 'Pass', queueLatency: extraDelayMs > 0 ? `${15 + extraDelayMs / 1000}s (Simulated High Queue Delay)` : '4.8s Average Network Delay' },
      outputs: { deliveryStatus: 'Delivered to Inbox' }
    },
    {
      step: 4,
      name: '⚠️ Context Switch #1 (Browser → Mail Client App)',
      status: 'failure',
      description: 'HIGH FRICTION: User is forced to leave the Relying Party browser application tab and launch their desktop or mobile mail app (Gmail / Outlook). Risk of user distraction or session drop-off.',
      inputs: { currentTab: 'EVP Relying Party Website', targetApp: 'Mobile Gmail App / Webmail' },
      outputs: { contextSwitchCost: 'Cognitive load + Tab loss', dropOffRate: '~12.5% user abandonment' }
    },
    {
      step: 5,
      name: 'Inbox Scanning & Code / Link Extraction',
      status: 'warning',
      description: 'User searches inbox, opens message, identifies 6-digit OTP code or locates Magic Link button inside email body.',
      inputs: { emailSubject: mode === 'otp' ? 'Your Verification Code' : 'Sign in to EVP Verifier' },
      outputs: mode === 'otp' ? { extractedOtp: generatedOtp } : { magicLinkUrl: `http://localhost:3000/auth/callback?token=${generatedMagicToken}` }
    },
    {
      step: 6,
      name: '⚠️ Context Switch #2 (Mail Client App → Browser Tab)',
      status: 'failure',
      description: mode === 'otp' ? 'HIGH FRICTION: User memorizes or copies 6-digit code, switches back to RP tab, and manually types or pastes numbers.' : 'HIGH FRICTION: Clicking Magic Link opens a NEW browser window/tab, requiring cross-tab session migration or cookie synchronization.',
      inputs: { actionTaken: mode === 'otp' ? 'Manual Copy & Paste' : 'New Browser Tab Spawning' },
      outputs: { userSatisfaction: 'Low', securityRisk: mode === 'otp' ? 'Adversary-in-the-Middle (AitM) Relay Phishing Vulnerability' : 'Link pre-fetching by corporate security bots burning token' }
    },
    {
      step: 7,
      name: 'Server Token Validation & Session Verification',
      status: 'success',
      description: 'RP backend matches submitted OTP / Magic Token against database record and grants user access.',
      inputs: mode === 'otp' ? { submittedCode: generatedOtp } : { token: generatedMagicToken },
      outputs: { verificationPassed: true, totalElapsedSeconds: '15s - 45s' }
    }
  ];

  traceSteps.forEach(step => {
    const stepEl = document.createElement('div');
    stepEl.className = `trace-step ${step.status}`;

    stepEl.innerHTML = `
      <div class="trace-step-header">
        <div class="trace-step-title">
          <span class="step-num">${step.step}</span>
          <span class="step-name">${escapeHtml(step.name)}</span>
        </div>
        <span class="step-badge ${step.status}">${step.status === 'failure' ? 'friction' : step.status}</span>
      </div>
      <div class="trace-step-body">
        <p class="step-desc">${escapeHtml(step.description)}</p>
        <div class="json-box-container">
          <button class="toggle-json-btn">
            <span>Show Inputs / Outputs</span>
            <span class="arrow">▼</span>
          </button>
          <div class="json-details hidden">
            <div class="json-label">Inputs:</div>
            <pre class="json-data">${escapeHtml(JSON.stringify(step.inputs, null, 2))}</pre>
            <div class="json-label">Outputs:</div>
            <pre class="json-data">${escapeHtml(JSON.stringify(step.outputs, null, 2))}</pre>
          </div>
        </div>
      </div>
    `;

    const header = stepEl.querySelector('.trace-step-header');
    const body = stepEl.querySelector('.trace-step-body');
    header.addEventListener('click', () => {
      body.classList.toggle('open');
    });

    const toggleJsonBtn = stepEl.querySelector('.toggle-json-btn');
    const jsonDetails = stepEl.querySelector('.json-details');
    const arrow = stepEl.querySelector('.arrow');
    toggleJsonBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      jsonDetails.classList.toggle('hidden');
      arrow.textContent = jsonDetails.classList.contains('hidden') ? '▼' : '▲';
    });

    container.appendChild(stepEl);
  });
}

// Render Security & Operational Cost Audit Log
function renderSecurityLogs(mode, email) {
  const terminal = document.getElementById('trad-security-terminal');
  if (!terminal) return;
  terminal.innerHTML = '';

  logTerminal(`=== OPERATIONAL AUDIT: TRADITIONAL EMAIL AUTH (${mode.toUpperCase()}) ===`, 'system');
  logTerminal(`[DELIVERABILITY & COST] Dispatching email to ${email}...`);
  logTerminal(`[COST METRIC] Average SMTP relay cost: $0.001 - $0.003 per verification email.`);
  logTerminal(`[LATENCY BURDEN] Outbound mail queue average delay: 5s to 30s network roundtrip.`);

  if (mode === 'otp') {
    logTerminal(`[SECURITY VULNERABILITY - AitM PHISHING] 6-Digit OTP codes are vulnerable to real-time Adversary-in-the-Middle (AitM) phishing proxies (e.g., Evilginx). Attackers relay OTP entries instantly!`, 'error');
    logTerminal(`[SECURITY VULNERABILITY - BRUTE FORCE & EXPIRATION] Passcodes require TTL expiration state (10m) and IP rate-limiting to prevent brute force enumeration.`, 'highlight');
  } else {
    logTerminal(`[SECURITY VULNERABILITY - SCANNER PRE-FETCH] Corporate email security scanners (Proofpoint, Barracuda) detonate Magic Links automatically to scan URLs, inadvertently burning single-use tokens!`, 'error');
    logTerminal(`[SECURITY VULNERABILITY - TAB / COOKIE LOSS] Magic link opens in default system browser tab, missing session state or cookies from original webview/tab.`, 'highlight');
  }

  logTerminal(`[CONVERSION IMPACT] Industry benchmark: 10% to 18% user drop-off due to email latency, spam folder confusion, and context switching fatigue.`, 'error');
  logTerminal(`=== COMPARE WITH EVP: Sub-second verification, zero context switches, zero SMTP costs, 100% phishing-proof origin binding. ===`, 'success');
}

function logTerminal(msg, type = '') {
  const terminal = document.getElementById('trad-security-terminal');
  if (!terminal) return;

  const line = document.createElement('div');
  line.className = `console-line ${type}`;

  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = `[${new Date().toLocaleTimeString()}]`;

  line.appendChild(timeSpan);
  line.appendChild(document.createTextNode(' ' + msg));
  terminal.appendChild(line);

  terminal.scrollTop = terminal.scrollHeight;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
