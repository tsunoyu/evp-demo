export function setupComparisonModal() {
  // Check if modal already exists in DOM; if not, inject it
  let modalBackdrop = document.getElementById('comparison-modal');
  if (!modalBackdrop) {
    const modalHTML = `
      <div class="modal-backdrop" id="comparison-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-dialog">
          <div class="modal-header">
            <h2 id="modal-title">⚡ EVP vs ✉️ Traditional Flow Comparison</h2>
            <button class="modal-close-btn" id="modal-close-btn" aria-label="Close modal">&times;</button>
          </div>
          <div class="modal-body">
            <!-- Metrics Summary Cards -->
            <div class="modal-metrics-summary">
              <div class="summary-card evp">
                <div class="summary-title">⚡ Email Verification Protocol (EVP)</div>
                <div class="summary-bullet">✓ Instant cryptographic verification (~0.2s)</div>
                <div class="summary-bullet">✓ Zero context switching (User never leaves RP tab)</div>
                <div class="summary-bullet">✓ 1-click execution via browser autofill dropdown</div>
                <div class="summary-bullet">✓ Origin & session bound (Phishing relay proof)</div>
                <div class="summary-bullet">✓ $0 infrastructure cost for Relying Party</div>
              </div>

              <div class="summary-card traditional">
                <div class="summary-title">✉️ Traditional Flow (OTP / Magic Link)</div>
                <div class="summary-bullet">✖ High latency delay (15s – 60s mail queueing)</div>
                <div class="summary-bullet">✖ Mandatory context switch (RP → Mail App → RP)</div>
                <div class="summary-bullet">✖ 5–7 manual user actions (type, open app, read, copy, paste)</div>
                <div class="summary-bullet">✖ Susceptible to AitM phishing relay & link pre-fetching</div>
                <div class="summary-bullet">✖ Recurring SMTP relay fees & deliverability headaches</div>
              </div>
            </div>

            <!-- Detailed Comparison Table -->
            <div class="comparison-table-wrapper">
              <table class="comparison-table">
                <thead>
                  <tr>
                    <th>Dimension</th>
                    <th>⚡ Email Verification Protocol (EVP)</th>
                    <th>✉️ Traditional OTP / Magic Link</th>
                    <th>Impact / Winner</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>Completion Time</strong></td>
                    <td>~0.2 – 0.5 Seconds</td>
                    <td>15.0 – 45.0+ Seconds</td>
                    <td><span class="badge-winner">⚡ EVP (~100x Faster)</span></td>
                  </tr>
                  <tr>
                    <td><strong>Context Switching</strong></td>
                    <td>0 App / Tab Switches</td>
                    <td>2 App Switches (Browser → Email → Browser)</td>
                    <td><span class="badge-winner">⚡ Zero Friction</span></td>
                  </tr>
                  <tr>
                    <td><strong>User Friction & Steps</strong></td>
                    <td>1 Click (Select email autofill)</td>
                    <td>5–7 Steps (Type email, switch app, scan inbox, copy code, paste code)</td>
                    <td><span class="badge-winner">⚡ Single Action</span></td>
                  </tr>
                  <tr>
                    <td><strong>User Drop-off / Abandonment</strong></td>
                    <td>Near 0% drop-off</td>
                    <td>10% – 20% drop-off due to latency, spam filters, or context fatigue</td>
                    <td><span class="badge-winner">⚡ Higher Conversion</span></td>
                  </tr>
                  <tr>
                    <td><strong>Phishing Resilience</strong></td>
                    <td><strong>Immune</strong> (Cryptographically bound to origin domain & session nonce)</td>
                    <td><strong>Vulnerable</strong> (OTP relay phishing, AitM proxy attacks)</td>
                    <td><span class="badge-winner">⚡ Cryptographic Proof</span></td>
                  </tr>
                  <tr>
                    <td><strong>Deliverability Failures</strong></td>
                    <td>0% (No SMTP dependency)</td>
                    <td>2% – 5% (Spam folders, greylisting, bad routing)</td>
                    <td><span class="badge-winner">⚡ 100% Reliable</span></td>
                  </tr>
                  <tr>
                    <td><strong>RP Server Overhead</strong></td>
                    <td>Stateless client or public-key verification</td>
                    <td>SMTP relay vendor costs, rate limiting, token DB state</td>
                    <td><span class="badge-winner">⚡ Zero Mail Overhead</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    modalBackdrop = document.getElementById('comparison-modal');
  }

  const compareBtns = document.querySelectorAll('.nav-btn-compare');
  const closeBtn = document.getElementById('modal-close-btn');

  const openModal = () => {
    if (modalBackdrop) modalBackdrop.classList.add('open');
  };

  const closeModal = () => {
    if (modalBackdrop) modalBackdrop.classList.remove('open');
  };

  compareBtns.forEach(btn => {
    btn.addEventListener('click', openModal);
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', closeModal);
  }

  if (modalBackdrop) {
    modalBackdrop.addEventListener('click', (e) => {
      if (e.target === modalBackdrop) closeModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modalBackdrop && modalBackdrop.classList.contains('open')) {
      closeModal();
    }
  });
}
