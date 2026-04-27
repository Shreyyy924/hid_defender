/**
 * Test Runner JavaScript Logic
 * Handles individual and bulk test execution with modal feedback
 */

function setStatus(group, idx, passed) {
  const el = document.getElementById(`status-${group}-${idx}`);
  if (!el) return;
  
  if (passed === null) {
    el.className = 'r-badge r-pending';
    el.innerHTML = '<span class="spinner"></span>';
    return;
  }
  
  el.className = 'r-badge ' + (passed ? 'r-pass' : 'r-fail');
  el.textContent = passed ? '✅ Pass' : '❌ Fail';
}

function openModal(title) {
  const modal = document.getElementById('results-modal');
  const mTitle = document.getElementById('modal-title');
  const mSummary = document.getElementById('modal-summary');
  const mConsole = document.getElementById('modal-console');

  modal.classList.add('active');
  mTitle.textContent = title;
  mSummary.innerHTML = `
    <div style="text-align:center;padding:2rem">
      <div class="spinner" style="width:30px;height:30px;border-width:3px"></div>
      <p style="margin-top:1rem;color:var(--muted)">Executing test suite, please wait...</p>
    </div>
  `;
  mConsole.textContent = "Waiting for results...";
  return { mSummary, mConsole };
}

function closeModal() {
  document.getElementById('results-modal').classList.remove('active');
}

async function runOne(testId, group, idx) {
  // Update UI to pending
  setStatus(group, idx, null);

  // Open modal with individual test title
  const { mSummary, mConsole } = openModal(`Running Test: ${testId.split('::').pop()}`);

  try {
    const res = await fetch('/api/tests/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ test_id: testId })
    });
    const data = await res.json();
    const r = data.result;

    // Update status badge on main list
    setStatus(group, idx, r.passed);

    // Update modal content
    mSummary.innerHTML = `
      <div style="display:flex; justify-content:center; gap:1.5rem;">
        <div class="scard" style="min-width:200px">
          <div class="sv ${r.passed ? 'sv-pass' : 'sv-fail'}">${r.passed ? 'PASSED' : 'FAILED'}</div>
          <div class="sl">Result</div>
        </div>
      </div>
    `;
    mConsole.textContent = (r.stdout || '') + (r.stderr ? '\n\n--- STDERR ---\n' + r.stderr : '');

  } catch (err) {
    mSummary.innerHTML = `<p style="color:var(--red);text-align:center">Error: ${err.message}</p>`;
    mConsole.textContent = err.stack;
  }
}

async function runAll(file) {
  // Reset all badges on the page
  document.querySelectorAll('.r-badge').forEach(b => {
    b.className = 'r-badge r-pending';
    b.textContent = 'Pending';
  });
  document.getElementById('summary-bar').style.display = 'none';

  // Open modal in loading state
  const { mSummary, mConsole } = openModal(file ? `Running Module: ${file}` : "Running All Tests");

  try {
    const res = await fetch('/api/tests/run/all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file })
    });
    const data = await res.json();

    // Update main page summary bar
    document.getElementById('s-total').textContent = data.pass_count + data.fail_count;
    document.getElementById('s-pass').textContent = data.pass_count;
    document.getElementById('s-fail').textContent = data.fail_count;
    document.getElementById('summary-bar').style.display = 'flex';

    // Update modal summary view
    mSummary.innerHTML = `
      <div style="display:flex;gap:1rem">
        <div class="scard" style="flex:1"><div class="sv sv-total">${data.pass_count + data.fail_count}</div><div class="sl">Total</div></div>
        <div class="scard" style="flex:1"><div class="sv sv-pass">${data.pass_count}</div><div class="sl">Passed</div></div>
        <div class="scard" style="flex:1"><div class="sv sv-fail">${data.fail_count}</div><div class="sl">Failed</div></div>
      </div>
    `;
    mConsole.textContent = data.stdout + (data.stderr ? '\n\n--- STDERR ---\n' + data.stderr : '');

    // Update individual badges on main page list from the bulk output
    const lines = (data.stdout || '').split('\n');
    lines.forEach(line => {
      const pm = line.match(/tests\/(test_\w+)\.py::(\w+)::(\w+)\s+(PASSED|FAILED)/);
      if (!pm) return;
      const [, mod, cls, func, verdict] = pm;
      document.querySelectorAll('tr[data-id]').forEach(row => {
        const id = row.getAttribute('data-id');
        if (id && id.includes(func)) {
          const badge = row.querySelector('.r-badge');
          if (badge) {
            badge.className = 'r-badge ' + (verdict === 'PASSED' ? 'r-pass' : 'r-fail');
            badge.textContent = verdict === 'PASSED' ? '✅ Pass' : '❌ Fail';
          }
        }
      });
    });
  } catch (err) {
    mSummary.innerHTML = `<p style="color:var(--red);text-align:center">Error: ${err.message}</p>`;
    mConsole.textContent = err.stack;
  }
}
