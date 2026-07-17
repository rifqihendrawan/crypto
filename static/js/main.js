/* ---------- Landing page hero decorative bits ---------- */
function initHeroBits() {
  const el = document.getElementById('heroBits');
  if (!el) return;
  let lines = [];
  for (let r = 0; r < 22; r++) {
    let line = '';
    for (let c = 0; c < 90; c++) line += Math.random() < 0.5 ? '0' : '1';
    lines.push(line);
  }
  el.textContent = lines.join('\n');
}

/* ---------- Bit box rendering ---------- */
function renderBitBoxes(container, value, groupSize) {
  container.innerHTML = '';
  const chars = String(value).split('');
  chars.forEach((ch, i) => {
    const box = document.createElement('span');
    box.className = 'bit-box';
    if (groupSize && i > 0 && i % groupSize === 0) box.classList.add('grp-start');
    if (ch === '1') box.classList.add('on');
    box.textContent = ch;
    box.style.animationDelay = (i * 12) + 'ms';
    container.appendChild(box);
  });
}

function groupSizeFor(value) {
  // bit strings group by nibble (4); hex strings group by 2
  const isBin = /^[01]+$/.test(value);
  return isBin ? 4 : 2;
}

/* ---------- Generic step renderer ---------- */
function renderStepField(step) {
  const wrap = document.createElement('div');
  wrap.className = 'step-card';

  const title = document.createElement('p');
  title.className = 'step-title';
  title.textContent = step.title;
  wrap.appendChild(title);

  if (step.type === 'bits') {
    step.content.forEach(item => {
      const field = document.createElement('div');
      field.className = 'step-field';
      const label = document.createElement('div');
      label.className = 'step-field-label';
      label.textContent = item.label + ' (' + item.value.length + (/^[01]+$/.test(item.value) ? ' bit' : ' digit') + ')';
      field.appendChild(label);
      const row = document.createElement('div');
      row.className = 'bit-row';
      field.appendChild(row);
      wrap.appendChild(field);
      renderBitBoxes(row, item.value, groupSizeFor(item.value));
    });
  } else if (step.type === 'keyvalue') {
    const kv = document.createElement('div');
    kv.className = 'step-kv';
    step.content.forEach(item => {
      const it = document.createElement('div');
      it.className = 'step-kv-item';
      const label = document.createElement('div');
      label.className = 'step-field-label';
      label.textContent = item.label;
      const val = document.createElement('div');
      val.className = 'step-kv-value';
      val.textContent = item.value;
      it.appendChild(label);
      it.appendChild(val);
      kv.appendChild(it);
    });
    wrap.appendChild(kv);
  } else if (step.type === 'table') {
    const table = document.createElement('table');
    table.className = 'step-table';
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    step.content.headers.forEach(h => {
      const th = document.createElement('th');
      th.textContent = h;
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    step.content.rows.forEach(row => {
      const tr = document.createElement('tr');
      row.forEach(cell => {
        const td = document.createElement('td');
        td.textContent = cell;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
  } else if (step.type === 'matrix') {
    const matrixWrap = document.createElement('div');
    matrixWrap.className = 'step-matrix-wrap';
    const table = document.createElement('table');
    table.className = 'step-matrix';
    const tbody = document.createElement('tbody');
    step.content.forEach(rowArr => {
      const tr = document.createElement('tr');
      rowArr.forEach(v => {
        const td = document.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    matrixWrap.appendChild(table);
    wrap.appendChild(matrixWrap);
  } else if (step.type === 'text') {
    const p = document.createElement('p');
    p.className = 'step-text';
    p.textContent = step.content;
    wrap.appendChild(p);
  }

  return wrap;
}

function renderSteps(steps, container) {
  container.innerHTML = '';
  steps.forEach(step => container.appendChild(renderStepField(step)));
}

/* ---------- Module page logic ---------- */
function initModulePage(cfg) {
  const form = document.getElementById('cipherForm');
  const textInput = document.getElementById('textInput');
  const keyInput = document.getElementById('keyInput');
  const textLabel = document.getElementById('textLabel');
  const textHint = document.getElementById('textHint');
  const keyHint = document.getElementById('keyHint');
  const modeBtns = document.querySelectorAll('.mode-btn');
  const resultEmpty = document.getElementById('resultEmpty');
  const resultBox = document.getElementById('resultBox');
  const resultLabel = document.getElementById('resultLabel');
  const resultBits = document.getElementById('resultBits');
  const resultHexWrap = document.getElementById('resultHexWrap');
  const formError = document.getElementById('formError');
  const toggleSolution = document.getElementById('toggleSolution');
  const solutionSteps = document.getElementById('solutionSteps');
  const resetBtn = document.getElementById('resetBtn');
  const exampleBtn = document.getElementById('exampleBtn');

  let mode = 'encrypt';
  let lastSteps = null;

  const unit = cfg.inputFormat === 'bin' ? 'bit' : 'digit hex';
  const textLen = cfg.inputFormat === 'bin' ? cfg.blockBits : cfg.blockBits / 4;
  const keyLen = cfg.inputFormat === 'bin' ? cfg.keyBits : cfg.keyBits / 4;
  textHint.textContent = `${textLen} ${unit} diperlukan`;
  keyHint.textContent = `${keyLen} ${unit} diperlukan`;

  function setMode(newMode) {
    mode = newMode;
    modeBtns.forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
    textLabel.textContent = (mode === 'encrypt' ? 'Plaintext' : 'Ciphertext') +
      ` (${cfg.blockBits}-bit, ${cfg.inputFormat === 'bin' ? 'biner' : 'hex'})`;
  }

  modeBtns.forEach(btn => {
    btn.addEventListener('click', () => setMode(btn.dataset.mode));
  });

  function resetForm() {
    textInput.value = '';
    keyInput.value = '';
    formError.hidden = true;
    resultBox.hidden = true;
    resultEmpty.hidden = false;
    toggleSolution.disabled = true;
    toggleSolution.textContent = 'Tampilkan Solusi Penyelesaian';
    solutionSteps.hidden = true;
    solutionSteps.innerHTML = '';
    lastSteps = null;
  }

  resetBtn.addEventListener('click', resetForm);

  exampleBtn.addEventListener('click', () => {
    textInput.value = cfg.exampleText;
    keyInput.value = cfg.exampleKey;
  });

  toggleSolution.addEventListener('click', () => {
    const showing = !solutionSteps.hidden;
    solutionSteps.hidden = showing;
    toggleSolution.textContent = showing ? 'Tampilkan Solusi Penyelesaian' : 'Sembunyikan Solusi Penyelesaian';
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    formError.hidden = true;

    const payload = {
      text: textInput.value.trim(),
      key: keyInput.value.trim(),
      mode: mode
    };

    const submitBtn = form.querySelector('.btn-primary');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Memproses...';

    try {
      const res = await fetch(cfg.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      if (!res.ok) {
        formError.textContent = data.error || 'Terjadi kesalahan.';
        formError.hidden = false;
        resultBox.hidden = true;
        resultEmpty.hidden = false;
        toggleSolution.disabled = true;
        return;
      }

      resultLabel.textContent = mode === 'encrypt' ? 'Ciphertext' : 'Plaintext';
      renderBitBoxes(resultBits, data.result, groupSizeFor(data.result));
      if (data.result_format === 'bin') {
        const hexVal = parseInt(data.result, 2).toString(16).toUpperCase().padStart(Math.ceil(data.result.length / 4), '0');
        resultHexWrap.textContent = 'Hex: ' + hexVal;
      } else {
        resultHexWrap.textContent = 'Biner: ' + parseInt(data.result, 16).toString(2).padStart(data.result.length * 4, '0');
      }

      resultEmpty.hidden = true;
      resultBox.hidden = false;

      lastSteps = data.steps;
      renderSteps(lastSteps, solutionSteps);
      toggleSolution.disabled = false;
      toggleSolution.textContent = 'Tampilkan Solusi Penyelesaian';
      solutionSteps.hidden = true;
    } catch (err) {
      formError.textContent = 'Gagal menghubungi server: ' + err.message;
      formError.hidden = false;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Submit';
    }
  });
}
