const FORMSPREE_URL = 'https://formspree.io/f/xzdwzzdo';

// Destaca opt-item ao selecionar
document.querySelectorAll('.opt-item input').forEach(inp => {
  inp.addEventListener('change', () => {
    if (inp.type === 'radio') {
      document.querySelectorAll(`input[name="${inp.name}"]`).forEach(r => {
        r.closest('.opt-item').classList.remove('checked');
      });
    }
    inp.closest('.opt-item').classList.toggle('checked', inp.checked);
  });
});

function mostrarConfirmacao(sucesso, data) {
  document.getElementById('form').style.display = 'none';
  document.getElementById('btn-submit').closest('.submit-area').style.display = 'none';
  const resBox = document.getElementById('resultado');
  resBox.style.display = 'block';
  resBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (sucesso) {
    document.getElementById('res-ok').style.display = 'block';
  } else {
    document.getElementById('res-erro').style.display = 'block';
    document.getElementById('json-out').textContent = JSON.stringify(data, null, 2);
  }
}

document.getElementById('form').addEventListener('submit', async e => {
  e.preventDefault();

  const data = {};
  const fd = new FormData(e.target);

  for (const [k, v] of fd.entries()) {
    if (data[k]) {
      data[k] = Array.isArray(data[k]) ? [...data[k], v] : [data[k], v];
    } else {
      data[k] = v;
    }
  }

  data._timestamp = new Date().toLocaleString('pt-BR');
  data._versao = 'avaliacao_autores_v1';

  const btn = document.getElementById('btn-submit');
  btn.disabled = true;
  btn.textContent = 'Enviando…';

  // Formspree free plan aceita apenas form-encoded (não JSON)
  const params = new URLSearchParams();
  const fd2 = new FormData(e.target);
  for (const [k, v] of fd2.entries()) params.append(k, v);
  params.append('_timestamp', data._timestamp);
  params.append('_versao', data._versao);

  try {
    const resp = await fetch(FORMSPREE_URL, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
      body: params,
    });
    mostrarConfirmacao(resp.ok, data);
  } catch (_) {
    mostrarConfirmacao(false, data);
  }
});

function copiarJSON() {
  const txt = document.getElementById('json-out').textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = event.target;
    btn.textContent = '✓ Copiado';
    setTimeout(() => btn.textContent = 'Copiar', 1800);
  });
}
