const FORMSPREE_URL = 'https://formspree.io/f/xzdwzzdo';

// Calcula caminho do index.html a partir de qualquer contexto
function indexUrl() {
  const loc = window.location;
  if (loc.protocol === 'file:') {
    // file:// — sobe um nível a partir de client/
    return loc.href.replace(/\/client\/[^/]+$/, '/index.html');
  }
  // HTTP/HTTPS — ../index.html relativo ao diretório atual
  return '../index.html';
}

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

document.getElementById('form').addEventListener('submit', async e => {
  e.preventDefault();

  const btn = document.getElementById('btn-submit');
  btn.disabled    = true;
  btn.textContent = 'Enviando…';

  // Coleta dados do formulário
  const data    = {};
  const fd      = new FormData(e.target);
  const params  = new URLSearchParams();

  for (const [k, v] of fd.entries()) {
    params.append(k, v);
    if (data[k]) {
      data[k] = Array.isArray(data[k]) ? [...data[k], v] : [data[k], v];
    } else {
      data[k] = v;
    }
  }

  data._timestamp = new Date().toLocaleString('pt-BR');
  data._versao    = 'avaliacao_autores_v1';
  params.append('_timestamp', data._timestamp);
  params.append('_versao',    data._versao);

  try {
    const resp = await fetch(FORMSPREE_URL, {
      method:  'POST',
      headers: { 'Accept': 'application/json' },
      body:    params,
    });

    // Lê o corpo independente do status
    const json = await resp.json().catch(() => ({}));
    const ok   = resp.ok && json.ok !== false;

    if (ok) {
      window.location.replace(indexUrl());
    } else {
      mostrarErro(json.error || `Erro ${resp.status}`, data);
    }

  } catch (err) {
    mostrarErro(err.message || 'Falha de rede', data);
  }
});

function mostrarErro(mensagem, data) {
  document.getElementById('form').style.display = 'none';
  document.getElementById('btn-submit').closest('.submit-area').style.display = 'none';

  const resBox = document.getElementById('resultado');
  resBox.style.display = 'block';
  resBox.scrollIntoView({ behavior: 'smooth', block: 'start' });

  document.getElementById('res-erro').style.display = 'block';
  document.getElementById('res-erro-msg').textContent = mensagem;
  document.getElementById('json-out').textContent = JSON.stringify(data, null, 2);
}

function copiarJSON() {
  const txt = document.getElementById('json-out').textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = event.target;
    btn.textContent = '✓ Copiado';
    setTimeout(() => btn.textContent = 'Copiar', 1800);
  });
}
