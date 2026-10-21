const list = document.querySelector('#todos');
const message = document.querySelector('#message');
const retry = document.querySelector('#retry');
let todos = [];
let filter = 'all';

async function api(path = '', options = {}) {
  const response = await fetch(`/api/todos${path}`, {
    ...options, headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Terjadi kesalahan.');
  return data;
}
function error(err) { message.textContent = err.message; retry.hidden = false; }
function render() {
  list.replaceChildren();
  const shown = todos.filter(t => filter === 'all' || (filter === 'completed' ? t.completed : !t.completed));
  document.querySelector('#count').textContent = `${todos.filter(t => !t.completed).length} belum selesai`;
  document.querySelector('#empty').hidden = shown.length > 0;
  for (const todo of shown) {
    const item = document.createElement('li');
    item.classList.toggle('done', todo.completed);
    const label = document.createElement('label');
    const check = document.createElement('input');
    check.type = 'checkbox'; check.checked = todo.completed;
    const text = document.createElement('span'); text.textContent = todo.title;
    check.addEventListener('change', async () => {
      check.disabled = true;
      try { await api(`/${todo.id}`, { method: 'PATCH', body: JSON.stringify({ completed: check.checked }) }); await load(); }
      catch (err) { check.checked = todo.completed; error(err); }
      finally { check.disabled = false; }
    });
    const remove = document.createElement('button');
    remove.className = 'delete'; remove.textContent = 'Hapus';
    remove.setAttribute('aria-label', `Hapus tugas ${todo.title}`);
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try { await api(`/${todo.id}`, { method: 'DELETE' }); await load(); }
      catch (err) { error(err); }
      finally { remove.disabled = false; }
    });
    label.append(check, text); item.append(label, remove); list.append(item);
  }
}
async function load() {
  try { todos = await api(); message.textContent = ''; retry.hidden = true; render(); }
  catch (err) { error(err); }
}
document.querySelector('#todo-form').addEventListener('submit', async event => {
  event.preventDefault();
  const input = document.querySelector('#title');
  const button = document.querySelector('#add-button');
  if (!input.value.trim()) { input.focus(); return; }
  button.disabled = true;
  try { await api('', { method: 'POST', body: JSON.stringify({ title: input.value }) }); input.value = ''; await load(); input.focus(); }
  catch (err) { error(err); }
  finally { button.disabled = false; }
});
document.querySelectorAll('.filter').forEach(button => button.addEventListener('click', () => {
  filter = button.dataset.filter;
  document.querySelectorAll('.filter').forEach(b => { const active = b === button; b.classList.toggle('active', active); b.setAttribute('aria-pressed', String(active)); });
  render();
}));
retry.addEventListener('click', load);
load();
