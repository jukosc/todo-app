import assert from 'node:assert/strict';
const base = process.env.TEST_URL || 'http://127.0.0.1:8080';
async function request(path, method = 'GET', data) {
  const response = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json' }, body: data === undefined ? undefined : JSON.stringify(data) });
  return { status: response.status, data: await response.json() };
}
assert.equal((await fetch(base)).status, 200);
assert.equal((await request('/healthz')).status, 200);
assert.equal((await request('/readyz')).status, 200);
assert.equal((await request('/api/todos', 'POST', { title: '   ' })).status, 400);
assert.equal((await request('/api/todos', 'POST', { title: 'x'.repeat(201) })).status, 400);
const created = await request('/api/todos', 'POST', { title: "Training ' <script>alert(1)</script>" });
assert.equal(created.status, 201);
const id = created.data.id;
try {
  assert.equal(created.data.completed, false);
  assert.ok((await request('/api/todos')).data.some(t => t.id === id));
  assert.equal((await request(`/api/todos/${id}`, 'PATCH', { completed: 'true' })).status, 400);
  const updated = await request(`/api/todos/${id}`, 'PATCH', { completed: true });
  assert.equal(updated.status, 200);
  assert.equal(updated.data.completed, true);
  assert.equal((await request('/api/todos')).data.find(t => t.id === id).completed, true);
} finally {
  assert.equal((await request(`/api/todos/${id}`, 'DELETE')).status, 200);
}
assert.equal((await request(`/api/todos/${id}`, 'DELETE')).status, 404);
assert.equal((await request('/api/todos/999999999999', 'DELETE')).status, 400);
console.log('PASS: UI response, health, CRUD, validation, and visible updates.');
