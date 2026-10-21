import { readFile } from 'node:fs/promises';

export async function createStorage(mode = process.env.STORAGE_MODE || 'postgres') {
  if (mode === 'memory') {
    const rows = new Map();
    let nextId = 1;
    return {
      mode,
      ready: async () => {},
      list: async () => [...rows.values()].sort((a, b) => b.id - a.id),
      create: async (title) => {
        const todo = { id: nextId++, title, completed: false, created_at: new Date().toISOString() };
        rows.set(todo.id, todo);
        return todo;
      },
      toggle: async (id, completed) => {
        const todo = rows.get(id);
        if (!todo) return null;
        todo.completed = completed;
        return todo;
      },
      remove: async (id) => rows.delete(id),
      close: async () => {},
    };
  }
  if (mode !== 'postgres') throw new Error('STORAGE_MODE must be memory or postgres.');
  const { default: pg } = await import('pg');
  const password = (await readFile(process.env.DB_PASSWORD_FILE || new URL('../../credential/postgres_password', import.meta.url), 'utf8')).trim();
  const pool = new pg.Pool({ password, max: 2, connectionTimeoutMillis: 3000, idleTimeoutMillis: 10000 });
  pool.on('error', () => console.error('Database connection interrupted.'));
  await pool.query(`CREATE TABLE IF NOT EXISTS todos (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title VARCHAR(200) NOT NULL CHECK (length(trim(title)) > 0),
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  return {
    mode,
    ready: () => pool.query('SELECT 1'),
    list: async () => (await pool.query('SELECT * FROM todos ORDER BY id DESC')).rows,
    create: async (title) => (await pool.query('INSERT INTO todos (title) VALUES ($1) RETURNING *', [title])).rows[0],
    toggle: async (id, completed) => (await pool.query('UPDATE todos SET completed = $1 WHERE id = $2 RETURNING *', [completed, id])).rows[0] || null,
    remove: async (id) => (await pool.query('DELETE FROM todos WHERE id = $1 RETURNING id', [id])).rowCount > 0,
    close: () => pool.end(),
  };
}
