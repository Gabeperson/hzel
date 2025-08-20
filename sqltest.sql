WITH ins AS (
  INSERT INTO items (id, owner_id, parent_id, path, type, created_at, transaction_id)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT (owner_id, path) DO NOTHING
  RETURNING id
)
SELECT id FROM ins
UNION ALL
SELECT id FROM items WHERE owner_id = ? AND path = ?
LIMIT 1;

