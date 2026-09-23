-- sqlc queries (для будущей генерации; сейчас store/sqlite.go написан вручную)

-- name: GetSubmission :one
SELECT * FROM submissions WHERE id = ?;

-- name: ListSubmissions :many
SELECT * FROM submissions WHERE org_id = ? ORDER BY received_at DESC LIMIT ? OFFSET ?;

-- name: DeleteSubmission :exec
DELETE FROM submissions WHERE id = ?;
