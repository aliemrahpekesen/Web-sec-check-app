-- Persist the coverage report on the scan so a reloaded completed scan keeps
-- its "X checks ran, Y passed" trust signal (previously only carried by the
-- live "done" SSE event and lost on refresh).
ALTER TABLE "Scan" ADD COLUMN "coverage" JSONB;
