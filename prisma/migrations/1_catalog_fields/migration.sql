-- Catalog engine: add category + references to findings.
ALTER TABLE "Finding" ADD COLUMN "category" TEXT;
ALTER TABLE "Finding" ADD COLUMN "references" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE INDEX "Finding_category_idx" ON "Finding"("category");
