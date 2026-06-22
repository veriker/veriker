-- =============================================================================
-- triggers_pack_rendered_expected.sql
-- Hand-rendered reference output for SQL trigger pack migrations 001-003.
--
-- Substitution parameters applied:
--   __TABLE__                  = vab_test_table
--   __ALLOWED_UPDATE_COLUMNS__ = single IF-block guarding column `id`
--                                (mutation allowlist = {status})
--   __TERMINAL_STATUS_VALUES__ = 'invalidated'
--   __SHA_COLUMN__             = spec_sha
--
-- For human inspection only (vab-005, AUDIT_BUNDLE_CONTRACT.md §C1-C3).
-- NOT auto-generated. NOT applied to any database.
-- =============================================================================


-- =============================================================================
-- [001] Append-only triple-trigger pack — vab_test_table
-- =============================================================================

CREATE OR REPLACE FUNCTION vab_test_table_block_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'P0001',
        MESSAGE = 'vab_test_table is append-only — DELETE is forbidden (AUDIT_BUNDLE_CONTRACT.md §C2).',
        DETAIL  = 'Use the sanctioned update path to transition the row to a terminal status. The original row must remain.',
        HINT    = 'If row erasure is required (e.g., GDPR right-to-erasure on a commercial-path record), do so via an explicitly-named superuser migration that documents the removal in LEDGER.md.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vab_test_table_no_delete ON vab_test_table;
CREATE TRIGGER vab_test_table_no_delete
    BEFORE DELETE ON vab_test_table
    FOR EACH ROW EXECUTE FUNCTION vab_test_table_block_delete();


CREATE OR REPLACE FUNCTION vab_test_table_block_truncate()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = 'P0001',
        MESSAGE = 'vab_test_table is append-only — TRUNCATE is forbidden (AUDIT_BUNDLE_CONTRACT.md §C2).';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vab_test_table_no_truncate ON vab_test_table;
CREATE TRIGGER vab_test_table_no_truncate
    BEFORE TRUNCATE ON vab_test_table
    FOR EACH STATEMENT EXECUTE FUNCTION vab_test_table_block_truncate();


CREATE OR REPLACE FUNCTION vab_test_table_restrict_update()
RETURNS TRIGGER AS $$
BEGIN

    -- (a) Column immutability — id is immutable; status is on the allowlist.
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'vab_test_table.id is immutable post-freeze (§C2).',
            DETAIL  = 'Column id is not in the mutation allowlist.';
    END IF;

    -- (b) Terminal-status lock.
    IF OLD.status IN ('invalidated') AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'vab_test_table.status is final once terminal — no transition out of ' || OLD.status || '.',
            DETAIL  = 'Once a row reaches a terminal status it is permanently frozen. Un-invalidation is forbidden (§C2).';
    END IF;

    IF OLD.status IN ('invalidated') AND NEW.invalidated_reason IS DISTINCT FROM OLD.invalidated_reason THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'vab_test_table.invalidated_reason is immutable once status is terminal.',
            DETAIL  = 'The terminal-state record is final; invalidated_reason cannot be amended post-terminal.';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vab_test_table_immutable_columns ON vab_test_table;
CREATE TRIGGER vab_test_table_immutable_columns
    BEFORE UPDATE ON vab_test_table
    FOR EACH ROW EXECUTE FUNCTION vab_test_table_restrict_update();


-- =============================================================================
-- [002] Verify-triggers RPC — vab_test_table
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_vab_test_table_triggers()
RETURNS TABLE (trigger_name TEXT, present BOOLEAN)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.expected_name::TEXT,
        EXISTS (
            SELECT 1
            FROM pg_trigger pt
            WHERE pt.tgrelid = 'vab_test_table'::regclass
              AND pt.tgname = t.expected_name
              AND NOT pt.tgisinternal
        ) AS present
    FROM (VALUES
        ('vab_test_table_no_delete'),
        ('vab_test_table_no_truncate'),
        ('vab_test_table_immutable_columns')
    ) AS t(expected_name);
END;
$$;

GRANT EXECUTE ON FUNCTION verify_vab_test_table_triggers() TO anon;
GRANT EXECUTE ON FUNCTION verify_vab_test_table_triggers() TO authenticated;


-- =============================================================================
-- [003] Spec-SHA stamp immutability — vab_test_table / spec_sha
-- =============================================================================

CREATE OR REPLACE FUNCTION vab_test_table_spec_sha_immutable_post_stamp()
RETURNS TRIGGER AS $$
BEGIN
    -- Once spec_sha is stamped (non-NULL), the digest is immutable.
    IF OLD.spec_sha IS NOT NULL
       AND NEW.spec_sha IS DISTINCT FROM OLD.spec_sha THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'vab_test_table.spec_sha is immutable once stamped (AUDIT_BUNDLE_CONTRACT.md §C1).',
            DETAIL  = 'Allowed transition: NULL → non-NULL (first stamp). '
                      'Forbidden: any mutation after the initial stamp. '
                      'Current stamped value must not change.',
            HINT    = 'If the spec document changed, create a new row rather '
                      'than mutating the existing stamp.';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vab_test_table_spec_sha_immutable_post_stamp ON vab_test_table;
CREATE TRIGGER vab_test_table_spec_sha_immutable_post_stamp
    BEFORE UPDATE ON vab_test_table
    FOR EACH ROW EXECUTE FUNCTION vab_test_table_spec_sha_immutable_post_stamp();
