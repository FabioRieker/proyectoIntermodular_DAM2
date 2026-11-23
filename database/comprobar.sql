-- En una base inicializada: psql -X -v ON_ERROR_STOP=1 -d <base> -f database/comprobar.sql
BEGIN;

DO $prueba$
DECLARE
    analista bigint;
BEGIN
    IF (SELECT array_agg(code ORDER BY code) FROM roles)
        IS DISTINCT FROM ARRAY['ADMIN', 'ANALYST', 'VIEWER']::varchar[] THEN
        RAISE EXCEPTION 'Se esperaban los roles ADMIN, ANALYST y VIEWER';
    END IF;
    RAISE NOTICE 'OK: roles ADMIN, ANALYST y VIEWER';

    SELECT id INTO STRICT analista FROM users WHERE email = 'analyst@vulnfollowup.local';

    -- Identificadores explícitos para que la prueba tampoco avance las secuencias.
    INSERT INTO assets (id, code, name, type, owner_id, environment) VALUES
        (-1, 'TEST-SQL-A1', 'Activo de prueba 1', 'API', analista, 'PRUEBAS'),
        (-2, 'TEST-SQL-A2', 'Activo de prueba 2', 'API', analista, 'PRUEBAS');
    INSERT INTO vulnerabilities (id, identifier, title, description, detected_on)
        VALUES (-1, 'TEST-SQL-V1', 'Caso de prueba', 'Entrada sintética', CURRENT_DATE);
    INSERT INTO vulnerability_assets (vulnerability_id, asset_id) VALUES (-1, -1), (-1, -2);

    IF (SELECT count(*) FROM vulnerability_assets WHERE vulnerability_id = -1) <> 2 THEN
        RAISE EXCEPTION 'Se esperaban dos activos enlazados al caso';
    END IF;
    RAISE NOTICE 'OK: un caso enlazado a dos activos';

    BEGIN
        INSERT INTO vulnerability_assets (vulnerability_id, asset_id) VALUES (-1, -1);
        RAISE EXCEPTION 'Se aceptó un enlace duplicado';
    EXCEPTION WHEN unique_violation THEN
        RAISE NOTICE 'OK: enlace duplicado rechazado (SQLSTATE %)', SQLSTATE;
    END;

    BEGIN
        INSERT INTO vulnerability_assets (vulnerability_id, asset_id) VALUES (-1, -3);
        RAISE EXCEPTION 'Se aceptó un enlace a un activo inexistente';
    EXCEPTION WHEN foreign_key_violation THEN
        RAISE NOTICE 'OK: activo inexistente rechazado (SQLSTATE %)', SQLSTATE;
    END;
END;
$prueba$;

ROLLBACK;
