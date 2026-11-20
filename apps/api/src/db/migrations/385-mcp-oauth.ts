import type { Kysely } from "kysely";
import { sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await sql`
    DO $mcp$ BEGIN
      CREATE TABLE jwks (
        id text PRIMARY KEY,
        public_key text NOT NULL,
        private_key text NOT NULL,
        created_at timestamptz NOT NULL,
        expires_at timestamptz,
        alg text,
        crv text
      );

      CREATE TABLE oauth_clients (
        id text PRIMARY KEY,
        client_id text NOT NULL UNIQUE,
        client_secret text,
        client_discovery_id text,
        disabled boolean,
        skip_consent boolean,
        enable_end_session boolean,
        subject_type text,
        scopes jsonb CHECK (jsonb_typeof(scopes) = 'array'),
        client_credentials_scopes jsonb CHECK (jsonb_typeof(client_credentials_scopes) = 'array'),
        user_id text REFERENCES users(id) ON DELETE CASCADE,
        created_at timestamptz,
        updated_at timestamptz,
        name text,
        uri text,
        icon text,
        contacts jsonb CHECK (jsonb_typeof(contacts) = 'array'),
        tos text,
        policy text,
        software_id text,
        software_version text,
        software_statement text,
        redirect_uris jsonb NOT NULL CHECK (jsonb_typeof(redirect_uris) = 'array'),
        post_logout_redirect_uris jsonb CHECK (jsonb_typeof(post_logout_redirect_uris) = 'array'),
        backchannel_logout_uri text,
        backchannel_logout_session_required boolean,
        token_endpoint_auth_method text,
        application_type text,
        jwks text,
        jwks_uri text,
        grant_types jsonb CHECK (jsonb_typeof(grant_types) = 'array'),
        response_types jsonb CHECK (jsonb_typeof(response_types) = 'array'),
        require_pkce boolean,
        dpop_bound_access_tokens boolean,
        reference_id text,
        metadata jsonb CHECK (jsonb_typeof(metadata) = 'object')
      );

      CREATE TABLE oauth_resources (
        id text PRIMARY KEY,
        identifier text NOT NULL UNIQUE,
        name text NOT NULL,
        access_token_ttl integer,
        refresh_token_ttl integer,
        signing_algorithm text,
        signing_key_id text,
        allowed_scopes jsonb CHECK (jsonb_typeof(allowed_scopes) = 'array'),
        custom_claims jsonb CHECK (jsonb_typeof(custom_claims) = 'object'),
        dpop_bound_access_tokens_required boolean,
        disabled boolean,
        created_at timestamptz,
        updated_at timestamptz,
        policy_version integer,
        metadata jsonb CHECK (jsonb_typeof(metadata) = 'object')
      );

      CREATE TABLE oauth_client_resources (
        id text PRIMARY KEY,
        client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
        resource_id text NOT NULL REFERENCES oauth_resources(identifier) ON DELETE CASCADE,
        metadata jsonb CHECK (jsonb_typeof(metadata) = 'object'),
        created_at timestamptz,
        UNIQUE (client_id, resource_id)
      );

      CREATE TABLE oauth_refresh_tokens (
        id text PRIMARY KEY,
        token text NOT NULL UNIQUE,
        client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
        session_id text REFERENCES sessions(id) ON DELETE SET NULL,
        user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reference_id text,
        authorization_code_id text,
        resources jsonb CHECK (jsonb_typeof(resources) = 'array'),
        requested_user_info_claims jsonb CHECK (jsonb_typeof(requested_user_info_claims) = 'array'),
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL,
        revoked timestamptz,
        rotated_at timestamptz,
        rotation_replay_response text,
        rotation_replay_expires_at timestamptz,
        auth_time timestamptz,
        confirmation jsonb CHECK (jsonb_typeof(confirmation) = 'object'),
        scopes jsonb NOT NULL CHECK (jsonb_typeof(scopes) = 'array')
      );

      CREATE TABLE oauth_access_tokens (
        id text PRIMARY KEY,
        token text NOT NULL UNIQUE,
        client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
        session_id text REFERENCES sessions(id) ON DELETE SET NULL,
        user_id text REFERENCES users(id) ON DELETE CASCADE,
        reference_id text,
        authorization_code_id text,
        resources jsonb CHECK (jsonb_typeof(resources) = 'array'),
        requested_user_info_claims jsonb CHECK (jsonb_typeof(requested_user_info_claims) = 'array'),
        refresh_id text REFERENCES oauth_refresh_tokens(id) ON DELETE CASCADE,
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL,
        revoked timestamptz,
        confirmation jsonb CHECK (jsonb_typeof(confirmation) = 'object'),
        scopes jsonb NOT NULL CHECK (jsonb_typeof(scopes) = 'array')
      );

      CREATE TABLE oauth_consents (
        id text PRIMARY KEY,
        client_id text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
        user_id text REFERENCES users(id) ON DELETE CASCADE,
        reference_id text,
        resources jsonb CHECK (jsonb_typeof(resources) = 'array'),
        requested_user_info_claims jsonb CHECK (jsonb_typeof(requested_user_info_claims) = 'array'),
        scopes jsonb NOT NULL CHECK (jsonb_typeof(scopes) = 'array'),
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
      );

      CREATE TABLE oauth_client_assertions (
        id text PRIMARY KEY,
        expires_at timestamptz NOT NULL
      );

      -- Better Auth's Kysely adapter pre-serializes arrays for PostgreSQL.
      -- postgres.js serializes them again when binding to a JSONB column.
      CREATE FUNCTION decode_oauth_json_arrays() RETURNS trigger LANGUAGE plpgsql AS $decode$
      DECLARE
        row_data jsonb := to_jsonb(NEW);
        column_name text;
      BEGIN
        FOREACH column_name IN ARRAY TG_ARGV LOOP
          IF jsonb_typeof(row_data -> column_name) = 'string' THEN
            row_data := jsonb_set(row_data, ARRAY[column_name], (row_data ->> column_name)::jsonb);
          END IF;
        END LOOP;
        RETURN jsonb_populate_record(NEW, row_data);
      END;
      $decode$;

      CREATE TRIGGER trg_oauth_clients_decode_arrays BEFORE INSERT OR UPDATE ON oauth_clients
        FOR EACH ROW EXECUTE FUNCTION decode_oauth_json_arrays(
          'scopes', 'client_credentials_scopes', 'contacts', 'redirect_uris',
          'post_logout_redirect_uris', 'grant_types', 'response_types'
        );
      CREATE TRIGGER trg_oauth_resources_decode_arrays BEFORE INSERT OR UPDATE ON oauth_resources
        FOR EACH ROW EXECUTE FUNCTION decode_oauth_json_arrays('allowed_scopes');
      CREATE TRIGGER trg_oauth_refresh_tokens_decode_arrays
        BEFORE INSERT OR UPDATE ON oauth_refresh_tokens FOR EACH ROW
        EXECUTE FUNCTION decode_oauth_json_arrays('resources', 'requested_user_info_claims', 'scopes');
      CREATE TRIGGER trg_oauth_access_tokens_decode_arrays
        BEFORE INSERT OR UPDATE ON oauth_access_tokens FOR EACH ROW
        EXECUTE FUNCTION decode_oauth_json_arrays('resources', 'requested_user_info_claims', 'scopes');
      CREATE TRIGGER trg_oauth_consents_decode_arrays BEFORE INSERT OR UPDATE ON oauth_consents
        FOR EACH ROW
        EXECUTE FUNCTION decode_oauth_json_arrays('resources', 'requested_user_info_claims', 'scopes');

      CREATE INDEX idx_oauth_client_user_id ON oauth_clients (user_id);
      CREATE INDEX idx_oauth_client_resource_resource_id ON oauth_client_resources (resource_id);
      CREATE INDEX idx_oauth_refresh_token_client_id ON oauth_refresh_tokens (client_id);
      CREATE INDEX idx_oauth_refresh_token_session_id ON oauth_refresh_tokens (session_id);
      CREATE INDEX idx_oauth_refresh_token_user_id ON oauth_refresh_tokens (user_id);
      CREATE INDEX idx_oauth_refresh_token_authorization_code_id ON oauth_refresh_tokens (authorization_code_id);
      CREATE INDEX idx_oauth_access_token_client_id ON oauth_access_tokens (client_id);
      CREATE INDEX idx_oauth_access_token_session_id ON oauth_access_tokens (session_id);
      CREATE INDEX idx_oauth_access_token_user_id ON oauth_access_tokens (user_id);
      CREATE INDEX idx_oauth_access_token_authorization_code_id ON oauth_access_tokens (authorization_code_id);
      CREATE INDEX idx_oauth_access_token_refresh_id ON oauth_access_tokens (refresh_id);
      CREATE INDEX idx_oauth_consent_client_id ON oauth_consents (client_id);
      CREATE INDEX idx_oauth_consent_user_id ON oauth_consents (user_id);
    END $mcp$
  `.execute(db);
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await sql`
    DROP TABLE
      oauth_client_assertions, oauth_consents, oauth_access_tokens, oauth_refresh_tokens,
      oauth_client_resources, oauth_resources, oauth_clients, jwks
  `.execute(db);
  await sql`DROP FUNCTION decode_oauth_json_arrays()`.execute(db);
}
