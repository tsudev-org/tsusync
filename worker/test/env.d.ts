declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    FILES: R2Bucket;
    TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
    OIDC_ISSUER: string;
    NAMESPACES: string;
    QUOTAS?: string;
    GLOBAL_DATA_BUDGET_MIB: string;
    GLOBAL_FILE_BUDGET_MIB: string;
    WRITE_RATE_PER_MIN: string;
    PURGE_MODE?: string;
    RP_CLIENT_ID: string;
    ENTITLEMENTS_STATUS_URL: string;
    RP_PRIVATE_JWK?: string;
    SUB_ENC_KEY?: string;
    DPOP_REQUIRED?: string;
    MAINTENANCE_SAMPLE?: string;
  }
}
