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
    PURGE_ENABLED: string;
    MAINTENANCE_SAMPLE?: string;
  }
}
