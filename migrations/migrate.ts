import 'dotenv/config';
import pg from 'pg';
import { initSchema, getDatabaseStatusInfo, getCleanDatabaseUrl, REQUIRED_TABLES } from '../src/db.js';

const { Pool } = pg;

function createDirectPool(): pg.Pool {
  const rawUrl = process.env.DATABASE_URL || '';
  const cleanUrl = getCleanDatabaseUrl();
  if (!cleanUrl) throw new Error('DATABASE_URL not configured');
  return new Pool({ connectionString: cleanUrl });
}

async function verifyRequiredTables(pool: pg.Pool): Promise<{ ok: boolean; found: number; missing: string[] }> {
  const res = await pool.query(
    `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`
  );
  const existing = new Set(res.rows.map((r: any) => String(r.table_name)));
  const tables = REQUIRED_TABLES as readonly string[];
  const missing = tables.filter((t) => !existing.has(t));
  return { ok: missing.length === 0, found: tables.length - missing.length, missing };
}

async function runMigration() {
  console.log('============================================================');
  console.log('FONER — POSTGRESQL SCHEMA MIGRATION & SEEDING');
  console.log('============================================================');

  const dbUrl = getCleanDatabaseUrl();
  if (!dbUrl || (!dbUrl.startsWith('postgres://') && !dbUrl.startsWith('postgresql://'))) {
    console.error('ERROR: DATABASE_URL is missing or invalid. Cannot initialize Foner database.');
    process.exit(1);
  }

  const meta = { databaseName: 'f', user: 'f_user', host: '127.0.0.1', port: 5432 };

  try {
    const status = await initSchema();
    const info = await getDatabaseStatusInfo();

    const directPool = createDirectPool();
    const verify = await verifyRequiredTables(directPool);
    await directPool.end();

    console.log(`DATABASE: ${meta.databaseName || 'f'}`);
    console.log(`USER: ${meta.user || 'f_user'}`);
    console.log(`ENGINE: PostgreSQL`);
    console.log(`SCHEMA: public`);
    console.log(`REQUIRED TABLES: ${verify.found}/${REQUIRED_TABLES.length}`);
    if (verify.missing.length > 0) {
      console.error('MISSING TABLES:', verify.missing.join(', '));
      process.exit(1);
    }
    console.log(`STATUS: SUCCESS`);

    if (!info.connected) {
      console.error('ERROR: Post-migration health check reports database disconnected.');
      process.exit(1);
    }

    console.log('Migration and initial seeding completed successfully.');
    process.exit(0);
  } catch (err: any) {
    console.error('Migration failed:', err?.message || err);
    process.exit(1);
  }
}

runMigration();
