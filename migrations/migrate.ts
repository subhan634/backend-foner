import 'dotenv/config';
import { initSchema, getDatabaseStatusInfo } from '../src/db.js';

async function runMigration() {
  console.log('============================================================');
  console.log('FONER — POSTGRESQL SCHEMA MIGRATION & SEEDING');
  console.log('============================================================');

  const status = await initSchema();
  const info = await getDatabaseStatusInfo();

  console.log(`Engine:         ${status.engine}`);
  console.log(`Connected:      ${info.connected ? 'YES (Live PostgreSQL)' : 'NO'}`);
  console.log('============================================================');

  if (!info.connected) {
    console.error(
      'ERROR: Could not connect to PostgreSQL. Verify DATABASE_URL is configured and PostgreSQL is running.'
    );
    process.exit(1);
  }

  console.log('Migration and initial seeding completed.');
  process.exit(0);
}

runMigration().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
