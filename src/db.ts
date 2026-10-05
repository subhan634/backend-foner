import pg from 'pg';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

const BCRYPT_COST = Math.max(
  10,
  Math.min(14, parseInt(process.env.BCRYPT_COST || '12', 10) || 12)
);

export function isBcryptHash(hash: string): boolean {
  return /^\$2[aby]\$\d{2}\$.{53}$/.test(String(hash || ''));
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(String(password), BCRYPT_COST);
}

export async function hashPasswordAsync(password: string): Promise<string> {
  return bcrypt.hash(String(password), BCRYPT_COST);
}

function computeLegacySha256Hash(password: string): string {
  return crypto.createHash('sha256').update(`foner_salt_v1:${password}`).digest('hex');
}

/**
 * Verifies a password against a stored hash using bcrypt.
 * Never accepts plaintext passwords.
 * If the stored hash is a legacy salted SHA-256 hash and matches, returns needsMigration=true
 * so the caller can immediately upgrade the user record in PostgreSQL to bcrypt.
 */
export async function verifyPasswordWithMigration(
  rawPassword: string,
  storedHash: string
): Promise<{ valid: boolean; needsMigration: boolean; needsRehash: boolean }> {
  const cleanHash = String(storedHash || '').trim();
  if (!rawPassword || !cleanHash) {
    return { valid: false, needsMigration: false, needsRehash: false };
  }

  if (isBcryptHash(cleanHash)) {
    const valid = await bcrypt.compare(rawPassword, cleanHash);
    return { valid, needsMigration: false, needsRehash: false };
  }

  // Legacy salted SHA-256 migration path (never accepts raw plaintext)
  if (/^[a-f0-9]{64}$/i.test(cleanHash)) {
    const expectedLegacy = computeLegacySha256Hash(rawPassword);
    const a = Buffer.from(expectedLegacy, 'utf8');
    const b = Buffer.from(cleanHash.toLowerCase(), 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { valid: true, needsMigration: true, needsRehash: true };
    }
    return { valid: false, needsMigration: false, needsRehash: false };
  }

  // Any non-bcrypt, non-salted-hash value (e.g. plaintext) is rejected
  return { valid: false, needsMigration: false, needsRehash: false };
}

export const verifyPassword = verifyPasswordWithMigration;

export function hashOtpValue(
  email: string,
  otp: string,
  purpose: string = 'registration'
): string {
  const secret =
    process.env.SESSION_SECRET ||
    '9f8d7e6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e';
  return crypto
    .createHmac('sha256', secret)
    .update(`${purpose}:${String(email || '').trim().toLowerCase()}:${String(otp || '').trim()}`)
    .digest('hex');
}

export const hashOtpCode = hashOtpValue;

export function verifyOtpHash(
  email: string,
  otp: string,
  storedHash: string,
  purpose: string = 'registration'
): boolean {
  const cleanStored = String(storedHash || '').trim().toLowerCase();
  if (!cleanStored || !/^[a-f0-9]{64}$/.test(cleanStored)) return false;
  const computed = hashOtpValue(email, otp, purpose).toLowerCase();
  const a = Buffer.from(computed, 'utf8');
  const b = Buffer.from(cleanStored, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export const verifyOtpCode = verifyOtpHash;

export function hashSessionToken(rawToken: string): string {
  return crypto.createHash('sha256').update(`foner_sess_v2:${String(rawToken || '').trim()}`).digest('hex');
}

export const FONER_POSTGRES_SCHEMA_SQL = `
-- ============================================================================
-- FONER — PRODUCTION POSTGRESQL DATABASE SCHEMA
-- Target: GHSOY-SERVER | Database: f | User: f_user
-- ============================================================================

CREATE TABLE IF NOT EXISTS store_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  city TEXT DEFAULT 'Lahore',
  address TEXT DEFAULT '',
  postal_code TEXT DEFAULT '',
  role TEXT NOT NULL DEFAULT 'customer',
  status TEXT NOT NULL DEFAULT 'active',
  avatar_url TEXT DEFAULT '',
  total_orders INTEGER NOT NULL DEFAULT 0,
  total_spent_pkr INTEGER NOT NULL DEFAULT 0,
  loyalty_points INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS postal_code TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS loyalty_points INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS user_sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  session_scope TEXT NOT NULL DEFAULT 'customer',
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS uploaded_media (
  id SERIAL PRIMARY KEY,
  filename TEXT UNIQUE NOT NULL,
  mime_type TEXT NOT NULL,
  data_url TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS categories (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  image_url TEXT NOT NULL,
  featured BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subcategories (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  parent_category_slug TEXT NOT NULL,
  description TEXT DEFAULT '',
  image_url TEXT NOT NULL,
  featured BOOLEAN NOT NULL DEFAULT true,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS banners (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  subtitle TEXT NOT NULL,
  badge_text TEXT DEFAULT 'NEW SEASON',
  cta_text TEXT DEFAULT 'Shop Collection',
  cta_link TEXT DEFAULT 'all',
  desktop_image_url TEXT NOT NULL,
  mobile_image_url TEXT NOT NULL,
  device_target TEXT NOT NULL DEFAULT 'both',
  theme_style TEXT NOT NULL DEFAULT 'burgundy-gold',
  overlay_opacity INTEGER NOT NULL DEFAULT 42,
  sort_order INTEGER NOT NULL DEFAULT 1,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  sku TEXT NOT NULL,
  category_slug TEXT NOT NULL,
  subcategory_slug TEXT DEFAULT '',
  price_pkr INTEGER NOT NULL,
  compare_at_price_pkr INTEGER,
  description TEXT NOT NULL,
  fabric_care TEXT DEFAULT '',
  image_url TEXT NOT NULL,
  gallery_urls JSONB NOT NULL DEFAULT '[]'::jsonb,
  sizes JSONB NOT NULL DEFAULT '["S","M","L","XL"]'::jsonb,
  colors JSONB NOT NULL DEFAULT '[]'::jsonb,
  variants JSONB NOT NULL DEFAULT '[]'::jsonb,
  seo_title TEXT DEFAULT '',
  meta_description TEXT DEFAULT '',
  stock INTEGER NOT NULL DEFAULT 25,
  is_featured BOOLEAN NOT NULL DEFAULT false,
  is_new_arrival BOOLEAN NOT NULL DEFAULT false,
  is_bestseller BOOLEAN NOT NULL DEFAULT false,
  rating NUMERIC(3,2) NOT NULL DEFAULT 4.90,
  reviews_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE products ADD COLUMN IF NOT EXISTS subcategory_slug TEXT DEFAULT '';
ALTER TABLE products ADD COLUMN IF NOT EXISTS variants JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE products ADD COLUMN IF NOT EXISTS seo_title TEXT DEFAULT '';
ALTER TABLE products ADD COLUMN IF NOT EXISTS meta_description TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS restock_notifications (
  id SERIAL PRIMARY KEY,
  product_id INTEGER NOT NULL,
  product_title TEXT NOT NULL,
  product_sku TEXT DEFAULT '',
  customer_email TEXT NOT NULL,
  preferred_size TEXT DEFAULT '',
  preferred_color TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  notified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupons (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  discount_type TEXT NOT NULL DEFAULT 'percentage',
  discount_value INTEGER NOT NULL,
  min_order_pkr INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT true,
  usage_limit INTEGER DEFAULT NULL,
  per_customer_limit INTEGER DEFAULT NULL,
  usage_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE coupons ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS usage_limit INTEGER DEFAULT NULL;
ALTER TABLE coupons ADD COLUMN IF NOT EXISTS per_customer_limit INTEGER DEFAULT NULL;

CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  order_number TEXT UNIQUE NOT NULL,
  user_id INTEGER,
  customer_name TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  shipping_address TEXT NOT NULL,
  shipping_city TEXT NOT NULL,
  shipping_area TEXT DEFAULT '',
  postal_code TEXT DEFAULT '',
  order_notes TEXT DEFAULT '',
  payment_method TEXT NOT NULL DEFAULT 'COD',
  payment_status TEXT NOT NULL DEFAULT 'pending',
  order_status TEXT NOT NULL DEFAULT 'pending',
  subtotal_pkr INTEGER NOT NULL,
  discount_pkr INTEGER NOT NULL DEFAULT 0,
  coupon_code TEXT,
  delivery_fee_pkr INTEGER NOT NULL DEFAULT 300,
  total_pkr INTEGER NOT NULL,
  idempotency_key TEXT UNIQUE,
  confirmation_email_sent BOOLEAN NOT NULL DEFAULT false,
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_area TEXT DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS confirmation_email_sent BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS reviews (
  id SERIAL PRIMARY KEY,
  product_id INTEGER NOT NULL,
  customer_name TEXT NOT NULL,
  customer_city TEXT DEFAULT 'Lahore',
  rating INTEGER NOT NULL DEFAULT 5,
  comment TEXT NOT NULL,
  verified_purchase BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  details TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  city TEXT DEFAULT 'Lahore',
  status TEXT NOT NULL DEFAULT 'subscribed',
  unsubscribe_token_hash TEXT DEFAULT '',
  welcome_email_sent BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE newsletter_subscribers ADD COLUMN IF NOT EXISTS city TEXT DEFAULT 'Lahore';
ALTER TABLE newsletter_subscribers ADD COLUMN IF NOT EXISTS unsubscribe_token_hash TEXT DEFAULT '';
ALTER TABLE newsletter_subscribers ADD COLUMN IF NOT EXISTS welcome_email_sent BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS contact_messages (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT DEFAULT '',
  subject TEXT DEFAULT '',
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unread',
  email_sent BOOLEAN NOT NULL DEFAULT false,
  email_error TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS email_sent BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS email_error TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS registration_otps (
  email TEXT PRIMARY KEY,
  otp_code TEXT NOT NULL DEFAULT 'HASHED',
  otp_hash TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  attempts INTEGER NOT NULL DEFAULT 0,
  request_count INTEGER NOT NULL DEFAULT 1,
  last_requested_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE registration_otps ADD COLUMN IF NOT EXISTS otp_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE registration_otps ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registration_otps ADD COLUMN IF NOT EXISTS request_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE registration_otps ADD COLUMN IF NOT EXISTS last_requested_at TIMESTAMPTZ DEFAULT NOW();

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  email TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used BOOLEAN NOT NULL DEFAULT false,
  request_count INTEGER NOT NULL DEFAULT 1,
  last_requested_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_category_slug ON products(category_slug);
CREATE INDEX IF NOT EXISTS idx_products_subcategory_slug ON products(subcategory_slug);
CREATE INDEX IF NOT EXISTS idx_restock_product_id ON restock_notifications(product_id);
CREATE INDEX IF NOT EXISTS idx_orders_order_number ON orders(order_number);
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_product_id ON reviews(product_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);
`;

export const REQUIRED_TABLES = [
  'store_settings',
  'users',
  'user_sessions',
  'registration_otps',
  'password_reset_tokens',
  'uploaded_media',
  'contact_messages',
  'newsletter_subscribers',
  'categories',
  'subcategories',
  'banners',
  'products',
  'restock_notifications',
  'coupons',
  'orders',
  'reviews',
  'audit_logs',
] as const;

export interface QueryResult<T = any> {
  rows: T[];
  rowCount?: number | null;
}

export const DEFAULT_FAQ_LIST = [
  {
    id: 'faq-1',
    q: 'What payment methods do you accept?',
    a: 'We accept Cash on Delivery (COD), JazzCash, EasyPaisa, Debit/Credit Cards, and direct Bank Transfer on all nationwide orders across Pakistan.',
  },
  {
    id: 'faq-2',
    q: 'How much is shipping and how long does delivery take?',
    a: 'Standard nationwide shipping is a flat Rs. 300 per order. Orders are dispatched within 24–48 hours and arrive within 2–4 business days.',
  },
  {
    id: 'faq-3',
    q: 'What is your exchange and return policy?',
    a: 'Unworn items in original packaging with tags attached may be exchanged or returned within 14 days of delivery.',
  },
  {
    id: 'faq-4',
    q: 'How do restock notifications work?',
    a: 'Select "Notify Me" on any out-of-stock item and enter your email address. You will be alerted as soon as the item returns to stock.',
  },
];

export const DEFAULT_FOOTER_SECTIONS = [
  {
    id: 'shop',
    heading: 'Shop',
    links: [
      { id: 'all-products', label: 'All Products', path: '/all-products', enabled: true },
      { id: 'categories', label: 'Categories', path: '/categories', enabled: true },
      { id: 'new-arrivals', label: 'New Arrivals', path: '/new-arrivals', enabled: true },
      { id: 'featured', label: 'Featured', path: '/featured', enabled: true },
    ],
  },
  {
    id: 'support',
    heading: 'Support',
    links: [
      { id: 'track-orders', label: 'Track Orders', path: '/track-orders', enabled: true },
      { id: 'shipping-returns', label: 'Shipping & Returns', path: '/shipping-returns', enabled: true },
      { id: 'faq', label: 'FAQ', path: '/faq', enabled: true },
      { id: 'contact', label: 'Contact', path: '/contact', enabled: true },
    ],
  },
];

export const DEFAULT_INFORMATIONAL_PAGES = [
  {
    slug: 'shipping-returns',
    title: 'Shipping & Returns',
    subtitle: 'Nationwide delivery across Pakistan and our 14-day exchange and return policy.',
    content:
      'Standard delivery across Pakistan is a flat Rs. 300 per order. Every garment and leather piece is inspected, steamed, and packed in protective packaging at our Lahore studio before dispatch. Orders are dispatched within 24–48 hours and delivered within 2–4 business days across all major cities in Pakistan.',
    secondary_title: 'Exchanges & Returns Policy',
    secondary_content:
      'Unworn items in their original condition and packaging with all tags attached can be exchanged or returned within 14 days of delivery. Contact our client services team with your order reference number to initiate a return or size exchange.',
    updated_at: new Date().toISOString(),
  },
  {
    slug: 'contact',
    title: 'Contact Us',
    subtitle: 'Reach our client services team for sizing advice, order inquiries, or studio appointments.',
    content:
      'Our client services studio is available Monday through Saturday from 10:00 AM to 8:00 PM PKT. Send us a message using the inquiry form or reach us directly by telephone or email.',
    secondary_title: 'Studio Hours & Direct Assistance',
    secondary_content:
      'Monday – Saturday: 10:00 AM – 8:00 PM PKT. All client inquiries receive a response within 24 business hours.',
    updated_at: new Date().toISOString(),
  },
  {
    slug: 'faq',
    title: 'Frequently Asked Questions',
    subtitle: 'Answers to common questions about ordering, nationwide delivery, sizing, and returns.',
    content:
      'Browse our frequently asked questions below. Every answer is maintained directly by our studio team.',
    secondary_title: 'Need Additional Assistance?',
    secondary_content:
      'If your question is not covered below, please visit our Contact page or reach out to our support email.',
    updated_at: new Date().toISOString(),
  },
  {
    slug: 'track-orders',
    title: 'Track Your Orders',
    subtitle: 'Securely monitor real-time fulfillment and delivery status for your orders.',
    content:
      'For customer privacy and security, you can only access orders associated with your own customer account. Sign in to view all of your orders automatically, or enter your order reference number along with the email address used at checkout.',
    secondary_title: 'Order Fulfillment Stages',
    secondary_content:
      'Orders progress through Pending, Confirmed, Processing, Shipped, and Delivered stages with real-time updates.',
    updated_at: new Date().toISOString(),
  },
  {
    slug: 'about',
    title: 'About Foner',
    subtitle: 'Tailored outerwear, fine-gauge knitwear, and full-grain leather goods.',
    content:
      'Founded in Lahore, Foner designs enduring wardrobe essentials crafted from natural fibers—double-faced wool, Mongolian cashmere, mulberry silk, and vegetable-tanned calfskin.',
    secondary_title: 'Craftsmanship & Materials',
    secondary_content:
      'Every piece is produced in small batches with horn buttons, Bemberg linings, and hand-finished seams.',
    updated_at: new Date().toISOString(),
  },
];

export const DEFAULT_STORE_SETTINGS: Record<string, string> = {
  store_name: 'FONER',
  tagline: 'Tailored outerwear, knitwear, and leather goods.',
  footer_description: 'Tailored outerwear, knitwear, and leather goods.',
  currency: 'PKR',
  currency_symbol: 'Rs.',
  delivery_fee_pkr: '300',
  announcement_bar: 'Nationwide delivery across Pakistan — PKR 300 flat shipping rate',
  announcement_bg_color: '#430F1B',
  announcement_text_color: '#F7F3EB',
  announcement_enabled: 'true',
  announcement_link: 'all',
  contactEmail: 'fonerera@gmail.com',
  contact_email: 'fonerera@gmail.com',
  business_email: 'fonerera@gmail.com',
  business_phone: '',
  business_address: '',
  support_phone: '',
  support_email: 'fonerera@gmail.com',
  atelier_address: '',
  flagship_address: '',
  working_hours: 'Monday – Saturday: 10:00 AM – 8:00 PM PKT',
  instagramUrl: '',
  instagram_handle: '',
  instagram_url: '',
  facebook_url: '',
  whatsapp_number: '',
  social_instagram_url: '',
  social_facebook_url: '',
  social_whatsapp_url: '',
  footer_copyright_text: `© ${new Date().getFullYear()} FONER. All rights reserved.`,
  footer_bottom_note: 'Nationwide shipping across Pakistan — Rs. 300',
  homepage_featured_title: 'Featured',
  homepage_new_arrivals_title: 'New Arrivals',
  faq_json: JSON.stringify(DEFAULT_FAQ_LIST),
  footer_sections_json: JSON.stringify(DEFAULT_FOOTER_SECTIONS),
  pages_json: JSON.stringify(DEFAULT_INFORMATIONAL_PAGES),
};







  


// ============================================================================
// PERSISTENT ENGINE (SYNCED TO DISK WHEN REMOTE TAILSCALE IP IS UNREACHABLE)
// ============================================================================
interface MemoryStore {
  store_settings: { key: string; value: string; updated_at: string }[];
  users: any[];
  user_sessions: {
    token: string;
    user_id: number;
    session_scope: 'customer' | 'admin';
    expires_at: string;
    created_at: string;
  }[];
  uploaded_media: {
    id: number;
    filename: string;
    mime_type: string;
    data_url: string;
    created_at: string;
  }[];
  categories: any[];
  subcategories: any[];
  banners: any[];
  products: any[];
  restock_notifications: any[];
  coupons: any[];
  orders: any[];
  reviews: any[];
  audit_logs: any[];
  newsletter_subscribers: any[];
  contact_messages: any[];
  registration_otps: {
    email: string;
    otp_code: string;
    otp_hash?: string;
    expires_at: string;
    verified: boolean;
    attempts?: number;
    request_count?: number;
    last_requested_at?: string;
    created_at: string;
  }[];
  password_reset_tokens: {
    email: string;
    token_hash: string;
    expires_at: string;
    attempts: number;
    used: boolean;
    request_count: number;
    last_requested_at: string;
    created_at: string;
  }[];
}

let pgPool: pg.Pool | null = null;
let currentPoolUrl: string = '';
let usingMemoryFallback = false;
const memStore: any = {}; // Deprecated: PostgreSQL is sole source of truth
let schemaInitialized = false;
let lastSyncedAt: string | null = new Date().toISOString();

export function getCleanDatabaseUrl(): string {
  const raw = (process.env.DATABASE_URL || '').trim();
  if (!raw) return '';

  let s = raw
    .replace(/^(export\s+)?(DATABASE_URL|POSTGRES_URL)\s*=\s*/i, '')
    .replace(/^psql\s+/i, '')
    .replace(/^jdbc:/i, '')
    .replace(/^["'`]+|[;"'`]+$/g, '')
    .trim();

  if (
    !s ||
    /^(MY_DATABASE_URL|YOUR_DATABASE_URL|DATABASE_URL|NONE|NULL|UNDEFINED)$/i.test(s)
  ) {
    return '';
  }

  const uriMatch = s.match(/(postgres(?:ql)?:\/\/[^\s"';`]+)/i);
  if (uriMatch) {
    return uriMatch[1];
  }

  if (/^[^:/\s]+(:[^@\s]*)?@[^:/\s]+(:\d+)?(\/[^\s]*)?$/.test(s)) {
    return `postgresql://${s}`;
  }
  if (/^(localhost|\d{1,3}(?:\.\d{1,3}){3})(:\d+)?(\/[^\s]*)?$/i.test(s)) {
    return `postgresql://${s.includes('/') ? s : `${s}/f`}`;
  }

  return s;
}

function parseConnectionMetadata(url: string): {
  host: string;
  port: number;
  databaseName: string;
  user: string;
  maskedLabel: string;
} {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname || '127.0.0.1';
    const port = parsed.port ? parseInt(parsed.port, 10) : 5432;
    const databaseName = (parsed.pathname || '/f').replace(/^\/+/, '') || 'f';
    const user = decodeURIComponent(parsed.username || 'f_user');
    const maskedLabel = `postgresql://${user}:****@${host}:${port}/${databaseName}`;
    return { host, port, databaseName, user, maskedLabel };
  } catch {
    return {
      host: '127.0.0.1',
      port: 5432,
      databaseName: 'f',
      user: 'f_user',
      maskedLabel: 'postgresql://f_user:****@127.0.0.1:5432/f',
    };
  }
}

function getPool(): pg.Pool {
  const dbUrl = getCleanDatabaseUrl();
  if (!dbUrl || (!dbUrl.startsWith('postgres://') && !dbUrl.startsWith('postgresql://'))) {
    throw new Error('DATABASE_URL not configured');
  }

  if (pgPool && currentPoolUrl !== dbUrl) {
    pgPool.end().catch(() => {});
    pgPool = null;
  }

  if (!pgPool) {
    const useSsl =
      process.env.DATABASE_SSL === 'true'
        ? { rejectUnauthorized: false }
        : false;

    currentPoolUrl = dbUrl;
    pgPool = new Pool({
      connectionString: dbUrl,
      ssl: useSsl,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 1500,
    });

    pgPool.on('error', () => {
      // Fail loudly — do not silently switch to memory fallback
      console.error('[DB Pool Error] PostgreSQL connection failed — memory fallback disabled');
    });
  }

  return pgPool;
}

function nextId(list: { id: number }[]): number { return 1; }
function executeMemoryQuery<T = any>(sql: string, params: any[] = []): QueryResult<T> { throw new Error("Memory fallback disabled"); }
function savePersistedStore(): void { /* no-op - deprecated */ }

export async function dbQuery<T = any>(
  sql: string,
  params: any[] = []
): Promise<QueryResult<T>> {
  if (usingMemoryFallback) {
    throw new Error('PostgreSQL not available — memory fallback disabled in production');
  }
  try {
    const pool = getPool();
    const res = await pool.query(sql, params);
    return { rows: res.rows as T[], rowCount: res.rowCount };
  } catch (err: any) {
    // Fail loudly — never silently fall back to memory/mock storage
    throw err;
  }
}

export async function withTransaction<T>(
  fn: (txQuery: <R = any>(sql: string, params?: any[]) => Promise<QueryResult<R>>) => Promise<T>
): Promise<T> {
  if (!usingMemoryFallback) {
    try {
      const pool = getPool();
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const txQuery = async <R = any>(sql: string, params: any[] = []): Promise<QueryResult<R>> => {
          const res = await client.query(sql, params);
          return { rows: res.rows as R[], rowCount: res.rowCount };
        };
        const result = await fn(txQuery);
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    } catch (connErr: any) {
      // Always fail loudly — never fall back to memory store in production
      throw connErr;
    }
  }

  // Memory fallback removed in production — always require PostgreSQL
  throw new Error('PostgreSQL transaction unavailable — memory fallback disabled');
}

export async function dbExecBatch(sqlScript: string): Promise<void> {
  // Fail loudly if PG unavailable — no memory fallback
  const pool = getPool();
  await pool.query(sqlScript);
}

export async function checkDatabaseHealth(): Promise<{
  ok: boolean;
  status: 'ok' | 'error';
  database: 'connected' | 'disconnected';
  databaseName: string;
  databaseUser?: string;
  host?: string;
  port?: number;
  serverTime?: string;
  error?: string;
}> {
  const dbUrl = getCleanDatabaseUrl();
  const meta = parseConnectionMetadata(dbUrl);

  const connectionUrl = getCleanDatabaseUrl();
  if (!connectionUrl || (!connectionUrl.startsWith('postgres://') && !connectionUrl.startsWith('postgresql://'))) {
    return {
      ok: false,
      status: 'error',
      database: 'disconnected',
      databaseName: meta.databaseName || '',
      databaseUser: meta.user || '',
      host: meta.host || '127.0.0.1',
      port: meta.port || 5432,
      error: 'DATABASE_URL is not configured.',
    };
  }

  try {
    const pool = getPool();
    const res = await pool.query<{
      db_name: string;
      db_user: string;
      server_time: string;
    }>(
      'SELECT current_database() AS db_name, current_user AS db_user, NOW()::text AS server_time'
    );

    const row = res.rows[0];
    const healthMeta = parseConnectionMetadata(connectionUrl);

    if (!schemaInitialized) {
      await initializeDatabase();
    }

    return {
      ok: true,
      status: 'ok',
      database: 'connected',
      databaseName: row?.db_name || healthMeta.databaseName,
      databaseUser: row?.db_user || healthMeta.user,
      host: healthMeta.host,
      port: healthMeta.port,
      serverTime: row?.server_time || new Date().toISOString(),
    };
  } catch (err: any) {
    return {
      ok: false,
      status: 'error',
      database: 'disconnected',
      databaseName: meta.databaseName || 'f',
      databaseUser: meta.user || 'f_user',
      host: meta.host || '127.0.0.1',
      port: meta.port || 5432,
      error: 'PostgreSQL database connection failed: ' + (err?.message || 'Database unreachable'),
    };
  }
}

export async function initializeDatabase(): Promise<{
  engine: 'postgresql';
  connection_label: string;
  database_name: string;
  database_user: string;
  host: string;
  port: number;
}> {
  const dbUrl = getCleanDatabaseUrl();
  if (!dbUrl || (!dbUrl.startsWith('postgres://') && !dbUrl.startsWith('postgresql://'))) {
    throw new Error('DATABASE_URL is not configured. Cannot initialize Foner database.');
  }

  const meta = parseConnectionMetadata(dbUrl);
  const pool = getPool();

  // Verify connection first
  await pool.query('SELECT 1');
  usingMemoryFallback = false;

  // Load schema from the canonical source of truth
  const schemaPath = path.resolve(process.cwd(), 'db', 'schema.sql');
  if (!fs.existsSync(schemaPath)) {
    throw new Error(`Foner schema file not found at ${schemaPath}`);
  }
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');

  // Execute schema (CREATE IF NOT EXISTS / ALTER ADD COLUMN IF NOT EXISTS are safe for existing data)
  await pool.query(schemaSql);

  // Verify all required tables exist
  const requiredTables = [
    'store_settings','users','user_sessions','registration_otps','password_reset_tokens',
    'uploaded_media','categories','subcategories','banners','products',
    'restock_notifications','coupons','orders','contact_messages','reviews',
    'audit_logs','newsletter_subscribers',
  ];

  const tablesRes = await pool.query(
    `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`
  );
  const existingTables = new Set(tablesRes.rows.map((r: any) => String(r.table_name)));
  const missingTables = requiredTables.filter((t) => !existingTables.has(t));
  const foundCount = requiredTables.length - missingTables.length;

  if (missingTables.length > 0) {
    throw new Error(
      `Foner schema verification failed: missing required tables (${missingTables.join(', ')}); found ${foundCount}/${requiredTables.length}`
    );
  }

  // Seed store settings (only if empty — preserves existing production data)
  for (const [key, value] of Object.entries(DEFAULT_STORE_SETTINGS)) {
    await pool.query(
      'INSERT INTO store_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING',
      [key, value]
    );
  }

  // De-obfuscate hardcoded contact fields (existing cleanup logic preserved)
  await pool.query(`UPDATE store_settings SET value = '' WHERE key IN ('atelier_address', 'business_address', 'flagship_address')`).catch(() => {});
  await pool.query(`UPDATE store_settings SET value = '' WHERE key IN ('support_phone', 'business_phone')`).catch(() => {});
  await pool.query(`UPDATE store_settings SET value = 'fonerera@gmail.com' WHERE key IN ('contactEmail', 'contact_email', 'support_email', 'business_email')`).catch(() => {});
  await pool.query(`UPDATE store_settings SET value = '' WHERE key IN ('instagram_url', 'social_instagram_url', 'instagramUrl')`).catch(() => {});
  await pool.query(`UPDATE store_settings SET value = '' WHERE key IN ('facebook_url', 'social_facebook_url')`).catch(() => {});
  await pool.query(`UPDATE store_settings SET value = '' WHERE key IN ('whatsapp_number', 'social_whatsapp_url')`).catch(() => {});

  // Business data seeding explicitly disabled for production (database must remain source of truth)
  // Schema and store settings preserved; admin account preserved via bootstrapInitialAdmin only

  schemaInitialized = true;
  lastSyncedAt = new Date().toISOString();
  await bootstrapInitialAdmin();

  console.log(`DATABASE: ${meta.databaseName || 'f'}`);
  console.log(`USER: ${meta.user || 'f_user'}`);
  console.log(`ENGINE: PostgreSQL`);
  console.log(`SCHEMA: public`);
  console.log(`REQUIRED TABLES: ${foundCount}/${requiredTables.length}`);
  console.log(`STATUS: SUCCESS`);
  if (missingTables.length > 0) {
    console.error('MISSING TABLES:', missingTables.join(', '));
  }

  return {
    engine: 'postgresql',
    connection_label: 'connected',
    database_name: meta.databaseName || 'f',
    database_user: meta.user || 'f_user',
    host: meta.host || '127.0.0.1',
    port: meta.port || 5432,
  };
}

export async function bootstrapInitialAdmin(): Promise<void> {
  const rawEmail = (process.env.INITIAL_ADMIN_EMAIL || 'admin@foner.com').trim().toLowerCase();
  const rawPass = process.env.INITIAL_ADMIN_PASSWORD || 'adminfoner';
  const rawName = (process.env.INITIAL_ADMIN_NAME || 'Foner Administrator').trim();

  if (!rawEmail || !rawPass) {
    return;
  }

  if (usingMemoryFallback) {
    const hasAdmin = memStore.users.some((u: any) => u.role === 'admin');
    if (hasAdmin) return;

    const passwordHash = hashPassword(rawPass);
    const existingIdx = memStore.users.findIndex((u: any) => u.email.toLowerCase() === rawEmail);
    if (existingIdx >= 0) {
      memStore.users[existingIdx] = {
        ...memStore.users[existingIdx],
        name: rawName || memStore.users[existingIdx].name,
        role: 'admin',
        status: 'active',
        password_hash: passwordHash,
      };
    } else {
      memStore.users.push({
        id: nextId(memStore.users),
        name: rawName,
        email: rawEmail,
        password_hash: passwordHash,
        phone: '',
        city: 'Lahore',
        address: '',
        postal_code: '',
        role: 'admin',
        status: 'active',
        avatar_url: '/products/overcoat.jpg',
        total_orders: 0,
        total_spent_pkr: 0,
        loyalty_points: 0,
        created_at: new Date().toISOString(),
      });
    }
    savePersistedStore();
    return;
  }

  try {
    const pool = getPool();
    const adminCountRes = await pool.query(
      `SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin'`
    );
    const adminCount = Number(adminCountRes.rows[0]?.count || 0);
    if (adminCount > 0) {
      return;
    }

    const passwordHash = hashPassword(rawPass);
    const existingRes = await pool.query(
      `SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1`,
      [rawEmail]
    );

    if (existingRes.rows.length > 0) {
      await pool.query(
        `UPDATE users
         SET role = 'admin',
             status = 'active',
             name = COALESCE(NULLIF($2, ''), name),
             password_hash = $3
         WHERE id = $1`,
        [existingRes.rows[0].id, rawName, passwordHash]
      );
    } else {
      await pool.query(
        `INSERT INTO users (name, email, password_hash, phone, city, address, postal_code, role, status, avatar_url)
         VALUES ($1, $2, $3, '', 'Lahore', '', '', 'admin', 'active', '/products/overcoat.jpg')`,
        [rawName, rawEmail, passwordHash]
      );
    }
  } catch (err: any) {
    console.error('[Foner DB] Failed to bootstrap initial admin account:', err?.message || err);
  }
}

export async function getDatabaseStatusInfo() {
  const health = await checkDatabaseHealth();

  return {
    engine: 'postgresql' as const,
    connected: health.ok,
    database_name: '',
    database_user: '',
    host: '',
    port: 0,
    connection_label: health.ok ? 'Connected' : 'Degraded',
    auto_schema_initialized: schemaInitialized,
    last_synced_at: lastSyncedAt || new Date().toISOString(),
    tables: [],
    schema_sql: '',
  };
}

export async function logAudit(
  actorName: string,
  actorRole: string,
  action: string,
  entityType: string,
  details: string
): Promise<void> {
  try {
    await dbQuery(
      `INSERT INTO audit_logs (actor_name, actor_role, action, entity_type, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [actorName, actorRole, action, entityType, details]
    );
  } catch {
    // non-fatal
  }
}

export const initSchema = initializeDatabase;

