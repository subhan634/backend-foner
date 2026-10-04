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

export const SEED_BANNERS = [
  {
    id: 1,
    title: 'Autumn & Winter Collection',
    subtitle:
      'Tailored wool coats, cashmere knitwear, and full-grain leather essentials built for everyday wear.',
    badge_text: 'NEW SEASON',
    cta_text: 'Shop Collection',
    cta_link: 'all',
    desktop_image_url: '/banners/desktop-banner-1.jpg',
    mobile_image_url: '/banners/mobile-banner-1.jpg',
    device_target: 'both',
    theme_style: 'burgundy-gold',
    overlay_opacity: 42,
    sort_order: 1,
    is_active: true,
    created_at: new Date().toISOString(),
  },
  {
    id: 2,
    title: 'Cashmere & Merino Knitwear',
    subtitle: 'Soft, breathable layers knitted from fine cashmere and combed merino wool.',
    badge_text: 'KNITWEAR',
    cta_text: 'Shop Knitwear',
    cta_link: 'knitwear',
    desktop_image_url: '/banners/desktop-banner-2.jpg',
    mobile_image_url: '/banners/mobile-banner-2.jpg',
    device_target: 'both',
    theme_style: 'burgundy-gold',
    overlay_opacity: 40,
    sort_order: 2,
    is_active: true,
    created_at: new Date().toISOString(),
  },
  {
    id: 3,
    title: 'Leather Goods & Footwear',
    subtitle: 'Full-grain calfskin travel bags and Goodyear-welted loafers.',
    badge_text: 'LEATHER & SHOES',
    cta_text: 'Shop Leather Goods',
    cta_link: 'leather-goods',
    desktop_image_url: '/banners/desktop-banner-1.jpg',
    mobile_image_url: '/banners/mobile-banner-2.jpg',
    device_target: 'both',
    theme_style: 'burgundy-gold',
    overlay_opacity: 44,
    sort_order: 3,
    is_active: true,
    created_at: new Date().toISOString(),
  },
];

export const SEED_CATEGORIES = [
  {
    id: 1,
    name: 'Outerwear',
    slug: 'outerwear',
    description: 'Wool overcoats, structured blazers, and weather-resistant trench coats.',
    image_url: '/products/overcoat.jpg',
    featured: true,
    sort_order: 1,
    created_at: new Date().toISOString(),
  },
  {
    id: 2,
    name: 'Knitwear',
    slug: 'knitwear',
    description: 'Cashmere rollnecks, crewnecks, and merino wool cardigans.',
    image_url: '/banners/mobile-banner-2.jpg',
    featured: true,
    sort_order: 2,
    created_at: new Date().toISOString(),
  },
  {
    id: 3,
    name: 'Tailoring',
    slug: 'silk-tailoring',
    description: 'Silk shirts and pleated wool trousers.',
    image_url: '/products/silk-tailoring.jpg',
    featured: true,
    sort_order: 3,
    created_at: new Date().toISOString(),
  },
  {
    id: 4,
    name: 'Leather Goods',
    slug: 'leather-goods',
    description: 'Calfskin weekender bags, totes, and small leather accessories.',
    image_url: '/products/weekender.jpg',
    featured: true,
    sort_order: 4,
    created_at: new Date().toISOString(),
  },
  {
    id: 5,
    name: 'Footwear',
    slug: 'footwear',
    description: 'Welted leather loafers and ankle boots.',
    image_url: '/products/loafers.jpg',
    featured: true,
    sort_order: 5,
    created_at: new Date().toISOString(),
  },
];

// Note: Footwear intentionally has no seeded subcategories so that selecting a category
// without subcategories can be verified directly alongside categories that have subcategories.
export const SEED_SUBCATEGORIES = [
  {
    id: 1,
    name: 'Overcoats',
    slug: 'wool-trench-coats',
    parent_category_slug: 'outerwear',
    description: 'Double-breasted wool coats and belted trenches.',
    image_url: '/products/overcoat.jpg',
    featured: true,
    sort_order: 1,
    created_at: new Date().toISOString(),
  },
  {
    id: 2,
    name: 'Blazers',
    slug: 'structured-blazers',
    parent_category_slug: 'outerwear',
    description: 'Single and double-breasted tailored jackets.',
    image_url: '/banners/mobile-banner-1.jpg',
    featured: true,
    sort_order: 2,
    created_at: new Date().toISOString(),
  },
  {
    id: 3,
    name: 'Cashmere Sweaters',
    slug: 'pure-cashmere-knits',
    parent_category_slug: 'knitwear',
    description: '12-gauge cashmere rollnecks and crewnecks.',
    image_url: '/banners/mobile-banner-2.jpg',
    featured: true,
    sort_order: 3,
    created_at: new Date().toISOString(),
  },
  {
    id: 4,
    name: 'Merino Cardigans',
    slug: 'merino-cardigans',
    parent_category_slug: 'knitwear',
    description: 'Combed merino wool polo knits and button cardigans.',
    image_url: '/banners/desktop-banner-2.jpg',
    featured: true,
    sort_order: 4,
    created_at: new Date().toISOString(),
  },
  {
    id: 5,
    name: 'Silk Shirts',
    slug: 'mulberry-silk-shirts',
    parent_category_slug: 'silk-tailoring',
    description: 'Sandwashed mulberry silk button-down shirts.',
    image_url: '/products/silk-tailoring.jpg',
    featured: true,
    sort_order: 5,
    created_at: new Date().toISOString(),
  },
  {
    id: 6,
    name: 'Tailored Trousers',
    slug: 'pleated-trousers',
    parent_category_slug: 'silk-tailoring',
    description: 'High-rise pleated wool trousers with side adjusters.',
    image_url: '/banners/desktop-banner-1.jpg',
    featured: true,
    sort_order: 6,
    created_at: new Date().toISOString(),
  },
  {
    id: 7,
    name: 'Travel Bags',
    slug: 'calfskin-bags',
    parent_category_slug: 'leather-goods',
    description: 'Hand-stitched calfskin weekenders and briefcases.',
    image_url: '/products/weekender.jpg',
    featured: true,
    sort_order: 7,
    created_at: new Date().toISOString(),
  },
];

export const SEED_PRODUCTS = [
  {
    id: 1,
    title: 'Double-Breasted Wool Overcoat',
    slug: 'double-breasted-wool-overcoat',
    sku: 'FNR-101',
    category_slug: 'outerwear',
    subcategory_slug: 'wool-trench-coats',
    price_pkr: 48500,
    compare_at_price_pkr: 58000,
    description:
      'Tailored from double-faced wool-cashmere cloth with peak lapels, horn buttons, and a full Bemberg lining.',
    fabric_care: '90% Virgin Wool, 10% Mongolian Cashmere. Dry clean only.',
    image_url: '/products/overcoat.jpg',
    gallery_urls: [
      '/products/overcoat.jpg',
      '/banners/mobile-banner-1.jpg',
      '/banners/desktop-banner-1.jpg',
      '/banners/mobile-banner-2.jpg',
    ],
    sizes: ['S', 'M', 'L', 'XL'],
    colors: [
      { name: 'Oxblood', hex: '#430F1B' },
      { name: 'Camel', hex: '#C5A06E' },
    ],
    variants: [
      { size: 'S', color: 'Oxblood', sku: 'FNR-101-OXB-S', stock: 3, price_pkr: 48500 },
      { size: 'M', color: 'Oxblood', sku: 'FNR-101-OXB-M', stock: 4, price_pkr: 48500 },
      { size: 'L', color: 'Oxblood', sku: 'FNR-101-OXB-L', stock: 3, price_pkr: 48500 },
      { size: 'M', color: 'Camel', sku: 'FNR-101-CML-M', stock: 2, price_pkr: 48500 },
      { size: 'XL', color: 'Camel', sku: 'FNR-101-CML-XL', stock: 2, price_pkr: 51500 },
    ],
    seo_title: 'Double-Breasted Wool Overcoat | Foner',
    meta_description: 'Tailored from double-faced wool-cashmere cloth with peak lapels, horn buttons, and a full Bemberg lining.',
    stock: 14,
    is_featured: true,
    is_new_arrival: true,
    is_bestseller: true,
    rating: 4.9,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 2,
    title: 'Calfskin Leather Weekender Bag',
    slug: 'calfskin-leather-weekender-bag',
    sku: 'FNR-102',
    category_slug: 'leather-goods',
    subcategory_slug: 'calfskin-bags',
    price_pkr: 64000,
    compare_at_price_pkr: 76000,
    description:
      'Constructed from vegetable-tanned full-grain calfskin with solid brass hardware, cotton twill lining, and a detachable shoulder strap.',
    fabric_care: '100% Full-Grain Calfskin Leather. Wipe with a soft dry cloth.',
    image_url: '/products/weekender.jpg',
    gallery_urls: [
      '/products/weekender.jpg',
      '/banners/desktop-banner-2.jpg',
      '/banners/mobile-banner-1.jpg',
      '/banners/desktop-banner-1.jpg',
    ],
    sizes: ['One Size'],
    colors: [
      { name: 'Bordeaux', hex: '#631828' },
      { name: 'Espresso', hex: '#2B1B17' },
    ],
    stock: 0,
    is_featured: true,
    is_new_arrival: false,
    is_bestseller: true,
    rating: 5.0,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 3,
    title: 'Cashmere Rollneck Sweater',
    slug: 'cashmere-rollneck-sweater',
    sku: 'FNR-103',
    category_slug: 'knitwear',
    subcategory_slug: 'pure-cashmere-knits',
    price_pkr: 26500,
    compare_at_price_pkr: 32000,
    description:
      'Knitted in a 12-gauge mid-weight weave from two-ply cashmere yarn with ribbed cuffs and hem.',
    fabric_care: '100% Grade-A Cashmere. Cold hand wash or dry clean.',
    image_url: '/banners/mobile-banner-2.jpg',
    gallery_urls: [
      '/banners/mobile-banner-2.jpg',
      '/banners/desktop-banner-2.jpg',
      '/products/overcoat.jpg',
      '/banners/mobile-banner-1.jpg',
    ],
    sizes: ['XS', 'S', 'M', 'L', 'XL'],
    colors: [
      { name: 'Oat', hex: '#E5DCCB' },
      { name: 'Burgundy', hex: '#631828' },
    ],
    stock: 4,
    is_featured: true,
    is_new_arrival: true,
    is_bestseller: true,
    rating: 4.8,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 4,
    title: 'Mulberry Silk Relaxed Shirt',
    slug: 'mulberry-silk-relaxed-shirt',
    sku: 'FNR-104',
    category_slug: 'silk-tailoring',
    subcategory_slug: 'mulberry-silk-shirts',
    price_pkr: 21500,
    compare_at_price_pkr: 26000,
    description:
      'Cut from 22-momme sandwashed mulberry silk with mother-of-pearl buttons and French seams.',
    fabric_care: '100% 22-Momme Mulberry Silk. Gentle hand wash cold or dry clean.',
    image_url: '/products/silk-tailoring.jpg',
    gallery_urls: [
      '/products/silk-tailoring.jpg',
      '/banners/mobile-banner-1.jpg',
      '/banners/desktop-banner-2.jpg',
      '/banners/desktop-banner-1.jpg',
    ],
    sizes: ['XS', 'S', 'M', 'L'],
    colors: [
      { name: 'Ivory', hex: '#F7F3EB' },
      { name: 'Garnet', hex: '#631828' },
    ],
    stock: 19,
    is_featured: true,
    is_new_arrival: false,
    is_bestseller: false,
    rating: 4.9,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 5,
    title: 'Calfskin Penny Loafers',
    slug: 'calfskin-penny-loafers',
    sku: 'FNR-105',
    category_slug: 'footwear',
    subcategory_slug: '',
    price_pkr: 36500,
    compare_at_price_pkr: 44000,
    description:
      'Goodyear-welted penny loafers crafted from burnished calfskin leather with a full leather lining and stacked heel.',
    fabric_care: '100% Burnished Calfskin. Condition with neutral leather cream.',
    image_url: '/products/loafers.jpg',
    gallery_urls: [
      '/products/loafers.jpg',
      '/banners/mobile-banner-2.jpg',
      '/banners/desktop-banner-1.jpg',
      '/banners/mobile-banner-1.jpg',
    ],
    sizes: ['40', '41', '42', '43', '44', '45'],
    colors: [
      { name: 'Oxblood', hex: '#430F1B' },
      { name: 'Dark Brown', hex: '#281A14' },
    ],
    variants: [
      { size: '40', color: 'Oxblood', sku: 'FNR-105-OXB-40', stock: 2, price_pkr: 36500 },
      { size: '41', color: 'Oxblood', sku: 'FNR-105-OXB-41', stock: 3, price_pkr: 36500 },
      { size: '42', color: 'Oxblood', sku: 'FNR-105-OXB-42', stock: 3, price_pkr: 36500 },
      { size: '43', color: 'Dark Brown', sku: 'FNR-105-DBR-43', stock: 2, price_pkr: 36500 },
      { size: '44', color: 'Dark Brown', sku: 'FNR-105-DBR-44', stock: 1, price_pkr: 38000 },
    ],
    seo_title: 'Calfskin Penny Loafers | Foner',
    meta_description: 'Goodyear-welted penny loafers crafted from burnished calfskin leather with a full leather lining and stacked heel.',
    stock: 11,
    is_featured: true,
    is_new_arrival: true,
    is_bestseller: false,
    rating: 4.9,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 6,
    title: 'Structured Wool Evening Blazer',
    slug: 'structured-wool-evening-blazer',
    sku: 'FNR-106',
    category_slug: 'outerwear',
    subcategory_slug: 'structured-blazers',
    price_pkr: 39500,
    compare_at_price_pkr: 47500,
    description:
      'Single-breasted tailored blazer in Super 130s merino wool with canvas chest construction and satin-trimmed lapels.',
    fabric_care: '100% Super 130s Virgin Wool. Dry clean only.',
    image_url: '/banners/mobile-banner-1.jpg',
    gallery_urls: [
      '/banners/mobile-banner-1.jpg',
      '/products/overcoat.jpg',
      '/banners/desktop-banner-1.jpg',
    ],
    sizes: ['S', 'M', 'L', 'XL'],
    colors: [
      { name: 'Burgundy', hex: '#631828' },
      { name: 'Obsidian', hex: '#1F181A' },
    ],
    stock: 0,
    is_featured: true,
    is_new_arrival: false,
    is_bestseller: false,
    rating: 4.9,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 7,
    title: 'Pleated Wool-Silk Trousers',
    slug: 'pleated-wool-silk-trousers',
    sku: 'FNR-107',
    category_slug: 'silk-tailoring',
    subcategory_slug: 'pleated-trousers',
    price_pkr: 19500,
    compare_at_price_pkr: 24000,
    description:
      'High-waisted double-pleated trousers tailored from a breathable wool-silk blend with side buckle adjusters.',
    fabric_care: '85% Virgin Wool, 15% Mulberry Silk. Dry clean only.',
    image_url: '/banners/desktop-banner-1.jpg',
    gallery_urls: [
      '/banners/desktop-banner-1.jpg',
      '/products/silk-tailoring.jpg',
      '/banners/mobile-banner-2.jpg',
    ],
    sizes: ['30', '32', '34', '36', '38'],
    colors: [
      { name: 'Stone', hex: '#E5DCCB' },
      { name: 'Charcoal', hex: '#1F181A' },
    ],
    stock: 22,
    is_featured: false,
    is_new_arrival: true,
    is_bestseller: false,
    rating: 4.8,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 8,
    title: 'Merino Ribbed Polo Cardigan',
    slug: 'merino-ribbed-polo-cardigan',
    sku: 'FNR-108',
    category_slug: 'knitwear',
    subcategory_slug: 'merino-cardigans',
    price_pkr: 22800,
    compare_at_price_pkr: 27000,
    description:
      'Fine 16-gauge merino wool cardigan with a polo collar and horn buttons.',
    fabric_care: '100% Extra-Fine Merino Wool. Hand wash cold or dry clean.',
    image_url: '/banners/desktop-banner-2.jpg',
    gallery_urls: [
      '/banners/desktop-banner-2.jpg',
      '/banners/mobile-banner-2.jpg',
      '/products/overcoat.jpg',
    ],
    sizes: ['S', 'M', 'L', 'XL'],
    colors: [
      { name: 'Wine', hex: '#631828' },
      { name: 'Oatmeal', hex: '#E5DCCB' },
    ],
    stock: 9,
    is_featured: false,
    is_new_arrival: false,
    is_bestseller: true,
    rating: 4.9,
    reviews_count: 0,
    created_at: new Date().toISOString(),
  },
];

export const SEED_USERS: any[] = [];

export const SEED_COUPONS = [
  {
    id: 1,
    code: 'FONER15',
    description: '15% off orders above Rs. 15,000',
    discount_type: 'percentage',
    discount_value: 15,
    min_order_pkr: 15000,
    expires_at: new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString(),
    is_active: true,
    usage_limit: 200,
    per_customer_limit: 3,
    usage_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 2,
    code: 'WELCOME20',
    description: '20% off orders above Rs. 25,000',
    discount_type: 'percentage',
    discount_value: 20,
    min_order_pkr: 25000,
    expires_at: new Date(Date.now() + 60 * 24 * 3600 * 1000).toISOString(),
    is_active: true,
    usage_limit: 100,
    per_customer_limit: 1,
    usage_count: 0,
    created_at: new Date().toISOString(),
  },
  {
    id: 3,
    code: 'SAVE500',
    description: 'PKR 500 off orders above Rs. 3,000',
    discount_type: 'fixed',
    discount_value: 500,
    min_order_pkr: 3000,
    expires_at: '2026-12-31T23:59:59.000Z',
    is_active: true,
    usage_limit: 100,
    per_customer_limit: 2,
    usage_count: 0,
    created_at: new Date().toISOString(),
  },
];

export const SEED_RESTOCK_NOTIFICATIONS = [
  {
    id: 1,
    product_id: 2,
    product_title: 'Calfskin Leather Weekender Bag',
    product_sku: 'FNR-102',
    customer_email: 'ayesha.sikandar@example.com',
    preferred_size: 'One Size',
    preferred_color: 'Bordeaux',
    status: 'pending',
    notified_at: null,
    created_at: new Date(Date.now() - 3600 * 1000 * 5).toISOString(),
  },
];

export const SEED_REVIEWS: any[] = [];

export const SEED_ORDERS = [
  {
    id: 1,
    order_number: 'FNR-1001',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: 'Call before delivery',
    payment_method: 'COD',
    payment_status: 'paid',
    order_status: 'delivered',
    subtotal_pkr: 48500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 48800,
    idempotency_key: 'seed-order-1001',
    items_json: [
      {
        product_id: 1,
        title: 'Double-Breasted Wool Overcoat',
        sku: 'FNR-101',
        price_pkr: 48500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Oxblood',
        image_url: '/products/overcoat.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: 2,
    order_number: 'FNR-1002',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'pending',
    order_status: 'confirmed',
    subtotal_pkr: 36500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 36800,
    idempotency_key: 'seed-order-1002',
    items_json: [
      {
        product_id: 5,
        title: 'Calfskin Penny Loafers',
        sku: 'FNR-105',
        price_pkr: 36500,
        quantity: 1,
        selected_size: '41',
        selected_color: 'Oxblood',
        image_url: '/products/loafers.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 12).toISOString(),
  },
  {
    id: 3,
    order_number: 'FNR-1003',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'pending',
    order_status: 'pending',
    subtotal_pkr: 21500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 21800,
    idempotency_key: 'seed-order-1003',
    items_json: [
      {
        product_id: 4,
        title: 'Mulberry Silk Relaxed Shirt',
        sku: 'FNR-104',
        price_pkr: 21500,
        quantity: 1,
        selected_size: 'S',
        selected_color: 'Ivory',
        image_url: '/products/silk-tailoring.jpg',
      },
    ],
    created_at: new Date(Date.now() - 3600 * 1000 * 6).toISOString(),
  },
  {
    id: 4,
    order_number: 'FNR-1004',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: 'Customer requested cancellation before dispatch',
    payment_method: 'COD',
    payment_status: 'refunded',
    order_status: 'cancelled',
    subtotal_pkr: 32500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 32800,
    idempotency_key: 'seed-order-1004',
    items_json: [
      {
        product_id: 3,
        title: 'Pleated Velvet Wide-Leg Trousers',
        sku: 'FNR-103',
        price_pkr: 32500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Burgundy',
        image_url: '/products/velvet-trousers.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
  },
  {
    id: 5,
    order_number: 'FNR-1005',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'paid',
    order_status: 'delivered',
    subtotal_pkr: 23500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 23800,
    idempotency_key: 'seed-order-1005',
    items_json: [
      {
        product_id: 6,
        title: 'Merino Knit Polo Cardigan',
        sku: 'FNR-106',
        price_pkr: 23500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Wine',
        image_url: '/banners/desktop-banner-2.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 6,
    order_number: 'FNR-1006',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'paid',
    order_status: 'delivered',
    subtotal_pkr: 70000,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 70300,
    idempotency_key: 'seed-order-1006',
    items_json: [
      {
        product_id: 1,
        title: 'Double-Breasted Wool Overcoat',
        sku: 'FNR-101',
        price_pkr: 48500,
        quantity: 1,
        selected_size: 'L',
        selected_color: 'Charcoal',
        image_url: '/products/overcoat.jpg',
      },
      {
        product_id: 4,
        title: 'Mulberry Silk Relaxed Shirt',
        sku: 'FNR-104',
        price_pkr: 21500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Ivory',
        image_url: '/products/silk-tailoring.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 21).toISOString(),
  },
  {
    id: 7,
    order_number: 'FNR-1007',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'paid',
    order_status: 'delivered',
    subtotal_pkr: 69000,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 69300,
    idempotency_key: 'seed-order-1007',
    items_json: [
      {
        product_id: 3,
        title: 'Pleated Velvet Wide-Leg Trousers',
        sku: 'FNR-103',
        price_pkr: 32500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Burgundy',
        image_url: '/products/velvet-trousers.jpg',
      },
      {
        product_id: 5,
        title: 'Calfskin Penny Loafers',
        sku: 'FNR-105',
        price_pkr: 36500,
        quantity: 1,
        selected_size: '41',
        selected_color: 'Oxblood',
        image_url: '/products/loafers.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 48).toISOString(),
  },
  {
    id: 8,
    order_number: 'FNR-1008',
    user_id: 2,
    customer_name: 'Ayesha Sikandar',
    customer_email: 'ayesha.sikandar@example.com',
    customer_phone: '+92 321 4491022',
    shipping_address: 'House 14, Street 8, DHA Phase 6',
    shipping_city: 'Karachi',
    shipping_area: 'DHA Phase 6',
    postal_code: '75500',
    order_notes: '',
    payment_method: 'COD',
    payment_status: 'paid',
    order_status: 'delivered',
    subtotal_pkr: 48500,
    discount_pkr: 0,
    coupon_code: null,
    delivery_fee_pkr: 300,
    total_pkr: 48800,
    idempotency_key: 'seed-order-1008',
    items_json: [
      {
        product_id: 1,
        title: 'Double-Breasted Wool Overcoat',
        sku: 'FNR-101',
        price_pkr: 48500,
        quantity: 1,
        selected_size: 'M',
        selected_color: 'Oxblood',
        image_url: '/products/overcoat.jpg',
      },
    ],
    created_at: new Date(Date.now() - 86400000 * 74).toISOString(),
  },
];

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

const PERSISTENCE_FILE_PATH = path.resolve(process.cwd(), 'database', '.pg_persistence.json');

function createDefaultStore(): MemoryStore {
  return {
    store_settings: Object.entries(DEFAULT_STORE_SETTINGS).map(([key, value]) => ({
      key,
      value,
      updated_at: new Date().toISOString(),
    })),
    users: structuredClone(SEED_USERS),
    user_sessions: [],
    uploaded_media: [],
    categories: structuredClone(SEED_CATEGORIES),
    subcategories: structuredClone(SEED_SUBCATEGORIES),
    banners: structuredClone(SEED_BANNERS),
    products: structuredClone(SEED_PRODUCTS),
    restock_notifications: structuredClone(SEED_RESTOCK_NOTIFICATIONS),
    coupons: structuredClone(SEED_COUPONS),
    orders: structuredClone(SEED_ORDERS),
    reviews: structuredClone(SEED_REVIEWS),
    audit_logs: [
      {
        id: 1,
        actor_name: 'System',
        actor_role: 'admin',
        action: 'DATABASE_INITIALIZED',
        entity_type: 'database',
        details: 'Database schema and catalog initialized.',
        created_at: new Date().toISOString(),
      },
    ],
    newsletter_subscribers: [],
    contact_messages: [],
    registration_otps: [],
    password_reset_tokens: [],
  };
}

let lastLoadedMtimeMs = 0;

function loadPersistedStore(): MemoryStore {
  try {
    if (fs.existsSync(PERSISTENCE_FILE_PATH)) {
      const stat = fs.statSync(PERSISTENCE_FILE_PATH);
      lastLoadedMtimeMs = stat.mtimeMs;
      const raw = fs.readFileSync(PERSISTENCE_FILE_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      const defaults = createDefaultStore();
      // Ensure all default store_settings keys exist
      const existingKeys = new Set((parsed.store_settings || []).map((s: any) => s.key));
      const mergedSettings = [...(parsed.store_settings || [])];
      for (const defSetting of defaults.store_settings) {
        if (!existingKeys.has(defSetting.key)) {
          mergedSettings.push(defSetting);
        }
      }
      // Strict sanitization of loaded contact info: no hardcoded address, no dummy phone, no old email, no hardcoded instagram
      const sanitizedSettings = mergedSettings.map((s: any) => {
        const k = String(s.key || '');
        let v = String(s.value ?? '');
        if (['atelier_address', 'business_address', 'flagship_address'].includes(k)) {
          if (v.toLowerCase().includes('mm alam road') || v.toLowerCase().includes('gulberg iii')) {
            v = '';
          }
        } else if (['support_phone', 'business_phone'].includes(k)) {
          if (v.includes('8429910') || v.includes('8429911')) {
            v = '';
          }
        } else if (['support_email', 'business_email', 'contactEmail', 'contact_email'].includes(k)) {
          if (v.toLowerCase() === 'support@foner.pk' || !v.trim()) {
            v = 'fonerera@gmail.com';
          }
        } else if (['instagram_url', 'social_instagram_url', 'instagramUrl'].includes(k)) {
          if (
            v.toLowerCase() === 'https://instagram.com/foner' ||
            v.toLowerCase() === 'http://instagram.com/foner' ||
            v.toLowerCase().includes('foner.atelier.pk') ||
            v.toLowerCase() === 'instagram (@foner)' ||
            v.toLowerCase() === '@foner'
          ) {
            v = '';
          }
        } else if (['whatsapp_number', 'social_whatsapp_url'].includes(k)) {
          if (v.includes('8429910') || v.includes('8429911')) {
            v = '';
          }
        }
        return { ...s, value: v };
      });
      // Ensure users have valid role, status, and bcrypt password_hash; strip any legacy mock admin@foner.pk
      const validRoles = ['admin', 'manager', 'editor', 'customer'];
      const legacySeedHash = computeLegacySha256Hash('customer123');
      const mergedUsers = (parsed.users || defaults.users)
        .filter((u: any) => String(u.email || '').trim().toLowerCase() !== 'admin@foner.pk')
        .map((u: any) => {
          const normalizedRole = validRoles.includes(u.role) ? u.role : 'customer';
          let pwdHash = String(u.password_hash || '');
          if (pwdHash === legacySeedHash) {
            pwdHash = hashPassword('customer123');
          }
          return {
            ...u,
            email: String(u.email || '').trim().toLowerCase(),
            role: normalizedRole,
            status: u.status === 'suspended' ? 'suspended' : 'active',
            password_hash: pwdHash,
          };
        });
      const existingOrderNums = new Set((parsed.orders || []).map((o: any) => o.order_number));
      const mergedOrders = [...(parsed.orders || [])];
      for (const seedOrd of defaults.orders) {
        if (!existingOrderNums.has(seedOrd.order_number)) {
          mergedOrders.push(seedOrd);
        }
      }
      const seedProductMap = new Map(defaults.products.map((p: any) => [p.id, p]));
      const mergedProducts = (parsed.products || defaults.products).map((p: any) => {
        const seedProd = seedProductMap.get(p.id) as any;
        return {
          ...p,
          variants: Array.isArray(p.variants) && p.variants.length > 0 ? p.variants : (seedProd?.variants || []),
          seo_title: p.seo_title || seedProd?.seo_title || `${p.title} | Foner`,
          meta_description: p.meta_description || seedProd?.meta_description || p.description || '',
        };
      });
      const existingCouponCodes = new Set((parsed.coupons || []).map((c: any) => String(c.code || '').toUpperCase()));
      const mergedCoupons = (parsed.coupons || []).map((c: any) => {
        const seedCoupon = defaults.coupons.find((sc: any) => sc.code === String(c.code || '').toUpperCase());
        return {
          ...c,
          usage_limit: c.usage_limit !== undefined ? c.usage_limit : (seedCoupon?.usage_limit ?? null),
          per_customer_limit: c.per_customer_limit !== undefined ? c.per_customer_limit : (seedCoupon?.per_customer_limit ?? null),
        };
      });
      for (const sc of defaults.coupons) {
        if (!existingCouponCodes.has(sc.code.toUpperCase())) {
          mergedCoupons.push(sc);
        }
      }
      return {
        ...defaults,
        ...parsed,
        store_settings: sanitizedSettings,
        users: mergedUsers,
        orders: mergedOrders,
        products: mergedProducts,
        coupons: mergedCoupons,
        user_sessions: parsed.user_sessions || [],
        uploaded_media: parsed.uploaded_media || [],
        contact_messages: parsed.contact_messages || [],
        registration_otps: (parsed.registration_otps || []).map((r: any) => ({
          ...r,
          otp_code: 'HASHED',
          otp_hash:
            r.otp_hash ||
            (/^\d{6}$/.test(String(r.otp_code || ''))
              ? hashOtpValue(r.email, String(r.otp_code), 'registration')
              : String(r.otp_code || '')),
          attempts: Number(r.attempts || 0),
          request_count: Number(r.request_count || 1),
          last_requested_at: r.last_requested_at || r.created_at || new Date().toISOString(),
        })),
        password_reset_tokens: parsed.password_reset_tokens || [],
      };
    }
  } catch (err) {
    console.error('Error loading persisted store:', err);
  }
  return createDefaultStore();
}

let memStore: MemoryStore = loadPersistedStore();
let inTransaction = false;

function reloadPersistedStoreIfChanged(): void {
  if (inTransaction) return;
  try {
    if (fs.existsSync(PERSISTENCE_FILE_PATH)) {
      const stat = fs.statSync(PERSISTENCE_FILE_PATH);
      if (stat.mtimeMs > lastLoadedMtimeMs) {
        memStore = loadPersistedStore();
      }
    }
  } catch {
    // ignore stat errors
  }
}

function savePersistedStore(): void {
  if (inTransaction) return;
  try {
    const dir = path.dirname(PERSISTENCE_FILE_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(PERSISTENCE_FILE_PATH, JSON.stringify(memStore, null, 2), 'utf8');
    if (fs.existsSync(PERSISTENCE_FILE_PATH)) {
      lastLoadedMtimeMs = fs.statSync(PERSISTENCE_FILE_PATH).mtimeMs;
    }
  } catch (err) {
    console.error('Error saving persisted store:', err);
  }
}

let pgPool: pg.Pool | null = null;
let currentPoolUrl: string = '';
let usingMemoryFallback = false;
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

function nextId(list: { id: number }[]): number {
  return list.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;
}

function executeMemoryQuery<T = any>(sql: string, params: any[] = []): QueryResult<T> {
  reloadPersistedStoreIfChanged();
  const s = sql.replace(/\s+/g, ' ').trim();
  const sUpper = s.toUpperCase();

  if (sUpper === 'BEGIN' || sUpper === 'COMMIT' || sUpper === 'ROLLBACK') {
    return { rows: [], rowCount: 0 };
  }

  if (sUpper.startsWith('SELECT 1') || sUpper.includes('CURRENT_DATABASE()')) {
    return {
      rows: [
        {
          db_name: 'f',
          db_user: 'f_user',
          server_time: new Date().toISOString(),
        } as any,
      ],
      rowCount: 1,
    };
  }

  // Information schema columns count
  if (sUpper.includes('INFORMATION_SCHEMA.COLUMNS')) {
    const tblName = String(params[0] || 'products') as keyof MemoryStore;
    const sample = (memStore[tblName] || [])[0];
    const colCount = sample ? Object.keys(sample).length : 8;
    return { rows: [{ count: String(colCount) } as any], rowCount: 1 };
  }

  // SELECT COUNT(*) FROM <table>
  const countMatch = s.match(/^SELECT COUNT\(\*\)(?:::text|::int)?\s+AS\s+count\s+FROM\s+([a-z_]+)/i);
  if (countMatch) {
    const tblName = countMatch[1].toLowerCase() as keyof MemoryStore;
    const arr = memStore[tblName] || [];
    return { rows: [{ count: String(arr.length) } as any], rowCount: 1 };
  }

  // store_settings
  if (
    sUpper.startsWith('SELECT KEY, VALUE FROM STORE_SETTINGS') ||
    sUpper.startsWith('SELECT * FROM STORE_SETTINGS')
  ) {
    return { rows: [...memStore.store_settings] as any, rowCount: memStore.store_settings.length };
  }
  if (sUpper.startsWith('INSERT INTO STORE_SETTINGS')) {
    const [key, value] = params;
    const existing = memStore.store_settings.find((r) => r.key === key);
    if (existing) {
      if (sUpper.includes('DO UPDATE')) {
        existing.value = String(value);
        existing.updated_at = new Date().toISOString();
      }
    } else if (key) {
      memStore.store_settings.push({
        key: String(key),
        value: String(value),
        updated_at: new Date().toISOString(),
      });
    }
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // user_sessions
  if (sUpper.startsWith('SELECT * FROM USER_SESSIONS WHERE TOKEN =')) {
    const token = String(params[0] || '');
    const scope = params[1] ? String(params[1]) : null;
    const now = Date.now();
    const found = memStore.user_sessions.filter(
      (sess) =>
        sess.token === token &&
        (!scope || sess.session_scope === scope) &&
        new Date(sess.expires_at).getTime() > now
    );
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM USER_SESSIONS')) {
    return { rows: [...memStore.user_sessions] as any, rowCount: memStore.user_sessions.length };
  }
  if (sUpper.startsWith('INSERT INTO USER_SESSIONS')) {
    const newSess = {
      token: String(params[0]),
      user_id: Number(params[1]),
      session_scope: (params[2] || 'customer') as 'customer' | 'admin',
      expires_at: String(params[3]),
      created_at: new Date().toISOString(),
    };
    memStore.user_sessions = memStore.user_sessions.filter((x) => x.token !== newSess.token);
    memStore.user_sessions.push(newSess);
    savePersistedStore();
    return { rows: [newSess as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM USER_SESSIONS WHERE USER_ID =')) {
    const userId = Number(params[0]);
    memStore.user_sessions = memStore.user_sessions.filter((x) => Number(x.user_id) !== userId);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM USER_SESSIONS WHERE TOKEN =')) {
    const token = String(params[0] || '');
    memStore.user_sessions = memStore.user_sessions.filter((x) => x.token !== token);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // uploaded_media
  if (sUpper.startsWith('SELECT * FROM UPLOADED_MEDIA WHERE FILENAME =')) {
    const filename = String(params[0] || '');
    const found = memStore.uploaded_media.filter((m) => m.filename === filename);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM UPLOADED_MEDIA')) {
    return { rows: [...memStore.uploaded_media] as any, rowCount: memStore.uploaded_media.length };
  }
  if (sUpper.startsWith('INSERT INTO UPLOADED_MEDIA')) {
    const filename = String(params[0]);
    const mime_type = String(params[1]);
    const data_url = String(params[2]);
    const existingIdx = memStore.uploaded_media.findIndex((m) => m.filename === filename);
    const row = {
      id: existingIdx >= 0 ? memStore.uploaded_media[existingIdx].id : nextId(memStore.uploaded_media),
      filename,
      mime_type,
      data_url,
      created_at: new Date().toISOString(),
    };
    if (existingIdx >= 0) {
      memStore.uploaded_media[existingIdx] = row;
    } else {
      memStore.uploaded_media.push(row);
    }
    savePersistedStore();
    return { rows: [row as any], rowCount: 1 };
  }

  // categories
  if (sUpper.startsWith('SELECT * FROM CATEGORIES')) {
    const sorted = [...memStore.categories].sort(
      (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.id - b.id
    );
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO CATEGORIES')) {
    const newRow = {
      id: nextId(memStore.categories),
      name: params[0],
      slug: params[1],
      description: params[2] || '',
      image_url: params[3],
      featured: Boolean(params[4] ?? true),
      sort_order: Number(params[5] ?? 1),
      created_at: new Date().toISOString(),
    };
    memStore.categories.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE CATEGORIES SET')) {
    const id = Number(params[6]);
    const idx = memStore.categories.findIndex((c) => c.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.categories[idx] = {
      ...memStore.categories[idx],
      name: params[0],
      slug: params[1],
      description: params[2],
      image_url: params[3],
      featured: Boolean(params[4]),
      sort_order: Number(params[5]),
    };
    savePersistedStore();
    return { rows: [memStore.categories[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM CATEGORIES')) {
    const id = Number(params[0]);
    memStore.categories = memStore.categories.filter((c) => c.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // subcategories
  if (sUpper.startsWith('SELECT * FROM SUBCATEGORIES WHERE PARENT_CATEGORY_SLUG =')) {
    const parentSlug = String(params[0] || '');
    const filtered = memStore.subcategories
      .filter((sc) => sc.parent_category_slug === parentSlug)
      .sort((a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.id - b.id);
    return { rows: filtered as any, rowCount: filtered.length };
  }
  if (sUpper.startsWith('SELECT * FROM SUBCATEGORIES')) {
    const sorted = [...memStore.subcategories].sort(
      (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.id - b.id
    );
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO SUBCATEGORIES')) {
    const newRow = {
      id: nextId(memStore.subcategories),
      name: params[0],
      slug: params[1],
      parent_category_slug: params[2] || 'outerwear',
      description: params[3] || '',
      image_url: params[4] || '/products/overcoat.jpg',
      featured: Boolean(params[5] ?? true),
      sort_order: Number(params[6] ?? 1),
      created_at: new Date().toISOString(),
    };
    memStore.subcategories.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE SUBCATEGORIES SET')) {
    const id = Number(params[7]);
    const idx = memStore.subcategories.findIndex((c) => c.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.subcategories[idx] = {
      ...memStore.subcategories[idx],
      name: params[0],
      slug: params[1],
      parent_category_slug: params[2],
      description: params[3],
      image_url: params[4],
      featured: Boolean(params[5]),
      sort_order: Number(params[6]),
    };
    savePersistedStore();
    return { rows: [memStore.subcategories[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM SUBCATEGORIES')) {
    const id = Number(params[0]);
    memStore.subcategories = memStore.subcategories.filter((c) => c.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // banners
  if (sUpper.startsWith('SELECT * FROM BANNERS')) {
    const sorted = [...memStore.banners].sort(
      (a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0) || a.id - b.id
    );
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO BANNERS')) {
    const newRow = {
      id: nextId(memStore.banners),
      title: params[0],
      subtitle: params[1],
      badge_text: params[2],
      cta_text: params[3],
      cta_link: params[4],
      desktop_image_url: params[5],
      mobile_image_url: params[6],
      device_target: params[7] || 'both',
      theme_style: params[8] || 'burgundy-gold',
      overlay_opacity: Number(params[9] ?? 42),
      sort_order: Number(params[10] ?? 1),
      is_active: Boolean(params[11] ?? true),
      created_at: new Date().toISOString(),
    };
    memStore.banners.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE BANNERS SET')) {
    const id = Number(params[12]);
    const idx = memStore.banners.findIndex((b) => b.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.banners[idx] = {
      ...memStore.banners[idx],
      title: params[0],
      subtitle: params[1],
      badge_text: params[2],
      cta_text: params[3],
      cta_link: params[4],
      desktop_image_url: params[5],
      mobile_image_url: params[6],
      device_target: params[7],
      theme_style: params[8],
      overlay_opacity: Number(params[9]),
      sort_order: Number(params[10]),
      is_active: Boolean(params[11]),
    };
    savePersistedStore();
    return { rows: [memStore.banners[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM BANNERS')) {
    const id = Number(params[0]);
    memStore.banners = memStore.banners.filter((b) => b.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // products
  if (sUpper.startsWith('SELECT * FROM PRODUCTS WHERE ID =')) {
    const id = Number(params[0]);
    const found = memStore.products.filter((p) => p.id === id);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM PRODUCTS WHERE LOWER(SLUG) =')) {
    const slug = String(params[0] || '').trim().toLowerCase();
    const found = memStore.products.filter((p) => String(p.slug || '').toLowerCase() === slug);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM PRODUCTS')) {
    const sorted = [...memStore.products].sort(
      (a, b) => Number(b.is_featured) - Number(a.is_featured) || a.id - b.id
    );
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO PRODUCTS')) {
    const hasExtendedCols = params.length >= 20;
    const newRow = {
      id: nextId(memStore.products),
      title: params[0],
      slug: params[1],
      sku: params[2],
      category_slug: params[3],
      subcategory_slug: params[4] || '',
      price_pkr: Number(params[5]),
      compare_at_price_pkr: params[6] ? Number(params[6]) : null,
      description: params[7] || '',
      fabric_care: params[8] || '',
      image_url: params[9],
      gallery_urls:
        typeof params[10] === 'string' ? JSON.parse(params[10]) : params[10] || [params[9]],
      sizes:
        typeof params[11] === 'string'
          ? JSON.parse(params[11])
          : params[11] || ['S', 'M', 'L', 'XL'],
      colors: typeof params[12] === 'string' ? JSON.parse(params[12]) : params[12] || [],
      stock: Number(params[13] ?? 20),
      is_featured: Boolean(params[14]),
      is_new_arrival: Boolean(params[15]),
      is_bestseller: Boolean(params[16]),
      variants: hasExtendedCols
        ? typeof params[17] === 'string'
          ? JSON.parse(params[17])
          : params[17] || []
        : [],
      seo_title: hasExtendedCols ? String(params[18] || '') : `${params[0]} | Foner`,
      meta_description: hasExtendedCols ? String(params[19] || '') : String(params[7] || ''),
      rating: 4.9,
      reviews_count: 0,
      created_at: new Date().toISOString(),
    };
    memStore.products.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET VARIANTS =')) {
    const variantsVal = typeof params[0] === 'string' ? JSON.parse(params[0]) : params[0] || [];
    const newStock = Number(params[1]);
    const id = Number(params[2]);
    const p = memStore.products.find((item) => item.id === id);
    if (!p) return { rows: [], rowCount: 0 };
    p.variants = variantsVal;
    if (!Number.isNaN(newStock)) {
      p.stock = Math.max(0, newStock);
    }
    savePersistedStore();
    return { rows: [p as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET STOCK = STOCK -')) {
    const qty = Number(params[0]);
    const id = Number(params[1]);
    const p = memStore.products.find((item) => item.id === id);
    if (!p || Number(p.stock) < qty) {
      return { rows: [], rowCount: 0 };
    }
    p.stock = Number(p.stock) - qty;
    savePersistedStore();
    return { rows: [p as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET STOCK = STOCK +')) {
    const qty = Number(params[0]);
    const id = Number(params[1]);
    const p = memStore.products.find((item) => item.id === id);
    if (p) {
      p.stock = Number(p.stock) + qty;
      savePersistedStore();
    }
    return { rows: p ? [p as any] : [], rowCount: p ? 1 : 0 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET STOCK = GREATEST')) {
    const qty = Number(params[0]);
    const id = Number(params[1]);
    const p = memStore.products.find((item) => item.id === id);
    if (p) {
      p.stock = Math.max(0, Number(p.stock) - qty);
      savePersistedStore();
    }
    return { rows: p ? [p as any] : [], rowCount: p ? 1 : 0 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET REVIEWS_COUNT = REVIEWS_COUNT + 1')) {
    const id = Number(params[0]);
    const p = memStore.products.find((item) => item.id === id);
    if (p) {
      p.reviews_count = Number(p.reviews_count || 0) + 1;
      savePersistedStore();
    }
    return { rows: p ? [p as any] : [], rowCount: p ? 1 : 0 };
  }
  if (sUpper.startsWith('UPDATE PRODUCTS SET')) {
    const hasExtendedUpdate = params.length >= 21;
    const id = Number(hasExtendedUpdate ? params[20] : params[16]);
    const idx = memStore.products.findIndex((p) => p.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.products[idx] = {
      ...memStore.products[idx],
      title: params[0],
      sku: params[1],
      category_slug: params[2],
      subcategory_slug: params[3] || '',
      price_pkr: Number(params[4]),
      compare_at_price_pkr: params[5] ? Number(params[5]) : null,
      description: params[6],
      fabric_care: params[7],
      image_url: params[8],
      gallery_urls: typeof params[9] === 'string' ? JSON.parse(params[9]) : params[9],
      sizes: typeof params[10] === 'string' ? JSON.parse(params[10]) : params[10],
      colors: typeof params[11] === 'string' ? JSON.parse(params[11]) : params[11],
      stock: Number(params[12]),
      is_featured: Boolean(params[13]),
      is_new_arrival: Boolean(params[14]),
      is_bestseller: Boolean(params[15]),
      ...(hasExtendedUpdate
        ? {
            slug: String(params[16] || memStore.products[idx].slug),
            variants:
              typeof params[17] === 'string' ? JSON.parse(params[17]) : params[17] || [],
            seo_title: String(params[18] ?? ''),
            meta_description: String(params[19] ?? ''),
          }
        : {}),
    };
    savePersistedStore();
    return { rows: [memStore.products[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM PRODUCTS')) {
    const id = Number(params[0]);
    memStore.products = memStore.products.filter((p) => p.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // restock_notifications
  if (sUpper.startsWith('SELECT * FROM RESTOCK_NOTIFICATIONS WHERE PRODUCT_ID =')) {
    const pid = Number(params[0]);
    if (params.length >= 2) {
      const email = String(params[1] || '').toLowerCase();
      const found = memStore.restock_notifications.filter(
        (n) =>
          n.product_id === pid &&
          n.customer_email.toLowerCase() === email &&
          n.status === 'pending'
      );
      return { rows: found as any, rowCount: found.length };
    }
    const found = memStore.restock_notifications.filter(
      (n) => n.product_id === pid && n.status === 'pending'
    );
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM RESTOCK_NOTIFICATIONS')) {
    const sorted = [...memStore.restock_notifications].sort((a, b) => b.id - a.id);
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO RESTOCK_NOTIFICATIONS')) {
    const newRow = {
      id: nextId(memStore.restock_notifications),
      product_id: Number(params[0]),
      product_title: params[1] || '',
      product_sku: params[2] || '',
      customer_email: String(params[3] || '').trim().toLowerCase(),
      preferred_size: params[4] || '',
      preferred_color: params[5] || '',
      status: 'pending',
      notified_at: null,
      created_at: new Date().toISOString(),
    };
    memStore.restock_notifications.unshift(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE RESTOCK_NOTIFICATIONS SET STATUS =')) {
    const nowIso = new Date().toISOString();
    const updated: any[] = [];
    if (sUpper.includes('WHERE ID =')) {
      const id = Number(params[0]);
      for (const n of memStore.restock_notifications) {
        if (n.id === id) {
          n.status = 'notified';
          n.notified_at = nowIso;
          updated.push(n);
        }
      }
    } else if (sUpper.includes('WHERE PRODUCT_ID =')) {
      const pid = Number(params[0]);
      for (const n of memStore.restock_notifications) {
        if (n.product_id === pid && n.status === 'pending') {
          n.status = 'notified';
          n.notified_at = nowIso;
          updated.push(n);
        }
      }
    } else {
      for (const n of memStore.restock_notifications) {
        if (n.status === 'pending') {
          n.status = 'notified';
          n.notified_at = nowIso;
          updated.push(n);
        }
      }
    }
    savePersistedStore();
    return { rows: updated as any, rowCount: updated.length };
  }
  if (sUpper.startsWith('DELETE FROM RESTOCK_NOTIFICATIONS')) {
    const id = Number(params[0]);
    memStore.restock_notifications = memStore.restock_notifications.filter((n) => n.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // coupons
  if (sUpper.startsWith('SELECT * FROM COUPONS WHERE UPPER(CODE)')) {
    const code = String(params[0] || '').toUpperCase();
    const requireActive = sUpper.includes('IS_ACTIVE = TRUE');
    const found = memStore.coupons.filter(
      (c) => c.code.toUpperCase() === code && (!requireActive || c.is_active)
    );
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM COUPONS')) {
    return { rows: [...memStore.coupons] as any, rowCount: memStore.coupons.length };
  }
  if (sUpper.startsWith('UPDATE COUPONS SET USAGE_COUNT = USAGE_COUNT + 1')) {
    const id = Number(params[0]);
    const c = memStore.coupons.find((item) => item.id === id);
    if (c) {
      c.usage_count = Number(c.usage_count || 0) + 1;
      savePersistedStore();
    }
    return { rows: c ? [c as any] : [], rowCount: c ? 1 : 0 };
  }
  if (sUpper.startsWith('INSERT INTO COUPONS')) {
    const newRow = {
      id: nextId(memStore.coupons),
      code: params[0],
      description: params[1],
      discount_type: params[2],
      discount_value: Number(params[3]),
      min_order_pkr: Number(params[4]),
      expires_at: params[5],
      is_active: Boolean(params[6]),
      usage_limit: params[7] !== undefined && params[7] !== null && params[7] !== '' ? Number(params[7]) : null,
      per_customer_limit: params[8] !== undefined && params[8] !== null && params[8] !== '' ? Number(params[8]) : null,
      usage_count: 0,
      created_at: new Date().toISOString(),
    };
    memStore.coupons.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE COUPONS SET')) {
    const hasLimits = params.length >= 10;
    const id = Number(hasLimits ? params[9] : params[7]);
    const idx = memStore.coupons.findIndex((c) => c.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.coupons[idx] = {
      ...memStore.coupons[idx],
      code: params[0],
      description: params[1],
      discount_type: params[2],
      discount_value: Number(params[3]),
      min_order_pkr: Number(params[4]),
      expires_at: params[5],
      is_active: Boolean(params[6]),
      ...(hasLimits
        ? {
            usage_limit:
              params[7] !== undefined && params[7] !== null && params[7] !== ''
                ? Number(params[7])
                : null,
            per_customer_limit:
              params[8] !== undefined && params[8] !== null && params[8] !== ''
                ? Number(params[8])
                : null,
          }
        : {}),
    };
    savePersistedStore();
    return { rows: [memStore.coupons[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM COUPONS')) {
    const id = Number(params[0]);
    memStore.coupons = memStore.coupons.filter((c) => c.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // users
  if (sUpper.startsWith('SELECT * FROM USERS WHERE ID =')) {
    const id = Number(params[0]);
    const found = memStore.users.filter((u) => u.id === id);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM USERS WHERE LOWER(EMAIL)')) {
    const email = String(params[0] || '').toLowerCase();
    const found = memStore.users.filter((u) => u.email.toLowerCase() === email);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM USERS')) {
    return { rows: [...memStore.users] as any, rowCount: memStore.users.length };
  }
  if (sUpper.startsWith('INSERT INTO USERS')) {
    const validRoles = ['admin', 'manager', 'editor', 'customer'];
    if (sUpper.includes('PASSWORD_HASH')) {
      const isEightParamCustomerInsert =
        params.length === 8 || !validRoles.includes(String(params[7] || ''));
      const resolvedRole = isEightParamCustomerInsert
        ? 'customer'
        : validRoles.includes(String(params[7]))
        ? String(params[7])
        : 'customer';
      const resolvedStatus = isEightParamCustomerInsert
        ? 'active'
        : params[8] === 'suspended'
        ? 'suspended'
        : 'active';
      const resolvedAvatar = isEightParamCustomerInsert
        ? params[7] || '/products/overcoat.jpg'
        : params[9] || '/products/overcoat.jpg';

      const newRow = {
        id: nextId(memStore.users),
        name: params[0],
        email: String(params[1] || '').trim().toLowerCase(),
        password_hash: params[2] || '',
        phone: params[3] || '',
        city: params[4] || 'Lahore',
        address: params[5] || '',
        postal_code: params[6] || '',
        role: resolvedRole,
        status: resolvedStatus,
        avatar_url: resolvedAvatar,
        total_orders: 0,
        total_spent_pkr: 0,
        loyalty_points: 0,
        created_at: new Date().toISOString(),
      };
      memStore.users.push(newRow);
      savePersistedStore();
      return { rows: [newRow as any], rowCount: 1 };
    }
    const isAuth = sUpper.includes("'CUSTOMER', 'ACTIVE'");
    const newRow = isAuth
      ? {
          id: nextId(memStore.users),
          name: params[0],
          email: String(params[1] || '').trim().toLowerCase(),
          password_hash: '',
          phone: params[2],
          city: params[3],
          address: params[4],
          postal_code: '',
          role: 'customer',
          status: 'active',
          avatar_url: params[5] || '/products/overcoat.jpg',
          total_orders: 0,
          total_spent_pkr: 0,
          loyalty_points: 0,
          created_at: new Date().toISOString(),
        }
      : {
          id: nextId(memStore.users),
          name: params[0],
          email: String(params[1] || '').trim().toLowerCase(),
          password_hash: '',
          phone: params[2],
          city: params[3],
          address: params[4],
          postal_code: '',
          role: validRoles.includes(String(params[5])) ? params[5] : 'customer',
          status: params[6] === 'suspended' ? 'suspended' : 'active',
          avatar_url: params[7] || '/products/overcoat.jpg',
          total_orders: 0,
          total_spent_pkr: 0,
          loyalty_points: 0,
          created_at: new Date().toISOString(),
        };
    memStore.users.push(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE USERS SET TOTAL_ORDERS = TOTAL_ORDERS + 1')) {
    const spent = Number(params[0]);
    const pts = Number(params[1]);
    const target = params[2];
    for (const u of memStore.users) {
      if (
        (sUpper.includes('WHERE ID =') && u.id === Number(target)) ||
        (sUpper.includes('LOWER(EMAIL)') &&
          u.email.toLowerCase() === String(target).toLowerCase()) ||
        (sUpper.includes('LOWER(NAME)') && u.name.toLowerCase() === String(target).toLowerCase())
      ) {
        u.total_orders = Number(u.total_orders || 0) + 1;
        u.total_spent_pkr = Number(u.total_spent_pkr || 0) + spent;
        u.loyalty_points = Number(u.loyalty_points || 0) + pts;
      }
    }
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE USERS SET PASSWORD_HASH =')) {
    const newHash = String(params[0] || '');
    if (sUpper.includes('WHERE LOWER(EMAIL)')) {
      const email = String(params[1] || '').trim().toLowerCase();
      const idx = memStore.users.findIndex((u) => u.email.toLowerCase() === email);
      if (idx === -1) return { rows: [], rowCount: 0 };
      memStore.users[idx] = { ...memStore.users[idx], password_hash: newHash };
      savePersistedStore();
      return { rows: [memStore.users[idx] as any], rowCount: 1 };
    }
    const id = Number(params[1]);
    const idx = memStore.users.findIndex((u) => u.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.users[idx] = { ...memStore.users[idx], password_hash: newHash };
    savePersistedStore();
    return { rows: [memStore.users[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE USERS SET')) {
    const validRoles = ['admin', 'manager', 'editor', 'customer'];
    // Support direct role updates: UPDATE users SET role = $1 WHERE email = $2 / WHERE id = $2 or literal SQL
    if (sUpper.startsWith('UPDATE USERS SET ROLE =')) {
      let newRole = params[0] ? String(params[0]).trim().toLowerCase() : '';
      if (!newRole) {
        const roleLiteralMatch = s.match(/SET\s+role\s*=\s*'([^']+)'/i);
        if (roleLiteralMatch) newRole = roleLiteralMatch[1].trim().toLowerCase();
      }
      if (!validRoles.includes(newRole)) newRole = 'customer';

      const updatedRows: any[] = [];
      for (const u of memStore.users) {
        let match = false;
        if (sUpper.includes('EMAIL')) {
          let targetEmail = params[1] ? String(params[1]).trim().toLowerCase() : params[0] && !validRoles.includes(String(params[0]).toLowerCase()) ? String(params[0]).trim().toLowerCase() : '';
          if (!targetEmail) {
            const emailLit = s.match(/email\s*=\s*'([^']+)'/i);
            if (emailLit) targetEmail = emailLit[1].trim().toLowerCase();
          }
          if (targetEmail && u.email.toLowerCase() === targetEmail) match = true;
        } else if (sUpper.includes('WHERE ID')) {
          let targetId = params[1] !== undefined ? Number(params[1]) : NaN;
          if (Number.isNaN(targetId)) {
            const idLit = s.match(/WHERE\s+id\s*=\s*(\d+)/i);
            if (idLit) targetId = Number(idLit[1]);
          }
          if (u.id === targetId) match = true;
        } else if (!sUpper.includes('WHERE')) {
          match = true;
        }
        if (match) {
          u.role = newRole;
          updatedRows.push(u);
        }
      }
      if (updatedRows.length > 0) {
        savePersistedStore();
      }
      return { rows: updatedRows as any, rowCount: updatedRows.length };
    }
    if (sUpper.includes('PASSWORD_HASH') && params.length === 10) {
      const id = Number(params[9]);
      const idx = memStore.users.findIndex((u) => u.id === id);
      if (idx === -1) return { rows: [], rowCount: 0 };
      memStore.users[idx] = {
        ...memStore.users[idx],
        name: params[0],
        email: String(params[1] || '').trim().toLowerCase(),
        password_hash: params[2],
        phone: params[3],
        city: params[4],
        address: params[5],
        postal_code: params[6],
        role: validRoles.includes(String(params[7])) ? params[7] : 'customer',
        status: params[8] === 'suspended' ? 'suspended' : 'active',
      };
      savePersistedStore();
      return { rows: [memStore.users[idx] as any], rowCount: 1 };
    }
    if (params.length === 9) {
      const id = Number(params[8]);
      const idx = memStore.users.findIndex((u) => u.id === id);
      if (idx === -1) return { rows: [], rowCount: 0 };
      memStore.users[idx] = {
        ...memStore.users[idx],
        name: params[0],
        email: String(params[1] || '').trim().toLowerCase(),
        phone: params[2],
        city: params[3],
        address: params[4],
        postal_code: params[5],
        role: validRoles.includes(String(params[6])) ? params[6] : 'customer',
        status: params[7] === 'suspended' ? 'suspended' : 'active',
      };
      savePersistedStore();
      return { rows: [memStore.users[idx] as any], rowCount: 1 };
    }
    const id = Number(params[7]);
    const idx = memStore.users.findIndex((u) => u.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.users[idx] = {
      ...memStore.users[idx],
      name: params[0],
      email: String(params[1] || '').trim().toLowerCase(),
      phone: params[2],
      city: params[3],
      address: params[4],
      role: validRoles.includes(String(params[5])) ? params[5] : 'customer',
      status: params[6] === 'suspended' ? 'suspended' : 'active',
    };
    savePersistedStore();
    return { rows: [memStore.users[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM USERS')) {
    const id = Number(params[0]);
    memStore.users = memStore.users.filter((u) => u.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // orders
  if (sUpper.startsWith('SELECT * FROM ORDERS WHERE IDEMPOTENCY_KEY =')) {
    const key = String(params[0] || '');
    const found = memStore.orders.filter((o) => o.idempotency_key && o.idempotency_key === key);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM ORDERS WHERE UPPER(ORDER_NUMBER) =')) {
    const num = String(params[0] || '').toUpperCase().trim();
    const found = memStore.orders.filter((o) => String(o.order_number || '').toUpperCase() === num);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM ORDERS WHERE USER_ID =')) {
    const uid = Number(params[0]);
    const found = memStore.orders
      .filter((o) => Number(o.user_id) === uid)
      .sort((a, b) => b.id - a.id);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM ORDERS WHERE ID =')) {
    const id = Number(params[0]);
    const found = memStore.orders.filter((o) => o.id === id);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM ORDERS')) {
    const sorted = [...memStore.orders].sort((a, b) => b.id - a.id);
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO ORDERS')) {
    if (params.length >= 20) {
      const newRow = {
        id: nextId(memStore.orders),
        order_number: params[0],
        user_id: params[1],
        customer_name: params[2],
        customer_email: params[3],
        customer_phone: params[4],
        shipping_address: params[5],
        shipping_city: params[6],
        shipping_area: params[7] || '',
        postal_code: params[8] || '',
        order_notes: params[9] || '',
        payment_method: params[10] || 'COD',
        payment_status: params[11] || 'pending',
        order_status: params[12] || 'pending',
        subtotal_pkr: Number(params[13]),
        discount_pkr: Number(params[14]),
        coupon_code: params[15],
        delivery_fee_pkr: Number(params[16]),
        total_pkr: Number(params[17]),
        idempotency_key: params[18] || null,
        items_json: typeof params[19] === 'string' ? JSON.parse(params[19]) : params[19],
        created_at: new Date().toISOString(),
      };
      memStore.orders.unshift(newRow);
      savePersistedStore();
      return { rows: [newRow as any], rowCount: 1 };
    }
    if (sUpper.includes('IDEMPOTENCY_KEY')) {
      const newRow = {
        id: nextId(memStore.orders),
        order_number: params[0],
        user_id: params[1],
        customer_name: params[2],
        customer_email: params[3],
        customer_phone: params[4],
        shipping_address: params[5],
        shipping_city: params[6],
        shipping_area: params[7] || '',
        postal_code: params[8] || '',
        order_notes: params[9] || '',
        payment_method: 'COD',
        payment_status: params[10] || 'pending',
        order_status: params[11] || 'pending',
        subtotal_pkr: Number(params[12]),
        discount_pkr: Number(params[13]),
        coupon_code: params[14],
        delivery_fee_pkr: Number(params[15]),
        total_pkr: Number(params[16]),
        idempotency_key: params[17] || null,
        items_json: typeof params[18] === 'string' ? JSON.parse(params[18]) : params[18],
        created_at: new Date().toISOString(),
      };
      memStore.orders.unshift(newRow);
      savePersistedStore();
      return { rows: [newRow as any], rowCount: 1 };
    }
    const newRow = {
      id: nextId(memStore.orders),
      order_number: params[0],
      user_id: params[1],
      customer_name: params[2],
      customer_email: params[3],
      customer_phone: params[4],
      shipping_address: params[5],
      shipping_city: params[6],
      shipping_area: '',
      postal_code: params[7],
      order_notes: params[8],
      payment_method: params[9] || 'COD',
      payment_status: params[10] || 'pending',
      order_status: 'pending',
      subtotal_pkr: Number(params[11]),
      discount_pkr: Number(params[12]),
      coupon_code: params[13],
      delivery_fee_pkr: Number(params[14]),
      total_pkr: Number(params[15]),
      idempotency_key: null,
      items_json: typeof params[16] === 'string' ? JSON.parse(params[16]) : params[16],
      created_at: new Date().toISOString(),
    };
    memStore.orders.unshift(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE ORDERS SET')) {
    const id = Number(params[2]);
    const idx = memStore.orders.findIndex((o) => o.id === id);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.orders[idx].order_status = params[0];
    memStore.orders[idx].payment_status = params[1];
    savePersistedStore();
    return { rows: [memStore.orders[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM ORDERS')) {
    const id = Number(params[0]);
    memStore.orders = memStore.orders.filter((o) => o.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // reviews
  if (sUpper.startsWith('SELECT * FROM REVIEWS')) {
    const sorted = [...memStore.reviews].sort((a, b) => b.id - a.id);
    return { rows: sorted as any, rowCount: sorted.length };
  }
  if (sUpper.startsWith('INSERT INTO REVIEWS')) {
    const newRow = {
      id: nextId(memStore.reviews),
      product_id: Number(params[0]),
      customer_name: params[1],
      customer_city: params[2],
      rating: Number(params[3]),
      comment: params[4],
      verified_purchase: true,
      created_at: new Date().toISOString(),
    };
    memStore.reviews.unshift(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM REVIEWS')) {
    const id = Number(params[0]);
    memStore.reviews = memStore.reviews.filter((r) => r.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // audit_logs
  if (sUpper.startsWith('SELECT * FROM AUDIT_LOGS')) {
    return { rows: memStore.audit_logs.slice(0, 100) as any, rowCount: memStore.audit_logs.length };
  }
  if (sUpper.startsWith('INSERT INTO AUDIT_LOGS')) {
    const newRow = {
      id: nextId(memStore.audit_logs),
      actor_name: params[0],
      actor_role: params[1],
      action: params[2],
      entity_type: params[3],
      details: params[4],
      created_at: new Date().toISOString(),
    };
    memStore.audit_logs.unshift(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }

  // newsletter_subscribers
  if (sUpper.startsWith('SELECT * FROM NEWSLETTER_SUBSCRIBERS')) {
    return {
      rows: [...memStore.newsletter_subscribers] as any,
      rowCount: memStore.newsletter_subscribers.length,
    };
  }
  if (sUpper.startsWith('INSERT INTO NEWSLETTER_SUBSCRIBERS')) {
    const email = String(params[0] || '').toLowerCase();
    let existing = memStore.newsletter_subscribers.find((n) => n.email === email);
    if (!existing) {
      existing = {
        id: nextId(memStore.newsletter_subscribers),
        email,
        status: 'subscribed',
        created_at: new Date().toISOString(),
      };
      memStore.newsletter_subscribers.unshift(existing);
      savePersistedStore();
    }
    return { rows: [existing as any], rowCount: 1 };
  }

  // newsletter_subscribers
  if (sUpper.startsWith('SELECT * FROM NEWSLETTER_SUBSCRIBERS WHERE LOWER(EMAIL)')) {
    const email = String(params[0] || '').trim().toLowerCase();
    const found = memStore.newsletter_subscribers.filter(
      (n) => String(n.email || '').toLowerCase() === email
    );
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('SELECT * FROM NEWSLETTER_SUBSCRIBERS')) {
    return {
      rows: [...memStore.newsletter_subscribers] as any,
      rowCount: memStore.newsletter_subscribers.length,
    };
  }
  if (sUpper.startsWith('INSERT INTO NEWSLETTER_SUBSCRIBERS')) {
    const email = String(params[0] || '').toLowerCase();
    const city = params[1] ? String(params[1]) : 'Lahore';
    const unsubHash = params[2] ? String(params[2]) : '';
    let existing = memStore.newsletter_subscribers.find((n) => n.email.toLowerCase() === email);
    if (existing) {
      existing.status = 'subscribed';
      if (city) existing.city = city;
      if (unsubHash) existing.unsubscribe_token_hash = unsubHash;
      savePersistedStore();
    } else {
      existing = {
        id: nextId(memStore.newsletter_subscribers),
        email,
        city,
        status: 'subscribed',
        unsubscribe_token_hash: unsubHash,
        welcome_email_sent: false,
        created_at: new Date().toISOString(),
      };
      memStore.newsletter_subscribers.unshift(existing);
      savePersistedStore();
    }
    return { rows: [existing as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE NEWSLETTER_SUBSCRIBERS SET WELCOME_EMAIL_SENT')) {
    const sent = Boolean(params[0]);
    const idOrEmail = params[1];
    const target = memStore.newsletter_subscribers.find(
      (n) => n.id === Number(idOrEmail) || String(n.email).toLowerCase() === String(idOrEmail).toLowerCase()
    );
    if (target) {
      target.welcome_email_sent = sent;
      savePersistedStore();
    }
    return { rows: target ? [target as any] : [], rowCount: target ? 1 : 0 };
  }

  // contact_messages
  if (sUpper.startsWith('SELECT * FROM CONTACT_MESSAGES')) {
    return {
      rows: [...memStore.contact_messages] as any,
      rowCount: memStore.contact_messages.length,
    };
  }
  if (sUpper.startsWith('INSERT INTO CONTACT_MESSAGES')) {
    const newRow = {
      id: nextId(memStore.contact_messages),
      name: String(params[0] || ''),
      email: String(params[1] || ''),
      phone: String(params[2] || ''),
      subject: String(params[3] || ''),
      message: String(params[4] || ''),
      status: 'unread',
      email_sent: Boolean(params[5] ?? false),
      email_error: String(params[6] || ''),
      created_at: new Date().toISOString(),
    };
    memStore.contact_messages.unshift(newRow);
    savePersistedStore();
    return { rows: [newRow as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE CONTACT_MESSAGES SET')) {
    if (sUpper.includes('EMAIL_SENT')) {
      const emailSent = Boolean(params[0]);
      const emailErr = String(params[1] || '');
      const id = Number(params[2]);
      const item = memStore.contact_messages.find((m) => m.id === id);
      if (item) {
        item.email_sent = emailSent;
        item.email_error = emailErr;
        savePersistedStore();
      }
      return { rows: item ? [item as any] : [], rowCount: item ? 1 : 0 };
    }
    const status = String(params[0] || 'read');
    const id = Number(params[1]);
    const item = memStore.contact_messages.find((m) => m.id === id);
    if (item) {
      item.status = status;
      savePersistedStore();
    }
    return { rows: item ? [item as any] : [], rowCount: item ? 1 : 0 };
  }
  if (sUpper.startsWith('DELETE FROM CONTACT_MESSAGES')) {
    const id = Number(params[0]);
    memStore.contact_messages = memStore.contact_messages.filter((m) => m.id !== id);
    savePersistedStore();
    return { rows: [], rowCount: 1 };
  }

  // registration_otps
  if (sUpper.startsWith('SELECT * FROM REGISTRATION_OTPS')) {
    if (!sUpper.includes('WHERE') || params.length === 0) {
      const all = memStore.registration_otps || [];
      return { rows: [...all] as any, rowCount: all.length };
    }
    const email = String(params[0] || '').trim().toLowerCase();
    const found = (memStore.registration_otps || []).filter(
      (r) => r.email.toLowerCase() === email
    );
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('INSERT INTO REGISTRATION_OTPS')) {
    const email = String(params[0] || '').trim().toLowerCase();
    const otp_hash = String(params[1] || '').trim();
    const expires_at = String(params[2] || new Date(Date.now() + 600000).toISOString());
    const request_count = Number(params[3] || 1);
    if (!memStore.registration_otps) memStore.registration_otps = [];
    const existingIdx = memStore.registration_otps.findIndex(
      (r) => r.email.toLowerCase() === email
    );
    const nowIso = new Date().toISOString();
    const row = {
      email,
      otp_code: 'HASHED',
      otp_hash,
      expires_at,
      verified: false,
      attempts: 0,
      request_count,
      last_requested_at: nowIso,
      created_at: nowIso,
    };
    if (existingIdx >= 0) {
      memStore.registration_otps[existingIdx] = row;
    } else {
      memStore.registration_otps.push(row);
    }
    savePersistedStore();
    return { rows: [row as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE REGISTRATION_OTPS SET ATTEMPTS =')) {
    const email = String(params[0] || '').trim().toLowerCase();
    if (!memStore.registration_otps) memStore.registration_otps = [];
    const idx = memStore.registration_otps.findIndex((r) => r.email.toLowerCase() === email);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.registration_otps[idx] = {
      ...memStore.registration_otps[idx],
      attempts: Number(memStore.registration_otps[idx].attempts || 0) + 1,
    };
    savePersistedStore();
    return { rows: [memStore.registration_otps[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE REGISTRATION_OTPS')) {
    const email = String(params[0] || '').trim().toLowerCase();
    if (!memStore.registration_otps) memStore.registration_otps = [];
    const idx = memStore.registration_otps.findIndex((r) => r.email.toLowerCase() === email);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.registration_otps[idx] = {
      ...memStore.registration_otps[idx],
      verified: true,
    };
    savePersistedStore();
    return { rows: [memStore.registration_otps[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM REGISTRATION_OTPS')) {
    const email = String(params[0] || '').trim().toLowerCase();
    if (memStore.registration_otps) {
      memStore.registration_otps = memStore.registration_otps.filter(
        (r) => r.email.toLowerCase() !== email
      );
      savePersistedStore();
    }
    return { rows: [], rowCount: 1 };
  }

  // password_reset_tokens
  if (sUpper.startsWith('SELECT * FROM PASSWORD_RESET_TOKENS')) {
    if (!memStore.password_reset_tokens) memStore.password_reset_tokens = [];
    if (!sUpper.includes('WHERE') || params.length === 0) {
      return {
        rows: [...memStore.password_reset_tokens] as any,
        rowCount: memStore.password_reset_tokens.length,
      };
    }
    const email = String(params[0] || '').trim().toLowerCase();
    const found = memStore.password_reset_tokens.filter((r) => r.email.toLowerCase() === email);
    return { rows: found as any, rowCount: found.length };
  }
  if (sUpper.startsWith('INSERT INTO PASSWORD_RESET_TOKENS')) {
    const email = String(params[0] || '').trim().toLowerCase();
    const token_hash = String(params[1] || '').trim();
    const expires_at = String(params[2] || new Date(Date.now() + 600000).toISOString());
    const request_count = Number(params[3] || 1);
    if (!memStore.password_reset_tokens) memStore.password_reset_tokens = [];
    const existingIdx = memStore.password_reset_tokens.findIndex(
      (r) => r.email.toLowerCase() === email
    );
    const nowIso = new Date().toISOString();
    const row = {
      email,
      token_hash,
      expires_at,
      attempts: 0,
      used: false,
      request_count,
      last_requested_at: nowIso,
      created_at: nowIso,
    };
    if (existingIdx >= 0) {
      memStore.password_reset_tokens[existingIdx] = row;
    } else {
      memStore.password_reset_tokens.push(row);
    }
    savePersistedStore();
    return { rows: [row as any], rowCount: 1 };
  }
  if (sUpper.startsWith('UPDATE PASSWORD_RESET_TOKENS SET ATTEMPTS =')) {
    const email = String(params[0] || '').trim().toLowerCase();
    if (!memStore.password_reset_tokens) memStore.password_reset_tokens = [];
    const idx = memStore.password_reset_tokens.findIndex((r) => r.email.toLowerCase() === email);
    if (idx === -1) return { rows: [], rowCount: 0 };
    memStore.password_reset_tokens[idx] = {
      ...memStore.password_reset_tokens[idx],
      attempts: Number(memStore.password_reset_tokens[idx].attempts || 0) + 1,
    };
    savePersistedStore();
    return { rows: [memStore.password_reset_tokens[idx] as any], rowCount: 1 };
  }
  if (sUpper.startsWith('DELETE FROM PASSWORD_RESET_TOKENS')) {
    const email = String(params[0] || '').trim().toLowerCase();
    if (memStore.password_reset_tokens) {
      memStore.password_reset_tokens = memStore.password_reset_tokens.filter(
        (r) => r.email.toLowerCase() !== email
      );
      savePersistedStore();
    }
    return { rows: [], rowCount: 1 };
  }

  return { rows: [], rowCount: 0 };
}

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

  // Seed banners, categories, subcategories, products, coupons, users only when empty (preserves existing data)
  const bannersCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM banners');
  if (parseInt(bannersCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const b of SEED_BANNERS) {
      await pool.query(
        `INSERT INTO banners (title, subtitle, badge_text, cta_text, cta_link, desktop_image_url, mobile_image_url, device_target, theme_style, overlay_opacity, sort_order, is_active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`,
        [b.title, b.subtitle, b.badge_text, b.cta_text, b.cta_link, b.desktop_image_url, b.mobile_image_url, b.device_target, b.theme_style, b.overlay_opacity, b.sort_order, b.is_active]
      );
    }
  }

  const catCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM categories');
  if (parseInt(catCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const c of SEED_CATEGORIES) {
      await pool.query(`INSERT INTO categories (name, slug, description, image_url, featured, sort_order) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (slug) DO NOTHING`, [c.name, c.slug, c.description, c.image_url, c.featured, c.sort_order]);
    }
  }

  const subCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM subcategories');
  if (parseInt(subCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const sc of SEED_SUBCATEGORIES) {
      await pool.query(`INSERT INTO subcategories (name, slug, parent_category_slug, description, image_url, featured, sort_order) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (slug) DO NOTHING`, [sc.name, sc.slug, sc.parent_category_slug, sc.description, sc.image_url, sc.featured, sc.sort_order]);
    }
  }

  const prodCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM products');
  if (parseInt(prodCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const p of SEED_PRODUCTS) {
      await pool.query(
        `INSERT INTO products (title, slug, sku, category_slug, subcategory_slug, price_pkr, compare_at_price_pkr, description, fabric_care, image_url, gallery_urls, sizes, colors, stock, is_featured, is_new_arrival, is_bestseller, rating, reviews_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,$18,$19) ON CONFLICT (slug) DO NOTHING`,
        [p.title, p.slug, p.sku, p.category_slug, p.subcategory_slug, p.price_pkr, p.compare_at_price_pkr, p.description, p.fabric_care, p.image_url, JSON.stringify(p.gallery_urls), JSON.stringify(p.sizes), JSON.stringify(p.colors), p.stock, p.is_featured, p.is_new_arrival, p.is_bestseller, p.rating, p.reviews_count]
      );
    }
  }

  await pool.query("DELETE FROM users WHERE LOWER(email) = 'admin@foner.pk'").catch(() => {});

  const userCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM users');
  if (parseInt(userCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const u of SEED_USERS) {
      await pool.query(
        `INSERT INTO users (name, email, password_hash, phone, city, address, postal_code, role, status, avatar_url, total_orders, total_spent_pkr, loyalty_points) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (email) DO NOTHING`,
        [u.name, u.email, u.password_hash, u.phone, u.city, u.address, u.postal_code, u.role, u.status, u.avatar_url, u.total_orders, u.total_spent_pkr, u.loyalty_points]
      );
    }
  }

  const couponCountRes = await pool.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM coupons');
  if (parseInt(couponCountRes.rows[0]?.count || '0', 10) === 0) {
    for (const c of SEED_COUPONS) {
      await pool.query(`INSERT INTO coupons (code, description, discount_type, discount_value, min_order_pkr, expires_at, is_active, usage_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (code) DO NOTHING`, [c.code, c.description, c.discount_type, c.discount_value, c.min_order_pkr, c.expires_at, c.is_active, c.usage_count]);
    }
  }

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
    const hasAdmin = memStore.users.some((u) => u.role === 'admin');
    if (hasAdmin) return;

    const passwordHash = hashPassword(rawPass);
    const existingIdx = memStore.users.findIndex((u) => u.email.toLowerCase() === rawEmail);
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

