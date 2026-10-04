-- ============================================================================
-- FONER — PRODUCTION POSTGRESQL SCHEMA
-- Target Server: GHSOY-SERVER
-- Database: f | User: f_user | Local Host: 127.0.0.1:5432
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

CREATE TABLE IF NOT EXISTS registration_otps (
  email TEXT PRIMARY KEY,
  otp_code TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  attempts INTEGER NOT NULL DEFAULT 0,
  request_count INTEGER NOT NULL DEFAULT 1,
  last_requested_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  email TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used BOOLEAN NOT NULL DEFAULT false,
  last_requested_at TIMESTAMPTZ DEFAULT NOW(),
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
  stock INTEGER NOT NULL DEFAULT 25,
  is_featured BOOLEAN NOT NULL DEFAULT false,
  is_new_arrival BOOLEAN NOT NULL DEFAULT false,
  is_bestseller BOOLEAN NOT NULL DEFAULT false,
  rating NUMERIC(3,2) NOT NULL DEFAULT 4.90,
  reviews_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE products ADD COLUMN IF NOT EXISTS subcategory_slug TEXT DEFAULT '';

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
  usage_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE coupons ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

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
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_area TEXT DEFAULT '';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS confirmation_email_sent BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS contact_messages (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT DEFAULT '',
  subject TEXT DEFAULT '',
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unread',
  email_sent BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

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
  status TEXT NOT NULL DEFAULT 'subscribed',
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
