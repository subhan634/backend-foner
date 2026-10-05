import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { z } from 'zod';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import {
  dbQuery,
  withTransaction,
  hashPassword,
  hashPasswordAsync,
  verifyPassword,
  hashOtpCode,
  verifyOtpCode,
  initializeDatabase,
  checkDatabaseHealth,
  getDatabaseStatusInfo,
  logAudit,
  REQUIRED_TABLES,
  DEFAULT_FAQ_LIST,
  DEFAULT_FOOTER_SECTIONS,
  DEFAULT_INFORMATIONAL_PAGES,
} from './src/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// SECURITY & SANITIZATION HELPERS
// ============================================================================
function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeEmailHeader(input: unknown): string {
  return String(input ?? '')
    .replace(/[\r\n\0]+/g, ' ')
    .replace(/[<>"]/g, '')
    .trim()
    .slice(0, 120);
}

function sanitizeText(input: unknown, maxLen = 5000): string {
  return String(input ?? '')
    .replace(/<\s*\/?\s*(script|iframe|object|embed|applet|meta|link|style|base|form)[^>]*>/gi, '')
    .replace(/\bon[a-z]+\s*=\s*(['"][^'"]*['"]|[^\s>]+)/gi, '')
    .replace(/(javascript|vbscript|data\s*:\s*text\/html)\s*:/gi, '')
    .trim()
    .slice(0, maxLen);
}

// ============================================================================
// SMTP EMAIL TRANSPORTER (ENVIRONMENT-CONFIGURED ONLY, NO HARDCODED SECRETS)
// ============================================================================
const SMTP_HOST = sanitizeEmailHeader(process.env.SMTP_HOST || 'smtp.gmail.com');
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = sanitizeEmailHeader(process.env.SMTP_USER || '');
const RAW_SMTP_PASSWORD = String(process.env.SMTP_PASS || process.env.SMTP_PASSWORD || '');
const SMTP_PASSWORD = RAW_SMTP_PASSWORD.replace(/\s+/g, '');
const SMTP_FROM = sanitizeEmailHeader(process.env.SMTP_FROM || SMTP_USER || 'fonerera@gmail.com');
const CONTACT_RECEIVER_EMAIL = sanitizeEmailHeader(
  process.env.CONTACT_RECEIVER_EMAIL || SMTP_FROM || 'fonerera@gmail.com'
);
const IS_SMTP_CONFIGURED = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASSWORD);

const smtpTransporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  requireTLS: SMTP_PORT === 587,
  name: 'foner.pk',
  pool: true,
  maxConnections: 3,
  maxMessages: 50,
  auth: IS_SMTP_CONFIGURED
    ? {
        user: SMTP_USER,
        pass: SMTP_PASSWORD,
      }
    : undefined,
  tls: {
    servername: SMTP_HOST,
    rejectUnauthorized: true,
  },
});

if (IS_SMTP_CONFIGURED) {
  smtpTransporter
    .verify()
    .then(() => {
      console.log(`[SMTP Ready]: Connected to ${SMTP_HOST}:${SMTP_PORT}`);
    })
    .catch((err) => {
      console.warn(`[SMTP Warning]: Initial verify check:`, err?.message || 'Unable to verify SMTP');
    });
}

const OTP_EXPIRY_MINUTES = Math.max(
  3,
  Math.min(15, parseInt(process.env.OTP_EXPIRY_MINUTES || '10', 10) || 10)
);
const OTP_COOLDOWN_SECONDS = Math.max(
  30,
  Math.min(300, parseInt(process.env.OTP_COOLDOWN_SECONDS || '60', 10) || 60)
);
const MAX_OTP_ATTEMPTS = 5;
const MAX_OTP_REQUESTS_PER_WINDOW = 5;

async function sendRegistrationOtpEmail(toEmail: string, toName: string, otpCode: string) {
  const safeEmail = sanitizeEmailHeader(toEmail).toLowerCase();
  const safeName = sanitizeEmailHeader(toName);
  const firstName = escapeHtml(safeName.split(/\s+/)[0] || 'there');
  const safeOtp = escapeHtml(otpCode);
  const domainPart = SMTP_FROM.split('@')[1] || 'foner.pk';
  const messageId = `<${crypto.randomUUID()}@${domainPart}>`;

  const plainText = [
    `Hi ${safeName.split(/\s+/)[0] || 'there'},`,
    ``,
    `Thank you for creating an account with Foner.`,
    ``,
    `Your verification code is: ${otpCode}`,
    ``,
    `Please enter this 6-digit code on the registration screen within the next ${OTP_EXPIRY_MINUTES} minutes to confirm your email address.`,
    ``,
    `If you did not request this code, no further action is needed.`,
    ``,
    `Best regards,`,
    `Foner Client Care`,
    `Lahore, Pakistan`,
  ].join('\r\n');

  const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Foner Verification Code</title>
</head>
<body style="margin: 0; padding: 24px 16px; background-color: #ffffff; color: #222222; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; line-height: 1.6;">
  <div style="max-width: 480px; margin: 0 auto;">
    <p style="margin: 0 0 16px; font-size: 16px; font-weight: 600; color: #111111;">
      Foner
    </p>
    <p style="margin: 0 0 16px;">
      Hi ${firstName},
    </p>
    <p style="margin: 0 0 16px;">
      Thank you for registering with Foner. Please use the verification code below to confirm your email address:
    </p>
    <p style="margin: 20px 0; padding: 14px 18px; background-color: #f6f6f6; border-left: 4px solid #631828; font-family: 'Courier New', Courier, monospace; font-size: 24px; font-weight: 700; letter-spacing: 4px; color: #111111;">
      ${safeOtp}
    </p>
    <p style="margin: 0 0 16px; font-size: 14px; color: #444444;">
      This code is valid for ${OTP_EXPIRY_MINUTES} minutes and is single-use.
    </p>
    <p style="margin: 0 0 24px; font-size: 13px; color: #666666;">
      If you did not request this email, you can safely ignore it.
    </p>
    <hr style="border: none; border-top: 1px solid #eaeaea; margin: 20px 0;" />
    <p style="margin: 0; font-size: 12px; color: #777777;">
      Foner Client Care &bull; Nationwide Pakistan
    </p>
  </div>
</body>
</html>`;

  if (!IS_SMTP_CONFIGURED) {
    throw new Error('Transactional email service (SMTP) is not configured on the server.');
  }

  const safeFrom = SMTP_FROM || SMTP_USER || 'fonerera@gmail.com';

  const mailOptions = {
    from: safeFrom,
    to: safeName ? `"${safeName}" <${safeEmail}>` : safeEmail,
    subject: 'Your Foner verification code',
    text: plainText,
    html: htmlBody,
  };

  try {
    const result = await smtpTransporter.sendMail(mailOptions);
    return result;
  } catch (err: any) {
    const safeLog = {
      code: err?.code || 'unknown',
      message: err?.message || 'Send failed',
      responseCode: err?.responseCode || null,
      command: err?.command || null,
      response: typeof err?.response === 'string' ? err.response.substring(0, 200) : null,
    };
    console.warn('[SMTP Registration Error] sendMail failed:', safeLog);
    throw new Error('SMTP send failed: ' + (err?.message || 'Unknown error'));
  }
}

async function sendPasswordResetOtpEmail(toEmail: string, toName: string, resetCode: string) {
  if (!IS_SMTP_CONFIGURED) return false;
  const safeEmail = sanitizeEmailHeader(toEmail).toLowerCase();
  const safeName = sanitizeEmailHeader(toName);
  const firstName = escapeHtml(safeName.split(/\s+/)[0] || 'Client');
  const safeCode = escapeHtml(resetCode);

  const plainText = [
    `Hi ${safeName.split(/\s+/)[0] || 'Client'},`,
    ``,
    `We received a request to reset the password for your Foner account.`,
    ``,
    `Your password reset verification code is: ${resetCode}`,
    ``,
    `This code expires in ${OTP_EXPIRY_MINUTES} minutes and can only be used once.`,
    `If you did not request a password reset, please ignore this message — your account remains secure.`,
    ``,
    `Foner Client Care`,
  ].join('\r\n');

  const htmlBody = `<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:24px 16px;background:#ffffff;color:#222222;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:15px;line-height:1.6;">
  <div style="max-width:480px;margin:0 auto;">
    <p style="margin:0 0 16px;font-size:16px;font-weight:600;color:#430F1B;">FONER — Password Reset</p>
    <p style="margin:0 0 16px;">Hi ${firstName},</p>
    <p style="margin:0 0 16px;">Use the single-use verification code below to reset your Foner account password:</p>
    <p style="margin:20px 0;padding:14px 18px;background:#f6f6f6;border-left:4px solid #631828;font-family:monospace;font-size:24px;font-weight:700;letter-spacing:4px;color:#111111;">${safeCode}</p>
    <p style="margin:0 0 16px;font-size:13px;color:#555555;">This code expires in ${OTP_EXPIRY_MINUTES} minutes. All existing sessions will be signed out once your password is changed.</p>
  </div>
</body>
</html>`;

  try {
    await smtpTransporter.sendMail({
      from: { name: 'Foner', address: SMTP_FROM },
      to: safeEmail,
      subject: 'Foner Password Reset Verification Code',
      text: plainText,
      html: htmlBody,
    });
    return true;
  } catch (err: any) {
    console.warn('[Password Reset Email Warning]:', err?.message || 'Send failed');
    return false;
  }
}

async function sendContactNotificationEmail(inquiry: {
  name: string;
  email: string;
  phone: string;
  subject: string;
  message: string;
}): Promise<boolean> {
  if (!IS_SMTP_CONFIGURED) return false;
  const safeName = sanitizeEmailHeader(inquiry.name);
  const safeEmail = sanitizeEmailHeader(inquiry.email).toLowerCase();
  const safePhone = sanitizeEmailHeader(inquiry.phone);
  const safeSubject = sanitizeEmailHeader(inquiry.subject || 'General Inquiry');
  const escapedName = escapeHtml(inquiry.name);
  const escapedEmail = escapeHtml(inquiry.email);
  const escapedPhone = escapeHtml(inquiry.phone || 'Not provided');
  const escapedSubject = escapeHtml(inquiry.subject || 'General Inquiry');
  const escapedMessage = escapeHtml(inquiry.message).replace(/\n/g, '<br/>');

  try {
    await smtpTransporter.sendMail({
      from: { name: 'Foner Client Care', address: SMTP_FROM },
      replyTo: safeEmail,
      to: CONTACT_RECEIVER_EMAIL,
      subject: `[Foner Contact] ${safeSubject} — from ${safeName}`,
      text: `Name: ${safeName}\nEmail: ${safeEmail}\nPhone: ${safePhone}\nSubject: ${safeSubject}\n\nMessage:\n${inquiry.message}`,
      html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#FAF7F2;border:1px solid #E5DCCB;color:#181214;">
        <h2 style="margin:0 0 16px;color:#430F1B;font-size:18px;">New Contact Inquiry — Foner</h2>
        <p style="margin:4px 0;"><strong>Name:</strong> ${escapedName}</p>
        <p style="margin:4px 0;"><strong>Email:</strong> ${escapedEmail}</p>
        <p style="margin:4px 0;"><strong>Phone:</strong> ${escapedPhone}</p>
        <p style="margin:4px 0 16px;"><strong>Subject:</strong> ${escapedSubject}</p>
        <div style="padding:16px;background:#ffffff;border:1px solid #E5DCCB;border-radius:6px;line-height:1.6;">${escapedMessage}</div>
      </div>`,
    });
    return true;
  } catch (err: any) {
    console.warn('[Contact Email Warning]:', err?.message || 'Send failed');
    return false;
  }
}

async function sendNewsletterWelcomeEmail(toEmail: string): Promise<boolean> {
  if (!IS_SMTP_CONFIGURED) return false;
  const safeEmail = sanitizeEmailHeader(toEmail).toLowerCase();
  if (!safeEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(safeEmail)) return false;

  try {
    await smtpTransporter.sendMail({
      from: { name: 'Foner', address: SMTP_FROM },
      to: safeEmail,
      subject: 'Welcome to Foner — Private Releases & Seasonal Dispatches',
      text: [
        'Welcome to Foner.',
        '',
        'Your email address has been added to our private dispatch list. You will receive early access to seasonal outerwear, knitwear, and leather goods from our Lahore studio.',
        '',
        'Foner Client Care',
      ].join('\r\n'),
      html: `<div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:540px;margin:0 auto;padding:32px 24px;background:#FAF7F2;border:1px solid #E5DCCB;color:#181214;">
        <h1 style="margin:0 0 12px;font-size:22px;letter-spacing:5px;color:#430F1B;">FONER</h1>
        <p style="margin:0 0 16px;font-size:14px;line-height:1.6;color:#5A4E48;">Thank you for joining the Foner mailing list. You will be notified first when new seasonal collections and limited studio pieces arrive.</p>
        <p style="margin:0;font-size:11px;color:#8E827A;">FONER • Client Care</p>
      </div>`,
    });
    return true;
  } catch (err: any) {
    console.warn('[Newsletter Welcome Email Warning]:', err?.message || 'Send failed');
    return false;
  }
}

async function sendOrderConfirmationEmail(order: any): Promise<boolean> {
  if (!IS_SMTP_CONFIGURED) return false;
  if (order?.confirmation_email_sent) return true;

  const recipient = sanitizeEmailHeader(order?.customer_email || '').toLowerCase();
  if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) return false;

  const items: any[] = Array.isArray(order.items_json)
    ? order.items_json
    : Array.isArray(order.items)
    ? order.items
    : [];

  const itemsRowsHtml = items
    .map((item) => {
      const qty = Number(item.quantity || 1);
      const unitPrice = Number(item.price_pkr || item.unit_price_pkr || 0);
      const lineTotal = unitPrice * qty;
      const variantLabel = [
        item.selected_size && item.selected_size !== 'Standard'
          ? `Size: ${escapeHtml(item.selected_size)}`
          : '',
        item.selected_color && item.selected_color !== 'Standard'
          ? `Color: ${escapeHtml(item.selected_color)}`
          : '',
      ]
        .filter(Boolean)
        .join(' • ');
      return `
        <tr>
          <td style="padding:12px 0;border-bottom:1px solid #EFEAE1;font-size:14px;color:#181214;">
            <div style="font-weight:600;">${escapeHtml(item.title)}</div>
            ${variantLabel ? `<div style="font-size:12px;color:#7A6E67;margin-top:2px;">${variantLabel}</div>` : ''}
            ${item.sku ? `<div style="font-size:11px;color:#8E827A;font-family:monospace;">SKU: ${escapeHtml(item.sku)}</div>` : ''}
          </td>
          <td style="padding:12px 8px;border-bottom:1px solid #EFEAE1;font-size:13px;color:#5A4E48;text-align:center;">
            ${qty}
          </td>
          <td style="padding:12px 0;border-bottom:1px solid #EFEAE1;font-size:14px;font-weight:600;color:#181214;text-align:right;">
            Rs. ${lineTotal.toLocaleString()}
          </td>
        </tr>
      `;
    })
    .join('');

  const subtotal = Number(order.subtotal_pkr || 0);
  const discount = Number(order.discount_pkr || 0);
  const delivery = Number(order.delivery_fee_pkr ?? 300);
  const total = Number(order.total_pkr || 0);
  const orderDate = new Date(order.created_at || Date.now()).toLocaleDateString('en-PK', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });

  const safeOrderNum = escapeHtml(order.order_number);
  const safeCustomerName = escapeHtml(order.customer_name);
  const safeAddress = escapeHtml(order.shipping_address);
  const safeArea = order.shipping_area ? `, ${escapeHtml(order.shipping_area)}` : '';
  const safeCity = escapeHtml(order.shipping_city);
  const safePostal = order.postal_code ? ` (${escapeHtml(order.postal_code)})` : '';
  const safeCoupon = order.coupon_code ? ` (${escapeHtml(order.coupon_code)})` : '';

  const text = [
    `FONER — Order Confirmation (${order.order_number})`,
    ``,
    `Dear ${order.customer_name},`,
    `Thank you for your order with Foner. Your order ${order.order_number} has been received and is being prepared.`,
    ``,
    `Order Reference: ${order.order_number}`,
    `Order Date: ${orderDate}`,
    `Payment Method: Cash on Delivery (COD)`,
    `Shipping Address: ${order.shipping_address}${order.shipping_area ? `, ${order.shipping_area}` : ''}, ${order.shipping_city}${order.postal_code ? ` ${order.postal_code}` : ''}`,
    ``,
    `Items:`,
    ...items.map(
      (i) =>
        `- ${i.title} (${i.selected_size || 'Standard'} / ${i.selected_color || 'Standard'}) x${i.quantity} — Rs. ${(Number(i.price_pkr) * Number(i.quantity)).toLocaleString()}`
    ),
    ``,
    `Subtotal: Rs. ${subtotal.toLocaleString()}`,
    ...(discount > 0 ? [`Discount: -Rs. ${discount.toLocaleString()}`] : []),
    `Shipping: Rs. ${delivery.toLocaleString()}`,
    `Total Payable on Delivery: Rs. ${total.toLocaleString()}`,
  ].join('\n');

  const html = `
    <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;background:#FAF7F2;border:1px solid #E5DCCB;color:#181214;">
      <div style="text-align:center;padding-bottom:20px;border-bottom:1px solid #E5DCCB;">
        <h1 style="margin:0;font-size:24px;letter-spacing:6px;color:#430F1B;font-weight:700;">FONER</h1>
        <p style="margin:6px 0 0;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#8E827A;">Order Confirmation</p>
      </div>
      <div style="padding:24px 0;">
        <p style="margin:0 0 12px;font-size:15px;">Dear <strong>${safeCustomerName}</strong>,</p>
        <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#5A4E48;">
          Thank you for shopping with Foner. Your order <strong>${safeOrderNum}</strong> has been received and is now being prepared at our Lahore studio.
        </p>
        <div style="background:#FFFFFF;border:1px solid #E5DCCB;border-radius:8px;padding:16px;margin-bottom:20px;">
          <div style="font-size:12px;color:#7A6E67;margin-bottom:6px;">
            <strong>Order ID:</strong> ${safeOrderNum} &nbsp;|&nbsp; <strong>Date:</strong> ${escapeHtml(orderDate)}
          </div>
          <div style="font-size:12px;color:#7A6E67;margin-bottom:6px;">
            <strong>Payment:</strong> Cash on Delivery (COD)
          </div>
          <div style="font-size:12px;color:#7A6E67;">
            <strong>Delivery Address:</strong> ${safeAddress}${safeArea}, ${safeCity}${safePostal}
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;margin-bottom:18px;">
          <thead>
            <tr>
              <th style="text-align:left;padding-bottom:8px;border-bottom:2px solid #430F1B;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#430F1B;">Item</th>
              <th style="text-align:center;padding-bottom:8px;border-bottom:2px solid #430F1B;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#430F1B;">Qty</th>
              <th style="text-align:right;padding-bottom:8px;border-bottom:2px solid #430F1B;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#430F1B;">Total</th>
            </tr>
          </thead>
          <tbody>
            ${itemsRowsHtml}
          </tbody>
        </table>
        <div style="border-top:1px solid #E5DCCB;padding-top:12px;font-size:13px;color:#5A4E48;">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
            <span>Subtotal:</span>
            <strong>Rs. ${subtotal.toLocaleString()}</strong>
          </div>
          ${
            discount > 0
              ? `<div style="display:flex;justify-content:space-between;margin-bottom:6px;color:#1F6E43;">
                  <span>Discount${safeCoupon}:</span>
                  <strong>-Rs. ${discount.toLocaleString()}</strong>
                </div>`
              : ''
          }
          <div style="display:flex;justify-content:space-between;margin-bottom:10px;">
            <span>Shipping:</span>
            <strong>Rs. ${delivery.toLocaleString()}</strong>
          </div>
          <div style="display:flex;justify-content:space-between;padding-top:10px;border-top:1px solid #E5DCCB;font-size:16px;color:#430F1B;">
            <strong>Total (COD):</strong>
            <strong>Rs. ${total.toLocaleString()}</strong>
          </div>
        </div>
      </div>
      <div style="text-align:center;padding-top:16px;border-top:1px solid #E5DCCB;font-size:11px;color:#8E827A;">
        FONER • Nationwide Pakistan • fonerera@gmail.com
      </div>
    </div>
  `;

  try {
    await smtpTransporter.sendMail({
      from: { name: 'Foner', address: SMTP_FROM },
      to: recipient,
      subject: sanitizeEmailHeader(`Order Confirmed — ${order.order_number} | Foner`),
      text,
      html,
    });
    if (order.id) {
      await dbQuery('UPDATE orders SET confirmation_email_sent = true WHERE id = $1', [
        Number(order.id),
      ]);
    }
    return true;
  } catch (err: any) {
    console.warn(`[Order Confirmation Email Warning] (${order.order_number}):`, err?.message || 'Send failed');
    return false;
  }
}

async function sendOrderStatusUpdateEmail(order: any, newStatus: string): Promise<boolean> {
  if (!IS_SMTP_CONFIGURED) return false;
  const recipient = sanitizeEmailHeader(order?.customer_email || '').toLowerCase();
  if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) return false;

  const statusLabels: Record<string, { label: string; message: string }> = {
    pending: {
      label: 'Pending Review',
      message: 'Your order is queued for verification by our studio team.',
    },
    confirmed: {
      label: 'Confirmed',
      message: 'Your order has been verified and confirmed for fulfillment.',
    },
    processing: {
      label: 'Processing',
      message: 'Your items are currently being inspected, steamed, and packed at our studio.',
    },
    shipped: {
      label: 'Shipped / Out for Delivery',
      message: 'Your parcel has been dispatched via courier. Please keep your COD amount ready upon delivery.',
    },
    delivered: {
      label: 'Delivered',
      message: 'Your Foner order has been marked as delivered. Thank you for shopping with us!',
    },
    cancelled: {
      label: 'Cancelled',
      message: 'Your order has been cancelled. If you have any questions, please reply to this email.',
    },
  };

  const normalizedKey = String(newStatus || order.order_status || 'pending').toLowerCase();
  const statusInfo = statusLabels[normalizedKey] || {
    label: escapeHtml(normalizedKey.toUpperCase()),
    message: `Your order status has been updated to ${escapeHtml(normalizedKey.toUpperCase())}.`,
  };

  const total = Number(order.total_pkr || 0);
  const safeCustomerName = escapeHtml(order.customer_name);
  const safeOrderNum = escapeHtml(order.order_number);
  const safeAddress = escapeHtml(order.shipping_address);
  const safeArea = order.shipping_area ? `, ${escapeHtml(order.shipping_area)}` : '';
  const safeCity = escapeHtml(order.shipping_city);

  const text = [
    `FONER — Order Status Update (${order.order_number})`,
    ``,
    `Dear ${order.customer_name},`,
    `Your order ${order.order_number} status is now: ${statusInfo.label}.`,
    statusInfo.message,
    ``,
    `Order Total (COD): Rs. ${total.toLocaleString()}`,
    `Delivery Address: ${order.shipping_address}, ${order.shipping_city}`,
  ].join('\n');

  const html = `
    <div style="font-family:'Helvetica Neue',Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px 24px;background:#FAF7F2;border:1px solid #E5DCCB;color:#181214;">
      <div style="text-align:center;padding-bottom:20px;border-bottom:1px solid #E5DCCB;">
        <h1 style="margin:0;font-size:24px;letter-spacing:6px;color:#430F1B;font-weight:700;">FONER</h1>
        <p style="margin:6px 0 0;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#8E827A;">Order Status Update</p>
      </div>
      <div style="padding:24px 0;">
        <p style="margin:0 0 12px;font-size:15px;">Dear <strong>${safeCustomerName}</strong>,</p>
        <p style="margin:0 0 16px;font-size:14px;line-height:1.6;color:#5A4E48;">
          The status of your order <strong>${safeOrderNum}</strong> has been updated:
        </p>
        <div style="background:#FFFFFF;border:1px solid #E5DCCB;border-left:4px solid #430F1B;border-radius:6px;padding:16px;margin-bottom:20px;">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#8E827A;margin-bottom:4px;">Current Status</div>
          <div style="font-size:18px;font-weight:700;color:#430F1B;margin-bottom:6px;">${statusInfo.label}</div>
          <div style="font-size:13px;color:#5A4E48;line-height:1.5;">${statusInfo.message}</div>
        </div>
        <div style="font-size:13px;color:#5A4E48;line-height:1.6;">
          <div><strong>Order Reference:</strong> ${safeOrderNum}</div>
          <div><strong>Payment Method:</strong> Cash on Delivery (Rs. ${total.toLocaleString()})</div>
          <div><strong>Delivery Address:</strong> ${safeAddress}${safeArea}, ${safeCity}</div>
        </div>
      </div>
      <div style="text-align:center;padding-top:16px;border-top:1px solid #E5DCCB;font-size:11px;color:#8E827A;">
        FONER • Nationwide Pakistan • fonerera@gmail.com
      </div>
    </div>
  `;

  try {
    await smtpTransporter.sendMail({
      from: { name: 'Foner', address: SMTP_FROM },
      to: recipient,
      subject: sanitizeEmailHeader(`Order ${order.order_number} Update: ${statusInfo.label} | Foner`),
      text,
      html,
    });
    return true;
  } catch (err: any) {
    console.warn(`[Order Status Email Warning] (${order.order_number}):`, err?.message || 'Send failed');
    return false;
  }
}

async function fetchStoreSettings() {
  const res = await dbQuery<{ key: string; value: string }>('SELECT key, value FROM store_settings');
  const map: Record<string, string> = {};
  for (const row of res.rows) {
    map[row.key] = row.value;
  }
  const deliveryFee = parseInt(map.delivery_fee_pkr || '300', 10);
  const storeName = map.store_name || 'FONER';
  const taglineText =
    map.footer_description ||
    (map.tagline && !map.tagline.toLowerCase().includes('beige')
      ? map.tagline
      : 'Tailored outerwear, knitwear, and leather goods.');

  const rawContactEmail = (
    map.contactEmail ||
    map.contact_email ||
    map.business_email ||
    map.support_email ||
    ''
  ).trim();
  const contactEmail =
    !rawContactEmail || rawContactEmail.toLowerCase() === 'support@foner.pk'
      ? 'fonerera@gmail.com'
      : rawContactEmail;

  const rawPhone = (map.business_phone || map.support_phone || '').trim();
  const businessPhone =
    rawPhone.includes('8429910') || rawPhone.includes('8429911') ? '' : rawPhone;

  const rawAddress = (
    map.business_address ||
    map.atelier_address ||
    map.flagship_address ||
    ''
  ).trim();
  const businessAddress =
    rawAddress.toLowerCase().includes('mm alam road') ||
    rawAddress.toLowerCase().includes('gulberg iii')
      ? ''
      : rawAddress;

  const rawInstagram = (
    map.instagramUrl ||
    map.instagram_url ||
    map.social_instagram_url ||
    ''
  ).trim();
  const instagramUrl =
    !rawInstagram ||
    rawInstagram.toLowerCase() === 'https://instagram.com/foner' ||
    rawInstagram.toLowerCase() === 'http://instagram.com/foner' ||
    rawInstagram.toLowerCase().includes('foner.atelier.pk') ||
    rawInstagram.toLowerCase() === 'instagram (@foner)' ||
    rawInstagram.toLowerCase() === '@foner'
      ? ''
      : rawInstagram.startsWith('http://') || rawInstagram.startsWith('https://')
      ? rawInstagram
      : `https://instagram.com/${rawInstagram.replace(/^@/, '')}`;

  return {
    store_name: storeName,
    tagline: taglineText,
    footer_description: map.footer_description || taglineText,
    currency: map.currency || 'PKR',
    currency_symbol: map.currency_symbol || 'Rs.',
    delivery_fee_pkr: deliveryFee,
    announcement_bar:
      map.announcement_bar || `Nationwide delivery across Pakistan — Rs. ${deliveryFee} flat shipping`,
    announcement_bg_color: map.announcement_bg_color || '#430F1B',
    announcement_text_color: map.announcement_text_color || '#F7F3EB',
    announcement_enabled: map.announcement_enabled !== 'false',
    announcement_link: map.announcement_link || 'all',
    homepage_featured_title: map.homepage_featured_title || 'Featured',
    homepage_new_arrivals_title: map.homepage_new_arrivals_title || 'New Arrivals',
    faq_json: map.faq_json || JSON.stringify(DEFAULT_FAQ_LIST),
    footer_sections_json: map.footer_sections_json || JSON.stringify(DEFAULT_FOOTER_SECTIONS),
    pages_json: map.pages_json || JSON.stringify(DEFAULT_INFORMATIONAL_PAGES),
    footer_copyright_text:
      map.footer_copyright_text || `© ${new Date().getFullYear()} ${storeName}. All rights reserved.`,
    footer_bottom_note:
      map.footer_bottom_note || `Nationwide shipping across Pakistan — Rs. ${deliveryFee}`,
    contactEmail,
    contact_email: contactEmail,
    business_email: contactEmail,
    support_email: contactEmail,
    business_phone: businessPhone,
    support_phone: businessPhone,
    business_address: businessAddress,
    atelier_address: businessAddress,
    flagship_address: businessAddress,
    instagramUrl,
    instagram_url: instagramUrl,
    social_instagram_url: instagramUrl,
    instagram_handle:
      map.instagram_handle &&
      map.instagram_handle !== '@foner' &&
      !map.instagram_handle.toLowerCase().includes('foner.atelier.pk')
        ? map.instagram_handle
        : '',
    facebook_url:
      map.facebook_url &&
      map.facebook_url.toLowerCase() !== 'https://facebook.com/foner' &&
      !map.facebook_url.toLowerCase().includes('foner.atelier.pk')
        ? map.facebook_url
        : map.social_facebook_url &&
          map.social_facebook_url.toLowerCase() !== 'https://facebook.com/foner' &&
          !map.social_facebook_url.toLowerCase().includes('foner.atelier.pk')
        ? map.social_facebook_url
        : '',
    social_facebook_url:
      map.social_facebook_url &&
      map.social_facebook_url.toLowerCase() !== 'https://facebook.com/foner' &&
      !map.social_facebook_url.toLowerCase().includes('foner.atelier.pk')
        ? map.social_facebook_url
        : map.facebook_url &&
          map.facebook_url.toLowerCase() !== 'https://facebook.com/foner' &&
          !map.facebook_url.toLowerCase().includes('foner.atelier.pk')
        ? map.facebook_url
        : '',
    whatsapp_number:
      map.whatsapp_number &&
      !map.whatsapp_number.includes('8429910') &&
      !map.whatsapp_number.includes('8429911')
        ? map.whatsapp_number
        : map.social_whatsapp_url &&
          !map.social_whatsapp_url.includes('8429910') &&
          !map.social_whatsapp_url.includes('8429911')
        ? map.social_whatsapp_url
        : '',
    social_whatsapp_url:
      map.social_whatsapp_url &&
      !map.social_whatsapp_url.includes('8429910') &&
      !map.social_whatsapp_url.includes('8429911')
        ? map.social_whatsapp_url
        : map.whatsapp_number &&
          !map.whatsapp_number.includes('8429910') &&
          !map.whatsapp_number.includes('8429911')
        ? map.whatsapp_number
        : '',
  };
}

function slugifyText(input: string): string {
  return String(input || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function normalizeProduct(row: any) {
  const pricePkr = Number(row.price_pkr);
  const rawCompareAt = row.compare_at_price_pkr ? Number(row.compare_at_price_pkr) : null;
  const rawVariants =
    typeof row.variants === 'string'
      ? JSON.parse(row.variants || '[]')
      : Array.isArray(row.variants)
      ? row.variants
      : [];
  const normalizedVariants = rawVariants
    .filter((v: any) => v && (v.size || v.color))
    .map((v: any, idx: number) => ({
      id: v.id || `${row.sku || 'VAR'}-${idx + 1}`,
      size: String(v.size || 'Standard').trim(),
      color: String(v.color || 'Standard').trim(),
      sku: String(v.sku || `${row.sku || 'FNR'}-${String(v.color || 'STD').slice(0, 3).toUpperCase()}-${String(v.size || 'OS').toUpperCase()}`).trim(),
      stock: Math.max(0, Number(v.stock ?? 0)),
      price_pkr:
        v.price_pkr !== undefined && v.price_pkr !== null && Number(v.price_pkr) > 0
          ? Number(v.price_pkr)
          : pricePkr,
    }));

  const cleanSlug = row.slug ? slugifyText(row.slug) : slugifyText(row.title || `product-${row.id}`);

  return {
    ...row,
    id: Number(row.id),
    slug: cleanSlug,
    subcategory_slug: row.subcategory_slug || '',
    price_pkr: pricePkr,
    compare_at_price_pkr:
      rawCompareAt && rawCompareAt > pricePkr ? rawCompareAt : Math.round(pricePkr * 1.2),
    stock: Number(row.stock),
    rating: Number(row.rating || 4.9),
    reviews_count: Number(row.reviews_count || 0),
    gallery_urls:
      typeof row.gallery_urls === 'string' ? JSON.parse(row.gallery_urls) : row.gallery_urls || [],
    sizes: typeof row.sizes === 'string' ? JSON.parse(row.sizes) : row.sizes || [],
    colors: typeof row.colors === 'string' ? JSON.parse(row.colors) : row.colors || [],
    variants: normalizedVariants,
    seo_title: row.seo_title ? String(row.seo_title).trim() : `${row.title} | Foner`,
    meta_description: row.meta_description
      ? String(row.meta_description).trim()
      : String(row.description || '').trim(),
    units_sold: Number(row.units_sold || 0),
    revenue_generated_pkr: Number(row.revenue_generated_pkr || 0),
  };
}

function enrichProductsWithSales(products: any[], rawOrders: any[]): any[] {
  const salesByProductId = new Map<number, { units: number; revenue: number }>();
  const salesBySku = new Map<string, { units: number; revenue: number }>();

  for (const ord of rawOrders || []) {
    const status = String(ord.order_status || ord.status || '').toLowerCase();
    if (status === 'cancelled') continue;
    const items =
      typeof ord.items_json === 'string'
        ? JSON.parse(ord.items_json || '[]')
        : ord.items_json || ord.items || [];
    for (const item of items) {
      const pid = Number(item.product_id || 0);
      const qty = Math.max(0, Number(item.quantity || 0));
      const rev = qty * Math.max(0, Number(item.price_pkr || item.unit_price_pkr || 0));
      if (pid > 0) {
        const prev = salesByProductId.get(pid) || { units: 0, revenue: 0 };
        salesByProductId.set(pid, { units: prev.units + qty, revenue: prev.revenue + rev });
      }
      if (item.sku) {
        const baseSku = String(item.sku).trim().toUpperCase();
        const prev = salesBySku.get(baseSku) || { units: 0, revenue: 0 };
        salesBySku.set(baseSku, { units: prev.units + qty, revenue: prev.revenue + rev });
      }
    }
  }

  return products.map((p) => {
    const normalized = normalizeProduct(p);
    const byId = salesByProductId.get(normalized.id);
    const bySku = salesBySku.get(String(normalized.sku || '').toUpperCase());
    const unitsSold = byId ? byId.units : bySku ? bySku.units : 0;
    const revenueGenerated = byId ? byId.revenue : bySku ? bySku.revenue : 0;
    return {
      ...normalized,
      units_sold: unitsSold,
      revenue_generated_pkr: revenueGenerated,
    };
  });
}

function normalizeBanner(b: any) {
  return {
    ...b,
    id: Number(b.id),
    overlay_opacity: Number(b.overlay_opacity ?? 40),
    sort_order: Number(b.sort_order ?? 1),
    is_active: b.is_active !== undefined ? Boolean(b.is_active) : true,
  };
}

function normalizeCoupon(c: any) {
  return {
    ...c,
    id: Number(c.id),
    discount_value: Number(c.discount_value),
    min_order_pkr: Number(c.min_order_pkr),
    expires_at: c.expires_at ? new Date(c.expires_at).toISOString() : null,
    is_active: c.is_active !== undefined ? Boolean(c.is_active) : true,
    usage_limit:
      c.usage_limit !== undefined && c.usage_limit !== null && c.usage_limit !== ''
        ? Number(c.usage_limit)
        : null,
    per_customer_limit:
      c.per_customer_limit !== undefined &&
      c.per_customer_limit !== null &&
      c.per_customer_limit !== ''
        ? Number(c.per_customer_limit)
        : null,
    usage_count: Number(c.usage_count || 0),
  };
}

function normalizeRestockNotification(n: any) {
  return {
    ...n,
    id: Number(n.id),
    product_id: Number(n.product_id),
    product_title: n.product_title || '',
    product_sku: n.product_sku || '',
    customer_email: n.customer_email || '',
    preferred_size: n.preferred_size || '',
    preferred_color: n.preferred_color || '',
    status: n.status === 'notified' ? 'notified' : 'pending',
    notified_at: n.notified_at ? new Date(n.notified_at).toISOString() : null,
    created_at: n.created_at ? new Date(n.created_at).toISOString() : new Date().toISOString(),
  };
}

const LOYALTY_POINTS_RATE = 0.05; // 5% of total order value awarded as loyalty points

function normalizeUser(u: any) {
  const totalSpent = Number(u.total_spent_pkr || 0);
  const rawPoints =
    u.loyalty_points !== undefined && u.loyalty_points !== null ? Number(u.loyalty_points) : 0;
  const { password_hash: _ignored, ...safeUser } = u;
  const validRoles = ['admin', 'manager', 'editor', 'customer'];
  const normalizedRole = validRoles.includes(u.role) ? u.role : 'customer';
  const rawAvatarUrl = String(u.avatar_url || '').trim();
  const avatarUrl = rawAvatarUrl ? (rawAvatarUrl.startsWith('/') ? rawAvatarUrl : `/uploads/${rawAvatarUrl}`) : '';
  const avatar = avatarUrl || '/favicon.svg';
  const normalizedStatus = u.status === 'suspended' ? 'suspended' : 'active';
  return {
    ...safeUser,
    id: Number(u.id),
    role: normalizedRole,
    status: normalizedStatus,
    avatar_url: avatarUrl,
    avatar,
    postal_code: u.postal_code || '',
    total_orders: Number(u.total_orders || 0),
    total_spent_pkr: totalSpent,
    loyalty_points: rawPoints > 0 ? rawPoints : Math.round(totalSpent * LOYALTY_POINTS_RATE),
  };
}

function normalizeOrder(row: any) {
  const totalPkr = Number(row.total_pkr);
  const itemsList =
    typeof row.items_json === 'string' ? JSON.parse(row.items_json) : row.items_json || [];
  return {
    ...row,
    id: Number(row.id),
    user_id: row.user_id ? Number(row.user_id) : null,
    shipping_city: row.shipping_city || row.city || 'Lahore',
    city: row.shipping_city || row.city || 'Lahore',
    shipping_area: row.shipping_area || '',
    order_status: row.order_status || row.status || 'pending',
    status: row.order_status || row.status || 'pending',
    subtotal_pkr: Number(row.subtotal_pkr),
    discount_pkr: Number(row.discount_pkr || 0),
    delivery_fee_pkr: Number(row.delivery_fee_pkr || 300),
    total_pkr: totalPkr,
    loyalty_points_awarded:
      row.loyalty_points_awarded !== undefined
        ? Number(row.loyalty_points_awarded)
        : Math.max(1, Math.round(totalPkr * LOYALTY_POINTS_RATE)),
    items_json: itemsList,
    items: itemsList,
  };
}

function normalizeReview(r: any) {
  return {
    ...r,
    id: Number(r.id),
    product_id: Number(r.product_id),
    rating: Number(r.rating),
  };
}

const SESSION_TTL_HOURS = Math.max(
  1,
  Math.min(168, parseInt(process.env.SESSION_TTL_HOURS || '24', 10) || 24)
);
const SESSION_TTL_SECONDS = SESSION_TTL_HOURS * 3600;
const SESSION_CSRF_SECRET =
  process.env.SESSION_SECRET ||
  process.env.CSRF_SECRET ||
  'foner-csrf-hmac-key-2025-production-atelier';

function computeCsrfToken(sessionToken: string): string {
  return crypto
    .createHmac('sha256', SESSION_CSRF_SECRET)
    .update(`csrf:${sessionToken}`)
    .digest('hex');
}

function isSecureRequest(req: express.Request): boolean {
  const env = process.env.NODE_ENV;
  if (env === 'development') return false;
  if (env === 'production') return true;
  if (req.secure) return true;
  const proto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  if (proto.includes('https')) return true;
  const origin = String(req.headers.origin || '').toLowerCase();
  const referer = String(req.headers.referer || '').toLowerCase();
  return origin.startsWith('https://') || referer.startsWith('https://');
}

function getCookieSameSiteAttributes(req: express.Request): string {
  if (isSecureRequest(req)) {
    return '; SameSite=None; Secure; Partitioned';
  }
  return '; SameSite=Lax';
}

function setSessionCookies(req: express.Request, res: express.Response, token: string) {
  const cookieAttrs = getCookieSameSiteAttributes(req);
  const csrfToken = computeCsrfToken(token);
  res.setHeader('Set-Cookie', [
    `foner_session=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly${cookieAttrs}`,
    `foner_csrf=${encodeURIComponent(csrfToken)}; Path=/; Max-Age=${SESSION_TTL_SECONDS}${cookieAttrs}`,
  ]);
  return csrfToken;
}

function clearSessionCookies(req: express.Request, res: express.Response) {
  const cookieAttrs = getCookieSameSiteAttributes(req);
  res.setHeader('Set-Cookie', [
    `foner_session=; Path=/; Max-Age=0; HttpOnly${cookieAttrs}`,
    `foner_csrf=; Path=/; Max-Age=0${cookieAttrs}`,
  ]);
}

function parseCookies(req: express.Request): Record<string, string> {
  const map: Record<string, string> = {};
  const cookieHeader = req.headers.cookie;
  if (typeof cookieHeader === 'string' && cookieHeader.trim()) {
    for (const part of cookieHeader.split(';')) {
      const [rawKey, ...rawValParts] = part.trim().split('=');
      if (rawKey && rawValParts.length > 0) {
        try {
          map[rawKey.trim()] = decodeURIComponent(rawValParts.join('='));
        } catch {
          map[rawKey.trim()] = rawValParts.join('=');
        }
      }
    }
  }
  return map;
}

function extractAllSessionTokens(req: express.Request): string[] {
  const tokens: string[] = [];
  const addToken = (val: unknown) => {
    if (typeof val === 'string' && val.trim() && val.trim().length <= 256 && !tokens.includes(val.trim())) {
      tokens.push(val.trim());
    }
  };
  addToken(req.headers['x-admin-token']);
  addToken(req.headers['x-customer-token']);
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
    addToken(authHeader.slice(7));
  }
  const cookies = parseCookies(req);
  if (cookies.foner_session) {
    addToken(cookies.foner_session);
  }
  return tokens;
}

function extractCustomerToken(req: express.Request): string | null {
  const tokens = extractAllSessionTokens(req);
  return tokens[0] || null;
}

function extractAdminToken(req: express.Request): string | null {
  const tokens = extractAllSessionTokens(req);
  return tokens[0] || null;
}

async function createUserSession(userId: number, scope: 'customer' | 'admin'): Promise<string> {
  const token = `${scope}_${crypto.randomBytes(32).toString('hex')}`;
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await dbQuery(
    `INSERT INTO user_sessions (token, user_id, session_scope, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [token, userId, scope, expiresAt]
  );
  return token;
}

async function revokeAllUserSessions(userId: number): Promise<void> {
  await dbQuery('DELETE FROM user_sessions WHERE user_id = $1', [Number(userId)]);
}

// ============================================================================
// SAFE CLIENT IP DETECTION, RATE LIMITING & LOGIN LOCKOUT PROTECTION
// ============================================================================
function getClientIp(req: express.Request): string {
  const trustProxy = process.env.TRUST_PROXY === 'true' || process.env.NODE_ENV === 'production';
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      const parts = xff
        .split(',')
        .map((p) => p.trim())
        .filter((p) => /^[0-9a-fA-F:.,]+$/.test(p) && p.length <= 45);
      if (parts.length > 0) {
        return parts[0];
      }
    }
  }
  const socketIp = String(req.socket?.remoteAddress || req.ip || '127.0.0.1').trim();
  return socketIp.slice(0, 45);
}

interface RateBucket {
  count: number;
  resetAt: number;
}

function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  message?: string;
  keyPrefix: string;
}): express.RequestHandler {
  const buckets = new Map<string, RateBucket>();

  return (req, res, next) => {
    const now = Date.now();
    if (buckets.size > 5000) {
      for (const [k, v] of buckets.entries()) {
        if (v.resetAt <= now) buckets.delete(k);
      }
    }

    const ip = getClientIp(req);
    const key = `${options.keyPrefix}:${ip}`;
    const existing = buckets.get(key);

    if (!existing || existing.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.maxRequests - 1)));
      return next();
    }

    existing.count += 1;
    const remaining = Math.max(0, options.maxRequests - existing.count);
    const retryAfterSec = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(remaining));

    if (existing.count > options.maxRequests) {
      res.setHeader('Retry-After', String(retryAfterSec));
      return res.status(429).json({
        error:
          options.message ||
          `Too many requests. Please wait ${retryAfterSec} seconds before trying again.`,
      });
    }

    return next();
  };
}

const authRateLimiter = createRateLimiter({
  keyPrefix: 'auth',
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  message: 'Too many authentication attempts. Please wait a few minutes and try again.',
});

const otpRequestRateLimiter = createRateLimiter({
  keyPrefix: 'otp_req',
  windowMs: 10 * 60 * 1000,
  maxRequests: 8,
  message: 'Too many verification code requests. Please wait a few minutes before requesting another code.',
});

const otpVerifyRateLimiter = createRateLimiter({
  keyPrefix: 'otp_verify',
  windowMs: 10 * 60 * 1000,
  maxRequests: 12,
  message: 'Too many OTP verification attempts. Please wait before trying again.',
});

const contactRateLimiter = createRateLimiter({
  keyPrefix: 'contact',
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  message: 'Too many contact messages submitted recently. Please try again later.',
});

const newsletterRateLimiter = createRateLimiter({
  keyPrefix: 'newsletter',
  windowMs: 15 * 60 * 1000,
  maxRequests: 12,
  message: 'Too many subscription attempts. Please try again later.',
});

const checkoutRateLimiter = createRateLimiter({
  keyPrefix: 'checkout',
  windowMs: 10 * 60 * 1000,
  maxRequests: 20,
  message: 'Too many checkout attempts. Please wait a moment and try again.',
});

const adminMutationRateLimiter = createRateLimiter({
  keyPrefix: 'admin_mut',
  windowMs: 5 * 60 * 1000,
  maxRequests: 150,
  message: 'Admin API rate limit reached. Please wait a moment.',
});

// Account login brute-force lockout tracker
const failedLoginMap = new Map<string, { failures: number; lockedUntil: number; lastAttempt: number }>();
const MAX_LOGIN_FAILURES = 6;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

function checkLoginLockout(email: string, ip: string): { locked: boolean; retryAfterSec: number } {
  const now = Date.now();
  const key = `${email.toLowerCase()}|${ip}`;
  const entry = failedLoginMap.get(key);
  if (!entry) return { locked: false, retryAfterSec: 0 };
  if (entry.lockedUntil > now) {
    return { locked: true, retryAfterSec: Math.ceil((entry.lockedUntil - now) / 1000) };
  }
  if (now - entry.lastAttempt > LOGIN_LOCKOUT_MS) {
    failedLoginMap.delete(key);
  }
  return { locked: false, retryAfterSec: 0 };
}

function recordFailedLogin(email: string, ip: string): void {
  const now = Date.now();
  const key = `${email.toLowerCase()}|${ip}`;
  const prev = failedLoginMap.get(key) || { failures: 0, lockedUntil: 0, lastAttempt: now };
  const failures = prev.failures + 1;
  const lockedUntil = failures >= MAX_LOGIN_FAILURES ? now + LOGIN_LOCKOUT_MS : 0;
  failedLoginMap.set(key, { failures, lockedUntil, lastAttempt: now });
}

function clearFailedLogin(email: string, ip: string): void {
  failedLoginMap.delete(`${email.toLowerCase()}|${ip}`);
}

/**
 * Queries the PostgreSQL database directly (`user_sessions` + `users`) to validate
 * the active session token and retrieve the user's real-time `role` and `status`.
 * Never trusts any role supplied by the client.
 */
async function verifySessionRoleFromDb(req: express.Request): Promise<{
  authenticated: boolean;
  isAdmin: boolean;
  role: string | null;
  user: any | null;
  token?: string;
}> {
  const candidateTokens = extractAllSessionTokens(req);
  if (candidateTokens.length === 0) {
    return { authenticated: false, isAdmin: false, role: null, user: null };
  }

  for (const token of candidateTokens) {
    const sessRes = await dbQuery('SELECT * FROM user_sessions WHERE token = $1', [token]);
    if (sessRes.rows.length === 0) continue;

    const sess = sessRes.rows[0];
    if (new Date(sess.expires_at).getTime() <= Date.now()) {
      await dbQuery('DELETE FROM user_sessions WHERE token = $1', [token]);
      continue;
    }

    const userRes = await dbQuery('SELECT * FROM users WHERE id = $1', [Number(sess.user_id)]);
    if (userRes.rows.length === 0) continue;

    const dbUser = userRes.rows[0];
    if (dbUser.status === 'suspended') {
      await dbQuery('DELETE FROM user_sessions WHERE token = $1', [token]);
      continue;
    }

    const normalized = normalizeUser(dbUser);
    const isAdmin = normalized.status === 'active' && normalized.role === 'admin';
    return {
      authenticated: true,
      isAdmin,
      role: normalized.role,
      user: normalized,
      token,
    };
  }

  return { authenticated: false, isAdmin: false, role: null, user: null };
}

/**
 * Resolves the authenticated PostgreSQL user from the session token and always reads
 * their live `role` and `status` directly from the PostgreSQL `users` table.
 */
async function getAuthenticatedUser(req: express.Request): Promise<any | null> {
  const verification = await verifySessionRoleFromDb(req);
  return verification.authenticated ? verification.user : null;
}

async function getAuthenticatedCustomer(req: express.Request): Promise<any | null> {
  return getAuthenticatedUser(req);
}

/**
 * Validates that the authenticated PostgreSQL user currently holds the `admin` role in PostgreSQL.
 */
async function getAuthenticatedAdmin(req: express.Request): Promise<any | null> {
  const verification = await verifySessionRoleFromDb(req);
  if (!verification.authenticated || !verification.isAdmin) return null;
  return verification.user;
}

const requireAuth: express.RequestHandler = async (req, res, next) => {
  try {
    const verification = await verifySessionRoleFromDb(req);
    if (!verification.authenticated || !verification.user) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }
    (req as any).authUser = verification.user;
    next();
  } catch (err: any) {
    return res.status(503).json({ error: 'Authentication check failed.' });
  }
};

function requireRole(allowedRoles: string[] = ['admin']): express.RequestHandler {
  return async (req, res, next) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (
        !verification.authenticated ||
        !verification.user ||
        !verification.role ||
        !allowedRoles.includes(verification.role)
      ) {
        return res.status(403).json({
          error: 'Forbidden: Administrator privileges in PostgreSQL are required to access this resource.',
        });
      }
      (req as any).authUser = verification.user;
      (req as any).adminUser = verification.user;
      next();
    } catch {
      return res.status(503).json({ error: 'Authorization check failed.' });
    }
  };
}

const requireAdmin: express.RequestHandler = requireRole(['admin']);

function getNormalizedRequestPath(req: express.Request): string {
  const raw = String(req.originalUrl || (req.baseUrl || '') + (req.path || '') || '/').split('?')[0];
  return raw.replace(/\/+$/, '') || '/';
}

/**
 * Determines whether an incoming HTTP request targets an administrative route or operation.
 */
function isAdminProtectedRequest(req: express.Request): boolean {
  const reqPath = getNormalizedRequestPath(req);
  const method = req.method.toUpperCase();

  // Allow login/logout endpoints so users can authenticate or destroy sessions
  if (
    reqPath === '/api/admin/auth/login' ||
    reqPath === '/api/auth/admin/login' ||
    reqPath === '/api/admin/auth/logout' ||
    reqPath === '/api/auth/admin/logout'
  ) {
    return false;
  }

  // 1. All /api/admin/* endpoints
  if (reqPath === '/api/admin' || reqPath.startsWith('/api/admin/')) {
    return true;
  }

  // 2. User management, audit logs, analytics, stats, and media upload endpoints
  if (
    reqPath === '/api/users' ||
    reqPath.startsWith('/api/users/') ||
    reqPath === '/api/audit-logs' ||
    reqPath === '/api/audit_logs' ||
    reqPath === '/api/upload' ||
    reqPath === '/api/stats' ||
    reqPath === '/api/analytics/revenue'
  ) {
    return true;
  }

  // 3. Order status mutations (PATCH / PUT / DELETE on /api/orders/:id...), excluding customer reorder & cancel
  if (
    reqPath.startsWith('/api/orders/') &&
    !reqPath.startsWith('/api/orders/track/') &&
    !reqPath.endsWith('/reorder') &&
    !reqPath.endsWith('/cancel') &&
    method !== 'GET'
  ) {
    return true;
  }

  // 4. Restock notifications admin operations (GET list, DELETE, POST /notify or /send)
  if (reqPath === '/api/restock-notifications' || reqPath.startsWith('/api/restock-notifications/')) {
    if (method !== 'POST' || reqPath.includes('/notify') || reqPath.includes('/send')) {
      return true;
    }
  }

  // 5. Coupons management (only POST /api/coupons/validate is accessible to customers)
  if (reqPath === '/api/coupons' || reqPath.startsWith('/api/coupons/')) {
    if (reqPath !== '/api/coupons/validate') {
      return true;
    }
  }

  // 6. Contact & Newsletter subscriber lists (GET is admin-only; POST is public submission)
  if ((reqPath === '/api/contact' || reqPath === '/api/newsletter') && method === 'GET') {
    return true;
  }

  // 7. Catalog & Store configuration mutations (POST, PUT, PATCH, DELETE)
  if (
    method !== 'GET' &&
    method !== 'HEAD' &&
    method !== 'OPTIONS' &&
    (reqPath === '/api/products' ||
      (reqPath.startsWith('/api/products/') && !reqPath.endsWith('/notify')) ||
      reqPath === '/api/categories' ||
      reqPath.startsWith('/api/categories/') ||
      reqPath === '/api/subcategories' ||
      reqPath.startsWith('/api/subcategories/') ||
      reqPath === '/api/banners' ||
      reqPath.startsWith('/api/banners/') ||
      reqPath === '/api/settings' ||
      reqPath === '/api/store_settings' ||
      reqPath === '/api/faqs' ||
      reqPath === '/api/pages' ||
      (reqPath.startsWith('/api/reviews/') && method === 'DELETE'))
  ) {
    return true;
  }

  return false;
}

/**
 * High-level server-side authorization middleware that intercepts all admin routes,
 * verifies the session's role directly from the PostgreSQL `users` table, and
 * rejects any non-admin request with a 403 Forbidden status code.
 */
const adminRouteAuthorizationMiddleware: express.RequestHandler = async (req, res, next) => {
  try {
    const reqPath = getNormalizedRequestPath(req);

    // Intercept direct /admin non-HTML API probes when unauthenticated or non-admin
    if (reqPath === '/admin' || reqPath.startsWith('/admin/')) {
      const acceptHeader = String(req.headers.accept || '');
      const isBrowserHtmlNavigation = acceptHeader.includes('text/html');
      if (!isBrowserHtmlNavigation) {
        const verification = await verifySessionRoleFromDb(req);
        if (!verification.authenticated || !verification.isAdmin) {
          return res.status(403).json({
            error: 'Forbidden: Administrator role in PostgreSQL is required to access /admin.',
          });
        }
        (req as any).authUser = verification.user;
        (req as any).adminUser = verification.user;
      }
      return next();
    }

    if (!isAdminProtectedRequest(req)) {
      return next();
    }

    const verification = await verifySessionRoleFromDb(req);
    if (!verification.authenticated || !verification.isAdmin || !verification.user) {
      return res.status(403).json({
        error: 'Forbidden: Administrator privileges in PostgreSQL are required to access this resource.',
      });
    }

    (req as any).authUser = verification.user;
    (req as any).adminUser = verification.user;
    return next();
  } catch {
    return res.status(503).json({
      error: 'Database authorization verification failed.',
    });
  }
};

function getAllowedCorsOrigins(): Set<string> {
  const allowed = new Set<string>();

  if (process.env.NODE_ENV !== 'production') {
    allowed.add('http://localhost:3000');
    allowed.add('http://localhost:5173');
    allowed.add('http://localhost:1420');
    allowed.add('http://127.0.0.1:3000');
    allowed.add('http://127.0.0.1:5173');
    allowed.add('http://127.0.0.1:1420');
  }

  const rawEnvLists = [
    process.env.FRONTEND_URL || '',
    process.env.APP_URL || '',
    process.env.CORS_ALLOWED_ORIGINS || '',
  ];
  for (const list of rawEnvLists) {
    for (const part of list.split(',')) {
      const clean = part.trim().replace(/\/+$/, '');
      if (clean && clean !== '*') {
        allowed.add(clean);
      }
    }
  }

  return allowed;
}

function isTrustedOrigin(rawUrlOrOrigin: string, req: express.Request): boolean {
  const trimmed = String(rawUrlOrOrigin || '').trim();
  if (!trimmed) return true;

  let normalizedOrigin = trimmed.replace(/\/+$/, '');
  let hostname = '';
  try {
    const parsed = new URL(trimmed);
    normalizedOrigin = `${parsed.protocol}//${parsed.host}`;
    hostname = parsed.hostname.toLowerCase();
  } catch {
    return false;
  }

  const allowedOrigins = getAllowedCorsOrigins();
  if (allowedOrigins.has(normalizedOrigin)) return true;

  const hostHeader = String(req.headers.host || '').trim();
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  if (
    (hostHeader &&
      (normalizedOrigin === `https://${hostHeader}` ||
        normalizedOrigin === `http://${hostHeader}`)) ||
    (forwardedHost &&
      (normalizedOrigin === `https://${forwardedHost}` ||
        normalizedOrigin === `http://${forwardedHost}`))
  ) {
    return true;
  }

  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname.endsWith('.run.app') ||
    hostname.endsWith('.google.com') ||
    hostname.endsWith('.usercontent.goog') ||
    hostname.endsWith('.googleusercontent.com') ||
    hostname.endsWith('.vercel.app')
  ) {
    return true;
  }

  return false;
}

/**
 * CSRF protection for cookie-authenticated state-changing requests.
 */
const csrfProtectionMiddleware: express.RequestHandler = (req, res, next) => {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }

  const reqPath = getNormalizedRequestPath(req);
  if (!reqPath.startsWith('/api/')) {
    return next();
  }

  const cookies = parseCookies(req);
  const cookieSession = cookies.foner_session;

  // If the request is not relying on a session cookie, custom token headers are inherently CSRF-safe
  if (!cookieSession) {
    return next();
  }

  // 1. Explicit CSRF token header match
  const csrfHeader = String(req.headers['x-csrf-token'] || '').trim();
  if (csrfHeader) {
    const expectedCsrf = computeCsrfToken(cookieSession);
    if (csrfHeader === expectedCsrf || (cookies.foner_csrf && csrfHeader === cookies.foner_csrf)) {
      return next();
    }
    return res.status(403).json({ error: 'Invalid CSRF token. Please refresh the page and try again.' });
  }

  // 2. Explicit custom auth header (cannot be sent cross-origin without CORS preflight)
  if (
    req.headers['x-customer-token'] ||
    req.headers['x-admin-token'] ||
    req.headers.authorization
  ) {
    return next();
  }

  // 3. Verify same-origin / allowed-origin via Origin or Referer header + JSON Content-Type
  const originHeader = String(req.headers.origin || '').trim();
  const refererHeader = String(req.headers.referer || '').trim();
  const isAllowedOrigin =
    (!originHeader && !refererHeader) ||
    (originHeader ? isTrustedOrigin(originHeader, req) : isTrustedOrigin(refererHeader, req));

  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (isAllowedOrigin && contentType.includes('application/json')) {
    return next();
  }

  return res.status(403).json({
    error: 'CSRF verification failed for state-changing request.',
  });
};

const ALLOWED_IMAGE_MIMES: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'image/avif': 'avif',
};

function verifyImageMagicBytes(buffer: Buffer, declaredMime: string): {
  valid: boolean;
  canonicalMime: string;
  ext: string;
} {
  if (!buffer || buffer.length < 16) {
    return { valid: false, canonicalMime: '', ext: '' };
  }

  // Check for embedded script/HTML tags inside image header/body
  const headAscii = buffer.subarray(0, Math.min(512, buffer.length)).toString('utf8').toLowerCase();
  if (
    headAscii.includes('<script') ||
    headAscii.includes('<!doctype html') ||
    headAscii.includes('<html') ||
    headAscii.includes('<?php')
  ) {
    return { valid: false, canonicalMime: '', ext: '' };
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { valid: true, canonicalMime: 'image/jpeg', ext: 'jpg' };
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    // Verify PNG IHDR dimensions > 0 and <= 12000
    const width = buffer.readUInt32BE(16);
    const height = buffer.readUInt32BE(20);
    if (width <= 0 || height <= 0 || width > 12000 || height > 12000) {
      return { valid: false, canonicalMime: '', ext: '' };
    }
    return { valid: true, canonicalMime: 'image/png', ext: 'png' };
  }

  // GIF: GIF87a or GIF89a
  if (
    buffer[0] === 0x47 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x38 &&
    (buffer[4] === 0x37 || buffer[4] === 0x39) &&
    buffer[5] === 0x61
  ) {
    const width = buffer.readUInt16LE(6);
    const height = buffer.readUInt16LE(8);
    if (width <= 0 || height <= 0 || width > 12000 || height > 12000) {
      return { valid: false, canonicalMime: '', ext: '' };
    }
    return { valid: true, canonicalMime: 'image/gif', ext: 'gif' };
  }

  // WEBP: RIFF....WEBP
  if (
    buffer[0] === 0x52 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x46 &&
    buffer[8] === 0x57 &&
    buffer[9] === 0x45 &&
    buffer[10] === 0x42 &&
    buffer[11] === 0x50
  ) {
    return { valid: true, canonicalMime: 'image/webp', ext: 'webp' };
  }

  // AVIF: ....ftypavif or ....ftypavis
  const ftyp = buffer.subarray(4, 12).toString('ascii');
  if (ftyp.startsWith('ftypavi') || ftyp.startsWith('ftypmif1')) {
    return { valid: true, canonicalMime: 'image/avif', ext: 'avif' };
  }

  const ext = ALLOWED_IMAGE_MIMES[declaredMime.toLowerCase()];
  if (!ext) {
    return { valid: false, canonicalMime: '', ext: '' };
  }
  return { valid: false, canonicalMime: '', ext: '' };
}

async function startServer() {
  try {
    const initInfo = await initializeDatabase();
    console.log(
      `[Database Ready]: database="${initInfo.database_name}" user="${initInfo.database_user}" host=${initInfo.host}:${initInfo.port}`
    );
  } catch (err: any) {
    console.warn('[Database Startup Status]:', err.message);
  }

  const app = express();
  app.disable('x-powered-by');

  // Production Security Headers (compatible with AI Studio preview iframe & standalone production)
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (process.env.X_FRAME_OPTIONS) {
      res.setHeader('X-Frame-Options', process.env.X_FRAME_OPTIONS);
    }
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (isSecureRequest(req)) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    const frameAncestors = process.env.CSP_FRAME_ANCESTORS || '*';
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self' https: http: data: blob: 'unsafe-inline' 'unsafe-eval'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: http: blob: data:",
        "style-src 'self' 'unsafe-inline' https: http:",
        "font-src 'self' https: http: data:",
        "img-src 'self' data: blob: https: http:",
        "connect-src 'self' https: http: ws: wss: data: blob:",
        "worker-src 'self' blob: data: https: http:",
        "frame-src 'self' https: http: data: blob:",
        `frame-ancestors ${frameAncestors}`,
        "base-uri 'self'",
        "object-src 'none'",
      ].join('; ')
    );
    next();
  });

  // Strict CORS Policy (trusts configured origins, same-host, and AI Studio / Cloud Run preview domains)
  app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin) {
      const normalizedOrigin = origin.replace(/\/+$/, '');
      if (isTrustedOrigin(normalizedOrigin, req)) {
        res.setHeader('Access-Control-Allow-Origin', normalizedOrigin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
        res.setHeader(
          'Access-Control-Allow-Headers',
          'Content-Type, Authorization, Accept, X-Customer-Token, X-Admin-Token, X-CSRF-Token'
        );
      } else if (req.method === 'OPTIONS') {
        return res.status(403).end();
      }
    }

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }
    next();
  });

  app.use(express.json({ limit: '12mb' }));
  app.use(csrfProtectionMiddleware);

  // High-level server-side authorization interceptor for all /api/admin/* and administrative routes
  app.use('/api/admin', adminRouteAuthorizationMiddleware);
  app.use(adminRouteAuthorizationMiddleware);

  // ============================================================================
  // UPLOADED MEDIA SERVING & DEVICE IMAGE UPLOAD (HARDENED AGAINST TRAVERSAL)
  // ============================================================================
  const candidateUploadDirs = [
    path.resolve(__dirname, '../frontend/public/uploads'),
    path.resolve(process.cwd(), 'frontend/public/uploads'),
    path.resolve(__dirname, 'public/uploads'),
  ];
  let uploadsDir = candidateUploadDirs[0];
  for (const dir of candidateUploadDirs) {
    if (fs.existsSync(dir)) {
      uploadsDir = dir;
      break;
    }
  }
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }

  const SAFE_UPLOAD_FILENAME_REGEX = /^[a-zA-Z0-9_-]{1,80}\.(jpg|jpeg|png|webp|gif|avif)$/;

  app.get('/uploads/:filename', async (req, res) => {
    try {
      const rawParam = String(req.params.filename || '').trim();
      if (
        !rawParam ||
        rawParam.includes('..') ||
        rawParam.includes('/') ||
        rawParam.includes('\\') ||
        rawParam.includes('\0') ||
        !SAFE_UPLOAD_FILENAME_REGEX.test(rawParam)
      ) {
        return res.status(400).send('Invalid filename');
      }

      const safeName = path.basename(rawParam);
      const resolvedPath = path.resolve(uploadsDir, safeName);
      if (!resolvedPath.startsWith(uploadsDir + path.sep)) {
        return res.status(403).send('Forbidden');
      }

      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");

      if (fs.existsSync(resolvedPath)) {
        return res.sendFile(resolvedPath);
      }
      const mediaRes = await dbQuery('SELECT * FROM uploaded_media WHERE filename = $1', [safeName]);
      if (mediaRes.rows.length > 0) {
        const media = mediaRes.rows[0];
        const match = String(media.data_url || '').match(/^data:([^;]+);base64,(.+)$/);
        if (match) {
          const mimeType = ALLOWED_IMAGE_MIMES[match[1].toLowerCase()] ? match[1].toLowerCase() : 'image/jpeg';
          const buffer = Buffer.from(match[2], 'base64');
          res.setHeader('Content-Type', mimeType);
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          return res.send(buffer);
        }
      }
      return res.status(404).send('Image not found');
    } catch {
      return res.status(404).send('Image not found');
    }
  });

  const MAX_UPLOAD_BYTES = 8 * 1024 * 1024; // 8 MB max per image

  const uploadMediaHandler: express.RequestHandler = async (req, res) => {
    try {
      const { data_url } = req.body || {};
      if (!data_url || typeof data_url !== 'string' || !data_url.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Valid image data_url is required.' });
      }
      const match = data_url.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,([A-Za-z0-9+/=\r\n]+)$/);
      if (!match) {
        return res.status(400).json({ error: 'Invalid base64 image format.' });
      }
      const declaredMime = match[1].toLowerCase();
      if (!ALLOWED_IMAGE_MIMES[declaredMime]) {
        return res.status(400).json({
          error: 'Unsupported image format. Only JPEG, PNG, WebP, GIF, and AVIF images are allowed.',
        });
      }

      const buffer = Buffer.from(match[2], 'base64');
      if (buffer.length === 0 || buffer.length > MAX_UPLOAD_BYTES) {
        return res.status(400).json({
          error: 'Image size must be between 1 byte and 8 MB.',
        });
      }

      const magicCheck = verifyImageMagicBytes(buffer, declaredMime);
      if (!magicCheck.valid) {
        return res.status(400).json({
          error: 'Invalid or corrupted image file signature.',
        });
      }

      const uniqueFilename = `foner_${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${magicCheck.ext}`;
      const resolvedPath = path.resolve(uploadsDir, uniqueFilename);
      if (!resolvedPath.startsWith(uploadsDir + path.sep)) {
        return res.status(400).json({ error: 'Invalid storage path.' });
      }

      fs.writeFileSync(resolvedPath, buffer, { mode: 0o644 });
      const normalizedDataUrl = `data:${magicCheck.canonicalMime};base64,${buffer.toString('base64')}`;

      await dbQuery(
        `INSERT INTO uploaded_media (filename, mime_type, data_url)
         VALUES ($1, $2, $3)
         ON CONFLICT (filename) DO UPDATE SET mime_type = EXCLUDED.mime_type, data_url = EXCLUDED.data_url`,
        [uniqueFilename, magicCheck.canonicalMime, normalizedDataUrl]
      );

      return res.status(201).json({
        url: `/uploads/${uniqueFilename}`,
        filename: uniqueFilename,
      });
    } catch {
      return res.status(500).json({ error: 'Image upload failed.' });
    }
  };

  app.post('/api/upload', adminMutationRateLimiter, adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, uploadMediaHandler);
  app.post('/api/admin/upload', adminMutationRateLimiter, adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, uploadMediaHandler);

  // ============================================================================
  // ============================================================================
  // HEALTH CHECK (REAL BACKEND CONNECTION TEST)
  // ============================================================================
  app.get('/api/health', async (_req, res) => {
    try {
      const health = await checkDatabaseHealth();
      return res.status(200).json({
        status: 'ok',
        backend: 'connected',
        database: health.ok ? 'connected' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime_seconds: Math.floor(process.uptime()),
      });
    } catch {
      return res.status(200).json({
        status: 'ok',
        backend: 'connected',
        database: 'error',
        timestamp: new Date().toISOString(),
      });
    }
  });

  // ============================================================================
  // CUSTOMER AUTHENTICATION (/api/auth/*) — COMPLETELY SEPARATE FROM ADMIN
  // ============================================================================
  const emailSchema = z.string().trim().toLowerCase().email().max(160);

  app.post('/api/auth/send-otp', otpRequestRateLimiter, async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      const cleanName = sanitizeText(req.body?.name || '', 100);

      if (!parsedEmail.success) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
      }
      cleanEmail = parsedEmail.data;

      // Prevent duplicate account registration on an already-registered email
      const existingUserRes = await dbQuery('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (existingUserRes.rows.length > 0) {
        return res.status(409).json({
          error: 'An account with this email address already exists. Please sign in instead.',
        });
      }

      // Enforce cooldown & request frequency limits per email
      const existingOtpRes = await dbQuery(
        'SELECT * FROM registration_otps WHERE LOWER(email) = LOWER($1)',
        [cleanEmail]
      );
      if (existingOtpRes.rows.length > 0) {
        const prevOtp = existingOtpRes.rows[0];
        const lastRequestedMs = new Date(
          prevOtp.last_requested_at || prevOtp.created_at || 0
        ).getTime();
        const elapsedSec = Math.floor((Date.now() - lastRequestedMs) / 1000);
        if (elapsedSec < OTP_COOLDOWN_SECONDS) {
          const waitSec = OTP_COOLDOWN_SECONDS - elapsedSec;
          return res.status(429).json({
            error: `Please wait ${waitSec} seconds before requesting another verification code.`,
            retry_after_seconds: waitSec,
          });
        }

        const withinWindow = Date.now() - new Date(prevOtp.created_at || 0).getTime() < 15 * 60 * 1000;
        if (withinWindow && Number(prevOtp.request_count || 1) >= MAX_OTP_REQUESTS_PER_WINDOW) {
          return res.status(429).json({
            error: 'Maximum OTP requests reached for this email. Please wait 15 minutes and try again.',
          });
        }
      }

      // Cryptographically secure 6-digit OTP
      const otpCode = String(crypto.randomInt(100000, 1000000));
      const otpHash = hashOtpCode(cleanEmail, otpCode, 'register');
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();

      await dbQuery(
        `INSERT INTO registration_otps (email, otp_code, expires_at, verified, attempts, request_count, last_requested_at, created_at)
         VALUES ($1, $2, $3, false, 0, 1, NOW(), NOW())
         ON CONFLICT (email) DO UPDATE SET
           otp_code = EXCLUDED.otp_code,
           expires_at = EXCLUDED.expires_at,
           verified = false,
           attempts = 0,
           request_count = COALESCE(registration_otps.request_count, 1) + 1,
           last_requested_at = NOW(),
           created_at = NOW()`,
        [cleanEmail, otpHash, expiresAt]
      );

      await sendRegistrationOtpEmail(cleanEmail, cleanName, otpCode);

      return res.status(200).json({
        success: true,
        expires_in_seconds: OTP_EXPIRY_MINUTES * 60,
        cooldown_seconds: OTP_COOLDOWN_SECONDS,
        message: `A 6-digit verification code has been sent to ${cleanEmail}.`,
      });
    } catch (err: any) {
      // Safe cleanup: if email delivery failed, remove misleading active OTP
      try {
        await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
      } catch {
        // ignore cleanup error
      }
      const safeLog = {
        error_type: 'registration_otp_send_failed',
        email_domain: cleanEmail ? cleanEmail.split('@')[1] || '' : '',
        smtp_error_code: err?.code || 'unknown',
        smtp_message: err?.message || 'Send failed',
        response_code: err?.responseCode || null,
      };
      console.warn('[SMTP Registration OTP Error]', safeLog);
      return res.status(500).json({
        error: 'Unable to send verification OTP email right now. Please verify the email address and try again.',
      });
    }
  });

  app.post('/api/auth/verify-otp', otpVerifyRateLimiter, async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      const cleanOtp = String(req.body?.otp || '').trim();

      if (!parsedEmail.success || !/^\d{6}$/.test(cleanOtp)) {
        return res.status(400).json({ error: 'Valid email and 6-digit OTP code are required.' });
      }
      cleanEmail = parsedEmail.data;

      const otpRes = await dbQuery('SELECT * FROM registration_otps WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (otpRes.rows.length === 0) {
        return res.status(400).json({
          error: 'No active verification code found for this email. Please request a new OTP.',
        });
      }

      const record = otpRes.rows[0];
      if (new Date(record.expires_at).getTime() <= Date.now()) {
        await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
        return res.status(400).json({
          error: 'Your verification code has expired. Please request a new OTP.',
        });
      }

      const attempts = Number(record.attempts || 0);
      if (attempts >= MAX_OTP_ATTEMPTS) {
        await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
        return res.status(429).json({
          error: 'Too many failed verification attempts. Please request a new OTP code.',
        });
      }

      const isMatch = verifyOtpCode(cleanEmail, cleanOtp, String(record.otp_code || ''), 'register');
      if (!isMatch) {
        const nextAttempts = attempts + 1;
        if (nextAttempts >= MAX_OTP_ATTEMPTS) {
          await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
          return res.status(429).json({
            error: 'Too many incorrect attempts. Your verification code has been invalidated.',
          });
        }
        await dbQuery(
          'UPDATE registration_otps SET attempts = COALESCE(attempts, 0) + 1 WHERE LOWER(email) = LOWER($1)',
          [cleanEmail]
        );
        return res.status(400).json({
          error: `Invalid verification code. ${MAX_OTP_ATTEMPTS - nextAttempts} attempt(s) remaining.`,
        });
      }

      await dbQuery('UPDATE registration_otps SET verified = true WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);

      return res.status(200).json({
        verified: true,
        message: 'Email verified! You can now complete registration.',
      });
    } catch {
      return res.status(500).json({ error: 'Failed to verify OTP.' });
    }
  });

  const registerSchema = z.object({
    name: z.string().trim().min(2, 'Full name must be at least 2 characters.').max(120),
    email: z.string().trim().toLowerCase().email('Please enter a valid email address.').max(160),
    password: z.string().min(6, 'Password must be at least 6 characters.').max(128),
    phone: z.string().trim().max(40).optional().default(''),
    city: z.string().trim().max(80).optional().default('Lahore'),
    address: z.string().trim().max(300).optional().default(''),
    postal_code: z.string().trim().max(24).optional().default(''),
    otp: z.string().trim().optional().default(''),
  });

  const registerHandler: express.RequestHandler = async (req, res) => {
    try {
      const parsed = registerSchema.safeParse(req.body || {});
      if (!parsed.success) {
        const firstIssue = parsed.error.issues[0];
        return res.status(400).json({ error: firstIssue?.message || 'Invalid registration data.' });
      }

      const {
        name: rawName,
        email: cleanEmail,
        password: rawPassword,
        phone,
        city,
        address,
        postal_code,
        otp: cleanOtp,
      } = parsed.data;
      const cleanName = sanitizeText(rawName, 120);

      // Strictly prevent duplicate accounts with an already-used email
      const existing = await dbQuery('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (existing.rows.length > 0) {
        return res.status(409).json({
          error: 'An account with this email address already exists. Please sign in instead.',
        });
      }

      // Verify OTP from registration_otps table to confirm the user owns the email
      const otpRes = await dbQuery('SELECT * FROM registration_otps WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (otpRes.rows.length === 0) {
        return res.status(400).json({
          error: 'Please verify your email address with the 6-digit OTP code before registering.',
          require_otp: true,
        });
      }
      const otpRecord = otpRes.rows[0];

      if (new Date(otpRecord.expires_at).getTime() <= Date.now()) {
        await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
        return res.status(400).json({
          error: 'Your OTP code has expired. Please request a new verification code.',
          require_otp: true,
        });
      }

      if (Number(otpRecord.attempts || 0) >= MAX_OTP_ATTEMPTS) {
        await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
        return res.status(429).json({
          error: 'Maximum OTP verification attempts exceeded. Please request a new code.',
          require_otp: true,
        });
      }

      const otpMatches =
        cleanOtp &&
        /^\d{6}$/.test(cleanOtp) &&
        verifyOtpCode(cleanEmail, cleanOtp, String(otpRecord.otp_code || ''), 'register');

      if (!otpRecord.verified && !otpMatches) {
        await dbQuery(
          'UPDATE registration_otps SET attempts = COALESCE(attempts, 0) + 1 WHERE LOWER(email) = LOWER($1)',
          [cleanEmail]
        );
        return res.status(400).json({
          error: 'Invalid verification OTP code. Please enter the 6-digit code sent to your email.',
          require_otp: true,
        });
      }

      // Single-use OTP: invalidate immediately upon verification
      await dbQuery('DELETE FROM registration_otps WHERE LOWER(email) = LOWER($1)', [cleanEmail]);

      const passwordHash = await hashPasswordAsync(rawPassword);

      const insertRes = await dbQuery(
        `INSERT INTO users (
          name, email, password_hash, phone, city, address, postal_code, role, status, avatar_url
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *`,
        [
          cleanName,
          cleanEmail,
          passwordHash,
          sanitizeText(phone || '', 40),
          sanitizeText(city || 'Lahore', 80),
          sanitizeText(address || '', 300),
          sanitizeText(postal_code || '', 24),
          'customer',
          'active',
          '/products/overcoat.jpg',
        ]
      );
      const savedUser = insertRes.rows[0];

      const resolvedUser = normalizeUser(savedUser);
      const token = await createUserSession(Number(resolvedUser.id), 'customer');
      const csrfToken = setSessionCookies(req, res, token);

      await logAudit(
        cleanName,
        'customer',
        'USER_REGISTERED',
        'users',
        `Customer registered & email OTP verified: ${cleanEmail}`
      );

      return res.status(201).json({
        token,
        csrf_token: csrfToken,
        user: resolvedUser,
      });
    } catch {
      return res.status(503).json({ error: 'Registration failed. Please try again.' });
    }
  };

  app.post('/api/auth/register', authRateLimiter, registerHandler);
  app.post('/api/auth/customer/register', authRateLimiter, registerHandler);

  const loginHandler: express.RequestHandler = async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      const rawPassword = String(req.body?.password || '');

      if (!parsedEmail.success || !rawPassword || rawPassword.length > 128) {
        return res.status(400).json({ error: 'Valid email and password are required.' });
      }
      cleanEmail = parsedEmail.data;
      const clientIp = getClientIp(req);

      const lockout = checkLoginLockout(cleanEmail, clientIp);
      if (lockout.locked) {
        res.setHeader('Retry-After', String(lockout.retryAfterSec));
        return res.status(429).json({
          error: `Too many failed sign-in attempts. Please wait ${Math.ceil(lockout.retryAfterSec / 60)} minute(s) before trying again.`,
        });
      }

      const existing = await dbQuery('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
      if (existing.rows.length === 0) {
        recordFailedLogin(cleanEmail, clientIp);
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      const user = existing.rows[existing.rows.length - 1];

      const pwVerification = await verifyPassword(rawPassword, String(user.password_hash || ''));
      if (!pwVerification.valid) {
        recordFailedLogin(cleanEmail, clientIp);
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      if (user.status === 'suspended') {
        return res.status(403).json({ error: 'This account is currently suspended.' });
      }

      clearFailedLogin(cleanEmail, clientIp);

      // Transparently upgrade legacy password hashes to bcrypt on successful authentication
      if (pwVerification.needsRehash) {
        const upgradedHash = await hashPasswordAsync(rawPassword);
        await dbQuery('UPDATE users SET password_hash = $1 WHERE id = $2', [
          upgradedHash,
          Number(user.id),
        ]);
      }

      const normalized = normalizeUser(user);
      const sessionScope = normalized.role === 'admin' ? 'admin' : 'customer';
      const token = await createUserSession(Number(normalized.id), sessionScope);
      const csrfToken = setSessionCookies(req, res, token);

      await logAudit(
        normalized.name,
        normalized.role,
        normalized.role === 'admin' ? 'ADMIN_LOGIN' : 'CUSTOMER_LOGIN',
        'users',
        `User signed in: ${normalized.email} (role: ${normalized.role})`
      );

      return res.status(200).json({
        token,
        csrf_token: csrfToken,
        user: normalized,
      });
    } catch {
      return res.status(503).json({ error: 'Sign in failed. Please try again.' });
    }
  };

  app.post('/api/auth/login', authRateLimiter, loginHandler);
  app.post('/api/auth/customer/login', authRateLimiter, loginHandler);

  // ============================================================================
  // PASSWORD RESET FLOW (SINGLE-USE HASHED TOKEN, SHORT EXPIRY, SESSION REVOCATION)
  // ============================================================================
  const requestPasswordResetHandler: express.RequestHandler = async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      if (!parsedEmail.success) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
      }
      cleanEmail = parsedEmail.data;

      // Generic message to prevent account enumeration
      const genericResponse = {
        success: true,
        message:
          'If an account is registered with that email address, a 6-digit password reset code has been sent.',
      };

      const userRes = await dbQuery('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (userRes.rows.length === 0) {
        return res.status(200).json(genericResponse);
      }

      const user = userRes.rows[userRes.rows.length - 1];
      if (user.status === 'suspended') {
        return res.status(200).json(genericResponse);
      }

      const existingResetRes = await dbQuery(
        'SELECT * FROM password_reset_tokens WHERE LOWER(email) = LOWER($1)',
        [cleanEmail]
      );
      if (existingResetRes.rows.length > 0) {
        const prev = existingResetRes.rows[0];
        const lastReqMs = new Date(prev.last_requested_at || prev.created_at || 0).getTime();
        if (Date.now() - lastReqMs < OTP_COOLDOWN_SECONDS * 1000) {
          return res.status(200).json(genericResponse);
        }
      }

      const resetCode = String(crypto.randomInt(100000, 1000000));
      const tokenHash = hashOtpCode(cleanEmail, resetCode, 'reset');
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();

      await dbQuery(
        `INSERT INTO password_reset_tokens (email, token_hash, expires_at, attempts, used, last_requested_at, created_at)
         VALUES ($1, $2, $3, 0, false, NOW(), NOW())
         ON CONFLICT (email) DO UPDATE SET
           token_hash = EXCLUDED.token_hash,
           expires_at = EXCLUDED.expires_at,
           attempts = 0,
           used = false,
           last_requested_at = NOW(),
           created_at = NOW()`,
        [cleanEmail, tokenHash, expiresAt]
      );

      await sendPasswordResetOtpEmail(cleanEmail, user.name || 'Client', resetCode);

      await logAudit(
        user.name || cleanEmail,
        user.role || 'customer',
        'PASSWORD_RESET_REQUESTED',
        'users',
        `Password reset verification code requested for ${cleanEmail}`
      );

      return res.status(200).json(genericResponse);
    } catch {
      return res.status(503).json({ error: 'Unable to process password reset request right now.' });
    }
  };

  app.post('/api/auth/password-reset/request', otpRequestRateLimiter, requestPasswordResetHandler);
  app.post('/api/auth/forgot-password', otpRequestRateLimiter, requestPasswordResetHandler);

  const confirmPasswordResetHandler: express.RequestHandler = async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      const cleanOtp = String(req.body?.otp || req.body?.code || req.body?.token || '').trim();
      const rawNewPassword =
        req.body?.newPassword !== undefined
          ? req.body.newPassword
          : req.body?.new_password !== undefined
          ? req.body.new_password
          : req.body?.password !== undefined
          ? req.body.password
          : '';
      const newPassword = String(rawNewPassword);

      if (!parsedEmail.success || !/^\d{6}$/.test(cleanOtp)) {
        return res.status(400).json({
          error: 'Valid email address and 6-digit verification code are required.',
        });
      }
      if (newPassword.length < 6 || newPassword.length > 128) {
        return res.status(400).json({
          error: 'New password must be between 6 and 128 characters.',
        });
      }
      cleanEmail = parsedEmail.data;

      const tokenRes = await dbQuery(
        'SELECT * FROM password_reset_tokens WHERE LOWER(email) = LOWER($1)',
        [cleanEmail]
      );
      if (tokenRes.rows.length === 0) {
        return res.status(400).json({
          error: 'Invalid or expired password reset code.',
        });
      }

      const tokenRow = tokenRes.rows[0];
      if (
        tokenRow.used ||
        new Date(tokenRow.expires_at).getTime() <= Date.now() ||
        Number(tokenRow.attempts || 0) >= MAX_OTP_ATTEMPTS
      ) {
        await dbQuery('DELETE FROM password_reset_tokens WHERE LOWER(email) = LOWER($1)', [
          cleanEmail,
        ]);
        return res.status(400).json({
          error: 'This password reset code has expired or been invalidated. Please request a new code.',
        });
      }

      const validCode = verifyOtpCode(
        cleanEmail,
        cleanOtp,
        String(tokenRow.token_hash || ''),
        'reset'
      );
      if (!validCode) {
        const nextAttempts = Number(tokenRow.attempts || 0) + 1;
        if (nextAttempts >= MAX_OTP_ATTEMPTS) {
          await dbQuery('DELETE FROM password_reset_tokens WHERE LOWER(email) = LOWER($1)', [
            cleanEmail,
          ]);
        } else {
          await dbQuery(
            'UPDATE password_reset_tokens SET attempts = COALESCE(attempts, 0) + 1 WHERE LOWER(email) = LOWER($1)',
            [cleanEmail]
          );
        }
        return res.status(400).json({ error: 'Invalid or expired password reset code.' });
      }

      // Single-use: immediately delete reset token
      await dbQuery('DELETE FROM password_reset_tokens WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);

      const userRes = await dbQuery('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (userRes.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired password reset code.' });
      }

      const user = userRes.rows[userRes.rows.length - 1];
      const newPasswordHash = await hashPasswordAsync(newPassword);

      await dbQuery('UPDATE users SET password_hash = $1 WHERE id = $2', [
        newPasswordHash,
        Number(user.id),
      ]);

      // Invalidate all existing sessions for this user after password reset
      await revokeAllUserSessions(Number(user.id));
      clearSessionCookies(req, res);

      await logAudit(
        user.name || cleanEmail,
        user.role || 'customer',
        'PASSWORD_RESET_COMPLETED',
        'users',
        `Password reset completed & all active sessions revoked for ${cleanEmail}`
      );

      return res.status(200).json({
        success: true,
        message: 'Your password has been reset successfully. Please sign in with your new password.',
      });
    } catch {
      return res.status(503).json({ error: 'Unable to reset password right now.' });
    }
  };

  app.post('/api/auth/password-reset/confirm', authRateLimiter, confirmPasswordResetHandler);
  app.post('/api/auth/reset-password', authRateLimiter, confirmPasswordResetHandler);

  const meHandler: express.RequestHandler = async (req, res) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (!verification.authenticated || !verification.user) {
        return res.status(401).json({ authenticated: false, error: 'Not authenticated.' });
      }
      const csrfToken = verification.token ? computeCsrfToken(verification.token) : undefined;
      return res.status(200).json({
        authenticated: true,
        csrf_token: csrfToken,
        user: normalizeUser(verification.user),
      });
    } catch {
      return res.status(503).json({ error: 'Unable to verify session.' });
    }
  };

  app.get('/api/auth/me', meHandler);
  app.get('/api/auth/customer/me', meHandler);

  const logoutHandler: express.RequestHandler = async (req, res) => {
    try {
      const tokens = extractAllSessionTokens(req);
      for (const token of tokens) {
        await dbQuery('DELETE FROM user_sessions WHERE token = $1', [token]);
      }
      clearSessionCookies(req, res);
      return res.status(200).json({ success: true });
    } catch {
      return res.status(503).json({ error: 'Logout failed.' });
    }
  };

  app.post('/api/auth/logout', logoutHandler);
  app.post('/api/auth/customer/logout', logoutHandler);

  // Avatar endpoints — reuse existing upload validation; only authenticated user can modify own avatar
  const avatarPatchHandler: express.RequestHandler = async (req, res) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (!verification.authenticated || !verification.user) {
        return res.status(401).json({ error: 'Not authenticated.' });
      }
      const userId = Number(verification.user.id);
      const { data_url } = req.body || {};
      if (!data_url || typeof data_url !== 'string' || !data_url.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Valid image data_url is required.' });
      }
      const match = data_url.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,([A-Za-z0-9+/=\r\n]+)$/);
      if (!match) {
        return res.status(400).json({ error: 'Invalid base64 image format.' });
      }
      const declaredMime = match[1].toLowerCase();
      if (!ALLOWED_IMAGE_MIMES[declaredMime]) {
        return res.status(400).json({ error: 'Unsupported image format.' });
      }
      const buffer = Buffer.from(match[2], 'base64');
      if (!buffer || buffer.length === 0 || buffer.length > 2 * 1024 * 1024) {
        return res.status(400).json({ error: 'Image must be between 1 byte and 2 MB.' });
      }
      const magicCheck = verifyImageMagicBytes(buffer, declaredMime);
      if (!magicCheck.valid) {
        return res.status(400).json({ error: 'Invalid or corrupted image file signature.' });
      }
      const uniqueFilename = `avatar_${userId}_${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${magicCheck.ext}`;
      const uploadsDir = path.resolve(__dirname, '..', 'uploads');
      const resolvedPath = path.resolve(uploadsDir, uniqueFilename);
      if (!resolvedPath.startsWith(uploadsDir + path.sep)) {
        return res.status(400).json({ error: 'Invalid storage path.' });
      }
      if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
      fs.writeFileSync(resolvedPath, buffer, { mode: 0o644 });
      const normalizedDataUrl = `data:${magicCheck.canonicalMime};base64,${buffer.toString('base64')}`;
      await dbQuery(
        `INSERT INTO uploaded_media (filename, mime_type, data_url)
         VALUES ($1, $2, $3)
         ON CONFLICT (filename) DO UPDATE SET mime_type = EXCLUDED.mime_type, data_url = EXCLUDED.data_url`,
        [uniqueFilename, magicCheck.canonicalMime, normalizedDataUrl]
      );
      await dbQuery('UPDATE users SET avatar_url = $1 WHERE id = $2', [uniqueFilename, userId]);
      const updated = await dbQuery('SELECT * FROM users WHERE id = $1', [userId]);
      return res.status(200).json({ success: true, user: normalizeUser(updated.rows[0]), avatar_url: uniqueFilename });
    } catch (err: any) {
      console.error('[Avatar Patch Error]', err?.message || err);
      return res.status(500).json({ error: 'Avatar upload failed.' });
    }
  };

  const avatarDeleteHandler: express.RequestHandler = async (req, res) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (!verification.authenticated || !verification.user) {
        return res.status(401).json({ error: 'Not authenticated.' });
      }
      const userId = Number(verification.user.id);
      const userRes = await dbQuery('SELECT avatar_url FROM users WHERE id = $1', [userId]);
      if (userRes.rows.length === 0) {
        return res.status(404).json({ error: 'User not found.' });
      }
      const oldFile = String(userRes.rows[0].avatar_url || '').trim();
      if (oldFile) {
        await dbQuery('UPDATE users SET avatar_url = \'\' WHERE id = $1', [userId]);
        try {
          const uploadsDir = path.resolve(__dirname, '..', 'uploads');
          const resolvedPath = path.resolve(uploadsDir, oldFile);
          if (resolvedPath.startsWith(uploadsDir + path.sep) && fs.existsSync(resolvedPath)) {
            fs.unlinkSync(resolvedPath);
          }
        } catch {
          // ignore cleanup errors
        }
      }
      const updated = await dbQuery('SELECT * FROM users WHERE id = $1', [userId]);
      return res.status(200).json({ success: true, user: normalizeUser(updated.rows[0]) });
    } catch (err: any) {
      console.error('[Avatar Delete Error]', err?.message || err);
      return res.status(500).json({ error: 'Avatar removal failed.' });
    }
  };

  app.patch('/api/auth/avatar', requireAuth, avatarPatchHandler);
  app.delete('/api/auth/avatar', requireAuth, avatarDeleteHandler);

  app.put('/api/auth/profile', requireAuth, async (req, res) => {
    try {
      const user = (req as any).authUser;
      const { name, phone, city, address, postal_code } = req.body || {};
      const cleanName = name ? sanitizeText(name, 120) : user.name;
      const cleanPhone = phone !== undefined ? sanitizeText(phone, 40) : user.phone || '';
      const cleanCity = city ? sanitizeText(city, 80) : user.city || 'Lahore';
      const cleanAddress = address !== undefined ? sanitizeText(address, 300) : user.address || '';
      const cleanPostal =
        postal_code !== undefined ? sanitizeText(postal_code, 24) : user.postal_code || '';

      const result = await dbQuery(
        `UPDATE users SET
          name = $1,
          email = $2,
          phone = $3,
          city = $4,
          address = $5,
          postal_code = $6,
          role = $7,
          status = $8
        WHERE id = $9
        RETURNING *`,
        [
          cleanName,
          user.email,
          cleanPhone,
          cleanCity,
          cleanAddress,
          cleanPostal,
          user.role,
          user.status || 'active',
          Number(user.id),
        ]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Account not found.' });
      }
      return res.status(200).json(normalizeUser(result.rows[0]));
    } catch {
      return res.status(503).json({ error: 'Unable to update profile.' });
    }
  });

  // ============================================================================
  // ADMIN AUTHENTICATION (/api/admin/auth/* & /api/auth/admin/*)
  // ============================================================================
  const adminLoginHandler: express.RequestHandler = async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      const rawPassword = String(req.body?.password || '');

      if (!parsedEmail.success || !rawPassword || rawPassword.length > 128) {
        return res.status(400).json({ error: 'Admin email and password are required.' });
      }
      cleanEmail = parsedEmail.data;
      const clientIp = getClientIp(req);

      const lockout = checkLoginLockout(cleanEmail, clientIp);
      if (lockout.locked) {
        res.setHeader('Retry-After', String(lockout.retryAfterSec));
        return res.status(429).json({
          error: `Too many failed sign-in attempts. Please wait ${Math.ceil(lockout.retryAfterSec / 60)} minute(s).`,
        });
      }

      const existing = await dbQuery('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
      if (existing.rows.length === 0) {
        recordFailedLogin(cleanEmail, clientIp);
        return res.status(401).json({ error: 'Invalid credentials.' });
      }

      const user = existing.rows[existing.rows.length - 1];
      const pwVerification = await verifyPassword(rawPassword, String(user.password_hash || ''));
      if (!pwVerification.valid) {
        recordFailedLogin(cleanEmail, clientIp);
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
      if (user.role !== 'admin') {
        recordFailedLogin(cleanEmail, clientIp);
        return res.status(403).json({ error: 'Forbidden: This account does not have administrative privileges.' });
      }
      if (user.status !== 'active') {
        return res.status(403).json({ error: 'This admin account is suspended.' });
      }

      clearFailedLogin(cleanEmail, clientIp);

      if (pwVerification.needsRehash) {
        const upgradedHash = await hashPasswordAsync(rawPassword);
        await dbQuery('UPDATE users SET password_hash = $1 WHERE id = $2', [
          upgradedHash,
          Number(user.id),
        ]);
      }

      const token = await createUserSession(Number(user.id), 'admin');
      const csrfToken = setSessionCookies(req, res, token);
      await logAudit(user.name, user.role, 'ADMIN_LOGIN', 'users', `Admin signed in: ${user.email}`);

      return res.status(200).json({
        token,
        csrf_token: csrfToken,
        user: normalizeUser(user),
      });
    } catch {
      return res.status(503).json({ error: 'Admin login failed.' });
    }
  };

  app.post('/api/admin/auth/login', authRateLimiter, adminLoginHandler);
  app.post('/api/auth/admin/login', authRateLimiter, adminLoginHandler);

  const adminMeHandler: express.RequestHandler = async (req, res) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (!verification.authenticated || !verification.isAdmin || !verification.user) {
        return res.status(403).json({
          authenticated: false,
          error: 'Forbidden: Administrator role in PostgreSQL is required.',
        });
      }
      const csrfToken = verification.token ? computeCsrfToken(verification.token) : undefined;
      return res.status(200).json({
        authenticated: true,
        csrf_token: csrfToken,
        user: verification.user,
      });
    } catch {
      return res.status(503).json({ error: 'Unable to verify admin session.' });
    }
  };

  app.get('/api/admin/auth/me', adminRouteAuthorizationMiddleware, requireAdmin, adminMeHandler);
  app.get('/api/auth/admin/me', adminRouteAuthorizationMiddleware, requireAdmin, adminMeHandler);

  app.post('/api/admin/auth/logout', logoutHandler);
  app.post('/api/auth/admin/logout', logoutHandler);

  const changeAdminCredentialsHandler: express.RequestHandler = async (req, res) => {
    try {
      const verification = await verifySessionRoleFromDb(req);
      if (!verification.authenticated || !verification.isAdmin || !verification.user) {
        return res.status(403).json({
          error: 'Forbidden: Administrator privileges in PostgreSQL are required.',
        });
      }
      const adminUser = verification.user;

      const currentPassword = String(req.body?.currentPassword || req.body?.current_password || '');
      const rawNewEmail = req.body?.newEmail !== undefined ? req.body.newEmail : req.body?.new_email;
      const rawNewPassword =
        req.body?.newPassword !== undefined
          ? req.body.newPassword
          : req.body?.new_password !== undefined
          ? req.body.new_password
          : req.body?.password !== undefined
          ? req.body.password
          : undefined;

      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required to update admin credentials.' });
      }

      // Verify current password against stored bcrypt hash in PostgreSQL
      const pwVerification = await verifyPassword(currentPassword, String(adminUser.password_hash || ''));
      if (!pwVerification.valid) {
        return res.status(401).json({ error: 'Current password does not match.' });
      }

      let updatedEmail = adminUser.email;
      if (rawNewEmail !== undefined && String(rawNewEmail).trim() !== '') {
        const parsedEmail = emailSchema.safeParse(rawNewEmail);
        if (!parsedEmail.success) {
          return res.status(400).json({ error: 'Please enter a valid new email address.' });
        }
        const cleanNewEmail = parsedEmail.data;
        // Ensure no conflicting account has this email
        const conflictRes = await dbQuery(
          'SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id != $2 LIMIT 1',
          [cleanNewEmail, Number(adminUser.id)]
        );
        if (conflictRes.rows.length > 0) {
          return res.status(400).json({ error: 'This email is already in use by another account.' });
        }
        updatedEmail = cleanNewEmail;
      }

      let updatedPasswordHash = adminUser.password_hash;
      if (rawNewPassword !== undefined && String(rawNewPassword) !== '') {
        const newPassword = String(rawNewPassword);
        if (newPassword.length < 6 || newPassword.length > 128) {
          return res.status(400).json({ error: 'New password must be between 6 and 128 characters.' });
        }
        updatedPasswordHash = await hashPasswordAsync(newPassword);
      }

      // Execute update in PostgreSQL
      const updateRes = await dbQuery(
        `UPDATE users
         SET email = $1, password_hash = $2
         WHERE id = $3
         RETURNING *`,
        [updatedEmail, updatedPasswordHash, Number(adminUser.id)]
      );

      if (updateRes.rows.length === 0) {
        return res.status(404).json({ error: 'Admin account not found in database.' });
      }

      const updatedRow = updateRes.rows[0];

      // Invalidate all other sessions for this user so old sessions can no longer be used
      const currentToken = verification.token || '';
      if (currentToken) {
        await dbQuery(
          'DELETE FROM user_sessions WHERE user_id = $1 AND token != $2',
          [Number(adminUser.id), currentToken]
        );
      }

      await logAudit(
        updatedRow.name,
        'admin',
        'CHANGE_ADMIN_CREDENTIALS',
        'users',
        `Admin credentials updated in PostgreSQL for ${updatedRow.email}`
      );

      return res.status(200).json({
        success: true,
        message: 'Admin credentials updated successfully.',
        user: normalizeUser(updatedRow),
      });
    } catch {
      return res.status(503).json({ error: 'Unable to update admin credentials right now.' });
    }
  };

  app.put('/api/admin/credentials', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, changeAdminCredentialsHandler);
  app.post('/api/admin/credentials', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, changeAdminCredentialsHandler);
  app.put('/api/admin/auth/credentials', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, changeAdminCredentialsHandler);
  app.post('/api/admin/auth/credentials', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, changeAdminCredentialsHandler);

  // ============================================================================
  // BOOTSTRAP STORE DATA
  // ============================================================================
  const bootstrapHandler: express.RequestHandler = async (req, res) => {
    try {
      const authUser = await getAuthenticatedUser(req);
      const isAdminUser = Boolean(authUser && authUser.role === 'admin');

      const [
        settings,
        categoriesRes,
        subcategoriesRes,
        bannersRes,
        productsRes,
        couponsRes,
        reviewsRes,
        allOrdersForSalesRes,
      ] = await Promise.all([
        fetchStoreSettings(),
        dbQuery('SELECT * FROM categories ORDER BY sort_order ASC, id ASC'),
        dbQuery('SELECT * FROM subcategories ORDER BY sort_order ASC, id ASC'),
        dbQuery('SELECT * FROM banners ORDER BY sort_order ASC, id ASC'),
        dbQuery('SELECT * FROM products ORDER BY is_featured DESC, id ASC'),
        dbQuery('SELECT * FROM coupons ORDER BY id ASC'),
        dbQuery('SELECT * FROM reviews ORDER BY id DESC'),
        dbQuery('SELECT * FROM orders ORDER BY id DESC'),
      ]);

      let restockList: any[] = [];
      let usersList: any[] = [];
      let ordersList: any[] = [];
      let auditList: any[] = [];
      let dbStatusInfo: any = null;

      if (isAdminUser) {
        const [restockRes, usersRes, auditRes, dbStatus] = await Promise.all([
          dbQuery('SELECT * FROM restock_notifications ORDER BY id DESC'),
          dbQuery('SELECT * FROM users ORDER BY id ASC'),
          dbQuery('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 40'),
          getDatabaseStatusInfo(),
        ]);
        restockList = restockRes.rows.map(normalizeRestockNotification);
        usersList = usersRes.rows.map(normalizeUser);
        ordersList = allOrdersForSalesRes.rows.map(normalizeOrder);
        auditList = auditRes.rows;
        dbStatusInfo = dbStatus;
      } else if (authUser) {
        const myOrdersRes = await dbQuery('SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC', [
          Number(authUser.id),
        ]);
        ordersList = myOrdersRes.rows.map(normalizeOrder);
      }

      const bannersList = bannersRes.rows.map(normalizeBanner);
      const categoriesList = categoriesRes.rows;
      const subcategoriesList = subcategoriesRes.rows;
      const rawProductsRows = productsRes.rows;
      const productsList = enrichProductsWithSales(rawProductsRows, allOrdersForSalesRes.rows);

      res.json({
        settings,
        categories: categoriesList,
        subcategories: subcategoriesList,
        banners: bannersList,
        products: productsList,
        restockNotifications: restockList,
        coupons: isAdminUser ? couponsRes.rows.map(normalizeCoupon) : [],
        users: usersList,
        orders: ordersList,
        reviews: reviewsRes.rows.map(normalizeReview),
        auditLogs: auditList,
        dbStatus: dbStatusInfo,
      });
    } catch (err: any) {
      console.warn('[Bootstrap Status]:', err.message);
      res.status(503).json({
        error: err.message || 'Database connection failed',
        database: 'disconnected',
      });
    }
  };

  app.get('/api/bootstrap', bootstrapHandler);
  app.get('/api/admin/bootstrap', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, bootstrapHandler);

  // ============================================================================
  // PRODUCTS ENDPOINTS (/api/products & /api/admin/products)
  // ============================================================================
  app.get('/api/products', async (req, res) => {
    try {
      const [prodRes, ordersRes] = await Promise.all([
        dbQuery('SELECT * FROM products ORDER BY is_featured DESC, id ASC'),
        dbQuery('SELECT * FROM orders ORDER BY id DESC'),
      ]);
      let items = enrichProductsWithSales(prodRes.rows, ordersRes.rows);

      const q = String(req.query.q || req.query.search || '').trim().toLowerCase();
      const cat = String(req.query.category || '').trim().toLowerCase();
      const subcat = String(req.query.subcategory || '').trim().toLowerCase();
      const minPrice = req.query.minPrice !== undefined ? Number(req.query.minPrice) : null;
      const maxPrice = req.query.maxPrice !== undefined ? Number(req.query.maxPrice) : null;
      const sort = String(req.query.sort || '').trim().toLowerCase();

      if (cat && cat !== 'all') {
        items = items.filter((p) => String(p.category_slug || '').toLowerCase() === cat);
      }
      if (subcat && subcat !== 'all') {
        items = items.filter((p) => String(p.subcategory_slug || '').toLowerCase() === subcat);
      }
      if (minPrice !== null && !Number.isNaN(minPrice)) {
        items = items.filter((p) => Number(p.price_pkr) >= minPrice);
      }
      if (maxPrice !== null && !Number.isNaN(maxPrice) && maxPrice > 0) {
        items = items.filter((p) => Number(p.price_pkr) <= maxPrice);
      }
      if (q) {
        items = items.filter((p) => {
          const haystack = [
            p.title,
            p.sku,
            p.category_slug,
            p.subcategory_slug,
            p.description,
            ...(Array.isArray(p.variants) ? p.variants.map((v: any) => v.sku) : []),
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          return haystack.includes(q);
        });
      }

      if (sort === 'price-asc' || sort === 'price_asc') {
        items.sort((a, b) => a.price_pkr - b.price_pkr);
      } else if (sort === 'price-desc' || sort === 'price_desc') {
        items.sort((a, b) => b.price_pkr - a.price_pkr);
      } else if (sort === 'newest') {
        items.sort((a, b) => b.id - a.id);
      } else if (sort === 'bestseller' || sort === 'popular') {
        items.sort(
          (a, b) =>
            Number(b.units_sold || 0) - Number(a.units_sold || 0) ||
            Number(b.is_bestseller) - Number(a.is_bestseller) ||
            b.rating - a.rating
        );
      }

      res.json(items);
    } catch (err: any) {
      res.status(503).json({ error: 'Unable to load products right now. Please try again.' });
    }
  });

  app.get('/api/products/:idOrSlug', async (req, res) => {
    try {
      const param = String(req.params.idOrSlug || '').trim();
      const [prodRes, ordersRes] = await Promise.all([
        dbQuery('SELECT * FROM products ORDER BY id ASC'),
        dbQuery('SELECT * FROM orders ORDER BY id DESC'),
      ]);
      const allProducts = enrichProductsWithSales(prodRes.rows, ordersRes.rows);
      const numericId = Number(param);
      const target = allProducts.find(
        (p) =>
          (!Number.isNaN(numericId) && p.id === numericId) ||
          String(p.slug || '').toLowerCase() === param.toLowerCase()
      );
      if (!target) {
        return res.status(404).json({ error: 'Product not found.' });
      }

      // Compute related products prioritized by: 1) Same subcategory, 2) Same category, 3) Similar/relevant
      const relatedProducts = allProducts
        .filter((p) => p.id !== target.id && Number(p.stock) >= 0)
        .map((p) => {
          let score = 0;
          if (
            target.subcategory_slug &&
            p.subcategory_slug &&
            p.subcategory_slug === target.subcategory_slug
          ) {
            score += 100;
          }
          if (p.category_slug === target.category_slug) {
            score += 50;
          }
          if (Number(p.stock) > 0) {
            score += 10;
          }
          return { product: p, score };
        })
        .sort((a, b) => b.score - a.score || Number(b.product.units_sold || 0) - Number(a.product.units_sold || 0))
        .slice(0, 4)
        .map((item) => item.product);

      return res.json({
        ...target,
        related_products: relatedProducts,
      });
    } catch {
      return res.status(503).json({ error: 'Unable to load product details right now.' });
    }
  });

  const createProductHandler: express.RequestHandler = async (req, res) => {
    try {
      const {
        title,
        slug: rawSlug,
        sku,
        category_slug,
        subcategory_slug,
        price_pkr,
        compare_at_price_pkr,
        description,
        fabric_care,
        image_url,
        gallery_urls,
        sizes,
        colors,
        variants,
        seo_title,
        meta_description,
        stock,
        is_featured,
        is_new_arrival,
        is_bestseller,
      } = req.body || {};

      if (!title || typeof title !== 'string' || !image_url || price_pkr === undefined) {
        return res.status(400).json({ error: 'Product title, image_url, and price_pkr are required.' });
      }

      const allProdsRes = await dbQuery('SELECT id, slug FROM products');
      const existingSlugs = new Set(
        allProdsRes.rows.map((r: any) => String(r.slug || '').toLowerCase())
      );

      let cleanSlug = slugifyText(rawSlug || title);
      if (!cleanSlug) {
        cleanSlug = `product-${Date.now().toString().slice(-4)}`;
      }
      if (rawSlug && String(rawSlug).trim()) {
        if (existingSlugs.has(cleanSlug.toLowerCase())) {
          return res.status(400).json({
            error: `The URL slug "${cleanSlug}" is already in use by another product. Please choose a unique slug.`,
          });
        }
      } else {
        let suffix = 2;
        const baseSlug = cleanSlug;
        while (existingSlugs.has(cleanSlug.toLowerCase())) {
          cleanSlug = `${baseSlug}-${suffix}`;
          suffix += 1;
        }
      }

      const normalizedVariants = Array.isArray(variants)
        ? variants
            .filter((v: any) => v && (v.size || v.color))
            .map((v: any, idx: number) => ({
              id: v.id || `${sku || 'FNR'}-V${idx + 1}`,
              size: String(v.size || 'Standard').trim(),
              color: String(v.color || 'Standard').trim(),
              sku: String(
                v.sku ||
                  `${sku || 'FNR'}-${String(v.color || 'STD')
                    .slice(0, 3)
                    .toUpperCase()}-${String(v.size || 'OS').toUpperCase()}`
              ).trim(),
              stock: Math.max(0, Number(v.stock ?? 0)),
              price_pkr:
                v.price_pkr !== undefined && v.price_pkr !== null && Number(v.price_pkr) > 0
                  ? Number(v.price_pkr)
                  : Number(price_pkr),
            }))
        : [];

      const computedStock =
        normalizedVariants.length > 0
          ? normalizedVariants.reduce((sum: number, v: any) => sum + Number(v.stock || 0), 0)
          : Math.max(0, Number(stock ?? 20));

      const cleanSeoTitle = seo_title ? String(seo_title).trim() : `${title.trim()} | Foner`;
      const cleanMetaDesc = meta_description
        ? String(meta_description).trim()
        : String(description || '').trim();

      const result = await dbQuery(
        `INSERT INTO products (
          title, slug, sku, category_slug, subcategory_slug, price_pkr, compare_at_price_pkr,
          description, fabric_care, image_url, gallery_urls, sizes, colors,
          stock, is_featured, is_new_arrival, is_bestseller, variants, seo_title, meta_description
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7,
          $8, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb,
          $14, $15, $16, $17, $18::jsonb, $19, $20
        ) RETURNING *`,
        [
          title.trim(),
          cleanSlug,
          sku || `FNR-${Math.floor(100 + Math.random() * 900)}`,
          category_slug || 'outerwear',
          subcategory_slug || '',
          Number(price_pkr),
          compare_at_price_pkr ? Number(compare_at_price_pkr) : null,
          description || '',
          fabric_care || 'Specialist dry clean recommended.',
          image_url.trim(),
          JSON.stringify(gallery_urls?.length ? gallery_urls : [image_url]),
          JSON.stringify(sizes?.length ? sizes : ['S', 'M', 'L', 'XL']),
          JSON.stringify(
            colors?.length
              ? colors
              : [
                  { name: 'Signature Bordeaux', hex: '#631828' },
                  { name: 'Warm Sand', hex: '#E5DCCB' },
                ]
          ),
          computedStock,
          Boolean(is_featured),
          Boolean(is_new_arrival),
          Boolean(is_bestseller),
          JSON.stringify(normalizedVariants),
          cleanSeoTitle,
          cleanMetaDesc,
        ]
      );

      await logAudit('Admin', 'admin', 'CREATE_PRODUCT', 'products', `Added product "${title}" (Rs. ${price_pkr}, slug: /${cleanSlug})`);
      res.status(201).json(normalizeProduct(result.rows[0]));
    } catch (err: any) {
      res.status(503).json({ error: 'Unable to create product right now. Please try again.' });
    }
  };

  const updateProductHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid product ID' });
      }
      const {
        title,
        slug: rawSlug,
        sku,
        category_slug,
        subcategory_slug,
        price_pkr,
        compare_at_price_pkr,
        description,
        fabric_care,
        image_url,
        gallery_urls,
        sizes,
        colors,
        variants,
        seo_title,
        meta_description,
        stock,
        is_featured,
        is_new_arrival,
        is_bestseller,
        notify_subscribers,
      } = req.body || {};

      const existingProdRes = await dbQuery('SELECT * FROM products WHERE id = $1', [id]);
      if (existingProdRes.rows.length === 0) {
        return res.status(404).json({ error: 'Product not found' });
      }
      const currentProd = existingProdRes.rows[0];

      const allProdsRes = await dbQuery('SELECT id, slug FROM products');
      const otherSlugs = new Set(
        allProdsRes.rows
          .filter((r: any) => Number(r.id) !== id)
          .map((r: any) => String(r.slug || '').toLowerCase())
      );

      let cleanSlug = rawSlug
        ? slugifyText(rawSlug)
        : currentProd.slug
        ? slugifyText(currentProd.slug)
        : slugifyText(title || currentProd.title);
      if (!cleanSlug) cleanSlug = `product-${id}`;

      if (otherSlugs.has(cleanSlug.toLowerCase())) {
        if (rawSlug && String(rawSlug).trim()) {
          return res.status(400).json({
            error: `The URL slug "${cleanSlug}" is already assigned to another product. Please choose a unique slug.`,
          });
        }
        cleanSlug = `${cleanSlug}-${id}`;
      }

      const normalizedVariants = Array.isArray(variants)
        ? variants
            .filter((v: any) => v && (v.size || v.color))
            .map((v: any, idx: number) => ({
              id: v.id || `${sku || currentProd.sku || 'FNR'}-V${idx + 1}`,
              size: String(v.size || 'Standard').trim(),
              color: String(v.color || 'Standard').trim(),
              sku: String(
                v.sku ||
                  `${sku || currentProd.sku || 'FNR'}-${String(v.color || 'STD')
                    .slice(0, 3)
                    .toUpperCase()}-${String(v.size || 'OS').toUpperCase()}`
              ).trim(),
              stock: Math.max(0, Number(v.stock ?? 0)),
              price_pkr:
                v.price_pkr !== undefined && v.price_pkr !== null && Number(v.price_pkr) > 0
                  ? Number(v.price_pkr)
                  : Number(price_pkr ?? currentProd.price_pkr),
            }))
        : typeof currentProd.variants === 'string'
        ? JSON.parse(currentProd.variants || '[]')
        : currentProd.variants || [];

      const newStock =
        Array.isArray(variants) && normalizedVariants.length > 0 && stock === undefined
          ? normalizedVariants.reduce((sum: number, v: any) => sum + Number(v.stock || 0), 0)
          : Math.max(0, Number(stock ?? currentProd.stock ?? 0));

      const cleanSeoTitle =
        seo_title !== undefined
          ? String(seo_title).trim()
          : currentProd.seo_title || `${title || currentProd.title} | Foner`;
      const cleanMetaDesc =
        meta_description !== undefined
          ? String(meta_description).trim()
          : currentProd.meta_description || description || currentProd.description || '';

      const result = await dbQuery(
        `UPDATE products SET
          title = $1,
          sku = $2,
          category_slug = $3,
          subcategory_slug = $4,
          price_pkr = $5,
          compare_at_price_pkr = $6,
          description = $7,
          fabric_care = $8,
          image_url = $9,
          gallery_urls = $10::jsonb,
          sizes = $11::jsonb,
          colors = $12::jsonb,
          stock = $13,
          is_featured = $14,
          is_new_arrival = $15,
          is_bestseller = $16,
          slug = $17,
          variants = $18::jsonb,
          seo_title = $19,
          meta_description = $20
        WHERE id = $21
        RETURNING *`,
        [
          title ?? currentProd.title,
          sku ?? currentProd.sku,
          category_slug ?? currentProd.category_slug,
          subcategory_slug !== undefined ? subcategory_slug : currentProd.subcategory_slug || '',
          Number(price_pkr ?? currentProd.price_pkr),
          compare_at_price_pkr ? Number(compare_at_price_pkr) : null,
          description ?? currentProd.description,
          fabric_care !== undefined ? fabric_care : currentProd.fabric_care || '',
          image_url ?? currentProd.image_url,
          JSON.stringify(gallery_urls || [image_url ?? currentProd.image_url]),
          JSON.stringify(sizes || ['S', 'M', 'L']),
          JSON.stringify(colors || []),
          newStock,
          Boolean(is_featured),
          Boolean(is_new_arrival),
          Boolean(is_bestseller),
          cleanSlug,
          JSON.stringify(normalizedVariants),
          cleanSeoTitle,
          cleanMetaDesc,
          id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Product not found' });
      }

      let notifiedEmails: string[] = [];
      if (newStock > 0 && notify_subscribers !== false) {
        const pendingRes = await dbQuery(
          `SELECT * FROM restock_notifications WHERE product_id = $1 AND status = 'pending'`,
          [id]
        );
        if (pendingRes.rows.length > 0) {
          await dbQuery(
            `UPDATE restock_notifications SET status = 'notified', notified_at = NOW() WHERE product_id = $1 AND status = 'pending'`,
            [id]
          );
          notifiedEmails = pendingRes.rows.map((r: any) => r.customer_email);
          await logAudit(
            'Admin',
            'admin',
            'RESTOCK_NOTIFICATION_SENT',
            'restock_notifications',
            `Inventory restocked to ${newStock} units for "${title}" — Sent restock alerts to ${notifiedEmails.length} subscriber(s): ${notifiedEmails.join(', ')}`
          );
        }
      }

      await logAudit(
        'Admin',
        'admin',
        'UPDATE_PRODUCT',
        'products',
        `Updated product "${title}" (#${id}) • Stock: ${newStock} units`
      );
      res.json({
        ...normalizeProduct(result.rows[0]),
        notified_emails: notifiedEmails,
        restockNotificationsSent: notifiedEmails.length,
      });
    } catch (err: any) {
      console.error('[Product Update Error]:', err);
      res.status(503).json({ error: 'Unable to update product right now. Please try again.' });
    }
  };

  const deleteProductHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid product ID' });
      }
      await dbQuery('DELETE FROM products WHERE id = $1', [id]);
      await logAudit('Admin', 'admin', 'DELETE_PRODUCT', 'products', `Deleted product #${id}`);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.get('/api/admin/products', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM products ORDER BY is_featured DESC, id ASC');
      res.json(result.rows.map(normalizeProduct));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });
  app.post('/api/products', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createProductHandler);
  app.post('/api/admin/products', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createProductHandler);
  app.put('/api/products/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateProductHandler);
  app.put('/api/admin/products/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateProductHandler);
  app.delete('/api/products/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteProductHandler);
  app.delete('/api/admin/products/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteProductHandler);

  // ============================================================================
  // RESTOCK NOTIFICATIONS ('NOTIFY ME' WHEN OUT OF STOCK)
  // ============================================================================
  const listRestockNotificationsHandler: express.RequestHandler = async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM restock_notifications ORDER BY id DESC');
      res.json(result.rows.map(normalizeRestockNotification));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };
  app.get('/api/restock-notifications', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listRestockNotificationsHandler);
  app.get('/api/admin/restock-notifications', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listRestockNotificationsHandler);

  const subscribeRestockHandler: express.RequestHandler = async (req, res) => {
    try {
      const productId = Number(req.params.id || req.body?.product_id);
      const rawEmail = String(req.body?.customer_email || req.body?.email || '')
        .trim()
        .toLowerCase();
      const preferredSize = String(req.body?.preferred_size || req.body?.size || '').trim();
      const preferredColor = String(req.body?.preferred_color || req.body?.color || '').trim();

      if (!productId || !Number.isInteger(productId) || productId <= 0) {
        return res.status(400).json({ error: 'Valid product_id is required.' });
      }
      if (!rawEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawEmail)) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
      }

      const existing = await dbQuery(
        `SELECT * FROM restock_notifications WHERE product_id = $1 AND LOWER(customer_email) = LOWER($2) AND status = 'pending'`,
        [productId, rawEmail]
      );
      if (existing.rows.length > 0) {
        return res.status(200).json({
          already_subscribed: true,
          notification: normalizeRestockNotification(existing.rows[0]),
          message: 'You are already registered for restock alerts for this item.',
        });
      }

      let productTitle = String(req.body?.product_title || 'Product');
      let productSku = String(req.body?.product_sku || '');
      const prodRes = await dbQuery('SELECT * FROM products WHERE id = $1', [productId]);
      if (prodRes.rows.length > 0) {
        productTitle = prodRes.rows[0].title;
        productSku = prodRes.rows[0].sku;
      }

      const result = await dbQuery(
        `INSERT INTO restock_notifications (
          product_id, product_title, product_sku, customer_email, preferred_size, preferred_color, status
        ) VALUES ($1, $2, $3, $4, $5, $6, 'pending')
        RETURNING *`,
        [productId, productTitle, productSku, rawEmail, preferredSize, preferredColor]
      );

      await logAudit(
        rawEmail,
        'customer',
        'RESTOCK_ALERT_REQUESTED',
        'restock_notifications',
        `Customer ${rawEmail} requested restock notification for "${productTitle}" (${productSku})`
      );

      res.status(201).json({
        already_subscribed: false,
        notification: normalizeRestockNotification(result.rows[0]),
        message: `We will email ${rawEmail} when "${productTitle}" is back in stock.`,
      });
    } catch (err: any) {
      console.error('[Restock Subscribe Error]:', err);
      res.status(503).json({ error: 'Unable to save your notification request right now.' });
    }
  };

  app.post('/api/restock-notifications', subscribeRestockHandler);
  app.post('/api/products/:id/notify', subscribeRestockHandler);

  const sendRestockNotificationsHandler: express.RequestHandler = async (req, res) => {
    try {
      const { notification_id, product_id, restock_quantity } = req.body || {};

      if (product_id && restock_quantity !== undefined && Number(restock_quantity) > 0) {
        const prodCheck = await dbQuery('SELECT * FROM products WHERE id = $1', [Number(product_id)]);
        if (prodCheck.rows.length > 0) {
          const p = prodCheck.rows[0];
          await dbQuery(
            `UPDATE products SET
              title = $1, sku = $2, category_slug = $3, subcategory_slug = $4,
              price_pkr = $5, compare_at_price_pkr = $6, description = $7, fabric_care = $8,
              image_url = $9, gallery_urls = $10::jsonb, sizes = $11::jsonb, colors = $12::jsonb,
              stock = $13, is_featured = $14, is_new_arrival = $15, is_bestseller = $16
            WHERE id = $17 RETURNING *`,
            [
              p.title,
              p.sku,
              p.category_slug,
              p.subcategory_slug || '',
              Number(p.price_pkr),
              p.compare_at_price_pkr ? Number(p.compare_at_price_pkr) : null,
              p.description,
              p.fabric_care || '',
              p.image_url,
              JSON.stringify(
                typeof p.gallery_urls === 'string'
                  ? JSON.parse(p.gallery_urls)
                  : p.gallery_urls || [p.image_url]
              ),
              JSON.stringify(
                typeof p.sizes === 'string' ? JSON.parse(p.sizes) : p.sizes || ['S', 'M', 'L']
              ),
              JSON.stringify(
                typeof p.colors === 'string' ? JSON.parse(p.colors) : p.colors || []
              ),
              Number(restock_quantity),
              Boolean(p.is_featured),
              Boolean(p.is_new_arrival),
              Boolean(p.is_bestseller),
              Number(product_id),
            ]
          );
        }
      }

      let updatedRows: any[] = [];
      if (notification_id) {
        const result = await dbQuery(
          `UPDATE restock_notifications SET status = 'notified', notified_at = NOW() WHERE id = $1 RETURNING *`,
          [Number(notification_id)]
        );
        updatedRows = result.rows;
      } else if (product_id) {
        const result = await dbQuery(
          `UPDATE restock_notifications SET status = 'notified', notified_at = NOW() WHERE product_id = $1 AND status = 'pending' RETURNING *`,
          [Number(product_id)]
        );
        updatedRows = result.rows;
      } else {
        const result = await dbQuery(
          `UPDATE restock_notifications SET status = 'notified', notified_at = NOW() WHERE status = 'pending' RETURNING *`
        );
        updatedRows = result.rows;
      }

      const emails = updatedRows.map((r: any) => r.customer_email);
      await logAudit(
        'Admin',
        'admin',
        'RESTOCK_NOTIFICATION_SENT',
        'restock_notifications',
        `Dispatched restock notification emails to ${emails.length} waiting customer(s): ${emails.join(', ') || 'none'}`
      );

      res.json({
        success: true,
        notifiedCount: updatedRows.length,
        notified_count: updatedRows.length,
        notified_emails: emails,
        notifications: updatedRows.map(normalizeRestockNotification),
      });
    } catch (err: any) {
      console.error('[Send Restock Notifications Error]:', err);
      res.status(503).json({ error: 'Unable to send restock alerts right now.' });
    }
  };

  app.post('/api/restock-notifications/send', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, sendRestockNotificationsHandler);
  app.post('/api/admin/restock-notifications/send', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, sendRestockNotificationsHandler);
  app.post('/api/restock-notifications/notify/:productId', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, (req, res, next) => {
    req.body = { ...(req.body || {}), product_id: Number(req.params.productId) };
    return sendRestockNotificationsHandler(req, res, next);
  });
  app.post('/api/admin/restock-notifications/notify/:productId', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, (req, res, next) => {
    req.body = { ...(req.body || {}), product_id: Number(req.params.productId) };
    return sendRestockNotificationsHandler(req, res, next);
  });

  const deleteRestockNotificationHandler: express.RequestHandler = async (req, res) => {
    try {
      await dbQuery('DELETE FROM restock_notifications WHERE id = $1', [Number(req.params.id)]);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };
  app.delete('/api/restock-notifications/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteRestockNotificationHandler);
  app.delete('/api/admin/restock-notifications/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteRestockNotificationHandler);

  // ============================================================================
  // BANNERS ENDPOINTS (/api/banners & /api/admin/banners)
  // ============================================================================
  app.get('/api/banners', async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM banners ORDER BY sort_order ASC, id ASC');
      res.json(result.rows.map(normalizeBanner));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });

  const createBannerHandler: express.RequestHandler = async (req, res) => {
    try {
      const {
        title,
        subtitle,
        badge_text = 'NEW SEASON',
        cta_text = 'Shop Collection',
        cta_link = 'all',
        desktop_image_url,
        mobile_image_url,
        device_target = 'both',
        theme_style = 'burgundy-gold',
        overlay_opacity = 42,
        sort_order = 1,
        is_active = true,
      } = req.body || {};

      if (!title || !desktop_image_url || !mobile_image_url) {
        return res
          .status(400)
          .json({ error: 'Title, Desktop Banner URL, and Mobile Banner URL are required.' });
      }

      const result = await dbQuery(
        `INSERT INTO banners (
          title, subtitle, badge_text, cta_text, cta_link,
          desktop_image_url, mobile_image_url, device_target,
          theme_style, overlay_opacity, sort_order, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *`,
        [
          title,
          subtitle || '',
          badge_text,
          cta_text,
          cta_link,
          desktop_image_url,
          mobile_image_url,
          device_target,
          theme_style,
          Number(overlay_opacity),
          Number(sort_order),
          Boolean(is_active),
        ]
      );

      await logAudit('Admin', 'admin', 'CREATE_BANNER', 'banners', `Created banner "${title}"`);
      res.status(201).json(normalizeBanner(result.rows[0]));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const updateBannerHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid banner ID' });
      }
      const {
        title,
        subtitle,
        badge_text,
        cta_text,
        cta_link,
        desktop_image_url,
        mobile_image_url,
        device_target,
        theme_style,
        overlay_opacity,
        sort_order,
        is_active,
      } = req.body || {};

      const result = await dbQuery(
        `UPDATE banners SET
          title = $1,
          subtitle = $2,
          badge_text = $3,
          cta_text = $4,
          cta_link = $5,
          desktop_image_url = $6,
          mobile_image_url = $7,
          device_target = $8,
          theme_style = $9,
          overlay_opacity = $10,
          sort_order = $11,
          is_active = $12
        WHERE id = $13
        RETURNING *`,
        [
          title,
          subtitle,
          badge_text,
          cta_text,
          cta_link,
          desktop_image_url,
          mobile_image_url,
          device_target || 'both',
          theme_style || 'burgundy-gold',
          Number(overlay_opacity ?? 42),
          Number(sort_order ?? 1),
          Boolean(is_active),
          id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Banner not found' });
      }

      await logAudit('Admin', 'admin', 'UPDATE_BANNER', 'banners', `Updated banner #${id} (${title})`);
      res.json(normalizeBanner(result.rows[0]));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const deleteBannerHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid banner ID' });
      }
      await dbQuery('DELETE FROM banners WHERE id = $1', [id]);
      await logAudit('Admin', 'admin', 'DELETE_BANNER', 'banners', `Deleted banner #${id}`);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.get('/api/admin/banners', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM banners ORDER BY sort_order ASC, id ASC');
      res.json(result.rows.map(normalizeBanner));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });
  app.post('/api/banners', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createBannerHandler);
  app.post('/api/admin/banners', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createBannerHandler);
  app.put('/api/banners/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateBannerHandler);
  app.put('/api/admin/banners/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateBannerHandler);
  app.delete('/api/banners/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteBannerHandler);
  app.delete('/api/admin/banners/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteBannerHandler);

  // ============================================================================
  // USERS & ROLE-BASED ACCESS CONTROL (/api/users & /api/admin/users)
  // ============================================================================
  const listUsersHandler: express.RequestHandler = async (req, res) => {
    try {
      const page = Math.max(1, parseInt(req.query.page as string) || 1);
      const limit = Math.min(50, Math.max(5, parseInt(req.query.limit as string) || 25));
      const offset = (page - 1) * limit;
      const search = String(req.query.search || '').trim();
      const roleFilter = String(req.query.role || '').trim();
      const orderBy = String(req.query.sort || 'newest').trim();

      const whereClauses: string[] = [];
      const params: (string | number)[] = [];

      if (search) {
        whereClauses.push('(name ILIKE $' + (params.length + 1) + ' OR email ILIKE $' + (params.length + 1) + ')');
        params.push('%' + search + '%');
      }
      if (roleFilter && ['admin', 'customer'].includes(roleFilter)) {
        whereClauses.push('role = $' + (params.length + 1));
        params.push(roleFilter);
      }

      const whereSql = whereClauses.length > 0 ? 'WHERE ' + whereClauses.join(' AND ') : '';

      let orderSql = 'ORDER BY created_at DESC';
      if (orderBy === 'oldest') orderSql = 'ORDER BY created_at ASC';
      if (orderBy === 'name') orderSql = 'ORDER BY name ASC';
      if (orderBy === 'email') orderSql = 'ORDER BY email ASC';

      const countRes = await dbQuery('SELECT COUNT(*)::int AS total FROM users ' + whereSql, params);
      const total = Number(countRes.rows[0]?.total || 0);

      const dataRes = await dbQuery(
        'SELECT id, name, email, role, status, created_at FROM users ' + whereSql + ' ' + orderSql +
        ' LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2),
        [...params, limit, offset]
      );

      res.json({
        users: dataRes.rows.map((r) => ({
          id: Number(r.id),
          name: String(r.name || ''),
          email: String(r.email || ''),
          role: String(r.role || 'customer'),
          status: String(r.status || 'active'),
          created_at: r.created_at ? new Date(r.created_at).toISOString() : null,
        })),
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      });
    } catch (err: any) {
      res.status(503).json({ error: err.message || 'Failed to fetch users.' });
    }
  };
  // Handler: Change a user's role (admin-only, with protections)
  const updateUserRoleHandler: express.RequestHandler = async (req, res) => {
    try {
      const authUser = (req as any).adminUser || (req as any).authUser;
      if (!authUser || authUser.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Administrator role required.' });
      }
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid user ID.' });
      }
      const { role } = req.body || {};
      const validRoles = ['admin', 'customer'];
      if (!role || !validRoles.includes(String(role))) {
        return res.status(400).json({ error: 'Invalid role. Supported roles: admin, customer.' });
      }
      const newRole = String(role);

      // --- Self-role-change prevention ---
      if (authUser.id === id) {
        return res.status(403).json({
          error: 'You cannot change your own administrator role.',
        });
      }

      const result = await dbQuery('SELECT * FROM users WHERE id = $1', [id]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found.' });
      }
      const targetUser = result.rows[0];
      const currentRole = targetUser.role || 'customer';

      // --- Admin → Customer: last-admin protection ---
      if (currentRole === 'admin' && newRole === 'customer') {
        const activeAdminCountRes = await dbQuery(
          "SELECT COUNT(*)::int AS cnt FROM users WHERE role = 'admin' AND status = 'active'"
        );
        const activeAdminCount = Number(activeAdminCountRes.rows[0]?.cnt || 0);
        if (activeAdminCount <= 1) {
          return res.status(403).json({
            error: 'You cannot remove the last administrator.',
          });
        }
      }

      // --- Self-promotion protection (customer → admin): not allowed via this endpoint for non-admin users ---
      // Since requireAdmin already verified the requester is an admin, only admins can call this endpoint.
      // But a customer calling this endpoint would be blocked by requireAdmin above.

      const updated = await dbQuery(
        `UPDATE users SET role = $1 WHERE id = $2 AND role <> $1 RETURNING *`,
        [newRole, id]
      );

      if (updated.rows.length === 0) {
        // Role was already the requested value
        return res.json({
          ...normalizeUser(targetUser),
          _changed: false,
          message: `Role is already ${newRole.toUpperCase()}.`,
        });
      }

      // Revoke existing sessions for the affected user so role change takes effect immediately
      await revokeAllUserSessions(id);

      await logAudit(
        authUser.name || 'Admin',
        authUser.role || 'admin',
        'USER_ROLE_CHANGED',
        'users',
        `User #${id} (${targetUser.name}): ${currentRole.toUpperCase()} → ${newRole.toUpperCase()} by Admin #${authUser.id}`
      );

      res.json({
        ...normalizeUser(updated.rows[0]),
        _changed: true,
        message: `User role updated to ${newRole.toUpperCase()}.`,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update user role.' });
    }
  };

  app.get('/api/users', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listUsersHandler);
  app.get('/api/admin/users', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listUsersHandler);

  // PATCH /api/admin/users/:id/role — Change a user's role (admin-only)
  app.patch(
    '/api/admin/users/:id/role',
    adminRouteAuthorizationMiddleware,
    requireAuth,
    requireAdmin,
    updateUserRoleHandler
  );

  const createUserHandler: express.RequestHandler = async (req, res) => {
    let cleanEmail: string | undefined;
    try {
      const {
        name,
        email,
        password,
        phone,
        city,
        address,
        postal_code = '',
        role = 'customer',
        status = 'active',
      } = req.body || {};
      const parsedEmail = emailSchema.safeParse(email);
      const cleanName = sanitizeText(name || '', 120);
      if (!cleanName || !parsedEmail.success) {
        return res.status(400).json({ error: 'Valid name and email address are required.' });
      }
      cleanEmail = parsedEmail.data;

      const existing = await dbQuery('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [
        cleanEmail,
      ]);
      if (existing.rows.length > 0) {
        return res.status(409).json({ error: 'A user with this email address already exists.' });
      }

      const validRoles = ['admin', 'manager', 'editor', 'customer'];
      const safeRole = validRoles.includes(String(role)) ? String(role) : 'customer';
      const safeStatus = status === 'suspended' ? 'suspended' : 'active';

      const pwdHash = password
        ? await hashPasswordAsync(String(password))
        : await hashPasswordAsync(crypto.randomBytes(16).toString('hex'));

      const result = await dbQuery(
        `INSERT INTO users (name, email, password_hash, phone, city, address, postal_code, role, status, avatar_url)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING *`,
        [
          cleanName,
          cleanEmail,
          pwdHash,
          sanitizeText(phone || '', 40),
          sanitizeText(city || 'Lahore', 80),
          sanitizeText(address || '', 300),
          sanitizeText(postal_code || '', 24),
          safeRole,
          safeStatus,
          '/products/overcoat.jpg',
        ]
      );

      await logAudit(
        'Admin',
        'admin',
        'CREATE_USER',
        'users',
        `Created user ${cleanName} (${cleanEmail}) with role [${safeRole.toUpperCase()}]`
      );
      res.status(201).json(normalizeUser(result.rows[0]));
    } catch {
      res.status(503).json({ error: 'Unable to create user.' });
    }
  };

  const updateUserHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid user ID' });
      }
      const { name, email, phone, city, address, postal_code, role, status } = req.body || {};

      const existingRes = await dbQuery('SELECT * FROM users WHERE id = $1', [id]);
      if (existingRes.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      const current = existingRes.rows[0];

      const validRoles = ['admin', 'manager', 'editor', 'customer'];
      const nextRole = role && validRoles.includes(String(role)) ? String(role) : current.role || 'customer';
      const nextStatus =
        status !== undefined ? (status === 'suspended' ? 'suspended' : 'active') : current.status || 'active';

      const result = await dbQuery(
        `UPDATE users SET
          name = $1,
          email = $2,
          phone = $3,
          city = $4,
          address = $5,
          postal_code = $6,
          role = $7,
          status = $8
        WHERE id = $9
        RETURNING *`,
        [
          name !== undefined ? sanitizeText(name, 120) : current.name,
          email !== undefined ? String(email).trim().toLowerCase() : current.email,
          phone !== undefined ? sanitizeText(phone, 40) : current.phone ?? '',
          city !== undefined ? sanitizeText(city, 80) : current.city ?? 'Lahore',
          address !== undefined ? sanitizeText(address, 300) : current.address ?? '',
          postal_code !== undefined ? sanitizeText(postal_code, 24) : current.postal_code ?? '',
          nextRole,
          nextStatus,
          id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      // If role or status changed, revoke existing sessions so security-sensitive changes take effect immediately
      if (nextRole !== current.role || nextStatus !== current.status) {
        await revokeAllUserSessions(id);
      }

      await logAudit(
        'Admin',
        'admin',
        'UPDATE_USER_AND_ROLE',
        'users',
        `Updated user #${id} (${result.rows[0].name}) — Role: [${String(result.rows[0].role).toUpperCase()}]`
      );
      res.json(normalizeUser(result.rows[0]));
    } catch {
      res.status(503).json({ error: 'Unable to update user.' });
    }
  };

  const deleteUserHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid user ID' });
      }
      await revokeAllUserSessions(id);
      await dbQuery('DELETE FROM users WHERE id = $1', [id]);
      await logAudit('Admin', 'admin', 'DELETE_USER', 'users', `Removed user #${id}`);
      res.json({ success: true });
    } catch {
      res.status(503).json({ error: 'Unable to delete user.' });
    }
  };

  app.post('/api/users', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), createUserHandler);
  app.post('/api/admin/users', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), createUserHandler);
  app.put('/api/users/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), updateUserHandler);
  app.put('/api/admin/users/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), updateUserHandler);
  app.delete('/api/users/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), deleteUserHandler);
  app.delete('/api/admin/users/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), deleteUserHandler);

  // ============================================================================
  // CATEGORIES & SUBCATEGORIES ENDPOINTS
  // ============================================================================
  app.get('/api/categories', async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM categories ORDER BY sort_order ASC, id ASC');
      res.json(result.rows);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });

  const createCategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const { name, slug, description, image_url, featured = true, sort_order = 1 } = req.body || {};
      if (!name || !image_url) {
        return res.status(400).json({ error: 'Category name and image_url are required' });
      }
      const cleanSlug =
        slug ||
        name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/(^-|-$)/g, '');
      const result = await dbQuery(
        `INSERT INTO categories (name, slug, description, image_url, featured, sort_order)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [name, cleanSlug, description || '', image_url, Boolean(featured), Number(sort_order)]
      );
      await logAudit('Admin', 'admin', 'CREATE_CATEGORY', 'categories', `Created category "${name}"`);
      res.status(201).json(result.rows[0]);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const updateCategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { name, slug, description, image_url, featured = true, sort_order = 1 } = req.body || {};
      const result = await dbQuery(
        `UPDATE categories SET name = $1, slug = $2, description = $3, image_url = $4, featured = $5, sort_order = $6
         WHERE id = $7 RETURNING *`,
        [name, slug, description || '', image_url, Boolean(featured), Number(sort_order), id]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Category not found' });
      res.json(result.rows[0]);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const deleteCategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      await dbQuery('DELETE FROM categories WHERE id = $1', [id]);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.get('/api/admin/categories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM categories ORDER BY sort_order ASC, id ASC');
      res.json(result.rows);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });
  app.post('/api/categories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createCategoryHandler);
  app.post('/api/admin/categories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createCategoryHandler);
  app.put('/api/categories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateCategoryHandler);
  app.put('/api/admin/categories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateCategoryHandler);
  app.delete('/api/categories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteCategoryHandler);
  app.delete('/api/admin/categories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteCategoryHandler);

  // SUBCATEGORIES
  app.get('/api/subcategories', async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM subcategories ORDER BY sort_order ASC, id ASC');
      res.json(result.rows);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });

  const createSubcategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const {
        name,
        slug,
        parent_category_slug = 'outerwear',
        description = '',
        image_url = '/products/overcoat.jpg',
        featured = true,
        sort_order = 1,
      } = req.body || {};
      if (!name) {
        return res.status(400).json({ error: 'Subcategory name is required' });
      }
      const cleanSlug =
        slug ||
        name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/(^-|-$)/g, '');
      const result = await dbQuery(
        `INSERT INTO subcategories (name, slug, parent_category_slug, description, image_url, featured, sort_order)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [name, cleanSlug, parent_category_slug, description, image_url, Boolean(featured), Number(sort_order)]
      );
      await logAudit('Admin', 'admin', 'CREATE_SUBCATEGORY', 'subcategories', `Created subcategory "${name}"`);
      res.status(201).json(result.rows[0]);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const updateSubcategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { name, slug, parent_category_slug, description, image_url, featured = true, sort_order = 1 } =
        req.body || {};
      const result = await dbQuery(
        `UPDATE subcategories SET name = $1, slug = $2, parent_category_slug = $3, description = $4, image_url = $5, featured = $6, sort_order = $7
         WHERE id = $8 RETURNING *`,
        [name, slug, parent_category_slug, description || '', image_url, Boolean(featured), Number(sort_order), id]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Subcategory not found' });
      res.json(result.rows[0]);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  const deleteSubcategoryHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      await dbQuery('DELETE FROM subcategories WHERE id = $1', [id]);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.get('/api/admin/subcategories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM subcategories ORDER BY sort_order ASC, id ASC');
      res.json(result.rows);
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });
  app.post('/api/subcategories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createSubcategoryHandler);
  app.post('/api/admin/subcategories', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createSubcategoryHandler);
  app.put('/api/subcategories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateSubcategoryHandler);
  app.put('/api/admin/subcategories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateSubcategoryHandler);
  app.delete('/api/subcategories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteSubcategoryHandler);
  app.delete('/api/admin/subcategories/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteSubcategoryHandler);

  // ============================================================================
  // COUPONS ENDPOINTS
  // ============================================================================
  const listCouponsHandler: express.RequestHandler = async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM coupons ORDER BY id ASC');
      res.json(result.rows.map(normalizeCoupon));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };
  app.get('/api/coupons', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listCouponsHandler);
  app.get('/api/admin/coupons', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listCouponsHandler);

  app.post('/api/coupons/validate', async (req, res) => {
    try {
      const { code, subtotal_pkr, customer_email } = req.body || {};
      const cleanCode = String(code || '').trim().toUpperCase();
      if (!cleanCode) return res.status(400).json({ error: 'Please enter a coupon code.' });

      const result = await dbQuery('SELECT * FROM coupons WHERE UPPER(code) = UPPER($1)', [
        cleanCode,
      ]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: `Coupon code "${cleanCode}" does not exist.` });
      }
      const coupon = normalizeCoupon(result.rows[0]);
      if (!coupon.is_active) {
        return res.status(400).json({ error: `Coupon code "${coupon.code}" is currently inactive.` });
      }
      if (coupon.expires_at && new Date(coupon.expires_at).getTime() < Date.now()) {
        return res.status(400).json({
          error: `Coupon code ${coupon.code} expired on ${new Date(coupon.expires_at).toLocaleDateString()}.`,
        });
      }
      if (
        coupon.usage_limit !== null &&
        coupon.usage_limit !== undefined &&
        Number(coupon.usage_limit) > 0 &&
        Number(coupon.usage_count || 0) >= Number(coupon.usage_limit)
      ) {
        return res.status(400).json({
          error: `Coupon code ${coupon.code} has reached its maximum usage limit (${coupon.usage_limit} uses).`,
        });
      }

      const authCustomer = await getAuthenticatedCustomer(req);
      const targetEmail = String(customer_email || authCustomer?.email || '')
        .trim()
        .toLowerCase();
      if (
        coupon.per_customer_limit !== null &&
        coupon.per_customer_limit !== undefined &&
        Number(coupon.per_customer_limit) > 0 &&
        (authCustomer?.id || targetEmail)
      ) {
        const allOrdersRes = await dbQuery('SELECT * FROM orders');
        const customerUses = allOrdersRes.rows.filter((o: any) => {
          const st = String(o.order_status || o.status || '').toLowerCase();
          if (st === 'cancelled') return false;
          if (String(o.coupon_code || '').toUpperCase() !== coupon.code.toUpperCase()) return false;
          const matchId = authCustomer?.id && Number(o.user_id) === Number(authCustomer.id);
          const matchEmail =
            targetEmail && String(o.customer_email || '').trim().toLowerCase() === targetEmail;
          return Boolean(matchId || matchEmail);
        }).length;
        if (customerUses >= Number(coupon.per_customer_limit)) {
          return res.status(400).json({
            error: `You have already used coupon ${coupon.code} the maximum allowed number of times (${coupon.per_customer_limit}).`,
          });
        }
      }

      const numericSubtotal = Math.max(0, Number(subtotal_pkr || 0));
      if (numericSubtotal < Number(coupon.min_order_pkr || 0)) {
        return res.status(400).json({
          error: `Minimum order of PKR ${Number(coupon.min_order_pkr).toLocaleString()} is required to use ${coupon.code}.`,
        });
      }

      if (!Number.isFinite(Number(coupon.discount_value)) || Number(coupon.discount_value) <= 0) {
        return res.status(400).json({ error: 'This coupon has an invalid discount value.' });
      }

      const rawDiscount =
        coupon.discount_type === 'percentage'
          ? Math.round((numericSubtotal * Math.min(100, Number(coupon.discount_value))) / 100)
          : Number(coupon.discount_value);
      const discount_pkr = Math.min(numericSubtotal, Math.max(0, rawDiscount));

      res.json({
        coupon,
        code: coupon.code,
        discount_pkr,
        final_subtotal_pkr: Math.max(0, numericSubtotal - discount_pkr),
      });
    } catch {
      res.status(503).json({ error: 'Unable to validate coupon right now. Please try again.' });
    }
  });

  const createCouponHandler: express.RequestHandler = async (req, res) => {
    try {
      const {
        code,
        description,
        discount_type,
        discount_value,
        min_order_pkr,
        expires_at,
        is_active = true,
        usage_limit,
        per_customer_limit,
      } = req.body || {};
      const cleanCode = String(code || '').toUpperCase().trim();
      if (!cleanCode) return res.status(400).json({ error: 'Coupon code is required.' });
      if (!discount_value || Number(discount_value) <= 0) {
        return res.status(400).json({ error: 'Discount value must be greater than 0.' });
      }
      if (discount_type === 'percentage' && Number(discount_value) > 100) {
        return res.status(400).json({ error: 'Percentage discount cannot exceed 100%.' });
      }

      const parsedExpiry = expires_at ? new Date(expires_at).toISOString() : null;
      const parsedUsageLimit =
        usage_limit !== undefined && usage_limit !== null && usage_limit !== '' && Number(usage_limit) > 0
          ? Number(usage_limit)
          : null;
      const parsedPerCustomerLimit =
        per_customer_limit !== undefined &&
        per_customer_limit !== null &&
        per_customer_limit !== '' &&
        Number(per_customer_limit) > 0
          ? Number(per_customer_limit)
          : null;

      const result = await dbQuery(
        `INSERT INTO coupons (code, description, discount_type, discount_value, min_order_pkr, expires_at, is_active, usage_limit, per_customer_limit)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
        [
          cleanCode,
          description || '',
          discount_type === 'fixed' ? 'fixed' : 'percentage',
          Number(discount_value),
          Math.max(0, Number(min_order_pkr || 0)),
          parsedExpiry,
          Boolean(is_active),
          parsedUsageLimit,
          parsedPerCustomerLimit,
        ]
      );
      await logAudit('Admin', 'admin', 'CREATE_COUPON', 'coupons', `Created promo code ${cleanCode}`);
      res.status(201).json(normalizeCoupon(result.rows[0]));
    } catch {
      res.status(503).json({ error: 'Unable to create coupon. Ensure the code is unique.' });
    }
  };

  const updateCouponHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      const {
        code,
        description,
        discount_type,
        discount_value,
        min_order_pkr,
        expires_at,
        is_active = true,
        usage_limit,
        per_customer_limit,
      } = req.body || {};
      const cleanCode = String(code || '').toUpperCase().trim();
      if (!cleanCode) return res.status(400).json({ error: 'Coupon code is required.' });
      if (!discount_value || Number(discount_value) <= 0) {
        return res.status(400).json({ error: 'Discount value must be greater than 0.' });
      }
      if (discount_type === 'percentage' && Number(discount_value) > 100) {
        return res.status(400).json({ error: 'Percentage discount cannot exceed 100%.' });
      }

      const parsedExpiry = expires_at ? new Date(expires_at).toISOString() : null;
      const parsedUsageLimit =
        usage_limit !== undefined && usage_limit !== null && usage_limit !== '' && Number(usage_limit) > 0
          ? Number(usage_limit)
          : null;
      const parsedPerCustomerLimit =
        per_customer_limit !== undefined &&
        per_customer_limit !== null &&
        per_customer_limit !== '' &&
        Number(per_customer_limit) > 0
          ? Number(per_customer_limit)
          : null;

      const result = await dbQuery(
        `UPDATE coupons SET code = $1, description = $2, discount_type = $3, discount_value = $4, min_order_pkr = $5, expires_at = $6, is_active = $7, usage_limit = $8, per_customer_limit = $9
         WHERE id = $10 RETURNING *`,
        [
          cleanCode,
          description || '',
          discount_type === 'fixed' ? 'fixed' : 'percentage',
          Number(discount_value),
          Math.max(0, Number(min_order_pkr || 0)),
          parsedExpiry,
          Boolean(is_active),
          parsedUsageLimit,
          parsedPerCustomerLimit,
          id,
        ]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Coupon not found' });
      await logAudit(
        'Admin',
        'admin',
        'UPDATE_COUPON',
        'coupons',
        `Updated promo code ${cleanCode}`
      );
      res.json(normalizeCoupon(result.rows[0]));
    } catch {
      res.status(503).json({ error: 'Unable to update coupon right now.' });
    }
  };

  const deleteCouponHandler: express.RequestHandler = async (req, res) => {
    try {
      await dbQuery('DELETE FROM coupons WHERE id = $1', [Number(req.params.id)]);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.post('/api/coupons', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createCouponHandler);
  app.post('/api/admin/coupons', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, createCouponHandler);
  app.put('/api/coupons/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateCouponHandler);
  app.put('/api/admin/coupons/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateCouponHandler);
  app.delete('/api/coupons/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteCouponHandler);
  app.delete('/api/admin/coupons/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteCouponHandler);

  // ============================================================================
  // ORDERS & TRANSACTIONAL PKR CHECKOUT (/api/orders & /api/admin/orders)
  // ============================================================================
  app.get('/api/orders', requireAuth, async (req, res) => {
    try {
      const user = (req as any).authUser;
      const result = await dbQuery('SELECT * FROM orders WHERE user_id = $1 ORDER BY id DESC', [
        Number(user.id),
      ]);
      res.json(result.rows.map(normalizeOrder));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });

  app.get('/api/admin/orders', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM orders ORDER BY id DESC');
      res.json(result.rows.map(normalizeOrder));
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  });

  const getRevenueAnalyticsHandler: express.RequestHandler = async (req, res) => {
    try {
      const rawRange = String(req.query.range || '30d').toLowerCase();
      const range: '7d' | '30d' | '3m' | '6m' | '1y' | 'all' =
        rawRange === '7d'
          ? '7d'
          : rawRange === '3m' || rawRange === '90d'
          ? '3m'
          : rawRange === '6m' || rawRange === '180d'
          ? '6m'
          : rawRange === '1y' || rawRange === '365d'
          ? '1y'
          : rawRange === 'all'
          ? 'all'
          : '30d';
      const daysCount =
        range === '7d'
          ? 7
          : range === '30d'
          ? 30
          : range === '3m'
          ? 90
          : range === '6m'
          ? 180
          : 365;
      const bucketSpanDays =
        range === '7d'
          ? 1
          : range === '30d'
          ? 1
          : range === '3m'
          ? 6
          : range === '6m'
          ? 12
          : 24;
      const bucketCount = Math.ceil(daysCount / bucketSpanDays);

      const result = await dbQuery('SELECT * FROM orders ORDER BY id DESC');
      const allOrders = result.rows.map(normalizeOrder);

      // Explicitly filter out cancelled orders for all-time revenue
      const allTimeValidOrders = allOrders.filter(
        (o) => String(o.order_status || o.status || '').toLowerCase() !== 'cancelled'
      );
      const allTimeCancelledOrders = allOrders.filter(
        (o) => String(o.order_status || o.status || '').toLowerCase() === 'cancelled'
      );
      const allTimeTotalRevenuePkr = allTimeValidOrders.reduce(
        (sum, o) => sum + Number(o.total_pkr || 0),
        0
      );
      const allTimeExcludedCancelledPkr = allTimeCancelledOrders.reduce(
        (sum, o) => sum + Number(o.total_pkr || 0),
        0
      );

      const now = new Date();
      const todayStartMs = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate(),
        0,
        0,
        0,
        0
      ).getTime();
      const endMs = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate(),
        23,
        59,
        59,
        999
      ).getTime();
      const startMs = todayStartMs - (daysCount - 1) * 86400000;

      const formatShortDate = (ms: number) =>
        new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

      const buckets = Array.from({ length: bucketCount }, (_, idx) => {
        const bucketStartDayOffset = idx * bucketSpanDays;
        const bucketEndDayOffset = Math.min(daysCount - 1, (idx + 1) * bucketSpanDays - 1);
        const bStartMs = startMs + bucketStartDayOffset * 86400000;
        const bEndMs = startMs + bucketEndDayOffset * 86400000 + 86399999;

        const label = formatShortDate(bEndMs);
        const tooltipDate =
          bucketSpanDays === 1
            ? new Date(bStartMs).toLocaleDateString('en-US', {
                weekday: 'short',
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              })
            : `${formatShortDate(bStartMs)} – ${formatShortDate(bEndMs)}`;

        return {
          label,
          tooltipDate,
          startMs: bStartMs,
          endMs: bEndMs,
          revenue_pkr: 0,
          completed_revenue_pkr: 0,
          valid_orders: 0,
          completed_orders: 0,
          cancelled_orders: 0,
          cancelled_pkr: 0,
          units_sold: 0,
        };
      });

      const ordersInRange = allOrders.filter((o) => {
        const ts = new Date(o.created_at).getTime();
        return Number.isFinite(ts) && ts >= startMs && ts <= endMs;
      });

      // Explicitly separate non-cancelled vs cancelled orders in range
      const validOrders = ordersInRange.filter(
        (o) => String(o.order_status || o.status || '').toLowerCase() !== 'cancelled'
      );
      const completedOrders = validOrders.filter((o) => {
        const st = String(o.order_status || o.status || '').toLowerCase();
        const paySt = String(o.payment_status || '').toLowerCase();
        return st === 'delivered' || st === 'completed' || paySt === 'paid';
      });
      const cancelledOrders = ordersInRange.filter(
        (o) => String(o.order_status || o.status || '').toLowerCase() === 'cancelled'
      );

      let totalProductsSoldInRange = 0;

      for (const order of ordersInRange) {
        const createdMs = new Date(order.created_at).getTime();
        const dayIndex = Math.max(
          0,
          Math.min(daysCount - 1, Math.floor((createdMs - startMs) / 86400000))
        );
        const bucketIndex = Math.min(bucketCount - 1, Math.floor(dayIndex / bucketSpanDays));
        const targetBucket = buckets[bucketIndex];
        if (!targetBucket) continue;

        const statusStr = String(order.order_status || order.status || '').toLowerCase();
        const payStr = String(order.payment_status || '').toLowerCase();
        const isCancelled = statusStr === 'cancelled';
        const isCompleted =
          !isCancelled &&
          (statusStr === 'delivered' || statusStr === 'completed' || payStr === 'paid');
        const orderTotal = Number(order.total_pkr || 0);
        const orderUnits = (order.items_json || []).reduce(
          (sum: number, item: any) => sum + Math.max(0, Number(item.quantity || 0)),
          0
        );

        if (isCancelled) {
          targetBucket.cancelled_orders += 1;
          targetBucket.cancelled_pkr += orderTotal;
        } else {
          targetBucket.revenue_pkr += orderTotal;
          targetBucket.valid_orders += 1;
          targetBucket.units_sold += orderUnits;
          totalProductsSoldInRange += orderUnits;
          if (isCompleted) {
            targetBucket.completed_revenue_pkr += orderTotal;
            targetBucket.completed_orders += 1;
          }
        }
      }

      const totalRevenuePkr = validOrders.reduce(
        (sum, o) => sum + Number(o.total_pkr || 0),
        0
      );
      const completedRevenuePkr = completedOrders.reduce(
        (sum, o) => sum + Number(o.total_pkr || 0),
        0
      );
      const excludedCancelledPkr = cancelledOrders.reduce(
        (sum, o) => sum + Number(o.total_pkr || 0),
        0
      );

      return res.json({
        range,
        daysCount,
        allTimeTotalRevenuePkr,
        allTimeExcludedCancelledPkr,
        totalRevenuePkr,
        completedRevenuePkr,
        validOrdersCount: validOrders.length,
        completedOrdersCount: completedOrders.length,
        cancelledOrdersCount: cancelledOrders.length,
        excludedCancelledPkr,
        totalProductsSold: totalProductsSoldInRange,
        averageOrderValuePkr:
          validOrders.length > 0 ? Math.round(totalRevenuePkr / validOrders.length) : 0,
        buckets,
      });
    } catch (err: any) {
      return res.status(503).json({ error: 'Unable to load revenue analytics right now.' });
    }
  };

  app.get('/api/admin/analytics/revenue', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, getRevenueAnalyticsHandler);
  app.get('/api/analytics/revenue', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, getRevenueAnalyticsHandler);

  /**
   * GET /api/admin/stats
   * Queries PostgreSQL (`orders` and `products` tables) directly and returns
   * aggregated store statistics:
   * - Revenue (Total Non-Cancelled, Completed/Delivered, Pending, Confirmed, Excluded Cancelled)
   * - Total Orders & Pending/Confirmed/Processing/Shipped/Delivered/Cancelled counts
   * - Low Stock & Out-of-Stock counts and product list
   */
  const getStoreStatisticsHandler: express.RequestHandler = async (req, res) => {
    try {
      const lowStockThreshold = Math.max(1, Number(req.query.threshold || 3));
      const [ordersRes, productsRes, usersRes, categoriesRes] = await Promise.all([
        dbQuery('SELECT * FROM orders ORDER BY id DESC'),
        dbQuery('SELECT * FROM products ORDER BY id ASC'),
        dbQuery('SELECT * FROM users ORDER BY id ASC'),
        dbQuery('SELECT * FROM categories ORDER BY sort_order ASC, id ASC'),
      ]);

      const allOrders = ordersRes.rows.map(normalizeOrder);
      const allProducts = productsRes.rows.map(normalizeProduct);
      const allUsers = usersRes.rows.map(normalizeUser);
      const allCategories = categoriesRes.rows;

      const productById = new Map<number, any>(allProducts.map((p) => [p.id, p]));
      const categoryNameBySlug = new Map<string, string>(
        allCategories.map((c: any) => [String(c.slug), String(c.name)])
      );

      let totalRevenuePkr = 0;
      let completedRevenuePkr = 0;
      let pendingRevenuePkr = 0;
      let confirmedRevenuePkr = 0;
      let excludedCancelledRevenuePkr = 0;

      let validOrdersCount = 0;
      let pendingOrdersCount = 0;
      let confirmedOrdersCount = 0;
      let processingOrdersCount = 0;
      let shippedOrdersCount = 0;
      let deliveredOrdersCount = 0;
      let cancelledOrdersCount = 0;
      let totalProductsSold = 0;

      const productSalesMap = new Map<
        number,
        {
          product_id: number;
          title: string;
          sku: string;
          image_url: string;
          category_slug: string;
          units_sold: number;
          revenue_pkr: number;
        }
      >();

      const categorySalesMap = new Map<
        string,
        {
          category_slug: string;
          category_name: string;
          products_sold: number;
          revenue_pkr: number;
          orderIds: Set<number>;
        }
      >();

      for (const cat of allCategories) {
        categorySalesMap.set(String(cat.slug), {
          category_slug: String(cat.slug),
          category_name: String(cat.name),
          products_sold: 0,
          revenue_pkr: 0,
          orderIds: new Set<number>(),
        });
      }

      for (const order of allOrders) {
        const statusStr = String(order.order_status || order.status || 'pending').toLowerCase();
        const payStr = String(order.payment_status || 'pending').toLowerCase();
        const orderTotal = Number(order.total_pkr || 0);

        if (statusStr === 'cancelled') {
          cancelledOrdersCount += 1;
          excludedCancelledRevenuePkr += orderTotal;
          continue;
        }

        validOrdersCount += 1;
        totalRevenuePkr += orderTotal;

        if (statusStr === 'pending') {
          pendingOrdersCount += 1;
          pendingRevenuePkr += orderTotal;
        } else if (statusStr === 'confirmed') {
          confirmedOrdersCount += 1;
          confirmedRevenuePkr += orderTotal;
        } else if (statusStr === 'processing' || statusStr === 'crafting') {
          processingOrdersCount += 1;
        } else if (statusStr === 'shipped' || statusStr === 'dispatched') {
          shippedOrdersCount += 1;
        } else if (statusStr === 'delivered' || statusStr === 'completed') {
          deliveredOrdersCount += 1;
        }

        if (statusStr === 'delivered' || statusStr === 'completed' || payStr === 'paid') {
          completedRevenuePkr += orderTotal;
        }

        const orderItems: any[] = Array.isArray(order.items_json) ? order.items_json : [];
        for (const item of orderItems) {
          const pid = Number(item.product_id || 0);
          const qty = Math.max(0, Number(item.quantity || 0));
          const unitPrice = Math.max(0, Number(item.price_pkr || item.unit_price_pkr || 0));
          const lineRevenue = qty * unitPrice;

          totalProductsSold += qty;

          const matchedProd = productById.get(pid);
          const title = matchedProd?.title || item.title || `Product #${pid}`;
          const sku = matchedProd?.sku || item.sku || '';
          const image_url = matchedProd?.image_url || item.image_url || '/products/overcoat.jpg';
          const catSlug = matchedProd?.category_slug || 'outerwear';

          const prevProd = productSalesMap.get(pid) || {
            product_id: pid,
            title,
            sku,
            image_url,
            category_slug: catSlug,
            units_sold: 0,
            revenue_pkr: 0,
          };
          prevProd.units_sold += qty;
          prevProd.revenue_pkr += lineRevenue;
          productSalesMap.set(pid, prevProd);

          const catName = categoryNameBySlug.get(catSlug) || catSlug;
          const prevCat = categorySalesMap.get(catSlug) || {
            category_slug: catSlug,
            category_name: catName,
            products_sold: 0,
            revenue_pkr: 0,
            orderIds: new Set<number>(),
          };
          prevCat.products_sold += qty;
          prevCat.revenue_pkr += lineRevenue;
          prevCat.orderIds.add(Number(order.id));
          categorySalesMap.set(catSlug, prevCat);
        }
      }

      // Include all catalog products so even 0-sale products can be seen if needed, ranked by units_sold DESC, revenue_pkr DESC
      for (const p of allProducts) {
        if (!productSalesMap.has(p.id)) {
          productSalesMap.set(p.id, {
            product_id: p.id,
            title: p.title,
            sku: p.sku,
            image_url: p.image_url,
            category_slug: p.category_slug,
            units_sold: 0,
            revenue_pkr: 0,
          });
        }
      }

      const topSellingProducts = Array.from(productSalesMap.values())
        .sort((a, b) => b.units_sold - a.units_sold || b.revenue_pkr - a.revenue_pkr)
        .slice(0, 8);

      const bestPerformingCategories = Array.from(categorySalesMap.values())
        .map((c) => ({
          category_slug: c.category_slug,
          category_name: c.category_name,
          products_sold: c.products_sold,
          orders_count: c.orderIds.size,
          revenue_pkr: c.revenue_pkr,
        }))
        .sort((a, b) => b.revenue_pkr - a.revenue_pkr || b.products_sold - a.products_sold);

      const customerEmailsSet = new Set<string>();
      for (const u of allUsers) {
        if (String(u.role || 'customer').toLowerCase() === 'customer' && u.email) {
          customerEmailsSet.add(String(u.email).toLowerCase());
        }
      }
      for (const o of allOrders) {
        if (o.customer_email) {
          customerEmailsSet.add(String(o.customer_email).toLowerCase());
        }
      }
      const totalCustomersCount = Math.max(
        allUsers.filter((u) => String(u.role || 'customer').toLowerCase() === 'customer').length,
        customerEmailsSet.size
      );

      const lowStockProducts = allProducts
        .filter((p) => Number(p.stock || 0) < lowStockThreshold)
        .map((p) => ({
          id: Number(p.id),
          title: String(p.title),
          sku: String(p.sku),
          stock: Number(p.stock || 0),
          price_pkr: Number(p.price_pkr || 0),
        }));

      const outOfStockCount = allProducts.filter((p) => Number(p.stock || 0) <= 0).length;

      const orderCountsByStatus = {
        pending: pendingOrdersCount,
        confirmed: confirmedOrdersCount,
        processing: processingOrdersCount,
        shipped: shippedOrdersCount,
        delivered: deliveredOrdersCount,
        cancelled: cancelledOrdersCount,
      };

      const averageOrderValuePkr =
        validOrdersCount > 0 ? Math.round(totalRevenuePkr / validOrdersCount) : 0;

      return res.json({
        total_revenue_pkr: totalRevenuePkr,
        completed_revenue_pkr: completedRevenuePkr,
        pending_revenue_pkr: pendingRevenuePkr,
        confirmed_revenue_pkr: confirmedRevenuePkr,
        excluded_cancelled_revenue_pkr: excludedCancelledRevenuePkr,
        total_orders: allOrders.length,
        valid_orders_count: validOrdersCount,
        pending_orders_count: pendingOrdersCount,
        confirmed_orders_count: confirmedOrdersCount,
        processing_orders_count: processingOrdersCount,
        shipped_orders_count: shippedOrdersCount,
        delivered_orders_count: deliveredOrdersCount,
        cancelled_orders_count: cancelledOrdersCount,
        order_counts_by_status: orderCountsByStatus,
        low_stock_count: lowStockProducts.length,
        out_of_stock_count: outOfStockCount,
        low_stock_threshold: lowStockThreshold,
        low_stock_products: lowStockProducts,
        average_order_value_pkr: averageOrderValuePkr,
        total_customers: totalCustomersCount,
        total_products_sold: totalProductsSold,
        top_selling_products: topSellingProducts,
        best_performing_categories: bestPerformingCategories,
        // CamelCase convenience fields
        totalRevenue: totalRevenuePkr,
        completedRevenue: completedRevenuePkr,
        totalOrders: allOrders.length,
        totalCustomers: totalCustomersCount,
        totalProductsSold,
        averageOrderValue: averageOrderValuePkr,
        topSellingProducts,
        bestPerformingCategories,
        orderCountsByStatus,
        lowStockCount: lowStockProducts.length,
        outOfStockCount,
        updated_at: new Date().toISOString(),
      });
    } catch (err: any) {
      return res.status(503).json({ error: 'Unable to load store statistics right now.' });
    }
  };

  app.get('/api/admin/stats', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, getStoreStatisticsHandler);
  app.get('/api/admin/statistics', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, getStoreStatisticsHandler);
  app.get('/api/stats', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, getStoreStatisticsHandler);

  app.get('/api/orders/track/:orderNumber', async (req, res) => {
    try {
      const orderNum = String(req.params.orderNumber || '').trim();
      if (!orderNum) {
        return res.status(400).json({ error: 'Order number is required.' });
      }
      const result = await dbQuery(
        'SELECT * FROM orders WHERE UPPER(order_number) = UPPER($1)',
        [orderNum]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Order not found.' });
      }
      const order = normalizeOrder(result.rows[0]);
      const customer = await getAuthenticatedCustomer(req);
      const admin = await getAuthenticatedAdmin(req);
      const verifyEmail = String(req.query.email || '').trim().toLowerCase();

      if (admin) {
        return res.json(order);
      }

      if (customer) {
        const ownsById = order.user_id && Number(order.user_id) === Number(customer.id);
        const ownsByEmail =
          String(order.customer_email || '').trim().toLowerCase() ===
          String(customer.email || '').trim().toLowerCase();
        if (!ownsById && !ownsByEmail) {
          return res.status(403).json({
            error: 'Access denied. You can only track orders placed under your own customer account.',
          });
        }
        return res.json(order);
      }

      if (
        verifyEmail &&
        verifyEmail === String(order.customer_email || '').trim().toLowerCase()
      ) {
        return res.json(order);
      }

      return res.status(401).json({
        error:
          'Please sign in to your customer account or provide the email address used for this order to view tracking information.',
      });
    } catch (err: any) {
      return res.status(503).json({ error: err.message });
    }
  });

  /**
   * POST /api/orders
   * Strictly requires a valid server-side authenticated session (`requireAuth`).
   * Never trusts `user_id`, `customerId`, `role`, product prices, stock, discounts, or totals supplied by the frontend.
   * Never substitutes the customer's profile address for the checkout shipping address.
   * Executes stock verification, stock deduction, coupon validation, and order creation atomically.
   */
  app.post('/api/orders', checkoutRateLimiter, requireAuth, async (req, res) => {
    try {
      // 1. Verify authenticated user from server-side session token
      const authenticatedCustomer = (req as any).authUser;
      if (!authenticatedCustomer) {
        return res.status(401).json({
          error: 'Authentication required. Please sign in to place an order.',
        });
      }

      const authenticatedUserId = Number(authenticatedCustomer.id);

      const {
        customer_name,
        shipping_name,
        customer_email,
        customer_phone,
        shipping_phone,
        shipping_address,
        shipping_city,
        city,
        shipping_area,
        area,
        postal_code,
        shipping_postal_code,
        order_notes,
        notes,
        payment_method = 'COD',
        coupon_code,
        idempotency_key,
        items,
      } = req.body || {};

      // Strictly use the shipping details submitted during checkout — NEVER fallback to profile address!
      const cleanName = sanitizeText(shipping_name ?? customer_name ?? '', 120);
      const cleanEmail = sanitizeEmailHeader(
        customer_email || authenticatedCustomer.email || ''
      ).toLowerCase();
      const cleanPhone = sanitizeText(shipping_phone ?? customer_phone ?? '', 40);
      const cleanAddress = sanitizeText(shipping_address ?? '', 300);
      const cleanCity = sanitizeText(shipping_city ?? city ?? '', 80);
      const cleanArea = sanitizeText(shipping_area ?? area ?? '', 120);
      const cleanPostal = sanitizeText(shipping_postal_code ?? postal_code ?? '', 24);
      const cleanNotes = sanitizeText(order_notes ?? notes ?? '', 500);
      const cleanIdempotencyKey = idempotency_key
        ? sanitizeText(idempotency_key, 100)
        : null;

      if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
        return res.status(400).json({
          error: 'Your cart is empty or exceeds the maximum item limit.',
        });
      }

      if (!cleanName) {
        return res.status(400).json({
          error: 'Full name is required in Shipping Information.',
        });
      }
      if (!cleanPhone) {
        return res.status(400).json({
          error: 'Phone number is required in Shipping Information.',
        });
      }
      if (!cleanAddress) {
        return res.status(400).json({
          error: 'Complete shipping address is required.',
        });
      }
      if (!cleanCity) {
        return res.status(400).json({
          error: 'City is required in Shipping Information.',
        });
      }

      const requestedPaymentMethod = String(payment_method || 'COD').trim().toUpperCase();
      if (requestedPaymentMethod !== 'COD') {
        return res.status(400).json({
          error: 'Only Cash on Delivery (COD) is supported.',
        });
      }

      // Check idempotency key to prevent duplicate submissions
      if (cleanIdempotencyKey) {
        const existingOrderRes = await dbQuery(
          'SELECT * FROM orders WHERE idempotency_key = $1',
          [cleanIdempotencyKey]
        );
        if (existingOrderRes.rows.length > 0) {
          return res.status(200).json(normalizeOrder(existingOrderRes.rows[0]));
        }
      }

      const settings = await fetchStoreSettings();
      const delivery_fee_pkr = Number(settings.delivery_fee_pkr || 300);

      // Run verification, stock deduction, and order insertion inside an atomic transaction
      const createdOrder = await withTransaction(async (txQuery) => {
        // Aggregate requested quantity per product_id
        const requestedQtyByProduct = new Map<number, number>();
        for (const rawItem of items) {
          const pid = Number(rawItem.product_id);
          const qty = Number(rawItem.quantity);
          if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(qty) || qty <= 0) {
            const err: any = new Error('Invalid cart item or quantity.');
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          requestedQtyByProduct.set(pid, (requestedQtyByProduct.get(pid) || 0) + qty);
        }

        // Verify product existence, live price, variant safety, and available stock in PostgreSQL
        const productMap = new Map<number, any>();
        for (const [pid, totalQty] of requestedQtyByProduct.entries()) {
          const prodRes = await txQuery('SELECT * FROM products WHERE id = $1', [pid]);
          if (prodRes.rows.length === 0) {
            const err: any = new Error(`Product #${pid} is no longer available.`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          const prod = normalizeProduct(prodRes.rows[0]);
          const currentStock = Number(prod.stock);
          if (currentStock < totalQty) {
            const err: any = new Error(
              currentStock <= 0
                ? `"${prod.title}" is currently out of stock.`
                : `Insufficient stock for "${prod.title}". Only ${currentStock} available.`
            );
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          productMap.set(pid, prod);
        }

        // Build verified line items, validate variants & variant stock, and calculate subtotal from DB prices
        let subtotal_pkr = 0;
        const variantDeductionsByProduct = new Map<number, Map<number, number>>();

        const verifiedItems = items.map((rawItem: any) => {
          const pid = Number(rawItem.product_id);
          const qty = Number(rawItem.quantity);
          const prod = productMap.get(pid);
          const selectedSize = String(rawItem.selected_size || 'Standard').trim();
          const selectedColor = String(rawItem.selected_color || 'Standard').trim();
          const requestedVariantSku = String(rawItem.variant_sku || '').trim();

          let unitPricePkr = Number(prod.price_pkr);
          let resolvedSku = String(prod.sku);

          if (Array.isArray(prod.variants) && prod.variants.length > 0) {
            const vIdx = prod.variants.findIndex(
              (v: any) =>
                (requestedVariantSku &&
                  String(v.sku || '').toLowerCase() === requestedVariantSku.toLowerCase()) ||
                (String(v.size || '').toLowerCase() === selectedSize.toLowerCase() &&
                  String(v.color || '').toLowerCase() === selectedColor.toLowerCase())
            );

            if (vIdx === -1) {
              const err: any = new Error(
                `Selected variant (${selectedColor} / ${selectedSize}) is no longer available for "${prod.title}".`
              );
              err.isBusinessError = true;
              err.statusCode = 400;
              throw err;
            }

            const matchedVariant = prod.variants[vIdx];
            const prodDeductions = variantDeductionsByProduct.get(pid) || new Map<number, number>();
            const prevRequestedForVariant = prodDeductions.get(vIdx) || 0;
            const newRequestedForVariant = prevRequestedForVariant + qty;

            if (Number(matchedVariant.stock) < newRequestedForVariant) {
              const err: any = new Error(
                Number(matchedVariant.stock) <= 0
                  ? `"${prod.title}" (${matchedVariant.color} / ${matchedVariant.size}) is out of stock.`
                  : `Insufficient stock for "${prod.title}" (${matchedVariant.color} / ${matchedVariant.size}). Only ${matchedVariant.stock} available.`
              );
              err.isBusinessError = true;
              err.statusCode = 400;
              throw err;
            }

            prodDeductions.set(vIdx, newRequestedForVariant);
            variantDeductionsByProduct.set(pid, prodDeductions);

            if (matchedVariant.price_pkr && Number(matchedVariant.price_pkr) > 0) {
              unitPricePkr = Number(matchedVariant.price_pkr);
            }
            if (matchedVariant.sku) {
              resolvedSku = String(matchedVariant.sku);
            }
          }

          subtotal_pkr += unitPricePkr * qty;

          return {
            product_id: pid,
            title: prod.title,
            sku: resolvedSku,
            variant_sku: resolvedSku,
            price_pkr: unitPricePkr,
            unit_price_pkr: unitPricePkr,
            quantity: qty,
            selected_size: selectedSize,
            selected_color: selectedColor,
            image_url: prod.image_url,
          };
        });

        // Validate coupon code against database if supplied
        let discount_pkr = 0;
        let validatedCouponCode: string | null = null;
        if (coupon_code && String(coupon_code).trim()) {
          const cleanCode = String(coupon_code).trim().toUpperCase();
          const cRes = await txQuery('SELECT * FROM coupons WHERE UPPER(code) = UPPER($1)', [
            cleanCode,
          ]);
          if (cRes.rows.length === 0) {
            const err: any = new Error(`Coupon code "${cleanCode}" does not exist.`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          const c = normalizeCoupon(cRes.rows[0]);
          if (!c.is_active) {
            const err: any = new Error(`Coupon code "${cleanCode}" is currently inactive.`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          if (c.expires_at && new Date(c.expires_at).getTime() < Date.now()) {
            const err: any = new Error(`Coupon code "${cleanCode}" has expired.`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          if (
            c.usage_limit !== null &&
            c.usage_limit !== undefined &&
            Number(c.usage_limit) > 0 &&
            Number(c.usage_count || 0) >= Number(c.usage_limit)
          ) {
            const err: any = new Error(
              `Coupon code "${cleanCode}" has reached its maximum usage limit.`
            );
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          if (
            c.per_customer_limit !== null &&
            c.per_customer_limit !== undefined &&
            Number(c.per_customer_limit) > 0
          ) {
            const existingOrdersForCoupon = await txQuery('SELECT * FROM orders');
            const customerUses = existingOrdersForCoupon.rows.filter((o: any) => {
              const st = String(o.order_status || o.status || '').toLowerCase();
              if (st === 'cancelled') return false;
              if (String(o.coupon_code || '').toUpperCase() !== cleanCode) return false;
              const matchId = Number(o.user_id) === authenticatedUserId;
              const matchEmail =
                cleanEmail && String(o.customer_email || '').trim().toLowerCase() === cleanEmail;
              return Boolean(matchId || matchEmail);
            }).length;
            if (customerUses >= Number(c.per_customer_limit)) {
              const err: any = new Error(
                `You have already used coupon "${cleanCode}" the maximum allowed number of times.`
              );
              err.isBusinessError = true;
              err.statusCode = 400;
              throw err;
            }
          }
          if (subtotal_pkr < Number(c.min_order_pkr)) {
            const err: any = new Error(
              `Minimum order of Rs. ${Number(c.min_order_pkr).toLocaleString()} required for promo code "${cleanCode}".`
            );
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          if (!Number.isFinite(Number(c.discount_value)) || Number(c.discount_value) <= 0) {
            const err: any = new Error(`Promo code "${cleanCode}" has an invalid discount value.`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }
          const rawDiscount =
            c.discount_type === 'percentage'
              ? Math.round((subtotal_pkr * Math.min(100, Number(c.discount_value))) / 100)
              : Number(c.discount_value);
          discount_pkr = Math.min(subtotal_pkr, Math.max(0, rawDiscount));
          validatedCouponCode = c.code;

          await txQuery('UPDATE coupons SET usage_count = usage_count + 1 WHERE id = $1', [c.id]);
        }

        // Deduct stock atomically (including variant stock when variants exist) and prevent negative stock
        for (const [pid, totalQty] of requestedQtyByProduct.entries()) {
          const prod = productMap.get(pid);
          const deductRes = await txQuery(
            'UPDATE products SET stock = stock - $1 WHERE id = $2 AND stock >= $1 RETURNING *',
            [totalQty, pid]
          );
          if (deductRes.rows.length === 0) {
            const err: any = new Error(`Insufficient stock for "${prod.title}".`);
            err.isBusinessError = true;
            err.statusCode = 400;
            throw err;
          }

          const variantDeductions = variantDeductionsByProduct.get(pid);
          if (variantDeductions && Array.isArray(prod.variants) && prod.variants.length > 0) {
            const updatedVariants = prod.variants.map((v: any, idx: number) => {
              const deductQty = variantDeductions.get(idx) || 0;
              if (deductQty <= 0) return v;
              return {
                ...v,
                stock: Math.max(0, Number(v.stock || 0) - deductQty),
              };
            });
            const newTotalStock = Math.max(0, Number(prod.stock) - totalQty);
            await txQuery(
              'UPDATE products SET variants = $1::jsonb, stock = $2 WHERE id = $3',
              [JSON.stringify(updatedVariants), newTotalStock, pid]
            );
          }
        }

        const total_pkr = Math.max(0, subtotal_pkr - discount_pkr) + delivery_fee_pkr;

        const allOrdersRes = await txQuery('SELECT * FROM orders');
        const maxOrderNum = allOrdersRes.rows.reduce((max: number, o: any) => {
          const match = String(o.order_number || '').match(/FNR-(\d+)/i);
          return match ? Math.max(max, parseInt(match[1], 10)) : max;
        }, 1000);
        const order_number = `FNR-${maxOrderNum + 1}`;

        const cleanPaymentMethod = 'COD';
        const payment_status = 'pending';
        const order_status = 'pending';

        const orderRes = await txQuery(
          `INSERT INTO orders (
            order_number, user_id, customer_name, customer_email, customer_phone,
            shipping_address, shipping_city, shipping_area, postal_code, order_notes,
            payment_method, payment_status, order_status,
            subtotal_pkr, discount_pkr, coupon_code, delivery_fee_pkr, total_pkr,
            idempotency_key, items_json
          ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, $12, $13,
            $14, $15, $16, $17, $18,
            $19, $20::jsonb
          ) RETURNING *`,
          [
            order_number,
            authenticatedUserId,
            cleanName,
            cleanEmail,
            cleanPhone,
            cleanAddress,
            cleanCity,
            cleanArea,
            cleanPostal,
            cleanNotes,
            cleanPaymentMethod,
            payment_status,
            order_status,
            subtotal_pkr,
            discount_pkr,
            validatedCouponCode,
            delivery_fee_pkr,
            total_pkr,
            cleanIdempotencyKey,
            JSON.stringify(verifiedItems),
          ]
        );

        const loyalty_points_awarded = Math.max(1, Math.round(total_pkr * LOYALTY_POINTS_RATE));

        await txQuery(
          `UPDATE users
           SET total_orders = total_orders + 1,
               total_spent_pkr = total_spent_pkr + $1,
               loyalty_points = COALESCE(loyalty_points, 0) + $2
           WHERE id = $3`,
          [total_pkr, loyalty_points_awarded, authenticatedUserId]
        );

        return {
          ...normalizeOrder(orderRes.rows[0]),
          loyalty_points_awarded,
        };
      });

      await logAudit(
        authenticatedCustomer.name,
        'customer',
        'ORDER_PLACED',
        'orders',
        `Customer #${authenticatedUserId} (${authenticatedCustomer.email}) placed order ${createdOrder.order_number} for Rs. ${createdOrder.total_pkr.toLocaleString()}`
      );

      const emailSent = await sendOrderConfirmationEmail(createdOrder);

      return res.status(201).json({
        ...createdOrder,
        email_sent: emailSent,
      });
    } catch (err: any) {
      const statusCode = err?.statusCode || 503;
      const safeMessage =
        err?.isBusinessError && err?.message
          ? err.message
          : 'Unable to complete your order right now. Please try again.';
      return res.status(statusCode).json({ error: safeMessage });
    }
  });

  const updateOrderHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { order_status, payment_status } = req.body || {};

      const existingRes = await dbQuery('SELECT * FROM orders WHERE id = $1', [id]);
      if (existingRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
      const prevOrder = normalizeOrder(existingRes.rows[0]);

      const result = await dbQuery(
        `UPDATE orders SET order_status = $1, payment_status = $2 WHERE id = $3 RETURNING *`,
        [order_status || prevOrder.order_status, payment_status || prevOrder.payment_status, id]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Order not found' });

      // Restore product stock and variant stock if order transitions to cancelled
      if (order_status === 'cancelled' && prevOrder.order_status !== 'cancelled') {
        for (const item of prevOrder.items_json || []) {
          const pid = Number(item.product_id);
          const qty = Number(item.quantity || 0);
          await dbQuery('UPDATE products SET stock = stock + $1 WHERE id = $2', [qty, pid]);

          const prodCheck = await dbQuery('SELECT * FROM products WHERE id = $1', [pid]);
          if (prodCheck.rows.length > 0) {
            const p = normalizeProduct(prodCheck.rows[0]);
            if (Array.isArray(p.variants) && p.variants.length > 0) {
              const updatedVariants = p.variants.map((v: any) => {
                const matchBySku =
                  item.sku && String(v.sku || '').toLowerCase() === String(item.sku).toLowerCase();
                const matchByAttrs =
                  String(v.size || '').toLowerCase() ===
                    String(item.selected_size || '').toLowerCase() &&
                  String(v.color || '').toLowerCase() ===
                    String(item.selected_color || '').toLowerCase();
                if (matchBySku || matchByAttrs) {
                  return { ...v, stock: Number(v.stock || 0) + qty };
                }
                return v;
              });
              await dbQuery('UPDATE products SET variants = $1::jsonb, stock = $2 WHERE id = $3', [
                JSON.stringify(updatedVariants),
                Number(p.stock),
                pid,
              ]);
            }
          }
        }
      }

      const updated = normalizeOrder(result.rows[0]);
      await logAudit(
        'Admin',
        'admin',
        'UPDATE_ORDER_STATUS',
        'orders',
        `Updated order ${updated.order_number} to status [${order_status}] / payment [${payment_status}]`
      );

      let emailSent = false;
      if (order_status && order_status !== prevOrder.order_status) {
        emailSent = await sendOrderStatusUpdateEmail(updated, order_status);
      }

      res.json({
        ...updated,
        email_sent: emailSent,
      });
    } catch (err: any) {
      res.status(503).json({ error: 'Unable to update order status right now.' });
    }
  };

  const deleteOrderHandler: express.RequestHandler = async (req, res) => {
    try {
      const id = Number(req.params.id);
      await dbQuery('DELETE FROM orders WHERE id = $1', [id]);
      await logAudit('Admin', 'admin', 'DELETE_ORDER', 'orders', `Deleted order #${id}`);
      res.json({ success: true });
    } catch (err: any) {
      res.status(503).json({ error: err.message });
    }
  };

  app.put('/api/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.patch('/api/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.patch('/api/orders/:id/status', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.put('/api/admin/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.patch('/api/admin/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.patch('/api/admin/orders/:id/status', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateOrderHandler);
  app.delete('/api/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), deleteOrderHandler);
  app.delete('/api/admin/orders/:id', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), deleteOrderHandler);

  // Customer self-service order cancellation (only while order_status is 'pending')
  app.post('/api/orders/:id/cancel', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid order ID.' });
      }
      const user = (req as any).authUser;
      const existingRes = await dbQuery('SELECT * FROM orders WHERE id = $1', [id]);
      if (existingRes.rows.length === 0) {
        return res.status(404).json({ error: 'Order not found.' });
      }
      const order = normalizeOrder(existingRes.rows[0]);
      const isOwner =
        Number(order.user_id) === Number(user.id) ||
        String(order.customer_email || '').toLowerCase() === String(user.email || '').toLowerCase();
      if (!isOwner && user.role !== 'admin') {
        return res.status(403).json({ error: 'You can only cancel your own orders.' });
      }
      if (String(order.order_status).toLowerCase() !== 'pending') {
        return res.status(400).json({
          error: 'Only pending orders can be cancelled before studio processing begins.',
        });
      }

      const result = await dbQuery(
        `UPDATE orders SET order_status = 'cancelled', payment_status = $1 WHERE id = $2 RETURNING *`,
        [order.payment_status, id]
      );

      for (const item of order.items_json || []) {
        const pid = Number(item.product_id);
        const qty = Number(item.quantity || 0);
        if (pid > 0 && qty > 0) {
          await dbQuery('UPDATE products SET stock = stock + $1 WHERE id = $2', [qty, pid]);
        }
      }

      const updated = normalizeOrder(result.rows[0]);
      await logAudit(
        user.name || user.email,
        user.role || 'customer',
        'CUSTOMER_CANCELLED_ORDER',
        'orders',
        `Cancelled pending order ${updated.order_number}`
      );
      await sendOrderStatusUpdateEmail(updated, 'cancelled');
      return res.json(updated);
    } catch {
      return res.status(503).json({ error: 'Unable to cancel order right now.' });
    }
  });

  // Customer reorder verification endpoint (returns live product availability & prices from PostgreSQL)
  app.post('/api/orders/:id/reorder', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid order ID.' });
      }
      const user = (req as any).authUser;
      const existingRes = await dbQuery('SELECT * FROM orders WHERE id = $1', [id]);
      if (existingRes.rows.length === 0) {
        return res.status(404).json({ error: 'Order not found.' });
      }
      const order = normalizeOrder(existingRes.rows[0]);
      const isOwner =
        Number(order.user_id) === Number(user.id) ||
        String(order.customer_email || '').toLowerCase() === String(user.email || '').toLowerCase();
      if (!isOwner && user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied.' });
      }

      const availableItems: any[] = [];
      const unavailableItems: string[] = [];

      for (const item of order.items_json || []) {
        const pid = Number(item.product_id);
        const prodRes = await dbQuery('SELECT * FROM products WHERE id = $1', [pid]);
        if (prodRes.rows.length === 0) {
          unavailableItems.push(item.title || `Item #${pid}`);
          continue;
        }
        const prod = normalizeProduct(prodRes.rows[0]);
        if (Number(prod.stock) <= 0) {
          unavailableItems.push(prod.title);
          continue;
        }
        availableItems.push({
          product: prod,
          quantity: Math.min(Number(item.quantity || 1), Number(prod.stock)),
          selected_size: item.selected_size || 'Standard',
          selected_color: item.selected_color || 'Standard',
          variant_sku: item.variant_sku || item.sku || prod.sku,
        });
      }

      return res.json({
        order_number: order.order_number,
        available_items: availableItems,
        unavailable_items: unavailableItems,
      });
    } catch {
      return res.status(503).json({ error: 'Unable to process reorder request.' });
    }
  });

  // ============================================================================
  // REVIEWS, STORE SETTINGS & AUDIT LOGS
  // ============================================================================
  app.get('/api/reviews', async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM reviews ORDER BY id DESC');
      res.json(result.rows.map(normalizeReview));
    } catch {
      res.status(503).json({ error: 'Unable to load reviews.' });
    }
  });

  app.post('/api/reviews', contactRateLimiter, async (req, res) => {
    try {
      const { product_id, customer_name, customer_city, rating, comment } = req.body || {};
      const pid = Number(product_id);
      const cleanName = sanitizeText(customer_name || '', 80);
      const cleanCity = sanitizeText(customer_city || 'Lahore', 60);
      const cleanComment = sanitizeText(comment || '', 1200);
      const safeRating = Math.max(1, Math.min(5, Math.round(Number(rating || 5))));

      if (!Number.isInteger(pid) || pid <= 0 || !cleanName || !cleanComment) {
        return res.status(400).json({ error: 'product_id, customer_name, and comment are required' });
      }
      const result = await dbQuery(
        `INSERT INTO reviews (product_id, customer_name, customer_city, rating, comment, verified_purchase)
         VALUES ($1, $2, $3, $4, $5, true) RETURNING *`,
        [pid, cleanName, cleanCity, safeRating, cleanComment]
      );
      await dbQuery('UPDATE products SET reviews_count = reviews_count + 1 WHERE id = $1', [pid]);
      res.status(201).json(normalizeReview(result.rows[0]));
    } catch {
      res.status(503).json({ error: 'Unable to submit review right now.' });
    }
  });

  const deleteReviewHandler: express.RequestHandler = async (req, res) => {
    try {
      await dbQuery('DELETE FROM reviews WHERE id = $1', [Number(req.params.id)]);
      res.json({ success: true });
    } catch {
      res.status(503).json({ error: 'Unable to delete review.' });
    }
  };
  app.delete('/api/reviews/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteReviewHandler);
  app.delete('/api/admin/reviews/:id', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, deleteReviewHandler);

  app.get('/api/store_settings', async (_req, res) => {
    try {
      const settings = await fetchStoreSettings();
      res.json(settings);
    } catch {
      res.status(503).json({ error: 'Unable to load store settings.' });
    }
  });

  app.get('/api/settings', async (_req, res) => {
    try {
      const settings = await fetchStoreSettings();
      res.json(settings);
    } catch {
      res.status(503).json({ error: 'Unable to load store settings.' });
    }
  });

  const ALLOWED_SETTINGS_KEYS = new Set([
    'store_name',
    'tagline',
    'footer_description',
    'currency',
    'currency_symbol',
    'delivery_fee_pkr',
    'announcement_bar',
    'announcement_bg_color',
    'announcement_text_color',
    'announcement_enabled',
    'announcement_link',
    'homepage_featured_title',
    'homepage_new_arrivals_title',
    'faq_json',
    'footer_sections_json',
    'pages_json',
    'footer_copyright_text',
    'footer_bottom_note',
    'contactEmail',
    'contact_email',
    'business_email',
    'business_phone',
    'business_address',
    'support_phone',
    'support_email',
    'atelier_address',
    'flagship_address',
    'working_hours',
    'instagramUrl',
    'instagram_handle',
    'instagram_url',
    'facebook_url',
    'whatsapp_number',
    'social_instagram_url',
    'social_facebook_url',
    'social_whatsapp_url',
    'social_tiktok_url',
  ]);

  const updateSettingsHandler: express.RequestHandler = async (req, res) => {
    try {
      const updates = { ...(req.body || {}) };
      if (updates.footer_description !== undefined && updates.tagline === undefined) {
        updates.tagline = updates.footer_description;
      } else if (updates.tagline !== undefined && updates.footer_description === undefined) {
        updates.footer_description = updates.tagline;
      }

      // Symmetrical sync for centralized business contact email
      const incomingEmail =
        updates.contactEmail ??
        updates.contact_email ??
        updates.business_email ??
        updates.support_email;
      if (incomingEmail !== undefined) {
        const cleanEmail = String(incomingEmail).trim();
        updates.contactEmail = cleanEmail;
        updates.contact_email = cleanEmail;
        updates.business_email = cleanEmail;
        updates.support_email = cleanEmail;
      }

      // Symmetrical sync for business phone
      const incomingPhone = updates.business_phone ?? updates.support_phone;
      if (incomingPhone !== undefined) {
        const cleanPhone = String(incomingPhone).trim();
        updates.business_phone = cleanPhone;
        updates.support_phone = cleanPhone;
      }

      // Symmetrical sync for business address
      const incomingAddress =
        updates.business_address ?? updates.atelier_address ?? updates.flagship_address;
      if (incomingAddress !== undefined) {
        const cleanAddress = String(incomingAddress).trim();
        updates.business_address = cleanAddress;
        updates.atelier_address = cleanAddress;
        updates.flagship_address = cleanAddress;
      }

      // Symmetrical sync for Instagram URL
      const incomingInstagram =
        updates.instagramUrl ?? updates.instagram_url ?? updates.social_instagram_url;
      if (incomingInstagram !== undefined) {
        const cleanInstagram = String(incomingInstagram).trim();
        updates.instagramUrl = cleanInstagram;
        updates.instagram_url = cleanInstagram;
        updates.social_instagram_url = cleanInstagram;
      }

      if (updates.facebook_url !== undefined) {
        updates.social_facebook_url = updates.facebook_url;
      } else if (updates.social_facebook_url !== undefined) {
        updates.facebook_url = updates.social_facebook_url;
      }

      if (updates.whatsapp_number !== undefined) {
        updates.social_whatsapp_url = updates.whatsapp_number;
      } else if (updates.social_whatsapp_url !== undefined) {
        updates.whatsapp_number = updates.social_whatsapp_url;
      }

      for (const [key, value] of Object.entries(updates)) {
        if (!ALLOWED_SETTINGS_KEYS.has(key) || value === undefined || value === null) continue;
        const serialized =
          typeof value === 'object' ? JSON.stringify(value) : sanitizeText(value, 50000);
        await dbQuery(
          `INSERT INTO store_settings (key, value, updated_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [key, serialized]
        );
      }
      await logAudit('Admin', 'admin', 'UPDATE_SETTINGS', 'store_settings', 'Updated Foner store & footer settings');
      const settings = await fetchStoreSettings();
      res.json(settings);
    } catch {
      res.status(503).json({ error: 'Unable to update store settings.' });
    }
  };

  app.get('/api/admin/settings', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, async (_req, res) => {
    try {
      const settings = await fetchStoreSettings();
      res.json(settings);
    } catch {
      res.status(503).json({ error: 'Unable to load store settings.' });
    }
  });
  app.put('/api/store_settings', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateSettingsHandler);
  app.put('/api/settings', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateSettingsHandler);
  app.put('/api/admin/settings', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateSettingsHandler);

  // ============================================================================
  // FAQ & INFORMATIONAL PAGES ENDPOINTS (BACKED BY POSTGRESQL store_settings)
  // ============================================================================
  app.get('/api/faqs', async (_req, res) => {
    try {
      const settings = await fetchStoreSettings();
      let faqs = DEFAULT_FAQ_LIST;
      try {
        const parsed = JSON.parse(settings.faq_json || '[]');
        if (Array.isArray(parsed)) faqs = parsed;
      } catch {
        // fallback to default
      }
      res.json(faqs);
    } catch {
      res.status(503).json({ error: 'Unable to load FAQs.' });
    }
  });

  const updateFaqsHandler: express.RequestHandler = async (req, res) => {
    try {
      const rawFaqs = Array.isArray(req.body) ? req.body : req.body?.faqs || [];
      const faqs = rawFaqs.slice(0, 100).map((f: any, idx: number) => ({
        id: sanitizeText(f?.id || `faq-${idx + 1}`, 60),
        category: sanitizeText(f?.category || 'General', 80),
        question: sanitizeText(f?.question || '', 400),
        answer: sanitizeText(f?.answer || '', 3000),
      }));
      const serialized = JSON.stringify(faqs);
      await dbQuery(
        `INSERT INTO store_settings (key, value, updated_at)
         VALUES ('faq_json', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [serialized]
      );
      await logAudit('Admin', 'admin', 'UPDATE_FAQS', 'store_settings', `Updated ${faqs.length} FAQ item(s)`);
      res.json({ success: true, faqs });
    } catch {
      res.status(503).json({ error: 'Unable to update FAQs.' });
    }
  };
  app.put('/api/faqs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateFaqsHandler);
  app.put('/api/admin/faqs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updateFaqsHandler);

  app.get('/api/pages', async (_req, res) => {
    try {
      const settings = await fetchStoreSettings();
      let pages = DEFAULT_INFORMATIONAL_PAGES;
      try {
        const parsed = JSON.parse(settings.pages_json || '[]');
        if (Array.isArray(parsed) && parsed.length > 0) pages = parsed;
      } catch {
        // fallback
      }
      res.json(pages);
    } catch {
      res.status(503).json({ error: 'Unable to load informational pages.' });
    }
  });

  const updatePagesHandler: express.RequestHandler = async (req, res) => {
    try {
      const rawPages = Array.isArray(req.body) ? req.body : req.body?.pages || [];
      const pages = rawPages.slice(0, 40).map((p: any, idx: number) => ({
        slug: slugifyText(p?.slug || p?.title || `page-${idx + 1}`),
        title: sanitizeText(p?.title || '', 160),
        subtitle: sanitizeText(p?.subtitle || '', 300),
        content: sanitizeText(p?.content || '', 20000),
        updated_at: new Date().toISOString(),
      }));
      const serialized = JSON.stringify(pages);
      await dbQuery(
        `INSERT INTO store_settings (key, value, updated_at)
         VALUES ('pages_json', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [serialized]
      );
      await logAudit('Admin', 'admin', 'UPDATE_PAGES', 'store_settings', 'Updated informational pages content');
      res.json({ success: true, pages });
    } catch {
      res.status(503).json({ error: 'Unable to update informational pages.' });
    }
  };
  app.put('/api/pages', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updatePagesHandler);
  app.put('/api/admin/pages', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, updatePagesHandler);

  // ============================================================================
  // CONTACT MESSAGES ENDPOINTS (/api/contact)
  // ============================================================================
  const listContactMessagesHandler: express.RequestHandler = async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM contact_messages ORDER BY id DESC LIMIT 100');
      res.json(result.rows);
    } catch {
      res.status(503).json({ error: 'Unable to load contact inquiries.' });
    }
  };
  app.get('/api/contact', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listContactMessagesHandler);
  app.get('/api/admin/contact', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listContactMessagesHandler);

  const contactSchema = z.object({
    name: z.string().trim().min(2, 'Please provide your name.').max(120),
    email: z.string().trim().toLowerCase().email('Please provide a valid email address.').max(160),
    phone: z.string().trim().max(40).optional().default(''),
    subject: z.string().trim().max(160).optional().default('General Inquiry'),
    message: z.string().trim().min(5, 'Please enter a message (at least 5 characters).').max(3000),
  });

  app.post('/api/contact', contactRateLimiter, async (req, res) => {
    try {
      const parsed = contactSchema.safeParse(req.body || {});
      if (!parsed.success) {
        return res.status(400).json({
          error:
            parsed.error.issues[0]?.message ||
            'Please provide your name, a valid email address, and message.',
        });
      }

      const cleanName = sanitizeText(parsed.data.name, 120);
      const cleanEmail = parsed.data.email;
      const cleanPhone = sanitizeText(parsed.data.phone, 40);
      const cleanSubject = sanitizeText(parsed.data.subject || 'General Inquiry', 160);
      const cleanMessage = sanitizeText(parsed.data.message, 3000);

      const result = await dbQuery(
        `INSERT INTO contact_messages (name, email, phone, subject, message, status)
         VALUES ($1, $2, $3, $4, $5, 'unread')
         RETURNING *`,
        [cleanName, cleanEmail, cleanPhone, cleanSubject, cleanMessage]
      );

      const savedInquiry = result.rows[0];
      const emailSent = await sendContactNotificationEmail({
        name: cleanName,
        email: cleanEmail,
        phone: cleanPhone,
        subject: cleanSubject,
        message: cleanMessage,
      });

      if (emailSent && savedInquiry?.id) {
        await dbQuery('UPDATE contact_messages SET email_sent = true WHERE id = $1', [
          Number(savedInquiry.id),
        ]);
      }

      await logAudit(
        cleanName,
        'customer',
        'CONTACT_MESSAGE_SUBMITTED',
        'contact_messages',
        `Contact inquiry from ${cleanName} (${cleanEmail}): ${cleanSubject}`
      );

      res.status(201).json({
        success: true,
        email_sent: emailSent,
        inquiry: { ...savedInquiry, email_sent: emailSent },
        message: 'Thank you for contacting Foner. Our client services team will respond within 24 hours.',
      });
    } catch {
      res.status(503).json({ error: 'Unable to submit message right now.' });
    }
  });

  const listAuditLogsHandler: express.RequestHandler = async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100');
      res.json(result.rows);
    } catch {
      res.status(503).json({ error: 'Unable to load audit logs.' });
    }
  };
  app.get('/api/audit_logs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listAuditLogsHandler);
  app.get('/api/audit-logs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listAuditLogsHandler);
  app.get('/api/admin/audit_logs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listAuditLogsHandler);
  app.get('/api/admin/audit-logs', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listAuditLogsHandler);

  // ============================================================================
  // NEWSLETTER MAILING LIST (/api/newsletter)
  // ============================================================================
  const listNewsletterSubscribersHandler: express.RequestHandler = async (_req, res) => {
    try {
      const result = await dbQuery('SELECT * FROM newsletter_subscribers ORDER BY id DESC LIMIT 200');
      res.json(result.rows);
    } catch {
      res.status(503).json({ error: 'Unable to load newsletter subscribers.' });
    }
  };
  app.get('/api/newsletter', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listNewsletterSubscribersHandler);
  app.get('/api/admin/newsletter', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, listNewsletterSubscribersHandler);

  const subscribeNewsletterHandler: express.RequestHandler = async (req, res) => {
    try {
      const parsedEmail = emailSchema.safeParse(req.body?.email);
      if (!parsedEmail.success) {
        return res.status(400).json({ error: 'Please provide a valid email address.' });
      }
      const rawEmail = parsedEmail.data;

      const existingSub = await dbQuery(
        'SELECT * FROM newsletter_subscribers WHERE LOWER(email) = LOWER($1)',
        [rawEmail]
      );
      const alreadySubscribed =
        existingSub.rows.length > 0 && existingSub.rows[0].status === 'subscribed';

      const result = await dbQuery(
        `INSERT INTO newsletter_subscribers (email, status)
         VALUES ($1, 'subscribed')
         ON CONFLICT (email) DO UPDATE SET status = 'subscribed'
         RETURNING id, email, status, created_at`,
        [rawEmail]
      );

      let welcomeSent = false;
      if (!alreadySubscribed) {
        welcomeSent = await sendNewsletterWelcomeEmail(rawEmail);
        if (welcomeSent && result.rows[0]?.id) {
          await dbQuery(
            'UPDATE newsletter_subscribers SET welcome_email_sent = true WHERE id = $1',
            [Number(result.rows[0].id)]
          );
        }
      }

      await logAudit(
        rawEmail,
        'customer',
        'NEWSLETTER_SUBSCRIBE',
        'newsletter_subscribers',
        `Joined Foner mailing list (${rawEmail})`
      );

      res.status(alreadySubscribed ? 200 : 201).json({
        status: 'subscribed',
        already_subscribed: alreadySubscribed,
        welcome_email_sent: welcomeSent,
        subscriber: result.rows[0],
        message: alreadySubscribed
          ? 'You are already subscribed to Foner email updates.'
          : 'You have been subscribed to email updates.',
      });
    } catch {
      res.status(503).json({ error: 'Unable to subscribe right now. Please try again.' });
    }
  };

  app.post('/api/newsletter', newsletterRateLimiter, subscribeNewsletterHandler);
  app.post('/api/newsletter/subscribe', newsletterRateLimiter, subscribeNewsletterHandler);

  // ============================================================================
  // DATABASE SCHEMA & LIVE TABLE INSPECTION
  // ============================================================================
  app.get('/api/admin/database/status', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), async (_req, res) => {
    try {
      const status = await getDatabaseStatusInfo();
      res.json(status);
    } catch {
      res.status(503).json({ error: 'Unable to retrieve database status.' });
    }
  });

  app.get('/api/admin/database/table/:tableName', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), async (req, res) => {
    try {
      const tableName = String(req.params.tableName || '').toLowerCase();
      if (!(REQUIRED_TABLES as readonly string[]).includes(tableName)) {
        return res.status(400).json({ error: 'Invalid table name' });
      }
      const orderByCol =
        tableName === 'store_settings'
          ? 'key'
          : tableName === 'user_sessions' ||
            tableName === 'registration_otps' ||
            tableName === 'password_reset_tokens'
          ? 'created_at'
          : 'id';
      const sql = `SELECT * FROM ${tableName} ORDER BY ${orderByCol} ASC LIMIT 100`;
      const result = await dbQuery(sql);
      const rows = result.rows.map((r: any) => {
        if (tableName === 'users') {
          const { password_hash: _ph, ...rest } = r;
          return rest;
        }
        if (tableName === 'user_sessions') {
          const { token: rawTok, ...rest } = r;
          return {
            ...rest,
            token: rawTok ? `${String(rawTok).slice(0, 10)}...[redacted]` : '[redacted]',
          };
        }
        if (tableName === 'registration_otps') {
          const { otp_code: _otp, ...rest } = r;
          return { ...rest, otp_code: '[hashed]' };
        }
        if (tableName === 'password_reset_tokens') {
          const { token_hash: _th, ...rest } = r;
          return { ...rest, token_hash: '[hashed]' };
        }
        return r;
      });
      const columns = rows.length > 0 ? Object.keys(rows[0]) : [];
      res.json({
        table_name: tableName,
        sql_executed: sql,
        row_count: rows.length,
        columns,
        rows,
        fetched_at: new Date().toISOString(),
      });
    } catch {
      res.status(503).json({ error: 'Unable to inspect table.' });
    }
  });

  app.post('/api/admin/database/initialize', adminRouteAuthorizationMiddleware, requireAuth, requireRole(['admin']), async (_req, res) => {
    try {
      const initResult = await initializeDatabase();
      await logAudit(
        'Admin',
        'admin',
        'DATABASE_SCHEMA_SYNC',
        'database',
        `Verified database schema on ${initResult.host}:${initResult.port}/${initResult.database_name}`
      );
      const status = await getDatabaseStatusInfo();
      res.json(status);
    } catch (err: any) {
      res.status(503).json({ error: err.message || 'Failed to initialize database schema' });
    }
  });

  // ============================================================================
  // DATABASE DIAGNOSTICS (REAL POSTGRESQL CONNECTION TEST VIA BACKEND)
  // Architecture: Admin Browser -> Backend API -> PostgreSQL (Frontend NEVER connects directly)
  // Executes minimal query `SELECT 1` without exposing passwords or credentials
  // ============================================================================
  app.get(
    '/api/admin/diagnostics/database',
    adminRouteAuthorizationMiddleware,
    requireAuth,
    requireRole(['admin']),
    async (_req, res) => {
      const startTime = Date.now();
      try {
        const queryRes = await dbQuery('SELECT 1 as ping, current_database() as db_name');
        const latencyMs = Date.now() - startTime;
        const row = queryRes.rows && queryRes.rows[0];
        const dbName = row?.db_name ? String(row.db_name) : 'f';

        return res.json({
          connected: true,
          database: dbName,
          query: 'SELECT 1',
          latency_ms: latencyMs,
          checked_at: new Date().toISOString(),
        });
      } catch (err: any) {
        const latencyMs = Date.now() - startTime;
        return res.status(503).json({
          connected: false,
          database: null,
          latency_ms: latencyMs,
          error: 'PostgreSQL database connection failed: ' + (err?.message || 'Database unreachable'),
          checked_at: new Date().toISOString(),
        });
      }
    }
  );

  // Catch-all for any unmatched /api/admin/* route — always intercepted by adminRouteAuthorizationMiddleware
  app.all('/api/admin/*', adminRouteAuthorizationMiddleware, requireAuth, requireAdmin, (_req, res) => {
    res.status(404).json({ error: 'Admin API endpoint not found.' });
  });

  // ============================================================================
  // VITE DEV SERVER OR STATIC PRODUCTION ASSETS
  // ============================================================================
  const candidateFrontendDirs = [
    path.resolve(__dirname, '../frontend'),
    path.resolve(process.cwd(), 'frontend'),
    path.resolve(__dirname, 'frontend'),
    path.resolve(process.cwd(), '.'),
  ];
  let frontendDir = candidateFrontendDirs[0];
  for (const dir of candidateFrontendDirs) {
    if (fs.existsSync(path.join(dir, 'index.html')) || fs.existsSync(path.join(dir, 'src', 'main.tsx'))) {
      frontendDir = dir;
      break;
    }
  }

  const candidateDistPaths = [
    path.resolve(__dirname, '../frontend/dist'),
    path.resolve(process.cwd(), 'frontend/dist'),
    path.resolve(process.cwd(), 'dist'),
    path.resolve(__dirname, 'dist'),
  ];
  let distPath = candidateDistPaths[0];
  for (const d of candidateDistPaths) {
    if (fs.existsSync(path.join(d, 'index.html'))) {
      distPath = d;
      break;
    }
  }

  let viteServer: Awaited<ReturnType<typeof createViteServer>> | null = null;
  if (process.env.NODE_ENV !== 'production' && fs.existsSync(frontendDir)) {
    viteServer = await createViteServer({
      root: frontendDir,
      server: { middlewareMode: true, hmr: false, watch: null },
      appType: 'spa',
    });
    app.use(viteServer.middlewares);
  } else if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    app.get('/', (_req, res) => {
      res.json({
        service: 'Foner Backend API',
        status: 'online',
        health_check: '/api/health',
        diagnostics: '/api/admin/diagnostics/database',
      });
    });
  }

  const HOST = process.env.HOST || '0.0.0.0';
  const PORT = Number(process.env.PORT || 3000);
  app.listen(PORT, HOST, () => {
    console.log(`Foner Backend listening on http://${HOST}:${PORT}`);
    if (viteServer) {
      Promise.allSettled([
        viteServer.transformRequest('/src/main.tsx'),
        viteServer.transformRequest('/src/index.css'),
        viteServer.transformRequest('/src/App.tsx'),
      ]).catch(() => {});
    }
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
