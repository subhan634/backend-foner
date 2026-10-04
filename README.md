# Foner Backend API

A secure REST API backend for the Foner Admin Dashboard.

## Overview

This backend provides admin-only APIs for managing users, orders, and other entities. All sensitive operations require `requireAdmin` authorization.

## Prerequisites

- **PostgreSQL** database with `DATABASE_URL` environment variable
- **Node.js** 18+ (for development)
- **npm** or **yarn**

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string (e.g., `postgresql://user:pass@localhost:5432/foner`) | Yes |
| `PORT` | Server port (default: `3000`) | No |
| `HOST` | Server host (default: `0.0.0.0`) | No |

## Setup

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your PostgreSQL credentials
# Example:
# DATABASE_URL=postgresql://f_user:secret@localhost:5432/foner
# PORT=3000
# HOST=0.0.0.0

# Install dependencies
npm install

# Start the server
npm run dev
```

## API Endpoints

### Health Check
- `GET /health` – Service health status
- `GET /api/health` – Detailed health info

### User Management (Admin Only)
- `GET /api/admin/users` – List all users (with pagination, search, filters)
- `GET /api/admin/users/:id` – Get user by ID
- `PATCH /api/admin/users/:id/role` – Update user role (admin only)
- `GET /api/admin/users/:id` – PATCH role change (via frontend)

### Order Management (Admin Only)
- `GET /api/orders` – List orders
- `PUT /api/orders/:id` – Update order
- `PATCH /api/orders/:id/status` – Update order status

### Diagnostics
- `GET /api/admin/diagnostics/database` – Database health status
- `GET /api/admin/diagnostics/audit` – Audit log entries

## Database Schema

The backend uses PostgreSQL with the following tables:
- `users` – User accounts (id, name, email, role, status, created_at)
- `orders` – Customer orders
- `user_sessions` – Authentication sessions
- `product_*` – Product catalog
- `audit_logs` – Audit trail of actions

## Authorization

- **Public** – Read-only API endpoints (health, diagnostics)
- **Admin** – Full CRUD access to users, orders, and system settings
- **Customer** – Limited read access (not implemented in this version)

## Security

- All admin endpoints require `requireAdmin` middleware
- Passwords are hashed with bcrypt
- CSRF protection enabled
- Input validation on all endpoints
- Audit logging for all role changes

## Deployment

### Development
```bash
npm run dev
```

### Production
```bash
npm run start
```

## Troubleshooting

- **Database connection failed** – Ensure `DATABASE_URL` is correctly configured
- **PostgreSQL unreachable** – Check network connectivity and port 5432
- **Missing dependencies** – Run `npm install`
