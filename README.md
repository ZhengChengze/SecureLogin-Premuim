# SecureLogin 🔐

**Enterprise-grade authentication and proxy security for Minecraft networks.**

SecureLogin is a high-performance authentication and security suite designed for Minecraft networks running **BungeeCord, Waterfall, or Velocity** with **Paper or Purpur** backend servers. Inspired by established authentication plugins such as nLogin, SecureLogin provides a secure and seamless experience for both premium Java Edition accounts and cracked (offline-mode) players.

With automatic premium account detection, cryptographically verified proxy-to-backend communication, secure password storage, and persistent session management, SecureLogin helps protect your network without compromising the player experience.

## ✨ Features

### 🔐 Automatic Premium Account Detection
- Automatically detects eligible Minecraft Java Edition premium accounts.
- Supports seamless authentication for premium players.
- Eliminates the need for `/register` and `/login` for verified premium accounts.
- Integrates premium authentication with your proxy network.

### 🛡️ Advanced Proxy-to-Backend Security
- Protects backend servers against unauthorized direct connections.
- Uses HMAC-SHA256 signatures to verify authentication payloads.
- Implements nonce verification to help prevent replay attacks.
- Uses the `securelogin:auth` plugin messaging channel for proxy-to-backend communication.
- Designed to prevent payload spoofing and tampering.

### 👤 Cracked Player Authentication
- Secure registration and login system for offline-mode players.
- BCrypt password hashing with unique salts.
- Password complexity requirements.
- Configurable temporary lockouts after repeated failed login attempts.
- IP-bound session caching for returning players.
- Architecture designed with future Argon2 support in mind.

### 🎨 Modern User Interface
- Adventure MiniMessage support, including gradients and advanced text formatting.
- Customizable login and registration messages.
- Action bar notifications and countdowns.
- Title and subtitle prompts.
- Configurable authentication feedback for a polished player experience.

### 🗄️ Flexible Database Support
- **SQLite** for simple, lightweight deployments.
- **MySQL / MariaDB** for larger networks and shared database environments.
- HikariCP connection pooling for efficient database connections.
- Modular database architecture designed for maintainability and scalability.

### 🔌 Ecosystem Integrations
- **LuckPerms:** Custom authentication and premium-status context support.
- **PlaceholderAPI:** Authentication placeholders, including `%securelogin_is_authenticated%`.
- Designed for mixed proxy and backend environments.

## 📦 Supported Platforms

| Component | Supported platforms |
|---|---|
| Proxy | BungeeCord, Waterfall, Velocity |
| Backend | Paper, Purpur |
| Database | SQLite, MySQL, MariaDB |
| Java Edition | Premium and offline-mode players |

*Compatibility depends on the specific build, Minecraft version, and available platform adapters.*

## 🏗️ Modular Architecture

SecureLogin uses a multi-module Maven architecture to separate authentication logic from platform-specific implementations.

- **`securelogin-common`** — Shared cryptographic utilities, HMAC signing, password hashing, database models, connection pooling, and JUnit 5 tests.
- **`securelogin-proxy`** — Proxy-side authentication coordination, premium account handling, and secure proxy-to-backend communication.
- **`securelogin-backend`** — Backend authentication enforcement, including restrictions on movement, chat, inventory interactions, commands, and combat until authentication succeeds.

## 🚀 Project Goals

SecureLogin aims to provide:

- Strong security for mixed premium and offline-mode networks.
- A seamless login experience for verified premium accounts.
- Reliable authentication for offline-mode players.
- Protection against common proxy-bypass and authentication-spoofing attacks.
- A modular, maintainable foundation for future features.

## 👨‍💻 Developer

**Author:** Chéngzé 

SecureLogin is built for server owners who want a unified authentication solution with security, performance, and flexibility at its core.
