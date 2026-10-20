# 🛡️ SecureLogin
**Enterprise-Grade Authentication, Automatic Premium & Bedrock Login, and Cryptographic Proxy Security**  
Developed by **Chéngzé** 

**SecureLogin** is a modern, lightweight, and ultra-low-overhead authentication plugin inspired by *nLogin*. Designed from the ground up for **Paper / Purpur (1.21.x+)** and proxy networks (**BungeeCord, Waterfall, Velocity**), SecureLogin seamlessly unites **Java Premium**, **Java Cracked/Offline**, and **Bedrock (Geyser/Floodgate)** players on a single server or multi-server network.

---

### ✨ Why Choose SecureLogin?

* 🚀 **Automatic Premium Login (Zero Commands):** Legitimate paid Minecraft Java Edition players are detected during the handshake, verified via official Mojang session encryption, and logged in automatically—never needing to type `/register` or `/login`.
* 📱 **Seamless Bedrock / Floodgate Support:** Native, zero-dependency detection for Geyser & Floodgate players (`00000000-0000-0000-...` Xbox Live UUIDs). Bedrock players can automatically skip password login (configurable) while cracked Java players are strictly blocked from spoofing Bedrock prefixes (`.`, `-`, `_`, `+`).
* 🌐 **Dual Deployment Architecture (2-in-1):**
  * **Standalone Mode (1 Server):** Drop `SecureLoginBackend` onto a single Paper/Purpur server and run immediately with zero proxy setup.
  * **Proxy Auth-Lobby Mode (Network):** Pair `SecureLoginProxy` + `SecureLoginBackend` to lock unauthenticated players inside an Auth Lobby and automatically transfer them to your `hub` or `survival` server upon login.
* 🔐 **HMAC-SHA256 Proxy-to-Backend Bridge:** Every proxy-to-backend authentication state is signed with **HMAC-SHA256**, timestamped, and protected by a one-time cryptographic nonce cache—completely eliminating direct-backend port bypasses, packet spoofing, and replay attacks.
* ⚡ **Ultra-Low Resource Usage:** Engineered with asynchronous HikariCP database workers, cached `MethodHandle` reflection, and an idle-sleep ticker that consumes **0% CPU** when all online players are authenticated.

![Preview](https://cdn.modrinth.com/data/cached_images/92bca8c5b83e8f4038fb2aeaf86325dcacc56490_0.webp)
---

### 🔒 Security & Account Protection

* **BCrypt Password Hashing:** Industry-standard salted hashing (`cost=12`) ensures plaintext passwords are never stored or logged.
* **Anti-Bedrock Spoofing Filter:** Blocks cracked Java players from joining with special symbols (`-`, `.`, `+`) to prevent them from impersonating Bedrock players or stealing items.
* **IP Registration Limiter:** Prevents bot attacks and alt-account abuse with a configurable maximum account limit per IP address (`max-accounts-per-ip`).
* **Smart IP Session Resumption:** Returning cracked players on the same verified IP address automatically resume their session without re-typing their password until the session expires.
* **Brute-Force Lockout:** Configurable maximum failed login attempts and temporary account lockouts.

---

### ⌨️ Commands & Permissions

| Command | Description | Permission |
| :--- | :--- | :--- |
| `/register <pass> [confirm]` | Register a new cracked account | *Default (All)* |
| `/login <password>` | Authenticate an existing cracked account | *Default (All)* |
| `/logout` | Safely end your active session | *Default (All)* |
| `/changepassword <old> <new>` | Change your account password & refresh sessions | *Default (All)* |
| `/premium <status\|link\|unlink>` | View or manage Mojang Premium verification | *Default (All)* |
| `/auth reload` | Reload configuration and message files | `securelogin.reload` |
| `/auth unregister <player>` | Delete a player's registration from the database | `securelogin.unregister` |
| `/auth force-login <player>` | Force-authenticate an online player (audit logged) | `securelogin.forcelogin` |

*Full administrative access node:* `securelogin.admin`

---

### 🔌 Integrations & Storage

* **Databases:** **SQLite** (out-of-the-box default) and **MySQL / MariaDB** (HikariCP pooled).
* **LuckPerms:** Registers real-time contexts (`securelogin:authenticated` and `securelogin:premium`).
* **PlaceholderAPI:**
  * `%securelogin_is_authenticated%` (`true` / `false`)
  * `%securelogin_account_type%` (`Premium` / `Cracked`)
* **UI & Formatting:** Full **Kyori Adventure MiniMessage** support with customizable gradients, BossBar countdowns, ActionBars, and Titles.
