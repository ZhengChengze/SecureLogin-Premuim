package com.chengze.securelogin.backend.manager;

import com.chengze.securelogin.backend.SecureLoginBackend;
import com.chengze.securelogin.backend.hook.LuckPermsHook;
import com.chengze.securelogin.common.crypto.PasswordHasher;
import com.chengze.securelogin.common.database.DatabaseManager;
import com.chengze.securelogin.common.model.AccountData;
import com.chengze.securelogin.common.model.AuthPayload;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.Sound;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitTask;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AuthSessionManager {
    private final SecureLoginBackend plugin;
    private final DatabaseManager db;
    private final LuckPermsHook luckPermsHook;

    private final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private final Set<UUID> verifiedPremiumPlayers = ConcurrentHashMap.newKeySet();
    private final Set<UUID> pendingPremiumLinkConfirmation = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> joinTimestamps = new ConcurrentHashMap<>();
    private final Map<UUID, BossBar> activeBossBars = new ConcurrentHashMap<>();
    private final Map<UUID, AuthPayload> proxyPayloads = new ConcurrentHashMap<>();
    private final BukkitTask tickerTask;

    public AuthSessionManager(SecureLoginBackend plugin, DatabaseManager db, LuckPermsHook luckPermsHook) {
        this.plugin = plugin;
        this.db = db;
        this.luckPermsHook = luckPermsHook;
        this.tickerTask = Bukkit.getScheduler().runTaskTimer(plugin, this::tickUnauthenticatedPlayers, 20L, 20L);
    }

    public void handleJoin(Player player) {
        UUID uuid = player.getUniqueId();
        authenticatedPlayers.remove(uuid);
        verifiedPremiumPlayers.remove(uuid);
        joinTimestamps.put(uuid, System.currentTimeMillis());

        // Delay BossBar by 10 ticks (0.5s) so Premium auto-login players never see an unauthenticated UI flash
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            if (!player.isOnline() || authenticatedPlayers.contains(uuid)) return;
            BossBar bar = BossBar.bossBar(
                    plugin.getRawMessage("bossbar.waiting"),
                    1.0f,
                    BossBar.Color.BLUE,
                    BossBar.Overlay.PROGRESS
            );
            activeBossBars.put(uuid, bar);
            player.showBossBar(bar);
        }, 10L);

        if (plugin.getConfig().getBoolean("proxy-security.require-signed-proxy-payload", true)) {
            Bukkit.getScheduler().runTaskLater(plugin, () -> {
                if (!player.isOnline()) return;
                if (!proxyPayloads.containsKey(uuid) && !authenticatedPlayers.contains(uuid)) {
                    player.kick(plugin.getMessage("kick.direct-backend-denied"));
                }
            }, 40L);
        } else {
            evaluateCrackedOrSessionState(player, getPlayerIp(player));
        }
    }

    public void processVerifiedProxyPayload(Player player, AuthPayload payload) {
        UUID uuid = player.getUniqueId();
        if (!uuid.equals(payload.playerUuid()) || !player.getName().equalsIgnoreCase(payload.username())) {
            player.kick(plugin.getMessage("kick.identity-mismatch"));
            return;
        }

        proxyPayloads.put(uuid, payload);

        db.findAccountByUsername(player.getName()).thenAccept(optAcc -> Bukkit.getScheduler().runTask(plugin, () -> {
            if (!player.isOnline()) return;

            if (payload.verifiedPremium() && payload.verifiedMojangUuid() != null) {
                if (optAcc.isPresent() && optAcc.get().mojangUuid() != null
                        && !optAcc.get().mojangUuid().equals(payload.verifiedMojangUuid())) {
                    player.kick(plugin.getMessage("kick.premium-uuid-mismatch"));
                    return;
                }

                db.upsertVerifiedPremiumAccount(uuid, player.getName(), payload.verifiedMojangUuid(), payload.playerIp())
                        .thenRun(() -> Bukkit.getScheduler().runTask(plugin, () -> {
                            verifiedPremiumPlayers.add(uuid);
                            completeAuthentication(player, true);
                            player.sendMessage(plugin.getMessage("auth.premium-auto-login"));
                        }));
                return;
            }

            if (optAcc.isPresent() && optAcc.get().premiumVerified()) {
                player.kick(plugin.getMessage("kick.premium-impersonation-blocked"));
                return;
            }

            evaluateCrackedOrSessionState(player, payload.playerIp());
        })).exceptionally(ex -> {
            Bukkit.getScheduler().runTask(plugin, () -> player.kick(plugin.getMessage("kick.database-error")));
            return null;
        });
    }

    private void evaluateCrackedOrSessionState(Player player, String ip) {
        db.findAccountByUsername(player.getName()).thenAccept(optAcc -> {
            if (optAcc.isEmpty() || !optAcc.get().isRegistered()) {
                Bukkit.getScheduler().runTask(plugin, () -> promptRegistration(player));
                return;
            }

            AccountData acc = optAcc.get();
            if (acc.isLockedOut()) {
                long secondsLeft = Math.max(1, (acc.lockedUntil() - System.currentTimeMillis()) / 1000);
                Bukkit.getScheduler().runTask(plugin, () ->
                        player.kick(plugin.getMessage("kick.temp-locked", "%seconds%", String.valueOf(secondsLeft))));
                return;
            }

            if (plugin.getConfig().getBoolean("session.enabled", true)) {
                db.getSession(acc.accountUuid()).thenAccept(optSession -> Bukkit.getScheduler().runTask(plugin, () -> {
                    if (optSession.isPresent()
                            && !optSession.get().isExpired()
                            && !optSession.get().premiumSession()
                            && optSession.get().ipAddress().equals(ip)) {
                        completeAuthentication(player, false);
                        player.sendMessage(plugin.getMessage("auth.session-resumed"));
                    } else {
                        promptLogin(player);
                    }
                }));
            } else {
                Bukkit.getScheduler().runTask(plugin, () -> promptLogin(player));
            }
        }).exceptionally(ex -> {
            Bukkit.getScheduler().runTask(plugin, () -> player.kick(plugin.getMessage("kick.database-error")));
            return null;
        });
    }

    public void completeAuthentication(Player player, boolean isPremium) {
        UUID uuid = player.getUniqueId();
        authenticatedPlayers.add(uuid);
        joinTimestamps.remove(uuid);

        BossBar bar = activeBossBars.remove(uuid);
        if (bar != null) {
            player.hideBossBar(bar);
        }

        player.clearTitle();
        player.playSound(player.getLocation(), Sound.ENTITY_PLAYER_LEVELUP, 0.8f, 1.2f);
        luckPermsHook.updateContext(player, true, isPremium);

        String ip = getPlayerIp(player);
        db.recordLoginSuccess(player.getName(), ip);

        if (!isPremium && plugin.getConfig().getBoolean("session.enabled", true)) {
            long sessionMinutes = plugin.getConfig().getLong("session.expiration-minutes", 60L);
            String tokenHash = PasswordHasher.sha256Hex(PasswordHasher.generateSecureToken());
            db.saveSession(uuid, tokenHash, ip, sessionMinutes * 60_000L, false);
        }
    }

    public void logoutPlayer(Player player) {
        UUID uuid = player.getUniqueId();
        authenticatedPlayers.remove(uuid);
        verifiedPremiumPlayers.remove(uuid);
        joinTimestamps.put(uuid, System.currentTimeMillis());
        luckPermsHook.updateContext(player, false, false);
        db.invalidateSession(uuid);
        promptLogin(player);
    }

    public void handleQuit(Player player) {
        UUID uuid = player.getUniqueId();
        authenticatedPlayers.remove(uuid);
        verifiedPremiumPlayers.remove(uuid);
        pendingPremiumLinkConfirmation.remove(uuid);
        joinTimestamps.remove(uuid);
        activeBossBars.remove(uuid);
        proxyPayloads.remove(uuid);
    }

    private void tickUnauthenticatedPlayers() {
        long timeoutSeconds = plugin.getConfig().getLong("security.auth-timeout-seconds", 60L);
        long now = System.currentTimeMillis();

        for (Player player : Bukkit.getOnlinePlayers()) {
            UUID uuid = player.getUniqueId();
            if (authenticatedPlayers.contains(uuid)) continue;

            long joinedAt = joinTimestamps.getOrDefault(uuid, now);
            long elapsedSeconds = (now - joinedAt) / 1000L;
            if (elapsedSeconds >= timeoutSeconds) {
                player.kick(plugin.getMessage("kick.timeout"));
                continue;
            }

            float progress = Math.max(0.0f, Math.min(1.0f, 1.0f - ((float) elapsedSeconds / timeoutSeconds)));
            BossBar bar = activeBossBars.get(uuid);
            if (bar != null) {
                bar.progress(progress);
            }
            player.sendActionBar(plugin.getRawMessage("actionbar.timer",
                    "%seconds%", String.valueOf(timeoutSeconds - elapsedSeconds)));
        }
    }

    public void promptRegistration(Player player) {
        player.sendMessage(plugin.getMessage("auth.register-prompt"));
        Title title = Title.title(
                plugin.getRawMessage("titles.register-title"),
                plugin.getRawMessage("titles.register-subtitle"),
                Title.Times.times(Duration.ofMillis(200), Duration.ofSeconds(4), Duration.ofMillis(400))
        );
        player.showTitle(title);
    }

    public void promptLogin(Player player) {
        player.sendMessage(plugin.getMessage("auth.login-prompt"));
        Title title = Title.title(
                plugin.getRawMessage("titles.login-title"),
                plugin.getRawMessage("titles.login-subtitle"),
                Title.Times.times(Duration.ofMillis(200), Duration.ofSeconds(4), Duration.ofMillis(400))
        );
        player.showTitle(title);
    }

    public boolean isAuthenticated(UUID uuid) {
        return authenticatedPlayers.contains(uuid);
    }

    public boolean isVerifiedPremium(UUID uuid) {
        return verifiedPremiumPlayers.contains(uuid);
    }

    public Set<UUID> getPendingPremiumLinkConfirmation() {
        return pendingPremiumLinkConfirmation;
    }

    public String getPlayerIp(Player player) {
        AuthPayload payload = proxyPayloads.get(player.getUniqueId());
        if (payload != null) return payload.playerIp();
        InetSocketAddress addr = player.getAddress();
        return addr != null ? addr.getAddress().getHostAddress() : "127.0.0.1";
    }

    public void shutdown() {
        if (tickerTask != null) {
            tickerTask.cancel();
        }
    }
}