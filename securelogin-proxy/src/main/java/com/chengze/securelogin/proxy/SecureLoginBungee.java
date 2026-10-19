package com.chengze.securelogin.proxy;

import com.chengze.securelogin.common.crypto.HmacSigner;
import com.chengze.securelogin.common.crypto.MojangProfileService;
import com.chengze.securelogin.common.model.AuthPayload;
import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.connection.Server;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PluginMessageEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerConnectedEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class SecureLoginBungee extends Plugin implements Listener {
    public static final String CHANNEL = "securelogin:auth";

    private HmacSigner hmacSigner;
    private MojangProfileService mojangProfileService;
    private boolean autoDetectPaidUsernames = true;

    private final Set<String> premiumEnforcedUsernames = ConcurrentHashMap.newKeySet();
    private final Set<String> crackedOverrideUsernames = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Boolean> verifiedPremiumConnections = new ConcurrentHashMap<>();
    private String authLobbyServer;
    private Set<String> protectedServers = new HashSet<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadConfiguration();
        getProxy().registerChannel(CHANNEL);
        getProxy().getPluginManager().registerListener(this, this);
        getLogger().info("SecureLoginProxy (BungeeCord/Waterfall) by Chéngzé enabled with Automatic Premium Detection.");
    }

    private void saveDefaultConfig() {
        if (!getDataFolder().exists()) {
            getDataFolder().mkdirs();
        }
        File file = new File(getDataFolder(), "proxy-config.yml");
        if (!file.exists()) {
            try (InputStream in = getResourceAsStream("proxy-config.yml")) {
                if (in != null) {
                    Files.copy(in, file.toPath());
                }
            } catch (IOException e) {
                throw new IllegalStateException("Unable to create proxy-config.yml", e);
            }
        }
    }

    private void loadConfiguration() {
        try {
            Configuration config = ConfigurationProvider.getProvider(YamlConfiguration.class)
                    .load(new File(getDataFolder(), "proxy-config.yml"));
            String secret = config.getString("security.shared-hmac-secret", "");
            long skew = config.getLong("security.max-clock-skew-ms", 10000L);
            this.hmacSigner = new HmacSigner(secret, skew);
            this.authLobbyServer = config.getString("routing.auth-lobby-server", "auth");
            this.protectedServers = new HashSet<>(config.getStringList("routing.protected-backends"));

            this.autoDetectPaidUsernames = config.getBoolean("premium.auto-detect-paid-usernames", true);
            long cacheMinutes = config.getLong("premium.mojang-cache-minutes", 30L);
            this.mojangProfileService = new MojangProfileService(cacheMinutes);

            this.premiumEnforcedUsernames.addAll(
                    config.getStringList("premium.enforced-usernames").stream().map(String::toLowerCase).toList()
            );
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load proxy-config.yml", e);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(PreLoginEvent event) {
        if (event.isCancelled()) return;
        PendingConnection conn = event.getConnection();
        String username = conn.getName();

        if (username == null || !username.matches("^[a-zA-Z0-9_]{3,16}$")) {
            event.setReason(TextComponent.fromLegacyText(ChatColor.RED + "Invalid Minecraft username format.")[0]);
            event.setCancelled(true);
            return;
        }

        String lowerName = username.toLowerCase();

        // 1. If player explicitly unlinked Premium to play in password/cracked mode
        if (crackedOverrideUsernames.contains(lowerName)) {
            conn.setOnlineMode(false);
            return;
        }

        // 2. If player is in enforced list or opted in via /premium link
        if (premiumEnforcedUsernames.contains(lowerName)) {
            conn.setOnlineMode(true);
            return;
        }

        // 3. Automatic Mojang Premium detection during handshake
        if (autoDetectPaidUsernames) {
            event.registerIntent(this);
            mojangProfileService.lookupPaidMojangUuid(username).whenComplete((optUuid, ex) -> {
                try {
                    if (optUuid.isPresent()) {
                        conn.setOnlineMode(true);
                        getLogger().info("[AutoPremium] Enabled Mojang Online-Mode encryption for paid username: " + username);
                    } else {
                        conn.setOnlineMode(false);
                    }
                } finally {
                    event.completeIntent(this);
                }
            });
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onLogin(LoginEvent event) {
        PendingConnection conn = event.getConnection();
        boolean verifiedOnline = conn.isOnlineMode();
        UUID assignedUuid = conn.getUniqueId();

        if (!verifiedOnline || assignedUuid == null) {
            assignedUuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + conn.getName()).getBytes(StandardCharsets.UTF_8));
        }
        verifiedPremiumConnections.put(assignedUuid, verifiedOnline);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onServerConnect(ServerConnectEvent event) {
        ProxiedPlayer player = event.getPlayer();
        boolean isVerifiedPremium = player.getPendingConnection().isOnlineMode()
                && Boolean.TRUE.equals(verifiedPremiumConnections.get(player.getUniqueId()));

        if (event.getReason() == ServerConnectEvent.Reason.JOIN_PROXY && !isVerifiedPremium) {
            if (protectedServers.contains(event.getTarget().getName()) && getProxy().getServerInfo(authLobbyServer) != null) {
                event.setTarget(getProxy().getServerInfo(authLobbyServer));
            }
        }
    }

    @EventHandler
    public void onServerConnected(ServerConnectedEvent event) {
        final ProxiedPlayer player = event.getPlayer();
        final boolean isVerifiedPremium = player.getPendingConnection().isOnlineMode()
                && Boolean.TRUE.equals(verifiedPremiumConnections.get(player.getUniqueId()));

        final String clientIp = (player.getSocketAddress() instanceof InetSocketAddress inet)
                ? inet.getAddress().getHostAddress()
                : "127.0.0.1";

        final UUID verifiedMojangUuid = isVerifiedPremium ? player.getUniqueId() : null;
        AuthPayload payload = hmacSigner.createSignedPayload(
                player.getUniqueId(),
                player.getName(),
                isVerifiedPremium,
                verifiedMojangUuid,
                clientIp
        );

        try {
            byte[] packet = HmacSigner.serialize(payload);
            event.getServer().sendData(CHANNEL, packet);

            getProxy().getScheduler().schedule(this, () -> {
                if (player.isConnected() && player.getServer() != null) {
                    AuthPayload retryPayload = hmacSigner.createSignedPayload(
                            player.getUniqueId(),
                            player.getName(),
                            isVerifiedPremium,
                            verifiedMojangUuid,
                            clientIp
                    );
                    try {
                        player.getServer().sendData(CHANNEL, HmacSigner.serialize(retryPayload));
                    } catch (IOException ignored) {
                    }
                }
            }, 250, TimeUnit.MILLISECONDS);
        } catch (IOException e) {
            getLogger().severe("Failed to dispatch signed AuthPayload for " + player.getName());
        }
    }

    @EventHandler
    public void onPluginMessage(PluginMessageEvent event) {
        if (!CHANNEL.equals(event.getTag())) return;
        if (!(event.getSender() instanceof Server)) {
            event.setCancelled(true);
            return;
        }

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(event.getData()))) {
            String subChannel = in.readUTF();
            if ("PREMIUM_MODE_UPDATE".equals(subChannel)) {
                String username = in.readUTF().toLowerCase();
                boolean enablePremium = in.readBoolean();
                String signature = in.readUTF();

                String expectedSig = hmacSigner.sign("PREMIUM_MODE_UPDATE|" + username + "|" + enablePremium);
                if (expectedSig.equals(signature)) {
                    if (enablePremium) {
                        crackedOverrideUsernames.remove(username);
                        premiumEnforcedUsernames.add(username);
                    } else {
                        premiumEnforcedUsernames.remove(username);
                        crackedOverrideUsernames.add(username);
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        verifiedPremiumConnections.remove(event.getPlayer().getUniqueId());
    }
}