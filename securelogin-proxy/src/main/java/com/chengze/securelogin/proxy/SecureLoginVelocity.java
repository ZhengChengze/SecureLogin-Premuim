package com.chengze.securelogin.proxy;

import com.chengze.securelogin.common.crypto.HmacSigner;
import com.chengze.securelogin.common.crypto.MojangProfileService;
import com.chengze.securelogin.common.model.AuthPayload;
import com.google.inject.Inject;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerPostConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Plugin(
        id = "securelogin-proxy",
        name = "SecureLoginProxy",
        version = "1.0.0-RELEASE",
        authors = {"Chéngzé"}
)
public class SecureLoginVelocity {
    public static final MinecraftChannelIdentifier CHANNEL = MinecraftChannelIdentifier.create("securelogin", "auth");
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private HmacSigner hmacSigner;
    private MojangProfileService mojangProfileService;
    private boolean autoDetectPaidUsernames = true;
    private final Set<String> enforcedPremiumUsers = ConcurrentHashMap.newKeySet();

    @Inject
    public SecureLoginVelocity(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInit(ProxyInitializeEvent event) {
        server.getChannelRegistrar().register(CHANNEL);
        loadVelocitySecret();
        this.mojangProfileService = new MojangProfileService(30L);
        logger.info("SecureLoginProxy (Velocity) by Chéngzé initialized with Automatic Premium Detection.");
    }

    private void loadVelocitySecret() {
        try {
            if (!Files.exists(dataDirectory)) {
                Files.createDirectories(dataDirectory);
            }
            Path propFile = dataDirectory.resolve("velocity-secret.properties");
            if (!Files.exists(propFile)) {
                Files.writeString(propFile,
                        "shared-hmac-secret=9f8e7d6c5b4a392817263544536271809a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\n" +
                        "max-clock-skew-ms=10000\n" +
                        "auto-detect-paid-usernames=true\n");
            }
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(propFile)) {
                props.load(in);
            }
            this.hmacSigner = new HmacSigner(
                    props.getProperty("shared-hmac-secret"),
                    Long.parseLong(props.getProperty("max-clock-skew-ms", "10000"))
            );
            this.autoDetectPaidUsernames = Boolean.parseBoolean(props.getProperty("auto-detect-paid-usernames", "true"));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize Velocity SecureLogin configuration", e);
        }
    }

    @Subscribe
    public EventTask onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        if (enforcedPremiumUsers.contains(username.toLowerCase())) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
            return null;
        }
        if (!autoDetectPaidUsernames) {
            return null;
        }
        return EventTask.resumeWhenComplete(
                mojangProfileService.lookupPaidMojangUuid(username).thenAccept(optUuid -> {
                    if (optUuid.isPresent()) {
                        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                        logger.info("[AutoPremium] Enabled Mojang Online-Mode encryption for paid username: {}", username);
                    } else {
                        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                    }
                })
        );
    }

    @Subscribe
    public void onServerPostConnect(ServerPostConnectEvent event) {
        Player player = event.getPlayer();
        boolean isVerifiedPremium = player.isOnlineMode();
        UUID mojangUuid = isVerifiedPremium ? player.getUniqueId() : null;
        String ip = player.getRemoteAddress().getAddress().getHostAddress();

        AuthPayload payload = hmacSigner.createSignedPayload(
                player.getUniqueId(),
                player.getUsername(),
                isVerifiedPremium,
                mojangUuid,
                ip
        );

        player.getCurrentServer().ifPresent(serverConn -> {
            try {
                serverConn.sendPluginMessage(CHANNEL, HmacSigner.serialize(payload));
            } catch (IOException e) {
                logger.error("Failed to dispatch signed AuthPayload for {}", player.getUsername(), e);
            }
        });
    }
}