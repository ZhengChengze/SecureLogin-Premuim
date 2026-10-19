package com.chengze.securelogin.backend.listener;

import com.chengze.securelogin.backend.SecureLoginBackend;
import com.chengze.securelogin.backend.manager.AuthSessionManager;
import com.chengze.securelogin.common.crypto.HmacSigner;
import com.chengze.securelogin.common.model.AuthPayload;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;

public class ProxyChannelListener implements PluginMessageListener {
    private final SecureLoginBackend plugin;
    private final HmacSigner hmacSigner;
    private final AuthSessionManager sessionManager;

    public ProxyChannelListener(SecureLoginBackend plugin, HmacSigner hmacSigner, AuthSessionManager sessionManager) {
        this.plugin = plugin;
        this.hmacSigner = hmacSigner;
        this.sessionManager = sessionManager;
    }

    @Override
    public void onPluginMessageReceived(@NotNull String channel, @NotNull Player player, byte @NotNull [] message) {
        if (!SecureLoginBackend.CHANNEL.equals(channel)) {
            return;
        }

        try {
            AuthPayload payload = HmacSigner.deserialize(message);
            if (!hmacSigner.verifyAndConsumeNonce(payload)) {
                plugin.getLogger().warning("SECURITY ALERT: Rejected forged or replayed proxy auth payload for " + player.getName());
                player.kick(plugin.getMessage("kick.forged-proxy-payload"));
                return;
            }
            sessionManager.processVerifiedProxyPayload(player, payload);
        } catch (IOException e) {
            plugin.getLogger().severe("Malformed plugin message on " + channel + " for " + player.getName());
            player.kick(plugin.getMessage("kick.forged-proxy-payload"));
        }
    }
}