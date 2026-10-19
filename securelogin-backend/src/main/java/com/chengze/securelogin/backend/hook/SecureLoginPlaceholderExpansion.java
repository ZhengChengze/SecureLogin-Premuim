package com.chengze.securelogin.backend.hook;

import com.chengze.securelogin.backend.SecureLoginBackend;
import com.chengze.securelogin.backend.manager.AuthSessionManager;
import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

public class SecureLoginPlaceholderExpansion extends PlaceholderExpansion {
    private final SecureLoginBackend plugin;
    private final AuthSessionManager sessionManager;

    public SecureLoginPlaceholderExpansion(SecureLoginBackend plugin, AuthSessionManager sessionManager) {
        this.plugin = plugin;
        this.sessionManager = sessionManager;
    }

    @Override
    public @NotNull String getIdentifier() {
        return "securelogin";
    }

    @Override
    public @NotNull String getAuthor() {
        return "Chéngzé";
    }

    @Override
    public @NotNull String getVersion() {
        return plugin.getDescription().getVersion();
    }

    @Override
    public boolean persist() {
        return true;
    }

    @Override
    public String onPlaceholderRequest(Player player, @NotNull String params) {
        if (player == null) return "";
        return switch (params.toLowerCase()) {
            case "is_authenticated" -> String.valueOf(sessionManager.isAuthenticated(player.getUniqueId()));
            case "account_type" -> sessionManager.isVerifiedPremium(player.getUniqueId()) ? "Premium" : "Cracked";
            default -> null;
        };
    }
}