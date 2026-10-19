package com.chengze.securelogin.backend.hook;

import com.chengze.securelogin.backend.SecureLoginBackend;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.context.ContextCalculator;
import net.luckperms.api.context.ContextConsumer;
import net.luckperms.api.context.ContextSet;
import net.luckperms.api.context.ImmutableContextSet;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.RegisteredServiceProvider;
import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LuckPermsHook {
    private final Map<UUID, Boolean> authStatus = new ConcurrentHashMap<>();
    private final Map<UUID, Boolean> premiumStatus = new ConcurrentHashMap<>();

    public LuckPermsHook(SecureLoginBackend plugin) {
        if (Bukkit.getPluginManager().getPlugin("LuckPerms") == null) return;
        RegisteredServiceProvider<LuckPerms> provider = Bukkit.getServicesManager().getRegistration(LuckPerms.class);
        if (provider != null) {
            LuckPerms api = provider.getProvider();
            api.getContextManager().registerCalculator(new SecureLoginContextCalculator());
            plugin.getLogger().info("Registered LuckPerms context calculator (securelogin:authenticated, securelogin:premium).");
        }
    }

    public void updateContext(Player player, boolean authenticated, boolean isPremium) {
        authStatus.put(player.getUniqueId(), authenticated);
        premiumStatus.put(player.getUniqueId(), isPremium);
    }

    private class SecureLoginContextCalculator implements ContextCalculator<Player> {
        @Override
        public void calculate(@NotNull Player target, @NotNull ContextConsumer consumer) {
            boolean isAuth = authStatus.getOrDefault(target.getUniqueId(), false);
            boolean isPrem = premiumStatus.getOrDefault(target.getUniqueId(), false);
            consumer.accept("securelogin:authenticated", String.valueOf(isAuth));
            consumer.accept("securelogin:premium", String.valueOf(isPrem));
        }

        @Override
        public @NotNull ContextSet estimatePotentialContexts() {
            return ImmutableContextSet.builder()
                    .add("securelogin:authenticated", "true")
                    .add("securelogin:authenticated", "false")
                    .add("securelogin:premium", "true")
                    .add("securelogin:premium", "false")
                    .build();
        }
    }
}