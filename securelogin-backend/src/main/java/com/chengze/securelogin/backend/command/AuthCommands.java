package com.chengze.securelogin.backend.command;

import com.chengze.securelogin.backend.SecureLoginBackend;
import com.chengze.securelogin.backend.manager.AuthSessionManager;
import com.chengze.securelogin.common.crypto.PasswordHasher;
import com.chengze.securelogin.common.database.DatabaseManager;
import com.chengze.securelogin.common.model.AccountData;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.UUID;

public class AuthCommands implements CommandExecutor {
    private final SecureLoginBackend plugin;
    private final AuthSessionManager sessionManager;
    private final DatabaseManager db;

    public AuthCommands(SecureLoginBackend plugin, AuthSessionManager sessionManager, DatabaseManager db) {
        this.plugin = plugin;
        this.sessionManager = sessionManager;
        this.db = db;
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label, @NotNull String[] args) {
        String cmd = command.getName().toLowerCase();
        return switch (cmd) {
            case "register" -> handleRegister(sender, args);
            case "login" -> handleLogin(sender, args);
            case "logout" -> handleLogout(sender);
            case "changepassword" -> handleChangePassword(sender, args);
            case "premium" -> handlePremium(sender, args);
            case "auth" -> handleAdminAuth(sender, args);
            default -> false;
        };
    }

    private boolean handleRegister(CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) return true;
        if (sessionManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getMessage("auth.already-authenticated"));
            return true;
        }

        boolean singlePassword = plugin.getConfig().getBoolean("registration.single-password", false);
        if ((singlePassword && args.length < 1) || (!singlePassword && args.length < 2)) {
            player.sendMessage(plugin.getMessage("auth.register-usage"));
            return true;
        }

        String password = args[0];
        if (!singlePassword && !password.equals(args[1])) {
            player.sendMessage(plugin.getMessage("auth.password-mismatch"));
            return true;
        }

        if (!isPasswordCompliant(password)) {
            player.sendMessage(plugin.getMessage("auth.password-weak"));
            return true;
        }

        String ip = sessionManager.getPlayerIp(player);
        UUID uuid = player.getUniqueId();

        db.findAccountByUsername(player.getName()).thenAccept(opt -> {
            if (opt.isPresent() && opt.get().isRegistered()) {
                Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(plugin.getMessage("auth.already-registered")));
                return;
            }
            String hash = PasswordHasher.hashPassword(password);
            db.registerCrackedAccount(uuid, player.getName(), hash, ip).thenAccept(success -> Bukkit.getScheduler().runTask(plugin, () -> {
                if (success) {
                    sessionManager.completeAuthentication(player, false);
                    db.recordAuditLog(uuid, player.getName(), "REGISTER_CRACKED", player.getName(), ip);
                    player.sendMessage(plugin.getMessage("auth.register-success"));
                } else {
                    player.sendMessage(plugin.getMessage("auth.already-registered"));
                }
            }));
        });
        return true;
    }

    private boolean handleLogin(CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) return true;
        if (sessionManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getMessage("auth.already-authenticated"));
            return true;
        }
        if (args.length != 1) {
            player.sendMessage(plugin.getMessage("auth.login-usage"));
            return true;
        }

        String rawPassword = args[0];
        String ip = sessionManager.getPlayerIp(player);

        db.findAccountByUsername(player.getName()).thenAccept(opt -> {
            if (opt.isEmpty() || !opt.get().isRegistered()) {
                Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(plugin.getMessage("auth.not-registered")));
                return;
            }
            AccountData acc = opt.get();
            if (acc.isLockedOut()) {
                long sec = Math.max(1, (acc.lockedUntil() - System.currentTimeMillis()) / 1000L);
                Bukkit.getScheduler().runTask(plugin, () ->
                        player.kick(plugin.getMessage("kick.temp-locked", "%seconds%", String.valueOf(sec))));
                return;
            }

            boolean verified = PasswordHasher.verifyPassword(rawPassword, acc.passwordHash());
            if (verified) {
                Bukkit.getScheduler().runTask(plugin, () -> {
                    sessionManager.completeAuthentication(player, false);
                    db.recordAuditLog(player.getUniqueId(), player.getName(), "LOGIN_SUCCESS", player.getName(), ip);
                    player.sendMessage(plugin.getMessage("auth.login-success"));
                });
            } else {
                int maxAttempts = plugin.getConfig().getInt("security.max-failed-attempts", 5);
                long lockoutMs = plugin.getConfig().getLong("security.lockout-duration-seconds", 300L) * 1000L;
                db.recordFailedAttempt(player.getName(), maxAttempts, lockoutMs).thenAccept(attempts -> Bukkit.getScheduler().runTask(plugin, () -> {
                    if (attempts >= maxAttempts) {
                        player.kick(plugin.getMessage("kick.temp-locked", "%seconds%", String.valueOf(lockoutMs / 1000L)));
                    } else {
                        player.sendMessage(plugin.getMessage("auth.wrong-password",
                                "%attempts%", String.valueOf(attempts),
                                "%max%", String.valueOf(maxAttempts)));
                    }
                }));
            }
        });
        return true;
    }

    private boolean handleLogout(CommandSender sender) {
        if (!(sender instanceof Player player)) return true;
        if (!sessionManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getMessage("auth.must-authenticate"));
            return true;
        }
        sessionManager.logoutPlayer(player);
        player.sendMessage(plugin.getMessage("auth.logout-success"));
        return true;
    }

    private boolean handleChangePassword(CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) return true;
        if (!sessionManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getMessage("auth.must-authenticate"));
            return true;
        }
        if (args.length != 2) {
            player.sendMessage(plugin.getMessage("auth.changepass-usage"));
            return true;
        }

        String oldPass = args[0];
        String newPass = args[1];
        if (!isPasswordCompliant(newPass)) {
            player.sendMessage(plugin.getMessage("auth.password-weak"));
            return true;
        }

        db.findAccountByUsername(player.getName()).thenAccept(opt -> {
            if (opt.isEmpty() || !PasswordHasher.verifyPassword(oldPass, opt.get().passwordHash())) {
                Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(plugin.getMessage("auth.wrong-old-password")));
                return;
            }
            String newHash = PasswordHasher.hashPassword(newPass);
            db.updatePassword(player.getName(), newHash).thenRun(() -> Bukkit.getScheduler().runTask(plugin, () -> {
                db.recordAuditLog(player.getUniqueId(), player.getName(), "CHANGE_PASSWORD", player.getName(), sessionManager.getPlayerIp(player));
                player.sendMessage(plugin.getMessage("auth.changepass-success"));
            }));
        });
        return true;
    }

    private boolean handlePremium(CommandSender sender, String[] args) {
        if (!(sender instanceof Player player)) return true;
        if (!sessionManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(plugin.getMessage("auth.must-authenticate"));
            return true;
        }
        if (args.length == 0 || args[0].equalsIgnoreCase("status")) {
            boolean verified = sessionManager.isVerifiedPremium(player.getUniqueId());
            player.sendMessage(plugin.getMessage(verified ? "premium.status-verified" : "premium.status-cracked"));
            return true;
        }

        String sub = args[0].toLowerCase();
        if ("link".equals(sub)) {
            if (!sessionManager.isVerifiedPremium(player.getUniqueId())) {
                player.sendMessage(plugin.getMessage("premium.link-requires-verified-session"));
                return true;
            }
            db.setPremiumLinkingState(player.getName(), true, player.getUniqueId()).thenRun(() ->
                    Bukkit.getScheduler().runTask(plugin, () -> player.sendMessage(plugin.getMessage("premium.link-success"))));
            return true;
        }

        if ("unlink".equals(sub)) {
            if (args.length < 2) {
                player.sendMessage(plugin.getMessage("premium.unlink-usage"));
                return true;
            }
            String newFallbackPassword = args[1];
            if (!isPasswordCompliant(newFallbackPassword)) {
                player.sendMessage(plugin.getMessage("auth.password-weak"));
                return true;
            }
            String newHash = PasswordHasher.hashPassword(newFallbackPassword);
            db.updatePassword(player.getName(), newHash).thenCompose(v ->
                    db.setPremiumLinkingState(player.getName(), false, null)).thenRun(() ->
                    Bukkit.getScheduler().runTask(plugin, () -> {
                        db.recordAuditLog(player.getUniqueId(), player.getName(), "PREMIUM_UNLINK", player.getName(), sessionManager.getPlayerIp(player));
                        player.sendMessage(plugin.getMessage("premium.unlink-success"));
                    }));
            return true;
        }
        return true;
    }

    private boolean handleAdminAuth(CommandSender sender, String[] args) {
        if (args.length == 0 || args[0].equalsIgnoreCase("help")) {
            sender.sendMessage(plugin.getMessage("admin.help"));
            return true;
        }

        String sub = args[0].toLowerCase();
        if ("reload".equals(sub)) {
            if (!sender.hasPermission("securelogin.reload") && !sender.hasPermission("securelogin.admin")) {
                sender.sendMessage(plugin.getMessage("admin.no-permission"));
                return true;
            }
            plugin.reloadAllConfigs();
            sender.sendMessage(plugin.getMessage("admin.reload-success"));
            return true;
        }

        if ("unregister".equals(sub) && args.length >= 2) {
            if (!sender.hasPermission("securelogin.unregister") && !sender.hasPermission("securelogin.admin")) {
                sender.sendMessage(plugin.getMessage("admin.no-permission"));
                return true;
            }
            String targetName = args[1];
            db.unregisterAccount(targetName).thenAccept(removed -> Bukkit.getScheduler().runTask(plugin, () -> {
                if (removed) {
                    db.recordAuditLog(null, targetName, "ADMIN_UNREGISTER", sender.getName(), "CONSOLE/ADMIN");
                    Player onlineTarget = Bukkit.getPlayerExact(targetName);
                    if (onlineTarget != null) {
                        onlineTarget.kick(plugin.getMessage("kick.account-unregistered"));
                    }
                    sender.sendMessage(plugin.getMessage("admin.unregister-success", "%player%", targetName));
                } else {
                    sender.sendMessage(plugin.getMessage("admin.account-not-found", "%player%", targetName));
                }
            }));
            return true;
        }

        if ("force-login".equals(sub) && args.length >= 2) {
            if (!sender.hasPermission("securelogin.forcelogin") && !sender.hasPermission("securelogin.admin")) {
                sender.sendMessage(plugin.getMessage("admin.no-permission"));
                return true;
            }
            Player target = Bukkit.getPlayerExact(args[1]);
            if (target == null) {
                sender.sendMessage(plugin.getMessage("admin.player-offline", "%player%", args[1]));
                return true;
            }
            sessionManager.completeAuthentication(target, false);
            db.recordAuditLog(target.getUniqueId(), target.getName(), "ADMIN_FORCE_LOGIN", sender.getName(), sessionManager.getPlayerIp(target));
            sender.sendMessage(plugin.getMessage("admin.forcelogin-success", "%player%", target.getName()));
            target.sendMessage(plugin.getMessage("auth.login-success"));
            return true;
        }
        return true;
    }

    private boolean isPasswordCompliant(String password) {
        int min = plugin.getConfig().getInt("password-policy.min-length", 8);
        int max = plugin.getConfig().getInt("password-policy.max-length", 64);
        if (password.length() < min || password.length() > max) return false;
        if (plugin.getConfig().getBoolean("password-policy.require-number", true) && !password.matches(".*\\d.*")) {
            return false;
        }
        return true;
    }
}