package com.chengze.securelogin.backend;

import com.chengze.securelogin.backend.command.AuthCommands;
import com.chengze.securelogin.backend.hook.LuckPermsHook;
import com.chengze.securelogin.backend.hook.SecureLoginPlaceholderExpansion;
import com.chengze.securelogin.backend.listener.ProtectionListener;
import com.chengze.securelogin.backend.listener.ProxyChannelListener;
import com.chengze.securelogin.backend.manager.AuthSessionManager;
import com.chengze.securelogin.common.crypto.HmacSigner;
import com.chengze.securelogin.common.database.DatabaseManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Objects;

public class SecureLoginBackend extends JavaPlugin {
    public static final String CHANNEL = "securelogin:auth";

    private DatabaseManager databaseManager;
    private HmacSigner hmacSigner;
    private AuthSessionManager sessionManager;
    private FileConfiguration messagesConfig;
    private FileConfiguration databaseConfig;
    private LuckPermsHook luckPermsHook;
    private final MiniMessage miniMessage = MiniMessage.miniMessage();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        saveResourceIfMissing("messages.yml");
        saveResourceIfMissing("database.yml");
        reloadAllConfigs();

        initDatabase();
        initSecurity();

        this.luckPermsHook = new LuckPermsHook(this);
        this.sessionManager = new AuthSessionManager(this, databaseManager, luckPermsHook);

        getServer().getMessenger().registerIncomingPluginChannel(this, CHANNEL, new ProxyChannelListener(this, hmacSigner, sessionManager));
        getServer().getMessenger().registerOutgoingPluginChannel(this, CHANNEL);
        getServer().getPluginManager().registerEvents(new ProtectionListener(this, sessionManager), this);

        AuthCommands authCommands = new AuthCommands(this, sessionManager, databaseManager);
        Objects.requireNonNull(getCommand("register")).setExecutor(authCommands);
        Objects.requireNonNull(getCommand("login")).setExecutor(authCommands);
        Objects.requireNonNull(getCommand("logout")).setExecutor(authCommands);
        Objects.requireNonNull(getCommand("changepassword")).setExecutor(authCommands);
        Objects.requireNonNull(getCommand("premium")).setExecutor(authCommands);
        Objects.requireNonNull(getCommand("auth")).setExecutor(authCommands);

        if (Bukkit.getPluginManager().getPlugin("PlaceholderAPI") != null) {
            new SecureLoginPlaceholderExpansion(this, sessionManager).register();
            getLogger().info("Hooked into PlaceholderAPI.");
        }

        getLogger().info("SecureLoginBackend by Chéngzé enabled successfully.");
    }

    @Override
    public void onDisable() {
        if (sessionManager != null) {
            sessionManager.shutdown();
        }
        if (databaseManager != null) {
            databaseManager.close();
        }
    }

    public void sendProxyPremiumModeUpdate(Player player, boolean enablePremium) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            String lowerName = player.getName().toLowerCase();
            String sig = hmacSigner.sign("PREMIUM_MODE_UPDATE|" + lowerName + "|" + enablePremium);
            out.writeUTF("PREMIUM_MODE_UPDATE");
            out.writeUTF(lowerName);
            out.writeBoolean(enablePremium);
            out.writeUTF(sig);
            player.sendPluginMessage(this, CHANNEL, baos.toByteArray());
        } catch (IOException e) {
            getLogger().warning("Could not send PREMIUM_MODE_UPDATE to proxy for " + player.getName());
        }
    }

    public void reloadAllConfigs() {
        reloadConfig();
        this.messagesConfig = YamlConfiguration.loadConfiguration(new File(getDataFolder(), "messages.yml"));
        this.databaseConfig = YamlConfiguration.loadConfiguration(new File(getDataFolder(), "database.yml"));
        initSecurity();
    }

    private void initSecurity() {
        String secret = getConfig().getString("proxy-security.shared-hmac-secret", "");
        long skew = getConfig().getLong("proxy-security.max-clock-skew-ms", 10000L);
        this.hmacSigner = new HmacSigner(secret, skew);
    }

    private void initDatabase() {
        String type = databaseConfig.getString("storage.type", "SQLITE");
        File sqliteFile = new File(getDataFolder(), databaseConfig.getString("storage.sqlite-file", "securelogin.db"));
        String host = databaseConfig.getString("storage.mysql.host", "127.0.0.1");
        int port = databaseConfig.getInt("storage.mysql.port", 3306);
        String db = databaseConfig.getString("storage.mysql.database", "securelogin");
        String user = databaseConfig.getString("storage.mysql.username", "root");
        String pass = databaseConfig.getString("storage.mysql.password", "");
        int pool = databaseConfig.getInt("storage.mysql.pool-size", 8);

        this.databaseManager = new DatabaseManager(type, sqliteFile, host, port, db, user, pass, pool);
    }

    private void saveResourceIfMissing(String fileName) {
        File file = new File(getDataFolder(), fileName);
        if (!file.exists()) {
            saveResource(fileName, false);
        }
    }

    public Component getMessage(String path, String... placeholders) {
        String prefix = messagesConfig.getString("prefix", "<gradient:#00d2ff:#3a7bd5><bold>SecureLogin</bold></gradient> <dark_gray>»</dark_gray> ");
        String raw = messagesConfig.getString(path, "<red>Missing message: " + path);
        String combined = prefix + raw;
        for (int i = 0; i + 1 < placeholders.length; i += 2) {
            combined = combined.replace(placeholders[i], placeholders[i + 1]);
        }
        return miniMessage.deserialize(combined);
    }

    public Component getRawMessage(String path, String... placeholders) {
        String raw = messagesConfig.getString(path, "");
        for (int i = 0; i + 1 < placeholders.length; i += 2) {
            raw = raw.replace(placeholders[i], placeholders[i + 1]);
        }
        return miniMessage.deserialize(raw);
    }
}