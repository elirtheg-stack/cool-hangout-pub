
 // ================================
 // KeyVault Bot - Part 1 of 3
 // Configuration, database, and helpers
 // ================================

const express = require("express");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  EmbedBuilder,
} = require("discord.js");
const { Pool } = require("pg");
const crypto = require("crypto");

// ================================
// Environment variables
// ================================

const {
  DISCORD_TOKEN,
  CLIENT_ID,
  GUILD_ID,
  SHARED_SECRET,
  BUYER_ROLE_ID,
  ACCESS_ROLE_ID,
  STAFF_ROLE_ID,
  DATABASE_URL,
  REDEMPTION_WEBHOOK_URL,
  TELEPORT_WEBHOOK_URL,
  PUBLIC_URL,
  TELEPORT_SHARED_SECRET,
} = process.env;

const requiredEnv = [
  "DISCORD_TOKEN",
  "CLIENT_ID",
  "GUILD_ID",
  "SHARED_SECRET",
  "BUYER_ROLE_ID",
  "ACCESS_ROLE_ID",
  "DATABASE_URL",
];

for (const name of requiredEnv) {
  if (!process.env[name]) {
    throw new Error(
      `Missing required environment variable: ${name}`
    );
  }
}

if (SHARED_SECRET.length < 32) {
  throw new Error("SHARED_SECRET must be at least 32 characters.");
}

// ================================
// Express API and Discord client
// ================================

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));

const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : undefined,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error.message);
});

const PORT = Number(process.env.PORT || 10000);

const BASE_URL = (
  PUBLIC_URL || "https://keyvault-whitelist-bot.onrender.com"
).replace(/\/+$/, "");

// ================================
// Key helpers
// ================================

function normalizeKey(key) {
  return String(key || "").trim().toUpperCase();
}

function hashKey(key) {
  return crypto
    .createHash("sha256")
    .update(normalizeKey(key))
    .digest("hex");
}

function newKey() {
  const part = () =>
    crypto.randomBytes(3).toString("hex").toUpperCase();

  return `KEY-${part()}-${part()}-${part()}`;
}

function newLinkCode() {
  return String(
    crypto.randomInt(100000, 1000000)
  );
}

function safeEqual(a, b) {
  const first = Buffer.from(String(a || ""));
  const second = Buffer.from(String(b || ""));

  return (
    first.length === second.length &&
    crypto.timingSafeEqual(first, second)
  );
}

function validDiscordId(value) {
  return /^\d{17,20}$/.test(String(value || ""));
}

function validRobloxId(value) {
  return /^\d{1,20}$/.test(String(value || ""));
}

// ================================
// API authentication
// ================================

function apiAuth(req, res, next) {
  const authorization = req.headers.authorization || "";

  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!safeEqual(supplied, SHARED_SECRET)) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  next();
}

// ================================
// Permissions
// ================================

function isAdmin(member) {
  return Boolean(
    member?.permissions?.has(
      PermissionFlagsBits.Administrator
    )
  );
}

function canCreateKeys(member) {
  return (
    isAdmin(member) ||
    Boolean(
      ACCESS_ROLE_ID &&
      member?.roles?.cache?.has(ACCESS_ROLE_ID)
    )
  );
}

function canManageKeys(member) {
  return (
    isAdmin(member) ||
    Boolean(
      STAFF_ROLE_ID &&
      member?.roles?.cache?.has(STAFF_ROLE_ID)
    )
  );
}

// ================================
// Database setup
// ================================

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      discord_id TEXT PRIMARY KEY,
      roblox_id TEXT UNIQUE NOT NULL,
      roblox_name TEXT NOT NULL,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS link_codes (
      code TEXT PRIMARY KEY,
      discord_id TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS keys (
      key_hash TEXT PRIMARY KEY,
      duration_hours INTEGER NOT NULL,
      redeemed_by TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      lifetime BOOLEAN NOT NULL DEFAULT FALSE
    );

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS lifetime
      BOOLEAN NOT NULL DEFAULT FALSE;

    CREATE TABLE IF NOT EXISTS whitelist (
      roblox_id TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ
    );

    ALTER TABLE whitelist
      ALTER COLUMN expires_at DROP NOT NULL;

    CREATE TABLE IF NOT EXISTS redemption_targets (
      discord_id TEXT PRIMARY KEY,
      roblox_id TEXT NOT NULL,
      roblox_name TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS key_blacklist (
      key_hash TEXT PRIMARY KEY,
      reason TEXT,
      blacklisted_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_grants (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT NOT NULL,
      discord_id TEXT NOT NULL,
      roblox_id TEXT NOT NULL,
      granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      lifetime BOOLEAN NOT NULL DEFAULT FALSE,
      revoked_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_access_grants_roblox
      ON access_grants (roblox_id);

    CREATE INDEX IF NOT EXISTS idx_access_grants_key
      ON access_grants (key_hash);

    CREATE INDEX IF NOT EXISTS idx_link_codes_expiry
      ON link_codes (expires_at);
  `);

  console.log("Database setup complete.");
}

// ================================
// Roblox API helpers
// ================================

async function resolveRobloxUser(username) {
  const response = await fetch(
    "https://users.roblox.com/v1/usernames/users",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        usernames: [username],
        excludeBannedUsers: true,
      }),
      signal: AbortSignal.timeout(10000),
    }
  );

  if (!response.ok) {
    throw new Error(
      `Roblox username lookup failed: HTTP ${response.status}`
    );
  }

  const data = await response.json();
  return data.data?.[0] || null;
}

async function getRobloxProfile(userId) {
  if (!validRobloxId(userId)) {
    return null;
  }

  const response = await fetch(
    `https://users.roblox.com/v1/users/${encodeURIComponent(userId)}`,
    {
      signal: AbortSignal.timeout(10000),
    }
  );

  if (!response.ok) {
    if (response.status === 404) {
      return null;
    }

    throw new Error(
      `Roblox profile lookup failed: HTTP ${response.status}`
    );
  }

  return response.json();
}

// ================================
// Webhook logging helpers
// ================================

async function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) {
    console.warn("Webhook not configured; skipping log.");
    return false;
  }

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      console.error(
        "Webhook request failed with HTTP status:",
        response.status
      );
      return false;
    }

    return true;
  } catch (error) {
    console.error(
      "Webhook request failed:",
      error.message
    );
    return false;
  }
}

async function logRedemption({
  discordId,
  robloxId,
  robloxName,
  expiresAt,
  lifetime,
}) {
  return sendWebhook(REDEMPTION_WEBHOOK_URL, {
    embeds: [
      {
        title: "Key Redeemed",
        color: 0x2ecc71,
        fields: [
          {
            name: "Discord ID",
            value: String(discordId || "Unknown"),
          },
          {
            name: "Roblox ID",
            value: String(robloxId || "Unknown"),
          },
          {
            name: "Roblox Username",
            value: String(robloxName || "Unknown"),
          },
          {
            name: "Access",
            value: lifetime
              ? "Lifetime"
              : expiresAt
                ? `Expires: ${new Date(expiresAt).toISOString()}`
                : "Temporary",
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
}

async function logTeleport({
  discordId,
  robloxId,
  robloxName,
  placeId,
  jobId,
}) {
  return sendWebhook(TELEPORT_WEBHOOK_URL, {
    embeds: [
      {
        title: "Roblox Teleport",
        color: 0x3498db,
        fields: [
          {
            name: "Discord ID",
            value: String(discordId || "Not linked"),
          },
          {
            name: "Roblox ID",
            value: String(robloxId || "Unknown"),
          },
          {
            name: "Roblox Username",
            value: String(robloxName || "Unknown"),
          },
          {
            name: "Place ID",
            value: String(placeId || "Unknown"),
          },
          {
            name: "Job ID",
            value: String(jobId || "Unknown"),
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
}

// ================================
// END OF PART 1
// Append Part 2 directly below this line.
// Do not add Markdown fences between parts.
// ================================

// ================================
// KeyVault Bot - Part 2 of 3
// Slash commands and command handlers
// ================================

const commands = [
  new SlashCommandBuilder()
    .setName("panel")
    .setDescription("Post the KeyVault user panel")
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

  new SlashCommandBuilder()
    .setName("key")
    .setDescription("Create a whitelist key")
    .addStringOption(option =>
      option
        .setName("type")
        .setDescription("Key duration")
        .setRequired(true)
        .addChoices(
          { name: "1 Hour", value: "1hour" },
          { name: "1 Day", value: "1day" },
          { name: "7 Days", value: "7day" },
          { name: "Lifetime", value: "lifetime" }
        )
    ),

  new SlashCommandBuilder()
    .setName("blacklistkey")
    .setDescription("Blacklist a key")
    .addStringOption(option =>
      option.setName("key").setDescription("Key to blacklist").setRequired(true)
    )
    .addStringOption(option =>
      option.setName("reason").setDescription("Reason").setRequired(false)
    ),

  new SlashCommandBuilder()
    .setName("unblacklistkey")
    .setDescription("Remove a key from the blacklist")
    .addStringOption(option =>
      option.setName("key").setDescription("Key to unblacklist").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("extendkey")
    .setDescription("Extend a Roblox user's access")
    .addStringOption(option =>
      option.setName("robloxid").setDescription("Roblox user ID").setRequired(true)
    )
    .addIntegerOption(option =>
      option
        .setName("hours")
        .setDescription("Hours to add")
        .setRequired(true)
        .setMinValue(1)
        .setMaxValue(8760)
    ),

  new SlashCommandBuilder()
    .setName("revokekey")
    .setDescription("Revoke a key or access grant")
    .addStringOption(option =>
      option
        .setName("target")
        .setDescription("Key or Roblox user ID")
        .setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("checkkey")
    .setDescription("Check a key's status")
    .addStringOption(option =>
      option.setName("key").setDescription("Key to check").setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("checkwhitelist")
    .setDescription("Check a Roblox user's whitelist")
    .addStringOption(option =>
      option.setName("robloxid").setDescription("Roblox user ID").setRequired(true)
    ),
].map(command => command.toJSON());

// ================================
// Register slash commands
// ================================

async function registerCommands() {
  const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

  await rest.put(
    Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID),
    { body: commands }
  );

  console.log("Slash commands registered.");
}

// ================================
// Command handler
// ================================

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;

  try {
    const { commandName } = interaction;
    const member = interaction.member;

    if (commandName === "panel") {
      if (!isAdmin(member)) {
        return interaction.reply({
          content: "Administrator permission required.",
          ephemeral: true,
        });
      }

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId("link_user")
          .setLabel("Link Roblox")
          .setStyle(ButtonStyle.Primary),
        new ButtonBuilder()
          .setCustomId("redeem_key")
          .setLabel("Redeem Key")
          .setStyle(ButtonStyle.Success),
        new ButtonBuilder()
          .setCustomId("get_role")
          .setLabel("Get Role")
          .setStyle(ButtonStyle.Secondary)
      );

      return interaction.reply({
        content: "**KeyVault Panel**\nLink your Roblox account, redeem a key, or claim your role.",
        components: [row],
      });
    }

    if (commandName === "key") {
      if (!canCreateKeys(member)) {
        return interaction.reply({
          content: "You don't have permission to create keys.",
          ephemeral: true,
        });
      }

      const type = interaction.options.getString("type", true);
      const durations = {
        "1hour": 1,
        "1day": 24,
        "7day": 168,
        "lifetime": 0,
      };

      const lifetime = type === "lifetime";
      const durationHours = durations[type];
      const key = newKey();
      const keyHash = hashKey(key);

      await pool.query(
        `INSERT INTO keys (key_hash, duration_hours, lifetime)
         VALUES ($1, $2, $3)`,
        [keyHash, durationHours, lifetime]
      );

      return interaction.reply({
        content: `**New Key:** \`${key}\`\n**Type:** ${type}`,
        ephemeral: true,
      });
    }

    if (!canManageKeys(member)) {
      return interaction.reply({
        content: "You don't have permission to manage keys.",
        ephemeral: true,
      });
    }

    if (commandName === "blacklistkey") {
      const key = interaction.options.getString("key", true);
      const reason =
        interaction.options.getString("reason") || "No reason provided";
      const keyHash = hashKey(key);

      const result = await pool.query(
        "SELECT key_hash FROM keys WHERE key_hash = $1",
        [keyHash]
      );

      if (!result.rowCount) {
        return interaction.reply({
          content: "Key not found.",
          ephemeral: true,
        });
      }

      await pool.query(
        `INSERT INTO key_blacklist (key_hash, reason, blacklisted_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (key_hash) DO UPDATE SET
           reason = EXCLUDED.reason,
           blacklisted_by = EXCLUDED.blacklisted_by,
           created_at = NOW()`,
        [keyHash, reason, interaction.user.id]
      );

      return interaction.reply({
        content: "Key blacklisted. Future redemption attempts will be rejected.",
        ephemeral: true,
      });
    }

    if (commandName === "unblacklistkey") {
      const key = interaction.options.getString("key", true);

      const result = await pool.query(
        "DELETE FROM key_blacklist WHERE key_hash = $1",
        [hashKey(key)]
      );

      return interaction.reply({
        content: result.rowCount
          ? "Key removed from blacklist. Previous access changes are not automatically reversed."
          : "That key wasn't blacklisted.",
        ephemeral: true,
      });
    }

    if (commandName === "extendkey") {
      const robloxId = interaction.options.getString("robloxid", true);
      const hours = interaction.options.getInteger("hours", true);

      if (!validRobloxId(robloxId)) {
        return interaction.reply({
          content: "Invalid Roblox user ID.",
          ephemeral: true,
        });
      }

      const result = await pool.query(
        "SELECT expires_at FROM whitelist WHERE roblox_id = $1",
        [robloxId]
      );

      if (!result.rowCount) {
        return interaction.reply({
          content: "That Roblox user has no whitelist entry.",
          ephemeral: true,
        });
      }

      const currentExpiry = result.rows[0].expires_at;

      if (currentExpiry === null) {
        return interaction.reply({
          content: "This user already has lifetime access.",
          ephemeral: true,
        });
      }

      const baseTime = Math.max(
        new Date(currentExpiry).getTime(),
        Date.now()
      );
      const newExpiry = new Date(baseTime + hours * 60 * 60 * 1000);

      await pool.query(
        "UPDATE whitelist SET expires_at = $1 WHERE roblox_id = $2",
        [newExpiry, robloxId]
      );

      return interaction.reply({
        content: `Whitelist extended until ${newExpiry.toISOString()}.`,
        ephemeral: true,
      });
    }

    if (commandName === "revokekey") {
      const target = interaction.options.getString("target", true).trim();

      if (target.length > 100) {
        return interaction.reply({
          content: "Invalid target.",
          ephemeral: true,
        });
      }

      const keyHash = hashKey(target);

      // Revoke a key and its associated grant.
      const keyResult = await pool.query(
        "SELECT key_hash FROM keys WHERE key_hash = $1",
        [keyHash]
      );

      if (keyResult.rowCount) {
        await pool.query("BEGIN");

        try {
          await pool.query(
            `UPDATE access_grants
             SET revoked_at = NOW()
             WHERE key_hash = $1 AND revoked_at IS NULL`,
            [keyHash]
          );

          await pool.query(
            `UPDATE keys
             SET redeemed_by = NULL, expires_at = NULL
             WHERE key_hash = $1`,
            [keyHash]
          );

          await pool.query(
            "DELETE FROM key_blacklist WHERE key_hash = $1",
            [keyHash]
          );

          await pool.query("COMMIT");

          return interaction.reply({
            content: "Key revoked. Existing whitelist access was not automatically recalculated; check the user's access before removing it.",
            ephemeral: true,
          });
        } catch (error) {
          await pool.query("ROLLBACK").catch(() => {});
          throw error;
        }
      }

      // Revoke a Roblox user's current whitelist entry.
      if (validRobloxId(target)) {
        const result = await pool.query(
          "DELETE FROM whitelist WHERE roblox_id = $1 RETURNING roblox_id",
          [target]
        );

        if (result.rowCount) {
          await pool.query(
            `UPDATE access_grants
             SET revoked_at = NOW()
             WHERE roblox_id = $1 AND revoked_at IS NULL`,
            [target]
          );

          return interaction.reply({
            content: "Whitelist entry removed.",
            ephemeral: true,
          });
        }
      }

      return interaction.reply({
        content: "No matching key or whitelisted Roblox ID was found.",
        ephemeral: true,
      });
    }

    if (commandName === "checkkey") {
      const keyHash = hashKey(interaction.options.getString("key", true));

      const result = await pool.query(
        `SELECT redeemed_by, expires_at, lifetime, created_at
         FROM keys WHERE key_hash = $1`,
        [keyHash]
      );

      if (!result.rowCount) {
        return interaction.reply({
          content: "Key not found.",
          ephemeral: true,
        });
      }

      const blacklist = await pool.query(
        "SELECT reason FROM key_blacklist WHERE key_hash = $1",
        [keyHash]
      );

      const data = result.rows[0];
      const status = blacklist.rowCount
        ? "Blacklisted"
        : data.redeemed_by
          ? "Redeemed"
          : "Unused";

      return interaction.reply({
        content:
          `**Status:** ${status}\n` +
          `**Lifetime:** ${data.lifetime ? "Yes" : "No"}\n` +
          `**Redeemed by:** ${data.redeemed_by || "Nobody"}\n` +
          `**Expiry:** ${data.expires_at ? new Date(data.expires_at).toISOString() : data.lifetime ? "Lifetime / no expiry" : "Not set"}`,
        ephemeral: true,
      });
    }

    if (commandName === "checkwhitelist") {
      const robloxId = interaction.options.getString("robloxid", true);

      if (!validRobloxId(robloxId)) {
        return interaction.reply({
          content: "Invalid Roblox user ID.",
          ephemeral: true,
        });
      }

      const result = await pool.query(
        "SELECT expires_at FROM whitelist WHERE roblox_id = $1",
        [robloxId]
      );

      if (!result.rowCount) {
        return interaction.reply({
          content: "This Roblox user is not whitelisted.",
          ephemeral: true,
        });
      }

      const expiry = result.rows[0].expires_at;
      const active = expiry === null || new Date(expiry) > new Date();

      return interaction.reply({
        content: !active
          ? "The whitelist entry has expired."
          : expiry === null
            ? "This Roblox user has lifetime access."
            : `Whitelisted until ${new Date(expiry).toISOString()}.`,
        ephemeral: true,
      });
    }
  } catch (error) {
    console.error("Command error:", error);

    const reply = {
      content: "An error occurred while running that command.",
      ephemeral: true,
    };

    if (interaction.replied || interaction.deferred) {
      await interaction.followUp(reply).catch(() => {});
    } else {
      await interaction.reply(reply).catch(() => {});
    }
  }
});

// ================================
// END OF PART 2
// Append Part 3 directly below this line.
// ================================

// ================================
// KeyVault Bot - Part 3 of 3
// API routes, linking, redemption, and startup
// ================================

// ================================
// Basic API routes
// ================================

app.get("/", (_req, res) => {
  res.send("KeyVault API is online.");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/linked", apiAuth, async (req, res) => {
  try {
    const discordId = String(req.query.discordId || "");

    if (!validDiscordId(discordId)) {
      return res.status(400).json({ error: "Invalid Discord ID." });
    }

    const result = await pool.query(
      `SELECT discord_id, roblox_id, roblox_name
       FROM links WHERE discord_id = $1`,
      [discordId]
    );

    return res.json({
      linked: result.rowCount > 0,
      account: result.rows[0] || null,
    });
  } catch (error) {
    console.error("Linked API error:", error.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ================================
// Confirm Roblox account ownership
// ================================

app.post("/link/confirm", apiAuth, async (req, res) => {
  const { code, userId, username } = req.body || {};

  if (
    typeof code !== "string" ||
    !/^\d{6}$/.test(code) ||
    !validRobloxId(userId) ||
    typeof username !== "string" ||
    username.length > 50
  ) {
    return res.status(400).json({ error: "Invalid linking data." });
  }

  try {
    const profile = await getRobloxProfile(String(userId));

    if (!profile || profile.name !== username) {
      return res.status(400).json({
        error: "Roblox profile could not be verified.",
      });
    }

    if (!String(profile.description || "").includes(code)) {
      return res.status(400).json({
        error: "Verification code was not found in the Roblox profile description.",
      });
    }

    const codeResult = await pool.query(
      `DELETE FROM link_codes
       WHERE code = $1 AND expires_at > NOW()
       RETURNING discord_id`,
      [code]
    );

    if (!codeResult.rowCount) {
      return res.status(400).json({
        error: "Invalid or expired linking code.",
      });
    }

    const discordId = codeResult.rows[0].discord_id;

    await pool.query("BEGIN");

    try {
      const existing = await pool.query(
        "SELECT discord_id FROM links WHERE roblox_id = $1",
        [String(userId)]
      );

      if (
        existing.rowCount &&
        existing.rows[0].discord_id !== discordId
      ) {
        await pool.query("ROLLBACK");
        return res.status(409).json({
          error: "Roblox account is already linked.",
        });
      }

      await pool.query(
        `INSERT INTO links (discord_id, roblox_id, roblox_name)
         VALUES ($1, $2, $3)
         ON CONFLICT (discord_id) DO UPDATE SET
           roblox_id = EXCLUDED.roblox_id,
           roblox_name = EXCLUDED.roblox_name,
           linked_at = NOW()`,
        [discordId, String(userId), profile.name]
      );

      await pool.query("COMMIT");

      return res.json({
        ok: true,
        discordId,
        userId: String(userId),
        username: profile.name,
      });
    } catch (error) {
      await pool.query("ROLLBACK").catch(() => {});
      throw error;
    }
  } catch (error) {
    console.error("Link confirmation error:", error.message);
    return res.status(500).json({ error: "Could not link account." });
  }
});

// ================================
// Verify a key before redemption
// ================================

app.post("/verify", apiAuth, async (req, res) => {
  const { key } = req.body || {};

  if (typeof key !== "string" || key.length > 100) {
    return res.status(400).json({ error: "Invalid key." });
  }

  try {
    const result = await pool.query(
      `SELECT k.redeemed_by, b.key_hash AS blacklisted
       FROM keys k
       LEFT JOIN key_blacklist b ON b.key_hash = k.key_hash
       WHERE k.key_hash = $1`,
      [hashKey(key)]
    );

    if (
      !result.rowCount ||
      result.rows[0].redeemed_by ||
      result.rows[0].blacklisted
    ) {
      return res.status(400).json({
        valid: false,
        error: "Key is invalid, already redeemed, or blacklisted.",
      });
    }

    return res.json({ valid: true });
  } catch (error) {
    console.error("Verify API error:", error.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ================================
// Redeem a key
// ================================

app.post("/redeem", apiAuth, async (req, res) => {
  const { key, discordId } = req.body || {};

  if (
    typeof key !== "string" ||
    key.length > 100 ||
    !validDiscordId(discordId)
  ) {
    return res.status(400).json({ error: "Invalid redemption data." });
  }

  const db = await pool.connect();
  let committed = false;

  try {
    await db.query("BEGIN");

    const link = await db.query(
      `SELECT roblox_id, roblox_name
       FROM links WHERE discord_id = $1`,
      [discordId]
    );

    if (!link.rowCount) {
      await db.query("ROLLBACK");
      return res.status(400).json({
        error: "Link your verified Roblox account first.",
      });
    }

    const keyResult = await db.query(
      `SELECT k.*
       FROM keys k
       LEFT JOIN key_blacklist b ON b.key_hash = k.key_hash
       WHERE k.key_hash = $1
         AND k.redeemed_by IS NULL
         AND b.key_hash IS NULL
       FOR UPDATE OF k`,
      [hashKey(key)]
    );

    if (!keyResult.rowCount) {
      await db.query("ROLLBACK");
      return res.status(400).json({
        error: "Key is invalid, already redeemed, or blacklisted.",
      });
    }

    const keyData = keyResult.rows[0];
    const roblox = link.rows[0];

    const existing = await db.query(
      `SELECT expires_at FROM whitelist
       WHERE roblox_id = $1 FOR UPDATE`,
      [roblox.roblox_id]
    );

    let expiresAt = null;

    if (!keyData.lifetime) {
      const currentExpiry = existing.rows[0]?.expires_at;
      const baseTime =
        currentExpiry && new Date(currentExpiry).getTime() > Date.now()
          ? new Date(currentExpiry).getTime()
          : Date.now();

      expiresAt = new Date(
        baseTime + Number(keyData.duration_hours) * 60 * 60 * 1000
      );
    }

    await db.query(
      `UPDATE keys
       SET redeemed_by = $1, expires_at = $2
       WHERE key_hash = $3`,
      [discordId, expiresAt, keyData.key_hash]
    );

    await db.query(
      `INSERT INTO access_grants
         (key_hash, discord_id, roblox_id, expires_at, lifetime)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        keyData.key_hash,
        discordId,
        roblox.roblox_id,
        expiresAt,
        keyData.lifetime,
      ]
    );

    await db.query(
      `INSERT INTO whitelist (roblox_id, expires_at)
       VALUES ($1, $2)
       ON CONFLICT (roblox_id) DO UPDATE SET
         expires_at = CASE
           WHEN whitelist.expires_at IS NULL OR EXCLUDED.expires_at IS NULL
             THEN NULL
           ELSE GREATEST(whitelist.expires_at, EXCLUDED.expires_at)
         END`,
      [roblox.roblox_id, expiresAt]
    );

    await db.query("COMMIT");
    committed = true;

    await logRedemption({
      discordId,
      robloxId: roblox.roblox_id,
      robloxName: roblox.roblox_name,
      expiresAt,
      lifetime: keyData.lifetime,
    });

    return res.json({
      ok: true,
      robloxId: roblox.roblox_id,
      robloxName: roblox.roblox_name,
      expiresAt,
      lifetime: keyData.lifetime,
    });
  } catch (error) {
    if (!committed) {
      await db.query("ROLLBACK").catch(() => {});
    }

    console.error("Redeem API error:", error.message);
    return res.status(500).json({ error: "Redemption failed." });
  } finally {
    db.release();
  }
});

// ================================
// Whitelist status API
// ================================

app.get("/whitelist", apiAuth, async (req, res) => {
  const robloxId = String(req.query.robloxId || "");

  if (!validRobloxId(robloxId)) {
    return res.status(400).json({ error: "Invalid Roblox ID." });
  }

  try {
    const result = await pool.query(
      "SELECT expires_at FROM whitelist WHERE roblox_id = $1",
      [robloxId]
    );

    if (!result.rowCount) {
      return res.json({ whitelisted: false, lifetime: false });
    }

    const expiry = result.rows[0].expires_at;
    const active = expiry === null || new Date(expiry) > new Date();

    return res.json({
      whitelisted: active,
      lifetime: active && expiry === null,
      expiresAt: expiry,
    });
  } catch (error) {
    console.error("Whitelist API error:", error.message);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ================================
// Discord panel interactions
// ================================

client.on("interactionCreate", async interaction => {
  try {
    if (interaction.isButton()) {
      if (interaction.customId === "link_user") {
        const modal = new ModalBuilder()
          .setCustomId("link_modal")
          .setTitle("Link Roblox Account");

        const username = new TextInputBuilder()
          .setCustomId("roblox_username")
          .setLabel("Roblox username")
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setMaxLength(20);

        modal.addComponents(
          new ActionRowBuilder().addComponents(username)
        );

        return interaction.showModal(modal);
      }

      if (interaction.customId === "redeem_key") {
        const modal = new ModalBuilder()
          .setCustomId("redeem_modal")
          .setTitle("Redeem Key");

        const keyInput = new TextInputBuilder()
          .setCustomId("key")
          .setLabel("Your key")
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setMaxLength(100);

        modal.addComponents(
          new ActionRowBuilder().addComponents(keyInput)
        );

        return interaction.showModal(modal);
      }

      if (interaction.customId === "get_role") {
        const result = await pool.query(
          `SELECT l.roblox_id, w.expires_at
           FROM links l
           JOIN whitelist w ON w.roblox_id = l.roblox_id
           WHERE l.discord_id = $1`,
          [interaction.user.id]
        );

        if (!result.rowCount) {
          return interaction.reply({
            content: "Link your Roblox account and redeem a key first.",
            ephemeral: true,
          });
        }

        const entry = result.rows[0];
        const active =
          entry.expires_at === null ||
          new Date(entry.expires_at) > new Date();

        if (!active) {
          return interaction.reply({
            content: "Your whitelist access has expired.",
            ephemeral: true,
          });
        }

        const guildMember = await interaction.guild.members.fetch(
          interaction.user.id
        );

        await guildMember.roles.add(BUYER_ROLE_ID);

        return interaction.reply({
          content: "Your access role has been granted.",
          ephemeral: true,
        });
      }
    }

    if (interaction.isModalSubmit()) {
      if (interaction.customId === "link_modal") {
        const username = interaction.fields
          .getTextInputValue("roblox_username")
          .trim();

        await interaction.deferReply({ ephemeral: true });

        const roblox = await resolveRobloxUser(username);

        if (!roblox) {
          return interaction.editReply("Roblox username not found.");
        }

        const pending = await pool.query(
          `SELECT code FROM link_codes
           WHERE discord_id = $1 AND expires_at > NOW()
           ORDER BY expires_at DESC LIMIT 1`,
          [interaction.user.id]
        );

        if (!pending.rowCount) {
          const code = newLinkCode();

          await pool.query(
            `DELETE FROM link_codes WHERE discord_id = $1`,
            [interaction.user.id]
          );

          await pool.query(
            `INSERT INTO link_codes (code, discord_id, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '15 minutes')`,
            [code, interaction.user.id]
          );

          return interaction.editReply(
            `**Step 1:** Edit your Roblox profile description and add this verification code:\n\n\`${code}\`\n\n**Step 2:** Save your Roblox profile, wait a moment, then press **Link Roblox** again and enter the same username. The code expires in 15 minutes. Remove the code from your description after linking.`
          );
        }

        const code = pending.rows[0].code;
        const profile = await getRobloxProfile(String(roblox.id));

        if (!profile || profile.name !== roblox.name) {
          return interaction.editReply(
            "Could not confirm that Roblox profile. Please try again."
          );
        }

        if (!String(profile.description || "").includes(code)) {
          return interaction.editReply(
            `I couldn't find your verification code in that Roblox profile's description.\n\nAdd \`${code}\` to the description, save it, and try again before the code expires.`
          );
        }

        await pool.query("BEGIN");

        try {
          const existing = await pool.query(
            "SELECT discord_id FROM links WHERE roblox_id = $1",
            [String(roblox.id)]
          );

          if (
            existing.rowCount &&
            existing.rows[0].discord_id !== interaction.user.id
          ) {
            await pool.query("ROLLBACK");
            return interaction.editReply(
              "That Roblox account is already linked to another Discord account."
            );
          }

          await pool.query(
            `INSERT INTO links (discord_id, roblox_id, roblox_name)
             VALUES ($1, $2, $3)
             ON CONFLICT (discord_id) DO UPDATE SET
               roblox_id = EXCLUDED.roblox_id,
               roblox_name = EXCLUDED.roblox_name,
               linked_at = NOW()`,
            [interaction.user.id, String(roblox.id), roblox.name]
          );

          await pool.query(
            "DELETE FROM link_codes WHERE discord_id = $1",
            [interaction.user.id]
          );

          await pool.query("COMMIT");

          return interaction.editReply(
            `Roblox account **${roblox.name}** has been verified and linked successfully.`
          );
        } catch (error) {
          await pool.query("ROLLBACK").catch(() => {});
          throw error;
        }
      }

      if (interaction.customId === "redeem_modal") {
        const key = interaction.fields.getTextInputValue("key").trim();

        await interaction.deferReply({ ephemeral: true });

        const response = await fetch(`${BASE_URL}/redeem`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${SHARED_SECRET}`,
          },
          body: JSON.stringify({
            key,
            discordId: interaction.user.id,
          }),
          signal: AbortSignal.timeout(15000),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok || !data.ok) {
          return interaction.editReply(
            data.error || "Could not redeem this key."
          );
        }

        return interaction.editReply(
          `Key redeemed successfully for **${data.robloxName}**! You can now press **Get Role**.`
        );
      }
    }
  } catch (error) {
    console.error("Panel interaction error:", error.message);

    const message = "An error occurred. Please try again later.";

    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({
        content: message,
        ephemeral: true,
      }).catch(() => {});
    } else if (interaction.isRepliable()) {
      await interaction.reply({
        content: message,
        ephemeral: true,
      }).catch(() => {});
    }
  }
});

// ================================
// Teleport webhook endpoint
// ================================

app.post("/teleport-log", async (req, res) => {
  const expected = TELEPORT_SHARED_SECRET;
  const supplied = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice(7)
    : "";

  if (!expected || !safeEqual(supplied, expected)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { robloxId, robloxName, placeId, jobId } = req.body || {};

  if (!validRobloxId(robloxId)) {
    return res.status(400).json({ error: "Invalid Roblox ID." });
  }

  try {
    const link = await pool.query(
      "SELECT discord_id FROM links WHERE roblox_id = $1",
      [String(robloxId)]
    );

    await logTeleport({
      discordId: link.rows[0]?.discord_id || null,
      robloxId,
      robloxName,
      placeId,
      jobId,
    });

    return res.json({ ok: true });
  } catch (error) {
    console.error("Teleport log error:", error.message);
    return res.status(500).json({ error: "Could not log teleport." });
  }
});

// ================================
// Startup
// ================================

async function start() {
  await setupDatabase();

  app.listen(PORT, () => {
    console.log(`KeyVault API listening on ${PORT}`);
  });

  await registerCommands();
  await client.login(DISCORD_TOKEN);
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
