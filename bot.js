
const express = require("express");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits,
} = require("discord.js");
const { Pool } = require("pg");
const crypto = require("crypto");

// ---------- Environment variables ----------

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const GUILD_ID = process.env.GUILD_ID;
const DATABASE_URL = process.env.DATABASE_URL;
const SHARED_SECRET = process.env.SHARED_SECRET;
const BUYER_ROLE_ID = process.env.BUYER_ROLE_ID;
const ACCESS_ROLE_ID = process.env.ACCESS_ROLE_ID;

const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID || "";
const REDEMPTION_WEBHOOK_URL =
  process.env.REDEMPTION_WEBHOOK_URL || "";
const TELEPORT_WEBHOOK_URL =
  process.env.TELEPORT_WEBHOOK_URL || "";
const TELEPORT_SHARED_SECRET =
  process.env.TELEPORT_SHARED_SECRET || "";

const PORT = Number(process.env.PORT) || 3000;

const requiredEnv = {
  DISCORD_TOKEN,
  CLIENT_ID,
  GUILD_ID,
  DATABASE_URL,
  SHARED_SECRET,
  BUYER_ROLE_ID,
  ACCESS_ROLE_ID,
};

const missingEnv = Object.entries(requiredEnv)
  .filter(([, value]) => !value)
  .map(([name]) => name);

if (missingEnv.length > 0) {
  throw new Error(
    `Missing environment variables: ${missingEnv.join(", ")}`,
  );
}

// ---------- Configuration ----------

const DURATIONS = {
  "1hour": { hours: 1, lifetime: false, label: "1 hour" },
  "1day": { hours: 24, lifetime: false, label: "1 day" },
  "1week": { hours: 168, lifetime: false, label: "1 week" },
  "1month": { hours: 720, lifetime: false, label: "1 month" },
  lifetime: { hours: null, lifetime: true, label: "Lifetime" },
};

const PRE_REVOKED_KEYS = [
  "KEY-G55SF6JXDAV3",
  "KEY-ZHTL3CMBRYEB",
];

// ---------- Application and database ----------

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));

const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "false"
      ? false
      : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on("error", error => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

// ---------- Key and security helpers ----------

function normalizeKey(value) {
  return String(value || "").trim().toUpperCase();
}

function hashKey(value) {
  return crypto
    .createHash("sha256")
    .update(normalizeKey(value), "utf8")
    .digest("hex");
}

function generateKey() {
  return `KEY-${crypto.randomBytes(8).toString("hex").toUpperCase()}`;
}

function generateLinkCode() {
  return `RBX-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a ?? ""), "utf8");
  const right = Buffer.from(String(b ?? ""), "utf8");

  return (
    left.length === right.length &&
    crypto.timingSafeEqual(left, right)
  );
}

function validDiscordId(value) {
  return /^\d{17,20}$/.test(String(value || ""));
}

function validRobloxId(value) {
  const text = String(value || "");

  return /^\d{1,20}$/.test(text) && BigInt(text) > 0n;
}

function apiAuth(req, res, next) {
  const supplied = req.get("x-shared-secret");

  if (!supplied || !safeEqual(supplied, SHARED_SECRET)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return next();
}

// ---------- Discord permissions ----------

function isAdmin(member) {
  return Boolean(
    member?.permissions?.has(PermissionFlagsBits.Administrator),
  );
}

function canCreateKeys(member) {
  return Boolean(
    isAdmin(member) ||
      member?.roles?.cache?.has(ACCESS_ROLE_ID),
  );
}

function canManageKeys(member) {
  return Boolean(
    isAdmin(member) ||
      (STAFF_ROLE_ID &&
        member?.roles?.cache?.has(STAFF_ROLE_ID)),
  );
}

function durationFor(name) {
  return DURATIONS[String(name || "").toLowerCase()] || null;
}

// ---------- Database setup and migrations ----------

async function setupDatabase() {
  // Create tables without indexes first.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      discord_id TEXT PRIMARY KEY,
      roblox_id TEXT UNIQUE NOT NULL,
      roblox_username TEXT,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS link_codes (
      discord_id TEXT PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS keys (
      key_hash TEXT PRIMARY KEY,
      duration_hours INTEGER,
      redeemed_by TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      lifetime BOOLEAN NOT NULL DEFAULT FALSE,
      inventory_type TEXT,
      inventory_status TEXT NOT NULL DEFAULT 'active',
      inventory_note TEXT
    );

    CREATE TABLE IF NOT EXISTS whitelist (
      roblox_id TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS key_blacklist (
      key_hash TEXT PRIMARY KEY,
      reason TEXT NOT NULL DEFAULT 'Revoked',
      blacklisted_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_grants (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT,
      discord_id TEXT NOT NULL,
      roblox_id TEXT NOT NULL,
      granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      lifetime BOOLEAN NOT NULL DEFAULT FALSE,
      revoked_at TIMESTAMPTZ
    );
  `);

  // Migrate existing keys tables.
  await pool.query(`
    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS duration_hours INTEGER;

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS redeemed_by TEXT;

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
      DEFAULT NOW();

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS lifetime BOOLEAN
      NOT NULL DEFAULT FALSE;

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS inventory_type TEXT;

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS inventory_status TEXT
      NOT NULL DEFAULT 'active';

    ALTER TABLE keys
      ADD COLUMN IF NOT EXISTS inventory_note TEXT;
  `);

  // Migrate existing links tables.
  await pool.query(`
    ALTER TABLE links
      ADD COLUMN IF NOT EXISTS roblox_username TEXT;

    ALTER TABLE links
      ADD COLUMN IF NOT EXISTS linked_at TIMESTAMPTZ
      NOT NULL DEFAULT NOW();
  `);

  // Copy the legacy username column when it exists.
  const legacyNameColumn = await pool.query(`
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'links'
      AND column_name = 'roblox_name'
  `);

  if (legacyNameColumn.rowCount > 0) {
    await pool.query(`
      UPDATE links
      SET roblox_username = roblox_name
      WHERE roblox_username IS NULL
        AND roblox_name IS NOT NULL
    `);
  }

  await pool.query(`
    UPDATE links
    SET roblox_username = ''
    WHERE roblox_username IS NULL;

    ALTER TABLE links
      ALTER COLUMN roblox_username SET NOT NULL;
  `);

  // Migrate access-grant columns for older installations.
  await pool.query(`
    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS key_hash TEXT;

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS discord_id TEXT;

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS roblox_id TEXT;

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS granted_at TIMESTAMPTZ
      NOT NULL DEFAULT NOW();

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS lifetime BOOLEAN
      NOT NULL DEFAULT FALSE;

    ALTER TABLE access_grants
      ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
  `);

  // FIX: manual whitelist grants use NULL for key_hash.
  await pool.query(`
    ALTER TABLE access_grants
      ALTER COLUMN key_hash DROP NOT NULL;
  `);

  // Create indexes after column migrations.
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_access_grants_roblox
      ON access_grants (roblox_id);

    CREATE INDEX IF NOT EXISTS idx_link_codes_expiry
      ON link_codes (expires_at);

    CREATE INDEX IF NOT EXISTS idx_keys_inventory
      ON keys (inventory_type, inventory_status);
  `);

  // Blacklist previously revoked keys without storing plaintext.
  for (const plainKey of PRE_REVOKED_KEYS) {
    const keyHash = hashKey(plainKey);

    await pool.query(
      `INSERT INTO key_blacklist (key_hash, reason)
       VALUES ($1, $2)
       ON CONFLICT (key_hash) DO NOTHING`,
      [keyHash, "Previously revoked key"],
    );

    await pool.query(
      `UPDATE keys
       SET inventory_status = 'revoked'
       WHERE key_hash = $1`,
      [keyHash],
    );
  }

  console.log("Database setup and migrations completed.");
}

// ---------- Roblox API helpers ----------

async function resolveRobloxUsername(robloxId) {
  if (!validRobloxId(robloxId)) {
    throw new Error("Invalid Roblox user ID.");
  }

  const response = await fetch(
    `https://users.roblox.com/v1/users/${encodeURIComponent(String(robloxId))}`,
  );

  if (!response.ok) {
    throw new Error(
      `Roblox user lookup failed: HTTP ${response.status}`,
    );
  }

  const profile = await response.json();
  return profile.name;
}

async function getRobloxProfile(robloxId) {
  if (!validRobloxId(robloxId)) {
    throw new Error("Invalid Roblox user ID.");
  }

  const response = await fetch(
    `https://users.roblox.com/v1/users/${encodeURIComponent(String(robloxId))}`,
  );

  if (!response.ok) {
    throw new Error(
      `Roblox profile lookup failed: HTTP ${response.status}`,
    );
  }

  return response.json();
}

async function getRobloxProfileByUsername(username) {
  const cleanUsername = String(username || "").trim();

  if (!cleanUsername || cleanUsername.length > 20) {
    throw new Error("Invalid Roblox username.");
  }

  const response = await fetch(
    "https://users.roblox.com/v1/usernames/users",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usernames: [cleanUsername],
        excludeBannedUsers: false,
      }),
    },
  );

  if (!response.ok) {
    throw new Error(
      `Roblox username lookup failed: HTTP ${response.status}`,
    );
  }

  const data = await response.json();
  const user = data.data?.[0];

  if (!user) {
    return null;
  }

  return {
    id: String(user.id),
    name: user.name,
    displayName: user.displayName,
  };
}

async function getRobloxDescription(robloxId) {
  const profile = await getRobloxProfile(robloxId);

  return typeof profile.description === "string"
    ? profile.description
    : "";
}

// ---------- Webhook helpers ----------

async function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) {
    return false;
  }

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      console.error("Webhook request failed:", response.status);
      return false;
    }

    return true;
  } catch (error) {
    console.error("Webhook request error:", error.message);
    return false;
  }
}

async function logRedemption({
  discordId,
  robloxId,
  robloxUsername,
  duration,
  expiresAt,
}) {
  return sendWebhook(REDEMPTION_WEBHOOK_URL, {
    username: "Whitelist Redemption Log",
    embeds: [
      {
        title: "Whitelist key redeemed",
        color: 0x2ecc71,
        fields: [
          {
            name: "Discord ID",
            value: String(discordId),
            inline: true,
          },
          {
            name: "Roblox ID",
            value: String(robloxId),
            inline: true,
          },
          {
            name: "Roblox username",
            value: String(robloxUsername || "Unknown"),
            inline: true,
          },
          {
            name: "Duration",
            value: String(duration),
            inline: true,
          },
          {
            name: "Expires",
            value: expiresAt
              ? new Date(expiresAt).toISOString()
              : "Lifetime",
            inline: false,
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
  robloxUsername,
  placeId,
  jobId,
}) {
  return sendWebhook(TELEPORT_WEBHOOK_URL, {
    username: "Roblox Teleport Log",
    embeds: [
      {
        title: "Teleport logged",
        color: 0x3498db,
        fields: [
          {
            name: "Discord ID",
            value: String(discordId || "Unknown"),
            inline: true,
          },
          {
            name: "Roblox ID",
            value: String(robloxId),
            inline: true,
          },
          {
            name: "Roblox username",
            value: String(robloxUsername || "Unknown"),
            inline: true,
          },
          {
            name: "Place ID",
            value: String(placeId),
            inline: true,
          },
          {
            name: "Job ID",
            value: String(jobId || "Not provided"),
            inline: false,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
}

 // ---------- Slash command definitions ----------

const commands = [
  new SlashCommandBuilder()
    .setName("link")
    .setDescription("Start linking your Roblox account"),

  new SlashCommandBuilder()
    .setName("linkconfirm")
    .setDescription("Continue Roblox account linking"),

  new SlashCommandBuilder()
    .setName("get_role")
    .setDescription("Get the buyer role"),

  new SlashCommandBuilder()
    .setName("verify")
    .setDescription("Verify and redeem a whitelist key")
    .addStringOption(option =>
      option.setName("key")
        .setDescription("Your whitelist key")
        .setRequired(true),
    ),

  new SlashCommandBuilder()
    .setName("redeem")
    .setDescription("Redeem a whitelist key")
    .addStringOption(option =>
      option.setName("key")
        .setDescription("Your whitelist key")
        .setRequired(true),
    ),

  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("Check your Roblox whitelist status"),

  new SlashCommandBuilder()
    .setName("whitelistuser")
    .setDescription("Grant whitelist access to a Roblox user")
    .addStringOption(option =>
      option.setName("username")
        .setDescription("Roblox username")
        .setRequired(true),
    )
    .addStringOption(option =>
      option.setName("duration")
        .setDescription("Access duration")
        .setRequired(true)
        .addChoices(
          { name: "1 hour", value: "1hour" },
          { name: "1 day", value: "1day" },
          { name: "1 week", value: "1week" },
          { name: "1 month", value: "1month" },
          { name: "Lifetime", value: "lifetime" },
        ),
    ),

  new SlashCommandBuilder()
    .setName("createkey")
    .setDescription("Create a whitelist key")
    .addStringOption(option =>
      option.setName("duration")
        .setDescription("Key duration")
        .setRequired(true)
        .addChoices(
          { name: "1 hour", value: "1hour" },
          { name: "1 day", value: "1day" },
          { name: "1 week", value: "1week" },
          { name: "1 month", value: "1month" },
          { name: "Lifetime", value: "lifetime" },
        ),
    ),

  new SlashCommandBuilder()
    .setName("blacklistkey")
    .setDescription("Blacklist a key and revoke its access")
    .addStringOption(option =>
      option.setName("key")
        .setDescription("Key to blacklist")
        .setRequired(true),
    )
    .addStringOption(option =>
      option.setName("reason")
        .setDescription("Reason for blacklisting")
        .setRequired(false),
    ),

  new SlashCommandBuilder()
    .setName("extendkey")
    .setDescription("Extend a Roblox user's whitelist access")
    .addStringOption(option =>
      option.setName("username")
        .setDescription("Roblox username")
        .setRequired(true),
    )
    .addStringOption(option =>
      option.setName("duration")
        .setDescription("Additional time")
        .setRequired(true)
        .addChoices(
          { name: "1 hour", value: "1hour" },
          { name: "1 day", value: "1day" },
          { name: "1 week", value: "1week" },
          { name: "1 month", value: "1month" },
        ),
    ),

  new SlashCommandBuilder()
    .setName("inventory")
    .setDescription("Manage whitelist key inventory")
    .addSubcommand(subcommand =>
      subcommand.setName("add")
        .setDescription("Create inventory keys")
        .addStringOption(option =>
          option.setName("duration")
            .setDescription("Key duration")
            .setRequired(true)
            .addChoices(
              { name: "1 hour", value: "1hour" },
              { name: "1 day", value: "1day" },
              { name: "1 week", value: "1week" },
              { name: "1 month", value: "1month" },
              { name: "Lifetime", value: "lifetime" },
            ),
        )
        .addIntegerOption(option =>
          option.setName("amount")
            .setDescription("Number of keys to create")
            .setRequired(true)
            .setMinValue(1)
            .setMaxValue(100),
        ),
    )
    .addSubcommand(subcommand =>
      subcommand.setName("list")
        .setDescription("Show inventory key counts"),
    ),

  new SlashCommandBuilder()
    .setName("teleport-log")
    .setDescription("Log a Roblox teleport")
    .addStringOption(option =>
      option.setName("roblox_username")
        .setDescription("Roblox username")
        .setRequired(true),
    )
    .addStringOption(option =>
      option.setName("place_id")
        .setDescription("Roblox place ID")
        .setRequired(true),
    )
    .addStringOption(option =>
      option.setName("job_id")
        .setDescription("Roblox server job ID")
        .setRequired(false),
    ),
];

async function registerCommands() {
  const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

  await rest.put(
    Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID),
    { body: commands.map(command => command.toJSON()) },
  );

  console.log("Discord slash commands registered.");
}

// ---------- Whitelist database helpers ----------

async function refreshWhitelist(robloxId) {
  const id = String(robloxId || "");

  if (!validRobloxId(id)) {
    throw new Error("Invalid Roblox user ID.");
  }

  const result = await pool.query(
    `SELECT
       COALESCE(BOOL_OR(lifetime), FALSE) AS has_lifetime,
       MAX(expires_at) AS latest_expiry
     FROM access_grants
     WHERE roblox_id = $1
       AND revoked_at IS NULL
       AND (lifetime = TRUE OR expires_at > NOW())`,
    [id],
  );

  const row = result.rows[0];
  const hasLifetime = row.has_lifetime === true;
  const latestExpiry = row.latest_expiry || null;

  if (!hasLifetime && !latestExpiry) {
    await pool.query(
      "DELETE FROM whitelist WHERE roblox_id = $1",
      [id],
    );
    return null;
  }

  const expiresAt = hasLifetime ? null : latestExpiry;

  await pool.query(
    `INSERT INTO whitelist (roblox_id, expires_at)
     VALUES ($1, $2)
     ON CONFLICT (roblox_id)
     DO UPDATE SET expires_at = EXCLUDED.expires_at`,
    [id, expiresAt],
  );

  return { robloxId: id, expiresAt };
}

async function getLinkedAccount(discordId) {
  const result = await pool.query(
    `SELECT discord_id, roblox_id, roblox_username, linked_at
     FROM links
     WHERE discord_id = $1`,
    [String(discordId)],
  );

  return result.rows[0] || null;
}

async function getKeyRecord(plainKey) {
  const keyHash = hashKey(plainKey);

  const blacklistResult = await pool.query(
    "SELECT 1 FROM key_blacklist WHERE key_hash = $1",
    [keyHash],
  );

  if (blacklistResult.rowCount > 0) {
    return { blacklisted: true, keyHash };
  }

  const result = await pool.query(
    `SELECT key_hash, duration_hours, redeemed_by, expires_at,
            lifetime, inventory_type, inventory_status, inventory_note
     FROM keys
     WHERE key_hash = $1`,
    [keyHash],
  );

  if (result.rowCount === 0) {
    return { notFound: true, keyHash };
  }

  return { ...result.rows[0], keyHash };
}

async function createKeyRecord(durationName, inventoryType = null) {
  const duration = durationFor(durationName);

  if (!duration) {
    throw new Error("Unsupported key duration.");
  }

  for (let attempt = 0; attempt < 5; attempt++) {
    const plainKey = generateKey();
    const keyHash = hashKey(plainKey);

    try {
      await pool.query(
        `INSERT INTO keys (
           key_hash, duration_hours, lifetime,
           inventory_type, inventory_status
         )
         VALUES ($1, $2, $3, $4, 'active')`,
        [
          keyHash,
          duration.hours,
          duration.lifetime,
          inventoryType,
        ],
      );

      return plainKey;
    } catch (error) {
      if (error.code !== "23505") {
        throw error;
      }
    }
  }

  throw new Error("Unable to generate a unique key.");
}

async function grantAccess({
  keyHash,
  discordId,
  robloxId,
  durationHours,
  lifetime,
}) {
  const id = String(robloxId || "");

  if (!validRobloxId(id) || !validDiscordId(discordId)) {
    throw new Error("Invalid Discord or Roblox ID.");
  }

  if (
    !lifetime &&
    (!Number.isFinite(Number(durationHours)) ||
      Number(durationHours) <= 0)
  ) {
    throw new Error("Invalid access duration.");
  }

  const expiresAt = lifetime
    ? null
    : new Date(
        Date.now() + Number(durationHours) * 60 * 60 * 1000,
      );

  await pool.query(
    `INSERT INTO access_grants (
       key_hash, discord_id, roblox_id, expires_at, lifetime
     )
     VALUES ($1, $2, $3, $4, $5)`,
    [
      keyHash,
      String(discordId),
      id,
      expiresAt,
      Boolean(lifetime),
    ],
  );

  await refreshWhitelist(id);

  return expiresAt;
}

// ---------- /link command handlers ----------

async function handleLinkCommand(interaction) {
  const discordId = interaction.user.id;
  const existing = await getLinkedAccount(discordId);

  if (existing) {
    return interaction.reply({
      content: `Your Discord account is already linked to Roblox **${existing.roblox_username}**.`,
      ephemeral: true,
    });
  }

  const code = generateLinkCode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await pool.query(
    `INSERT INTO link_codes (discord_id, code, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (discord_id)
     DO UPDATE SET
       code = EXCLUDED.code,
       expires_at = EXCLUDED.expires_at`,
    [discordId, code, expiresAt],
  );

  return interaction.reply({
    content:
      "**Link your Roblox account**\n\n" +
      "1. Open your Roblox profile.\n" +
      "2. Add this code to your profile description:\n" +
      `\`${code}\`\n` +
      "3. Save your Roblox profile.\n" +
      "4. Run `/linkconfirm` here.\n\n" +
      "The code expires in 10 minutes.",
    ephemeral: true,
  });
}

async function handleLinkConfirm(interaction) {
  const discordId = interaction.user.id;

  const result = await pool.query(
    `SELECT code, expires_at
     FROM link_codes
     WHERE discord_id = $1`,
    [discordId],
  );

  if (!result.rowCount) {
    return interaction.reply({
      content: "You don't have a linking code. Run `/link` first.",
      ephemeral: true,
    });
  }

  const linkCode = result.rows[0];

  if (new Date(linkCode.expires_at).getTime() <= Date.now()) {
    await pool.query(
      "DELETE FROM link_codes WHERE discord_id = $1",
      [discordId],
    );

    return interaction.reply({
      content: "Your code expired. Run `/link` to generate a new one.",
      ephemeral: true,
    });
  }

  return interaction.reply({
    content:
      "Your code is still pending. This bot needs a trusted Roblox-profile " +
      "verification service before it can safely confirm ownership. " +
      "Your account has **not** been linked yet.",
    ephemeral: true,
  });
}

// ---------- Buyer role ----------

async function handleGetRole(interaction) {
  const member = interaction.member;

  if (!member || !member.roles?.cache) {
    return interaction.reply({
      content: "I couldn't read your server roles.",
      ephemeral: true,
    });
  }

  if (member.roles.cache.has(BUYER_ROLE_ID)) {
    return interaction.reply({
      content: "You already have the buyer role.",
      ephemeral: true,
    });
  }

  try {
    await member.roles.add(BUYER_ROLE_ID);

    return interaction.reply({
      content: "The buyer role has been granted.",
      ephemeral: true,
    });
  } catch (error) {
    console.error("Could not grant buyer role:", error);

    return interaction.reply({
      content: "I couldn't grant the role. Check my role position and permissions.",
      ephemeral: true,
    });
  }
}

// ---------- Whitelist status ----------

async function handleWhitelistStatus(interaction) {
  const linked = await getLinkedAccount(interaction.user.id);

  if (!linked) {
    return interaction.reply({
      content: "Link your Roblox account first with `/link`.",
      ephemeral: true,
    });
  }

  await refreshWhitelist(linked.roblox_id);

  const result = await pool.query(
    `SELECT expires_at
     FROM whitelist
     WHERE roblox_id = $1`,
    [linked.roblox_id],
  );

  if (!result.rowCount) {
    return interaction.reply({
      content: `**${linked.roblox_username}** does not currently have whitelist access.`,
      ephemeral: true,
    });
  }

  const expiresAt = result.rows[0].expires_at;

  return interaction.reply({
    content: expiresAt
      ? `Whitelist access for **${linked.roblox_username}** expires <t:${Math.floor(new Date(expiresAt).getTime() / 1000)}:F>.`
      : `**${linked.roblox_username}** has lifetime whitelist access.`,
    ephemeral: true,
  });
}

// ---------- Redeem a key ----------

async function handleRedeem(interaction) {
  const plainKey = normalizeKey(
    interaction.options.getString("key", true),
  );

  const linked = await getLinkedAccount(interaction.user.id);

  if (!linked) {
    return interaction.reply({
      content: "Link your Roblox account before redeeming a key.",
      ephemeral: true,
    });
  }

  const key = await getKeyRecord(plainKey);

  if (key.blacklisted) {
    return interaction.reply({
      content: "That key has been revoked.",
      ephemeral: true,
    });
  }

  if (key.notFound) {
    return interaction.reply({
      content: "That key is invalid.",
      ephemeral: true,
    });
  }

  const dbClient = await pool.connect();

  try {
    await dbClient.query("BEGIN");

    const lockedResult = await dbClient.query(
      `SELECT key_hash, duration_hours, redeemed_by,
              lifetime, inventory_status
       FROM keys
       WHERE key_hash = $1
       FOR UPDATE`,
      [key.keyHash],
    );

    if (!lockedResult.rowCount) {
      await dbClient.query("ROLLBACK");

      return interaction.reply({
        content: "That key is invalid.",
        ephemeral: true,
      });
    }

    const lockedKey = lockedResult.rows[0];

    const blacklistResult = await dbClient.query(
      "SELECT 1 FROM key_blacklist WHERE key_hash = $1",
      [key.keyHash],
    );

    if (
      blacklistResult.rowCount ||
      lockedKey.inventory_status === "revoked"
    ) {
      await dbClient.query("ROLLBACK");

      return interaction.reply({
        content: "That key has been revoked.",
        ephemeral: true,
      });
    }

    if (lockedKey.redeemed_by) {
      await dbClient.query("ROLLBACK");

      return interaction.reply({
        content: "That key has already been redeemed.",
        ephemeral: true,
      });
    }

    const durationHours = Number(lockedKey.duration_hours);

    if (
      !lockedKey.lifetime &&
      (!Number.isFinite(durationHours) || durationHours <= 0)
    ) {
      await dbClient.query("ROLLBACK");

      return interaction.reply({
        content: "This key has an invalid duration. Contact an administrator.",
        ephemeral: true,
      });
    }

    const expiresAt = lockedKey.lifetime
      ? null
      : new Date(Date.now() + durationHours * 60 * 60 * 1000);

    await dbClient.query(
      `UPDATE keys
       SET redeemed_by = $1,
           expires_at = $2,
           inventory_status = 'redeemed'
       WHERE key_hash = $3`,
      [interaction.user.id, expiresAt, key.keyHash],
    );

    await dbClient.query(
      `INSERT INTO access_grants (
         key_hash, discord_id, roblox_id, expires_at, lifetime
       )
       VALUES ($1, $2, $3, $4, $5)`,
      [
        key.keyHash,
        interaction.user.id,
        linked.roblox_id,
        expiresAt,
        Boolean(lockedKey.lifetime),
      ],
    );

    await dbClient.query("COMMIT");

    await refreshWhitelist(linked.roblox_id);

    await logRedemption({
      discordId: interaction.user.id,
      robloxId: linked.roblox_id,
      robloxUsername: linked.roblox_username,
      duration: lockedKey.lifetime
        ? "Lifetime"
        : `${durationHours} hours`,
      expiresAt,
    });

    return interaction.reply({
      content: lockedKey.lifetime
        ? `Success! **${linked.roblox_username}** now has lifetime whitelist access.`
        : `Success! **${linked.roblox_username}** has access until <t:${Math.floor(expiresAt.getTime() / 1000)}:F>.`,
      ephemeral: true,
    });
  } catch (error) {
    try {
      await dbClient.query("ROLLBACK");
    } catch {
      // The transaction may already have been rolled back.
    }

    console.error("Key redemption error:", error);

    if (!interaction.replied && !interaction.deferred) {
      return interaction.reply({
        content: "Redemption failed because of a server error. Try again later.",
        ephemeral: true,
      });
    }
  } finally {
    dbClient.release();
  }
}

// ---------- Create keys ----------

async function handleCreateKey(interaction) {
  if (!canCreateKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to create keys.",
      ephemeral: true,
    });
  }

  const duration = interaction.options.getString("duration", true);

  try {
    const plainKey = await createKeyRecord(duration);

    return interaction.reply({
      content: `Created a **${duration}** key:\n\`${plainKey}\`\nKeep it private; it won't be shown again.`,
      ephemeral: true,
    });
  } catch (error) {
    console.error("Create key error:", error);

    return interaction.reply({
      content: "Couldn't create the key. Check the server logs.",
      ephemeral: true,
    });
  }
}

// ---------- Key inventory ----------

async function handleInventory(interaction) {
  if (!canManageKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to manage inventory.",
      ephemeral: true,
    });
  }

  const subcommand = interaction.options.getSubcommand();

  if (subcommand === "add") {
    const duration = interaction.options.getString("duration", true);
    const amount = interaction.options.getInteger("amount", true);
    const createdKeys = [];

    try {
      for (let i = 0; i < amount; i++) {
        createdKeys.push(
          await createKeyRecord(duration, "inventory"),
        );
      }

      return interaction.reply({
        content:
          `Created ${createdKeys.length} inventory keys (${duration}).\n` +
          "Save these securely; they are displayed only once.\n" +
          "```text\n" +
          createdKeys.join("\n") +
          "\n```",
        ephemeral: true,
      });
    } catch (error) {
      console.error("Inventory creation error:", error);

      return interaction.reply({
        content: "Inventory creation failed. Check the server logs.",
        ephemeral: true,
      });
    }
  }

  if (subcommand === "list") {
    const result = await pool.query(
      `SELECT inventory_status, COUNT(*)::int AS count
       FROM keys
       WHERE inventory_type = 'inventory'
       GROUP BY inventory_status
       ORDER BY inventory_status`,
    );

    const summary = result.rows.length
      ? result.rows
          .map(row => `${row.inventory_status}: ${row.count}`)
          .join("\n")
      : "No inventory keys found.";

    return interaction.reply({
      content: `**Inventory counts**\n${summary}`,
      ephemeral: true,
    });
  }
}

// ---------- Blacklist and revoke a key ----------

async function handleBlacklistKey(interaction) {
  if (!canManageKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to blacklist keys.",
      ephemeral: true,
    });
  }

  const plainKey = normalizeKey(
    interaction.options.getString("key", true),
  );

  const reason = (
    interaction.options.getString("reason") ||
    "No reason provided"
  ).slice(0, 500);

  const keyHash = hashKey(plainKey);
  const dbClient = await pool.connect();

  try {
    await dbClient.query("BEGIN");

    await dbClient.query(
      `INSERT INTO key_blacklist (key_hash, reason, blacklisted_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (key_hash)
       DO UPDATE SET
         reason = EXCLUDED.reason,
         blacklisted_by = EXCLUDED.blacklisted_by`,
      [keyHash, reason, interaction.user.id],
    );

    await dbClient.query(
      `UPDATE keys
       SET inventory_status = 'revoked'
       WHERE key_hash = $1`,
      [keyHash],
    );

    await dbClient.query(
      `UPDATE access_grants
       SET revoked_at = NOW()
       WHERE key_hash = $1 AND revoked_at IS NULL`,
      [keyHash],
    );

    const affected = await dbClient.query(
      `SELECT DISTINCT roblox_id
       FROM access_grants
       WHERE key_hash = $1`,
      [keyHash],
    );

    await dbClient.query("COMMIT");

    for (const row of affected.rows) {
      await refreshWhitelist(row.roblox_id);
    }

    return interaction.reply({
      content: "The key has been blacklisted and its access revoked.",
      ephemeral: true,
    });
  } catch (error) {
    try {
      await dbClient.query("ROLLBACK");
    } catch {
      // The transaction may already have ended.
    }

    console.error("Blacklist key error:", error);

    return interaction.reply({
      content: "Couldn't blacklist the key. Check the server logs.",
      ephemeral: true,
    });
  } finally {
    dbClient.release();
  }
}

// ---------- Admin: grant whitelist access ----------

async function handleWhitelistUser(interaction) {
  if (!canManageKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to grant whitelist access.",
      ephemeral: true,
    });
  }

  const username = interaction.options.getString("username", true);
  const durationName = interaction.options.getString("duration", true);
  const duration = durationFor(durationName);

  if (!duration) {
    return interaction.reply({
      content: "Invalid duration.",
      ephemeral: true,
    });
  }

  try {
    const profile = await getRobloxProfileByUsername(username);

    if (!profile) {
      return interaction.reply({
        content: "Roblox username not found.",
        ephemeral: true,
      });
    }

    const expiresAt = duration.lifetime
      ? null
      : new Date(Date.now() + duration.hours * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO access_grants
         (key_hash, discord_id, roblox_id, expires_at, lifetime)
       VALUES (NULL, $1, $2, $3, $4)`,
      [
        interaction.user.id,
        profile.id,
        expiresAt,
        duration.lifetime,
      ],
    );

    await refreshWhitelist(profile.id);

    return interaction.reply({
      content: duration.lifetime
        ? `Granted lifetime whitelist access to **${profile.name}**.`
        : `Granted whitelist access to **${profile.name}** until <t:${Math.floor(expiresAt.getTime() / 1000)}:F>.`,
      ephemeral: true,
    });
  } catch (error) {
    console.error("Manual whitelist grant failed:", error);

    return interaction.reply({
      content: "Couldn't grant whitelist access. Check the server logs.",
      ephemeral: true,
    });
  }
}

// ---------- Admin: extend whitelist access ----------

async function handleExtendKey(interaction) {
  if (!canManageKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to extend access.",
      ephemeral: true,
    });
  }

  const username = interaction.options.getString("username", true);
  const durationName = interaction.options.getString("duration", true);
  const duration = durationFor(durationName);

  if (!duration || duration.lifetime) {
    return interaction.reply({
      content: "Choose a valid extension duration.",
      ephemeral: true,
    });
  }

  try {
    const profile = await getRobloxProfileByUsername(username);

    if (!profile) {
      return interaction.reply({
        content: "Roblox username not found.",
        ephemeral: true,
      });
    }

    const existing = await pool.query(
      `SELECT
         COALESCE(BOOL_OR(lifetime), FALSE) AS has_lifetime,
         MAX(expires_at) AS latest_expiry
       FROM access_grants
       WHERE roblox_id = $1
         AND revoked_at IS NULL
         AND (lifetime = TRUE OR expires_at > NOW())`,
      [profile.id],
    );

    const row = existing.rows[0];

    if (row.has_lifetime) {
      return interaction.reply({
        content: `**${profile.name}** already has lifetime access.`,
        ephemeral: true,
      });
    }

    if (!row.latest_expiry) {
      return interaction.reply({
        content: `**${profile.name}** has no active access to extend. Use \`/whitelistuser\` instead.`,
        ephemeral: true,
      });
    }

    const expiresAt = new Date(
      new Date(row.latest_expiry).getTime() +
      duration.hours * 60 * 60 * 1000,
    );

    await pool.query(
      `UPDATE access_grants
       SET expires_at = $1
       WHERE roblox_id = $2
         AND revoked_at IS NULL
         AND lifetime = FALSE
         AND expires_at > NOW()`,
      [expiresAt, profile.id],
    );

    await refreshWhitelist(profile.id);

    return interaction.reply({
      content: `Extended **${profile.name}**'s access until <t:${Math.floor(expiresAt.getTime() / 1000)}:F>.`,
      ephemeral: true,
    });
  } catch (error) {
    console.error("Access extension failed:", error);

    return interaction.reply({
      content: "Couldn't extend access. Check the server logs.",
      ephemeral: true,
    });
  }
}

// ---------- Teleport logging slash command ----------

async function handleTeleportLog(interaction) {
  if (!canManageKeys(interaction.member)) {
    return interaction.reply({
      content: "You don't have permission to use this command.",
      ephemeral: true,
    });
  }

  const username = interaction.options.getString("roblox_username", true);
  const placeId = interaction.options.getString("place_id", true);
  const jobId = interaction.options.getString("job_id") || "";

  if (!/^\d{1,30}$/.test(placeId)) {
    return interaction.reply({
      content: "The place ID must contain digits only.",
      ephemeral: true,
    });
  }

  if (jobId.length > 100) {
    return interaction.reply({
      content: "The job ID is too long.",
      ephemeral: true,
    });
  }

  try {
    const profile = await getRobloxProfileByUsername(username);

    if (!profile) {
      return interaction.reply({
        content: "Roblox username not found.",
        ephemeral: true,
      });
    }

    await logTeleport({
      discordId: interaction.user.id,
      robloxId: profile.id,
      robloxUsername: profile.name,
      placeId,
      jobId,
    });

    return interaction.reply({
      content: `Teleport log submitted for **${profile.name}**.`,
      ephemeral: true,
    });
  } catch (error) {
    console.error("Teleport logging failed:", error);

    return interaction.reply({
      content: "Couldn't submit the teleport log.",
      ephemeral: true,
    });
  }
}

// ---------- Express API ----------

app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "whitelist-bot",
  });
});

// Trusted server-to-server integrations only.
// Never expose SHARED_SECRET in a browser or Roblox client script.
app.post("/api/teleport", (req, res, next) => {
  const secret = req.get("x-teleport-secret");

  if (
    !TELEPORT_SHARED_SECRET ||
    !secret ||
    !safeEqual(secret, TELEPORT_SHARED_SECRET)
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return next();
}, async (req, res) => {
  try {
    const { robloxId, placeId, jobId, discordId } = req.body || {};

    if (
      !validRobloxId(robloxId) ||
      !/^\d{1,30}$/.test(String(placeId || "")) ||
      (discordId && !validDiscordId(discordId))
    ) {
      return res.status(400).json({
        error: "Invalid teleport data",
      });
    }

    const profile = await getRobloxProfile(robloxId);

    await logTeleport({
      discordId: discordId || "Unknown",
      robloxId: String(robloxId),
      robloxUsername: profile.name,
      placeId: String(placeId),
      jobId: String(jobId || ""),
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Teleport API error:", error);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

// ---------- Discord interaction routing ----------

client.on("interactionCreate", async interaction => {
  if (!interaction.isChatInputCommand()) return;

  try {
    switch (interaction.commandName) {
      case "link":
        await handleLinkCommand(interaction);
        break;

      case "linkconfirm":
        await handleLinkConfirm(interaction);
        break;

      case "get_role":
        await handleGetRole(interaction);
        break;

      case "verify":
      case "redeem":
        await handleRedeem(interaction);
        break;

      case "whitelist":
        await handleWhitelistStatus(interaction);
        break;

      case "whitelistuser":
        await handleWhitelistUser(interaction);
        break;

      case "createkey":
        await handleCreateKey(interaction);
        break;

      case "blacklistkey":
        await handleBlacklistKey(interaction);
        break;

      case "extendkey":
        await handleExtendKey(interaction);
        break;

      case "inventory":
        await handleInventory(interaction);
        break;

      case "teleport-log":
        await handleTeleportLog(interaction);
        break;

      default:
        await interaction.reply({
          content: "Unknown command.",
          ephemeral: true,
        });
    }
  } catch (error) {
    console.error(
      `Command /${interaction.commandName} failed:`,
      error,
    );

    try {
      const reply = {
        content: "Something went wrong. Check the server logs.",
        ephemeral: true,
      };

      if (interaction.replied || interaction.deferred) {
        await interaction.followUp(reply);
      } else {
        await interaction.reply(reply);
      }
    } catch (replyError) {
      console.error("Could not send error response:", replyError);
    }
  }
});

// ---------- Startup and shutdown ----------

let httpServer;

async function start() {
  await setupDatabase();
  await registerCommands();
  await client.login(DISCORD_TOKEN);

  httpServer = app.listen(PORT, "0.0.0.0", () => {
    console.log(`HTTP server listening on port ${PORT}`);
  });

  console.log(`Discord bot logged in as ${client.user.tag}`);
}

async function shutdown(signal) {
  console.log(`Received ${signal}; shutting down...`);

  if (httpServer) {
    await new Promise(resolve => httpServer.close(resolve));
  }

  if (client.isReady()) {
    client.destroy();
  }

  await pool.end();
  process.exit(0);
}

process.once("SIGTERM", () => {
  shutdown("SIGTERM").catch(error => {
    console.error("Shutdown error:", error);
    process.exit(1);
  });
});

process.once("SIGINT", () => {
  shutdown("SIGINT").catch(error => {
    console.error("Shutdown error:", error);
    process.exit(1);
  });
});

start().catch(error => {
  console.error("Fatal startup error:", error);
  process.exit(1);
});
