
const fs = require("fs");
const crypto = require("crypto");
const { Pool } = require("pg");

const revokedKeys = new Set([
  "KEY-G55SF6JXDAV3",
  "KEY-ZHTL3CMBRYEB",
]);

const categories = {
  "1 HOUR": { type: "1hour", hours: 1, lifetime: false },
  "1 DAY": { type: "1day", hours: 24, lifetime: false },
  "1 WEEK": { type: "1week", hours: 168, lifetime: false },
  "1 MONTH": { type: "1month", hours: 720, lifetime: false },
  LIFETIME: { type: "lifetime", hours: 0, lifetime: true },
};

const hashKey = key =>
  crypto.createHash("sha256").update(key).digest("hex");

async function main() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is missing.");
  }

  const text = fs.readFileSync("codes.txt", "utf8");
  const lines = text.split(/\r?\n/);

  let category = null;
  const imported = [];
  const seen = new Set();

  for (const line of lines) {
    const heading = line.match(
      /={3,}\s*(1 HOUR|1 DAY|1 WEEK|1 MONTH|LIFETIME)\s*\(\s*100\s*\)\s*={3,}/i
    );

    if (heading) {
      category = categories[heading[1].toUpperCase()];
      continue;
    }

    const match = line.match(/\b(KEY-[A-Z0-9]+)\b/i);

    if (!match || !category) continue;

    const key = match[1].toUpperCase();

    if (seen.has(key)) {
      throw new Error("Duplicate key found. Import cancelled.");
    }

    seen.add(key);
    imported.push({
      key,
      type: category.type,
      hours: category.hours,
      lifetime: category.lifetime,
      revoked: revokedKeys.has(key),
    });
  }

  for (const [label, config] of Object.entries(categories)) {
    const count = imported.filter(
      item => item.type === config.type
    ).length;

    if (count !== 100) {
      throw new Error(
        `${label}: expected 100 keys, found ${count}. Import cancelled.`
      );
    }
  }

  if (imported.length !== 500) {
    throw new Error(
      `Expected 500 unique keys, found ${imported.length}. Import cancelled.`
    );
  }

  for (const key of revokedKeys) {
    const item = imported.find(entry => entry.key === key);

    if (!item || item.type !== "1week") {
      throw new Error(
        "A pre-revoked key is missing from the 1 WEEK category."
      );
    }
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : undefined,
  });

  const db = await pool.connect();

  try {
    await db.query("BEGIN");

    const hashes = imported.map(item => hashKey(item.key));

    const existing = await db.query(
      `SELECT key_hash, inventory_type, inventory_status,
              redeemed_by, lifetime, duration_hours
       FROM keys
       WHERE key_hash = ANY($1::text[])`,
      [hashes]
    );

    if (existing.rowCount > 0) {
      const existingByHash = new Map(
        existing.rows.map(row => [row.key_hash, row])
      );

      const allAlreadyImported = imported.every(item => {
        const row = existingByHash.get(hashKey(item.key));

        return row &&
          row.inventory_type === item.type &&
          Number(row.duration_hours) === item.hours &&
          row.lifetime === item.lifetime &&
          (item.revoked
            ? row.inventory_status === "revoked"
            : true);
      });

      if (!allAlreadyImported) {
        throw new Error(
          "Some keys already exist with different or incomplete inventory data. Nothing was imported."
        );
      }

      console.log("All 500 keys are already imported correctly.");
    } else {
      for (const item of imported) {
        const keyHash = hashKey(item.key);

        await db.query(
          `INSERT INTO keys
             (key_hash, duration_hours, lifetime,
              inventory_type, inventory_status,
              inventory_note, redeemed_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            keyHash,
            item.hours,
            item.lifetime,
            item.type,
            item.revoked ? "revoked" : "active",
            item.revoked ? "Pre-revoked inventory key" : null,
            item.revoked ? "admin:pre-revoked" : null,
          ]
        );
      }

      console.log("Imported 500 keys.");
    }

    for (const key of revokedKeys) {
      await db.query(
        `INSERT INTO key_blacklist
           (key_hash, reason, blacklisted_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (key_hash) DO NOTHING`,
        [
          hashKey(key),
          "Pre-revoked inventory key",
          "system",
        ]
      );
    }

    await db.query("COMMIT");
    console.log("Import completed successfully.");
    console.log("1 HOUR: 100 | 1 DAY: 100 | 1 WEEK: 100");
    console.log("1 MONTH: 100 | LIFETIME: 100");
    console.log("Revoked keys remain blocked.");
  } catch (error) {
    await db.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    db.release();
    await pool.end();
  }
}

main().catch(error => {
  console.error("Import failed:", error.message);
  process.exitCode = 1;
});
