const { bot } = require("./Config.js"); // adjust path if needed
const http = require("http");
const { Client, GatewayIntentBits } = require("discord.js");
const nacl = require("tweetnacl");

// Discord client
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// ✅ PRP public key is HEX (NOT base64)
const PUBLIC_KEY = Buffer.from(bot.prpPublicKey, "hex");

// ---------------- VERIFY SIGNATURE ----------------
function verifyPRPSignature(signature, timestamp, body) {
    try {
        if (!signature || !timestamp) return false;

        const sig = Buffer.from(signature, "hex");
        const msg = Buffer.concat([
            Buffer.from(timestamp, "utf8"),
            body
        ]);

        return nacl.sign.detached.verify(msg, sig, PUBLIC_KEY);
    } catch {
        return false;
    }
}

// ---------------- LOG TO DISCORD ----------------
async function logToDiscord(content) {
    try {
        const channel = await client.channels.fetch(bot.discordEmbedChannelId);
        if (!channel) return console.log("Channel not found");

        await channel.send(content);
    } catch (err) {
        console.error("Discord log error:", err);
    }
}

// ---------------- WEBHOOK SERVER ----------------
const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/event-webhook") {
        let chunks = [];

        req.on("data", chunk => chunks.push(chunk));

        req.on("end", () => {
            const body = Buffer.concat(chunks);

            // ✅ ALWAYS RESPOND IMMEDIATELY (required by PRP)
            res.writeHead(200);
            res.end("OK");

            (async () => {
                try {
                    const signature = req.headers["x-signature-ed25519"];
                    const timestamp = req.headers["x-signature-timestamp"];

                    // ✅ STRICT SIGNATURE CHECK
                    if (!verifyPRPSignature(signature, timestamp, body)) {
                        console.log("❌ Invalid signature - request ignored");
                        return;
                    }

                    const payload = JSON.parse(body.toString());
                    console.log("Incoming payload:", payload);

                    let command = null;
                    let username = "Unknown User";

                    if (payload.content) {
                        command = payload.content;
                        username = payload.user?.username || username;
                    } else if (payload.data?.command) {
                        command = payload.data.command;
                        username = payload.data.username || username;
                    }

                    if (command && command.startsWith(";")) {
                        const logMessage =
`User: ${username}
Command: ${command}`;

                        await logToDiscord(logMessage);
                        console.log(`Logged: ${username} -> ${command}`);
                    }

                } catch (err) {
                    console.error("Webhook error:", err);
                }
            })();
        });

    } else {
        // ✅ prevent 404 (PRP requires valid response)
        res.writeHead(200);
        res.end("OK");
    }
});

// ---------------- START SERVER ----------------
server.listen(bot.port, () => {
    console.log(`Webhook server listening on port ${bot.port}`);
});

// ---------------- DISCORD READY ----------------
client.once("ready", () => {
    console.log(`Discord bot ready as ${client.user.tag}`);
});

// ---------------- LOGIN ----------------
client.login(bot.token);
