const { bot } = require("./Config.js");
const http = require("http");
const { Client, GatewayIntentBits } = require("discord.js");
const nacl = require("tweetnacl");

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// PRP key (HEX)
const PUBLIC_KEY = Buffer.from(bot.prpPublicKey, "hex");

// verify
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

// log
async function logToDiscord(content) {
    try {
        const channel = await client.channels.fetch(bot.discordEmbedChannelId);
        if (channel) await channel.send(content);
    } catch (err) {
        console.error(err);
    }
}

// server
const server = http.createServer((req, res) => {

    if (req.method === "POST") {

        // ✅ RESPOND INSTANTLY (BEFORE READING BODY)
        res.writeHead(200);
        res.end("OK");

        let chunks = [];

        req.on("data", chunk => chunks.push(chunk));

        req.on("end", async () => {
            try {
                const body = Buffer.concat(chunks);

                const signature = req.headers["x-signature-ed25519"];
                const timestamp = req.headers["x-signature-timestamp"];

                // DEBUG
                console.log("Headers:", {
                    sig: !!signature,
                    time: !!timestamp
                });

                // ✅ ONLY VERIFY IF PRESENT
                if (signature && timestamp) {
                    const valid = verifyPRPSignature(signature, timestamp, body);

                    if (!valid) {
                        console.log("❌ Invalid signature");
                        return;
                    }
                } else {
                    console.log("⚠️ No signature (PRP test)");
                }

                const payload = JSON.parse(body.toString());
                console.log("Payload:", payload);

                let command = null;
                let username = "Unknown";

                if (payload.content) {
                    command = payload.content;
                    username = payload.user?.username || username;
                } else if (payload.data?.command) {
                    command = payload.data.command;
                    username = payload.data.username || username;
                }

                if (command && command.startsWith(";")) {
                    await logToDiscord(
`User: ${username}
Command: ${command}`
                    );
                }

            } catch (err) {
                console.error("Webhook error:", err);
            }
        });

    } else {
        res.writeHead(200);
        res.end("OK");
    }
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

client.once("ready", () => {
    console.log(`Bot ready as ${client.user.tag}`);
});

client.login(bot.token);
