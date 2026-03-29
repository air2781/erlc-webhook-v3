const { bot } = require("./Config.js"); // adjust path if needed
const http = require("http");
const { Client, GatewayIntentBits } = require("discord.js");
const nacl = require("tweetnacl");

// Discord client
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// PRP public key for signature verification
const PUBLIC_KEY = Buffer.from(bot.prpPublicKey, "base64"); // PRP gives base64 key

// Verify PRP signature
function verifyPRPSignature(signature, timestamp, body) {
    const sig = Buffer.from(signature, "hex");
    const message = Buffer.concat([Buffer.from(timestamp, "utf8"), body]);
    return nacl.sign.detached.verify(message, sig, PUBLIC_KEY);
}

// Log to Discord channel
async function logToDiscord(content) {
    const channel = await client.channels.fetch(bot.discordEmbedChannelId);
    if (!channel) return console.log("Channel not found");
    channel.send(content).catch(console.error);
}

const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/event-webhook") {
        let chunks = [];

        req.on("data", chunk => chunks.push(chunk));

        req.on("end", () => {
            const body = Buffer.concat(chunks);

            // ✅ RESPOND IMMEDIATELY (THIS FIXES PRP SAVING)
            res.writeHead(200);
            res.end("OK");

            // Everything below runs AFTER response
            (async () => {
                try {
                    const signature = req.headers["x-signature-ed25519"];
                    const timestamp = req.headers["x-signature-timestamp"];

                    // Optional verification (non-blocking)
                    if (signature && timestamp) {
                        const valid = verifyPRPSignature(signature, timestamp, body);
                        if (!valid) {
                            console.log("Invalid signature (ignored)");
                        }
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
                        const logMessage = `User: ${username}\nCommand: ${command}`;
                        await logToDiscord(logMessage);
                        console.log(`Logged: ${username} -> ${command}`);
                    }

                } catch (err) {
                    console.error("Webhook error:", err);
                }
            })();
        });

    } else {
        res.writeHead(200); // also important: don't 404 root
        res.end("OK");
    }
});

server.listen(bot.port, () => {
    console.log(`Webhook server listening on port ${bot.port}`);
});

// Discord bot ready
client.once("ready", () => {
    console.log(`Discord bot ready as ${client.user.tag}`);
});

// Login Discord bot
client.login(bot.token);
