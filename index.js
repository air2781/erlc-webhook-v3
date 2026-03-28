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

// Webhook server
const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/event-webhook") {
        let chunks = [];
        req.on("data", chunk => chunks.push(chunk));
        req.on("end", async () => {
            const body = Buffer.concat(chunks);
            const signature = req.headers["x-signature-ed25519"];
            const timestamp = req.headers["x-signature-timestamp"];

            // Verify signature
            if (!verifyPRPSignature(signature, timestamp, body)) {
                res.writeHead(401);
                return res.end("Invalid signature");
            }

            const payload = JSON.parse(body.toString());

            // Only log commands starting with ";"
            if (payload.content && payload.content.startsWith(";")) {
                const logMessage = `User: ${payload.user.username}\nCommand: ${payload.content}`;
                await logToDiscord(logMessage);
            }

            res.writeHead(200);
            res.end("OK");
        });
    } else {
        res.writeHead(404);
        res.end("Not found");
    }
});

// Start webhook server
server.listen(bot.port, () => console.log(`Webhook server listening on port ${bot.port}`));

// Discord bot ready
client.once("ready", () => {
    console.log(`Discord bot ready as ${client.user.tag}`);
});

// Login Discord bot
client.login(bot.token);
