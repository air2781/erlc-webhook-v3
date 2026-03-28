const { bot } = require("./Config.js");
const { Client, GatewayIntentBits, ChannelType } = require("discord.js");
const http = require("http");
const nacl = require("tweetnacl");

// ------------------- Discord Client -------------------
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once("ready", () => {
    console.log(`Discord client logged in as ${client.user.tag}`);
});

client.login(process.env.BOT_TOKEN);

// ------------------- PRP Webhook Server -------------------
const PORT = bot.port;
const PUBLIC_KEY = Buffer.from(bot.prpPublicKey, "hex");

function verifyPRPSignature(signature, timestamp, body) {
    const sig = Buffer.from(signature, "hex");
    const message = Buffer.concat([Buffer.from(timestamp, "utf8"), body]);
    return nacl.sign.detached.verify(message, sig, PUBLIC_KEY);
}

const server = http.createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/event-webhook") {
        let chunks = [];
        req.on("data", chunk => chunks.push(chunk));
        req.on("end", async () => {
            const body = Buffer.concat(chunks);
            const signature = req.headers["x-signature-ed25519"];
            const timestamp = req.headers["x-signature-timestamp"];

            if (!verifyPRPSignature(signature, timestamp, body)) {
                res.writeHead(401);
                return res.end("Invalid signature");
            }

            const payload = JSON.parse(body.toString());

            // Log all modcalls or commands
            if (payload.type === "modcall" && payload.data?.command?.startsWith(";")) {
                const cmd = payload.data.command;
                const username = payload.data.username || "Unknown User";

                // Send to Discord channel
                const channel = await client.channels.fetch("1485452768406802524");
                if (channel && channel.type === ChannelType.GuildText) {
                    channel.send(`**Command:** ${cmd}\n**User:** ${username}`);
                }

                console.log(`Logged command from ${username}: ${cmd}`);
            }

            res.writeHead(200);
            res.end("OK");
        });
    } else {
        res.writeHead(404);
        res.end("Not found");
    }
});

server.listen(PORT, () => console.log(`PRP webhook server listening on port ${PORT}`));
