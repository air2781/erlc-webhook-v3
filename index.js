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
        if (!channel) return;

        await channel.send(content);
    } catch (err) {
        console.error(err);
    }
}

// server
const server = http.createServer((req, res) => {

    if (req.method === "POST") {

        let chunks = [];

        req.on("data", chunk => chunks.push(chunk));

        req.on("end", async () => {
            const body = Buffer.concat(chunks);

            // respond instantly (IMPORTANT)
            res.writeHead(200);
            res.end("OK");

            try {
                const signature = req.headers["x-signature-ed25519"];
                const timestamp = req.headers["x-signature-timestamp"];

                if (signature && timestamp) {
                    const valid = verifyPRPSignature(signature, timestamp, body);

                    if (!valid) {
                        console.log("Invalid signature (ignored)");
                        return;
                    }
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

// render port
const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// discord
client.once("ready", () => {
    console.log(`Bot ready as ${client.user.tag}`);
});

client.login(bot.token);
