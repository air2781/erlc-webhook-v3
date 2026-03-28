const { bot } = require("./config.js");
const http = require("http");
const nacl = require("tweetnacl");

const PORT = bot.port;
const PUBLIC_KEY = Buffer.from(bot.prpPublicKey, "hex");

function verifyPRPSignature(signature, timestamp, body) {
    const sig = Buffer.from(signature, "hex");
    const message = Buffer.concat([Buffer.from(timestamp, "utf8"), body]);
    return nacl.sign.detached.verify(message, sig, PUBLIC_KEY);
}

const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/event-webhook") {
        let chunks = [];
        req.on("data", chunk => chunks.push(chunk));
        req.on("end", () => {
            const body = Buffer.concat(chunks);
            const signature = req.headers["x-signature-ed25519"];
            const timestamp = req.headers["x-signature-timestamp"];

            if (!verifyPRPSignature(signature, timestamp, body)) {
                res.writeHead(401);
                return res.end("Invalid signature");
            }

            const payload = JSON.parse(body.toString());
            console.log("PRP Webhook payload:", payload);

            // Example: log modcalls only
            if (payload.type === "modcall") {
                console.log("Modcall event:", payload);
            }

            res.writeHead(200);
            res.end("OK");
        });
    } else {
        res.writeHead(404);
        res.end("Not found");
    }
});

server.listen(PORT, () => console.log(`Webhook server listening on port ${PORT}`));
