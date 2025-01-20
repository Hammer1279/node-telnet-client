const fs = require("fs");
const path = require("path");
const { createConnection } = require('net');
const { createHash, createECDH, createCipheriv, createDecipheriv, randomBytes } = require('crypto');
const { Transform } = require('stream');

// Application settings
const port = process.argv[3] || 23;
const hostname = process.argv[2] || (process.pkg ? "dom.ht-dev.de" : "localhost");
let delayMs = process.argv[4] || 100; // Command delay in milliseconds
const encryptionDelay = 200; // additional delay for encryption
const initializationDelay = 500; // additional delay for initialization

const advancedFeatures = true; // Enable advanced features

class MemoryStream extends Transform {
    constructor(options = {}) {
        super(options);
    }

    _transform(chunk, encoding, callback) {
        this.push(chunk);
        callback();
    }
}

const writer = new MemoryStream();
let initialized = false; // Initialization status, do not modify directly, runtime only
let encrypted = false; // Encryption status, do not modify directly, runtime only
let privateKey; // Private key, do not modify directly, runtime only
let keyCurve; // Key curve, do not modify directly, runtime only
let encryptionAlgorithm; // Encryption algorithm, do not modify directly, runtime only
let echdKey; // ECDH key, do not modify directly, runtime only

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const send = async (command) => {
    await delay(delayMs);
    writer.write(command); // Command
    await delay(delayMs);
    writer.write("\r\n"); // Line Feed
};

// Numeric Buffer values
const NUL = Buffer.from([0x00]); // Null
const ONE = Buffer.from([0x01]); // One

// Telnet commands
const IAC = Buffer.from([0xff]); // Interpret As Command
const DONT = Buffer.from([0xfe]); // Don't
const DO = Buffer.from([0xfd]); // Do
const WONT = Buffer.from([0xfc]); // Won't
const WILL = Buffer.from([0xfb]); // Will
const SB = Buffer.from([0xfa]); // Subnegotiation Begin
const GA = Buffer.from([0xf9]); // Go Ahead
const EL = Buffer.from([0xf8]); // Erase Line
const EC = Buffer.from([0xf7]); // Erase Character
const AYT = Buffer.from([0xf6]); // Are You There
const AO = Buffer.from([0xf5]); // Abort Output
const IP = Buffer.from([0xf4]); // Interrupt Process
const BRK = Buffer.from([0xf3]); // Break
const DM = Buffer.from([0xf2]); // Data Mark
const NOP = Buffer.from([0xf1]); // No Operation
const SE = Buffer.from([0xf0]); // Subnegotiation End

// Common Telnet options or features
const ECHO = Buffer.from([0x01]); // Echo
const SUPPRESS_GO_AHEAD = Buffer.from([0x03]); // Suppress Go Ahead
const STATUS = Buffer.from([0x05]); // Status
const TIMING_MARK = Buffer.from([0x06]); // Timing Mark
const TERMINAL_TYPE = Buffer.from([0x18]); // Terminal Type
const NAWS = Buffer.from([0x1f]); // Negotiate About Window Size
const TERMINAL_SPEED = Buffer.from([0x20]); // Terminal Speed
const REMOTE_FLOW_CONTROL = Buffer.from([0x21]); // Remote Flow Control
const LINEMODE = Buffer.from([0x22]); // Line Mode
const ENVIRONMENT_VARIABLES = Buffer.from([0x24]); // Environment Variables

// custom codes for own client
const CUSTOM_CLIENT_INIT = Buffer.from([0x80]); // Custom Client Initialization
const KEY_EXCHANGE = Buffer.from([0x81]); // Key Exchange
const ENCRYPTION = Buffer.from([0x82]); // Encryption
const AUTHENTICATION = Buffer.from([0x83]); // Authentication
// 0x84 reserved for future use
const FILE_TRANSFER = Buffer.from([0x85]); // File Transfer
const PAUSE = Buffer.from([0x86]); // Pause
const RESUME = Buffer.from([0x87]); // Resume
const START_CONTENT = Buffer.from([0x88]); // Start Content
const END_CONTENT = Buffer.from([0x89]); // End Content

// Encrypt
function encrypt(plaintext, key = privateKey, encoding = 'utf8') {
    // Generate a random IV (12 bytes recommended for GCM)
    const iv = randomBytes(12);

    // Create cipher, providing algo, key, and IV
    const cipher = createCipheriv(encryptionAlgorithm, key, iv);

    // Encrypt data
    const encrypted = Buffer.concat([cipher.update(plaintext, encoding), cipher.final()]);
    const authTag = cipher.getAuthTag(); // Integrity tag

    // Return IV + tag + ciphertext
    return Buffer.concat([iv, authTag, encrypted]);
}

// Decrypt
function decrypt(ciphertext, key = privateKey, encoding = 'utf8') {
    // Extract IV (first 12 bytes)
    const iv = ciphertext.slice(0, 12);
    
    // Extract tag (next 16 bytes)
    const tag = ciphertext.slice(12, 28);
    
    // Remainder is the actual encrypted data
    const data = ciphertext.slice(28);

    // Create decipher, set auth tag
    const decipher = createDecipheriv(encryptionAlgorithm, key, iv);
    decipher.setAuthTag(tag);

    // Decrypt data
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString(encoding);
}

//  Set the path of the project folder base on whether it is run with nodejs or as an executable
let project_folder;
if (process.pkg) {
    //  It is run as an executable
    project_folder = path.dirname(process.execPath)

} else {
    //  It is run with nodejs
    project_folder = __dirname
}

if (process.pkg) {
    console.debug = () => { }; // Disable debug logging when run as an executable
    fs.writeFileSync(path.join(project_folder, "README.md"), fs.readFileSync(path.join(__dirname, "README.md"))); // copy newest readme to folder
    fs.writeFileSync(path.join(project_folder, "LICENSE"), fs.readFileSync(path.join(__dirname, "LICENSE"))); // copy newest license to folder
}

const socket = createConnection(port, hostname);

writer.pipe(socket);

let hold = false; // Hold input
let holdBuffer = ""; // Buffer data when on hold

process.stdin.setEncoding("ascii");
process.stdin.setRawMode(true);
process.stdin.resume();

// format keys before sending to server
process.stdin.on('data', async (key) => {
    if (key === '\u0004') { // Ctrl+D
        process.exit();
    } else if (key === '\u0003') { // Ctrl+C
        send(IP); // Interrupt Process
    } else if (key === '\u0018') { // Ctrl+X
        process.stdout.write("\r");
        console.log("Entered client command mode");
        hold = true; // Hold input
        process.stdin.setRawMode(false);
        // Add any additional functionality for Ctrl+X here
    }

    // Log Unicode values of input for debugging
    // console.debug("Key pressed:", Array.from(key).map(b => '\\u' + b.toString(16).padStart(4, '0')));

    if (key == "\r") {
        // Enter key
        socket.write("\r\n");
    } else if (!hold) {
        socket.write(key);
    } else {
        // console.debug("Input on hold");
        const command = key.replace(/\r?\n|\r/g, ''); // Remove new line characters
        if (["exit", "quit"].includes(command)) {
            hold = false; // Release input
            process.stdin.setRawMode(true);
            console.log("Exited client command mode");
            process.stdout.write(holdBuffer);
            holdBuffer = "";
            process.stdout.write("> ");
        } else if (command == "disconnect") {
            send(IP); // Interrupt Process
        } else if (command == "status") {
            console.log("Client status:");
            console.log("Host:", hostname + ":" + port);
            console.log("Advanced Features unlocked:", advancedFeatures);
            console.log("Initialized:", initialized);
            console.log("Encrypted:", encrypted);
            console.log("Batch Delay:", delayMs + "ms");
            // console.log("Public Key:", key.getPublicKey() ? key.getPublicKey().toString("hex") : "null");
            // console.log("Private Key:", privateKey ? privateKey.toString("hex") : "null");
            process.stdout.write("$ ");
        } else if (command == "keyinfo") {
            console.log("Key Information:");
            console.log("Key Curve:", keyCurve);
            console.log("Encryption Algorithm:", encryptionAlgorithm);
            console.log("Public Key:", echdKey.getPublicKey() ? echdKey.getPublicKey().toString("hex") : "null");
            console.log("Private Key:", privateKey ? privateKey.toString("hex") : "null");
            process.stdout.write("$ ");
        } else if (command == "help") {
            // Add any additional functionality for client side commands
            console.log("Client commands:");
            console.log("status - Show client status");
            console.log("keyinfo - Show key information");
            console.log("disconnect - Disconnect from server");
            console.log("exit - Exit client command mode");
            process.stdout.write("$ ");
        } else {
            process.stdout.write("$ ");
        }
    }
});

socket.on("data", (data) => {
    if (!encrypted || !initialized) {
        if (data.equals(PAUSE)) {
            process.stdin.pause();
        } else if (data.equals(RESUME)) {
            process.stdin.resume();
        } else if (data.equals(IP)) {
            process.exit();
        } else if (data.includes(Buffer.concat([IAC, SB, CUSTOM_CLIENT_INIT, NUL]))) {
            const offsetBegin = data.indexOf(SB) + 2;
            const offsetEnd = data.lastIndexOf(SE) - 1;
            const algorithmData = data.subarray(offsetBegin + 1, offsetEnd);
            keyCurve = algorithmData.toString('utf8');
            echdKey = createECDH(keyCurve);
            console.debug("Using key curve:", keyCurve);
        } else if (data.equals(Buffer.concat([IAC, DO, CUSTOM_CLIENT_INIT]))) {
            // server supports custom client features
            socket.write(Buffer.concat([IAC, WILL, KEY_EXCHANGE])); // Start Key Exchange
        } else if (data.includes(Buffer.concat([IAC, DO, KEY_EXCHANGE]))) {
            // generate keys
            const publicKey = echdKey.generateKeys();
            console.debug("Generated Key: " + publicKey.toString("hex"));
        } else if (data.equals(Buffer.concat([IAC, SB, KEY_EXCHANGE, ONE /* value required */, IAC, SE]))) {
            socket.write(Buffer.concat([IAC, SB, KEY_EXCHANGE, NUL, echdKey.getPublicKey(), IAC, SE]));
            // send key to server
        } else if (data.includes(Buffer.concat([IAC, SB, KEY_EXCHANGE, NUL /* value provided */]))) {
            // server sent its key, generate secret
            console.debug("Key exchange received");
            const offsetBegin = data.indexOf(SB) + 2;
            const offsetEnd = data.lastIndexOf(SE) - 1;
            const keyData = data.subarray(offsetBegin + 1, offsetEnd); // client public key
            console.log("Extracted key:", keyData.toString("hex"));
            privateKey = echdKey.computeSecret(keyData);
            socket.write(Buffer.concat([IAC, WILL, ENCRYPTION])); // Enable Encryption
        } else if (data.includes(Buffer.concat([IAC, SB, ENCRYPTION, NUL]))) {
            const offsetBegin = data.indexOf(SB) + 2;
            const offsetEnd = data.lastIndexOf(SE) - 1;
            const algorithmData = data.subarray(offsetBegin + 1, offsetEnd);
            encryptionAlgorithm = algorithmData.toString('utf8');
            console.debug("Using encryption algorithm:", encryptionAlgorithm);
        } else if (data.equals(Buffer.concat([IAC, DO, ENCRYPTION]))) {
            // enable encryption
            encrypted = true;
            console.debug("Encryption enabled");
            console.debug("Private Key: " + privateKey.toString("hex"));
        } else if (!hold) {
            process.stdout.write(data);
        } else {
            // console.debug("Data on hold");
            holdBuffer += data.toString();
        }
    } else {
        // decrypt data
        try {
            const decryptedData = decrypt(data, privateKey);
            process.stdout.write(decryptedData);
        } catch (error) {
            console.error("Decryption error:", error);
            console.error("Data:", data.toString("hex"));
            console.debug("Algorithm:", encryptionAlgorithm);
            console.debug("Private Key:", privateKey.toString("hex"));
            console.debug("Public Key:", echdKey.getPublicKey().toString("hex"));
        }
    }
});

socket.on("connect", async () => {
    console.log("Connected to server");
    process.stdin.pause(); // Pause input

    // initialization
    const columns = process.stdout.columns || 80;
    const rows = process.stdout.rows || 24;

    // Create buffer for window size: [columns-high, columns-low, rows-high, rows-low]
    const windowSize = Buffer.from([
        (columns >> 8) & 0xFF,  // high byte of columns
        columns & 0xFF,         // low byte of columns
        (rows >> 8) & 0xFF,    // high byte of rows
        rows & 0xFF            // low byte of rows
    ]);
    socket.write(Buffer.concat([IAC, WILL, NAWS, SB, NAWS, windowSize, SE])); // Negotiate About Window Size
    await delay(delayMs); // Wait for server to process
    socket.write(Buffer.concat([IAC, WILL, TERMINAL_TYPE, IAC, SB, TERMINAL_TYPE, NUL, Buffer.from("xterm-256color"), IAC, SE])); // Terminal Type
    await delay(delayMs);
    socket.write(Buffer.concat([IAC, DO, ECHO])); // Echo
    await delay(delayMs);
    if (advancedFeatures) {
        socket.write(Buffer.concat([IAC, WILL, CUSTOM_CLIENT_INIT])); // Custom Client Initialization
        await delay(delayMs);
    }
    if (encrypted) {
        // increase delay for encryption
        delayMs += encryptionDelay;
    }
    await delay(initializationDelay); // Wait for server to process
    await send(""); // Send empty command to initialize connection
    initialized = true;
    console.debug("Initialization complete");
    // socket.write(Buffer.from([0x0d, 0x0a])); // Line Feed
    // from here on encryption is enabled, do not use socket.write() directly anymore
    // initialization complete

    await send("help");
    await delay(delayMs);
    process.stdout.write("\rCtrl+X for client side commands\r\nCtrl+C to exit, Ctrl+D to force close\r\n> ");
    process.stdin.resume(); // Resume input
    // more commands can be added here

    // console.log("Test:", decrypt(Buffer.from("eaffd8d028120ac5b1e8634438c522a91ca5bd9cbda1c5ac88321cd6d743b185b6e43cec1c1d6b1b1ad5fc623012582e666a0d1b83f7656dbdd2a8609e0ec9f1e6123ebb442455316a4bfe883d46", "hex"), privateKey))

    if (fs.existsSync("batchrun.txt")) {
        const batchCommands = fs.readFileSync("batchrun.txt", "utf-8").split("\n");
        for (const command of batchCommands) {
            if (command.trim()) {
                await send(command.trim());
                await delay(delayMs);
            }
        }
    }

});

socket.on("end", () => {
    console.log("\nDisconnected from server");
    process.exit();
});

module.exports = {
    delay,
    send,
    project_folder
};
