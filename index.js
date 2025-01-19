const fs = require("fs");
const path = require("path");
const { createConnection } = require('net');
const { createHash, createECDH } = require('crypto');
const { Transform } = require('stream');

// Application settings
const port = process.argv[3] || 23;
const hostname = process.argv[2] || (process.pkg ? "dom.ht-dev.de" : "localhost");
let delayMs = process.argv[4] || 100; // Command delay in milliseconds

const advancedFeatures = false; // Enable advanced features

// Diffie-Hellman parameters
const keyCurve = "prime256v1"; // key exchange curve, make this negotiable in the future

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
const key = createECDH(keyCurve);

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
        } else if (command == "help") {
            // Add any additional functionality for client side commands
            console.log("Client commands:");
            console.log("status - Show client status");
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
        } else if (data.equals(Buffer.concat([IAC, DO, CUSTOM_CLIENT_INIT]))) {
            // server supports custom client features
            socket.write(Buffer.concat([IAC, WILL, KEY_EXCHANGE])); // Start Key Exchange
        } else if (data.includes(Buffer.concat([IAC, DO, KEY_EXCHANGE]))) {
            // generate keys
            const publicKey = key.generateKeys();
            console.debug("Generated Key: " + publicKey.toString("hex"));
        } else if (data.equals(Buffer.concat([IAC, SB, KEY_EXCHANGE, ONE /* value required */, IAC, SE]))) {
            socket.write(Buffer.concat([IAC, SB, KEY_EXCHANGE, NUL, key.getPublicKey(), IAC, SE]));
            // send key to server
        } else if (data.includes(Buffer.concat([IAC, SB, KEY_EXCHANGE, NUL /* value provided */]))) {
            // server sent its key, generate secret
            console.debug("Key exchange received");
            const offsetBegin = data.indexOf(SB) + 2;
            const offsetEnd = data.lastIndexOf(SE) - 1;
            const keyData = data.subarray(offsetBegin + 1, offsetEnd); // client public key
            console.log("Extracted key:", keyData.toString("hex"));
            privateKey = key.computeSecret(keyData);
            socket.write(Buffer.concat([IAC, WILL, ENCRYPTION])); // Enable Encryption
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
    socket.write(Buffer.from([0x0d, 0x0a])); // Line Feed
    if (encrypted) {
        // increase delay for encryption
        delayMs += 200;
    }
    // from here on encryption is enabled, do not use socket.write() directly anymore
    await delay(delayMs);
    console.debug("Initialization complete");
    initialized = true;
    // initialization complete

    await send("help");
    await delay(delayMs);
    process.stdout.write("\rCtrl+X for client side commands\r\nCtrl+C to exit, Ctrl+D to force close\r\n> ");
    process.stdin.resume(); // Resume input
    // more commands can be added here

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
