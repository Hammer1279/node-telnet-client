const fs = require("fs");
const path = require("path");
const { createConnection } = require('net');
const { createDiffieHellman, createDiffieHellmanGroup } = require('crypto');

const port = process.argv[3] || 23;
const hostname = process.argv[2] || (process.pkg ? "dom.ht-dev.de" : "localhost");
const delayMs = process.argv[4] || 100; // Command delay in milliseconds

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
    console.debug = () => {}; // Disable debug logging when run as an executable
    fs.writeFileSync(path.join(project_folder, "README.md"), fs.readFileSync(path.join(__dirname, "README.md"))); // copy newest readme to folder
    fs.writeFileSync(path.join(project_folder, "LICENSE"), fs.readFileSync(path.join(__dirname, "LICENSE"))); // copy newest license to folder
}

const socket = createConnection(port, hostname);

let hold = false; // Hold input

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
            process.stdout.write("> ");
        } else if (command == "disconnect") {
            send(IP); // Interrupt Process
        } else if (command == "help") {
            // Add any additional functionality for client side commands
            console.log("Client commands:");
            console.log("disconnect - Disconnect from server");
            console.log("exit - Exit client command mode");
            process.stdout.write("$ ");
        } else {
            process.stdout.write("$ ");
        }
    }
});

socket.on("data", (data) => {
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
    } else if (data.equals(Buffer.concat([IAC, SB, KEY_EXCHANGE, ONE /* value required */, IAC, SE]))) {
        // send key to server
    } else {
        process.stdout.write(data);
    }
});

socket.on("connect", async () => {
    console.log("Connected to server");

    // initialization
    socket.write(Buffer.concat([IAC, WILL, NAWS, SB, NAWS, Buffer.from([/* 24x80 */ 0x00, 0x18, 0x00, 0x50]), SE])); // Negotiate About Window Size
    await delay(delayMs); // Wait for server to process
    socket.write(Buffer.concat([IAC, WILL, TERMINAL_TYPE, IAC, SB, TERMINAL_TYPE, NUL, Buffer.from("xterm-256color"), IAC, SE])); // Terminal Type
    await delay(delayMs);
    socket.write(Buffer.concat([IAC, DO, ECHO])); // Echo
    await delay(delayMs);
    socket.write(Buffer.concat([IAC, WILL, CUSTOM_CLIENT_INIT])); // Custom Client Initialization
    await delay(delayMs * 10);
    socket.write(Buffer.from([0x0d, 0x0a])); // Line Feed
    await delay(delayMs);
    // initialization complete

    await send("help");
    await delay(500);
    process.stdout.write("\rCtrl+X for client side commands\r\nCtrl+C to exit, Ctrl+D to force close\r\n> ");
    // more commands can be added here


});

socket.on("end", () => {
    console.log("\nDisconnected from server");
    process.exit();
});

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const send = async (command) => {
    await delay(delayMs);
    socket.write(command); // Command
    await delay(delayMs);
    socket.write("\r\n"); // Line Feed
};

module.exports = {
    delay,
    send,
    project_folder
};
