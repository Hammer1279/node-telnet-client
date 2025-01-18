import { createConnection } from 'net'

const port = 23;
const hostname = "localhost";
const delayMs = 100; // Command delay in milliseconds

export const IAC = Buffer.from([0xff]); // Interpret As Command
export const DONT = Buffer.from([0xfe]); // Don't
export const DO = Buffer.from([0xfd]); // Do
export const WONT = Buffer.from([0xfc]); // Won't
export const WILL = Buffer.from([0xfb]); // Will
export const SB = Buffer.from([0xfa]); // Subnegotiation Begin
export const GA = Buffer.from([0xf9]); // Go Ahead
export const EL = Buffer.from([0xf8]); // Erase Line
export const EC = Buffer.from([0xf7]); // Erase Character
export const AYT = Buffer.from([0xf6]); // Are You There
export const AO = Buffer.from([0xf5]); // Abort Output
export const IP = Buffer.from([0xf4]); // Interrupt Process
export const BRK = Buffer.from([0xf3]); // Break
export const DM = Buffer.from([0xf2]); // Data Mark
export const NOP = Buffer.from([0xf1]); // No Operation
export const SE = Buffer.from([0xf0]); // Subnegotiation End

// Common Telnet options or features
export const ECHO = Buffer.from([0x01]); // Echo
export const SUPPRESS_GO_AHEAD = Buffer.from([0x03]); // Suppress Go Ahead
export const STATUS = Buffer.from([0x05]); // Status
export const TIMING_MARK = Buffer.from([0x06]); // Timing Mark
export const TERMINAL_TYPE = Buffer.from([0x18]); // Terminal Type
export const NAWS = Buffer.from([0x1f]); // Negotiate About Window Size
export const TERMINAL_SPEED = Buffer.from([0x20]); // Terminal Speed
export const REMOTE_FLOW_CONTROL = Buffer.from([0x21]); // Remote Flow Control
export const LINEMODE = Buffer.from([0x22]); // Line Mode
export const ENVIRONMENT_VARIABLES = Buffer.from([0x24]); // Environment Variables

// custom codes for own client
export const CUSTOM_CLIENT_INIT = Buffer.from([0x80]); // Custom Client Initialization
export const KEY_EXCHANGE = Buffer.from([0x81]); // Key Exchange
export const ENCRYPTION = Buffer.from([0x82]); // Encryption
export const AUTHENTICATION = Buffer.from([0x83]); // Authentication
// 0x84 reserved for future use
export const FILE_TRANSFER = Buffer.from([0x85]); // File Transfer
export const PAUSE = Buffer.from([0x86]); // Pause
export const RESUME = Buffer.from([0x87]); // Resume

const socket = createConnection(port, hostname);

process.stdin.setEncoding("ascii");
process.stdin.setRawMode(true);
process.stdin.resume();

// format keys before sending to server
process.stdin.on('data', (key) => {
    if (key === '\u0003') { // Ctrl+C
        process.exit();
    }
    
    // Log hex values of input for debugging
    // console.log("Key pressed:", Array.from(key).map(b => '0x' + b.toString(16)));
    
    if (key == "\r") {
        // Enter key
        socket.write("\r\n");
    } else {
        socket.write(key);
    }
});

socket.on("data", (data) => {
    if (data.equals(PAUSE)) {
        process.stdin.pause();
    } else if (data.equals(RESUME)) {
        process.stdin.resume();
    } else {
        process.stdout.write(data);
    }
});

socket.on("connect", async () => {
    console.log("Connected to server");
    socket.write(Buffer.concat([IAC, WILL, NAWS, SB, NAWS, Buffer.from([/* 24x80 */ 0x00, 0x18, 0x00, 0x50]), SE])); // Negotiate About Window Size
    await delay(delayMs); // Wait for server to process
    socket.write(Buffer.concat([IAC, WILL, TERMINAL_TYPE, IAC, SB, TERMINAL_TYPE, Buffer.from("xterm-256color"), IAC, SE])); // Terminal Type
    await delay(delayMs);
    socket.write(Buffer.concat([IAC, WILL, ECHO])); // Echo
    await delay(delayMs);
    socket.write(Buffer.from([0x0d, 0x0a])); // Line Feed
    await delay(delayMs);
    // initialization complete

    await send("help");
});

export const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export const send = async (command) => {
    await delay(delayMs);
    socket.write(command); // Command
    await delay(delayMs);
    socket.write("\r\n"); // Line Feed
};