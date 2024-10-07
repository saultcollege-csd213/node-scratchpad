// A simple file server using only standard Node.js modules

// Import some necessary modules
import http from "http";
import fs from "fs";
import path from "path";

const PORT = 8001; // The port for the server to listen on; this can be changed

// Configure our HTTP server to respond to any requests.
// First, using the createServer function, we set the handler function that will handle all requests
// The createServer function returns an instance of an HTTP server, which we can then tell to 
// listen on a specific port and host.
// The final argument to the listen function will be called when the server is ready to start accepting requests.
// Here, we log a message to the console to let the user know that the server is ready to accept requests.
http.createServer(handleRequest)
    .listen(PORT, () => {
        console.log(`Serving contents of public folder at http://localhost:${PORT}/`);
    });

// This is te main function that handles requests (referred to in the createServer call above)
function handleRequest(request, response) {
    // Log the request method and URL
    console.log(`Request: ${request.method} ${request.url}`);

    let filePath = path.join('./public', request.url);

    // If the requested path exists...
    if (fs.existsSync(filePath)) {
        
        // If it's a file, serve it...
        if (fs.statSync(filePath).isFile()) {
            sendFile(response, filePath);
            return;
        }
        // If it's a directory, and there is an index.html, serve that...
        if (fs.statSync(filePath).isDirectory()) {
            const indexFilePath = path.join(filePath, "index.html");
            if (fs.existsSync(indexFilePath)) {
                sendFile(response, indexFilePath);
            }
        }
    } else {
        send404(response, "File not found");
    }
}

function sendFile(response, filePath) {
    try {
        // Get the file's contents and send them to the client
        const fileContent = fs.readFileSync(filePath, { encoding: "utf-8" });
        // Set the HTTP headers
        response.writeHead(200, { 
            // Set the Content-Type header based on the file extension
            "Content-Type": contentType(filePath),
        });
        // Send the file contents to the client
        response.end(fileContent, "utf-8");
    } catch (error) {
        console.log("Error: " + error);
        send404(response, "Could not open file");
        return;
    }
}

function send404(response, message) {
    response.writeHead(404);
    response.end(message);
}

/**
 * @param {string} filePath The path to a file
 * @returns {string} The MIME type of the file, based on its file extension
 */
function contentType(filePath) {
    const extname = path.extname(filePath);
    switch (extname) {
        case ".html":
            return "text/html";
        case ".js":
            return "text/javascript";
        case ".css":
            return "text/css";
        case ".json":
            return "application/json";
        case ".png":
            return "image/png";
        case ".jpg":
            return "image/jpg";
        case ".ico":
            return "image/x-icon";
        default:
            return "application/octet-stream";
    }
}