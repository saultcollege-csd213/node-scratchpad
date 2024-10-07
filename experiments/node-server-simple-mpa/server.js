// A simple multi-page app server using only Node.js modules plus a simple custom template parser

// Import some necessary modules
import http from "http";
import fs from "fs";
import path from "path";
import templateParser from "./template-parser.js";

const PORT = 8002; // The port for the server to listen on; this can be changed

// Configure our HTTP server to respond to any requests.
// First, using the createServer function, we set the handler function that will handle all requests
// The createServer function returns an instance of an HTTP server, which we can then tell to 
// listen on a specific port and host.
// The final argument to the listen function will be called when the server is ready to start accepting requests.
// Here, we log a message to the console to let the user know that the server is ready to accept requests.
http.createServer(handleRequest)
    .listen(PORT, () => {
        console.log(`App running at http://localhost:${PORT}/`);
    });

// This is te main function that handles requests (referred to in the createServer call above)
function handleRequest(request, response) {
    // Log the request method and URL
    console.log(`Request: ${request.method} ${request.url}`);

    // If the requested URL exists and is a file in the public folder, then just serve it...
    let publicFilePath = path.join('./app/public', request.url);
    if (fs.existsSync(publicFilePath) && fs.statSync(publicFilePath).isFile()) {    
        sendFile(response, publicFilePath);
    } else {
        // Otherwise, we assume the request is for a .page file, 
        // in which case we need to parse it, convert it to HTML, and serve that
        
        // First, let's check if there's a .page file at the request URL
        const pageFilePath = path.join('./app/pages', request.url + ".page");
        if ( fs.existsSync(pageFilePath) ) {
            sendPage(response, pageFilePath);
            return;
        } 

        // If the file doesn't exist, check if there's an index.page file at the request URL
        const indexFilePath = path.join('./app/pages', request.url, "index.page");
        if ( fs.existsSync(indexFilePath)) {
            sendPage(response, indexFilePath);
        } else {
            send404(response, "Page not found");
        }
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

/**
 * 
 * @param {object} response The HTTP response object
 * @param {string} pageFilePath The path to a .page file to serve
 */
function sendPage(response, pageFilePath) {
    // If the file exists, read its contents
    const pageContent = fs.readFileSync(pageFilePath, { encoding: "utf-8" });

    // Read the template file that defines the HTML layout of the page
    const template = fs.readFileSync('./app/layout/main.html', { encoding: "utf-8" });

    // Parse the page content and merge it with the template
    const html = templateParser.toHtml(pageContent, template, getPagesInFolder);

    // Set the HTTP headers
    response.writeHead(200, { 
        "Content-Type": "text/html",
    });

    // Send the HTML content to the client
    response.end(html, "utf-8");
}

/**
 * @param {string} folder The name of a folder
 * @return {string[]} An array of the names of the pages in the given folder, or [] if the folder doesn't exist
 */
function getPagesInFolder(folder) {
    const folderPath = path.join('./app/pages/', folder);

    if ( fs.existsSync(folderPath) && fs.statSync(folderPath).isDirectory() ) {
        return fs.readdirSync(folderPath)
            .filter(file => file.endsWith(".page")) // Only include .page files
            .map(file => file.slice(0, -5));        // Remove the .page extension
    } else {
        return [];
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