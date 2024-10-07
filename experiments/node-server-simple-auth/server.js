import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import querystring from 'querystring';
import url from 'url';

// A session store to keep track of which session IDs are valid
// This would typically be stored in a database, but for simplicity we're using an in-memory Map here
const sessions = new Map();

/**
 * Creates a random session ID to be used in session-based authentication.
 * To maximize security, session IDs should be long, random, unique, 
 * and should not reveal any information about the user associated with the session.
 * @returns {string} A new session ID
 */
function generateSessionId() {
    return crypto.randomBytes(16).toString("hex");
}

// The key and cert options are required to create an HTTPS server.
// They must contain the private key and certificate for the server, respectively.
// These keys may be generated using a tool like OpenSSL and a command like the following:
// openssl req -nodes -new -x509 -keyout server.key -out server.cert
const options = {
    key: fs.readFileSync(process.env.HTTPS_KEY),
    cert: fs.readFileSync(process.env.HTTPS_CERT)
};
const PORT = 8443;
const server = https.createServer(options, handleRequest);
server.listen(PORT, () => { console.log(`App running at https://localhost:${PORT}/`); });

function handleRequest(request, response) {

    // A helper function to send an error response with a given status code and message
    function sendError(statusCode, message) {
        response.writeHead(statusCode);
        response.end(message);
    }

    // Log the request method and URL
    console.log(`Request: ${request.method} ${request.url}`);

    // Parse the URL into its components
    const { pathname, query } = url.parse(request.url, true);

    if ( request.method === "GET" && pathname === "/login" ) {
        response.writeHead(200, { "Content-Type": "text/html" });
        response.end(fs.readFileSync('app/pages/login.html', { encoding: "utf-8" }));

    } else if ( request.method === "POST" && pathname === "/login" ) {
        
        parseFormData(request, (formData) => {
            // Destructure the form data obejct into its individual parts
            const { username, password } = formData;

            // Check if we have a valid username/password combination
            if ( isValidUser(username, password) ) {

                // If we do, go ahead and associate that use to a new session ID
                const sessionId = generateSessionId();
                // Store that session ID in our session store
                sessions.set(sessionId, { username });

                // Redirect to the user's page
                response.writeHead(302, { 
                    "Location": "/user/" + username, 

                    // The Set-Cookie header is used to set cookies in the client's browser
                    // Cookies are key-value pairs that are stored client-side, 
                    // and sent from the client to the server with each request to the server
                    // In node, we can set multiple cookies by including an array of strings in the Set-Cookie header
                    "Set-Cookie": [
                        // Set the session ID as a cookie in the response
                        // This will allow the client to send the session ID with future requests
                        // HttpOnly => The cookie is NOT available to client-side code
                        // Secure => The cookie will ONLY be transmitted over HTTPS (never over HTTP)
                        // SameSite => The cookie will only be sent with requests from the same SameSite
                        `sessionId=${sessionId}; HttpOnly; Secure; SameSite=Strict`,

                        // This is just an example of setting another cookie. You can set as many as you like.
                        // This cookie is not HttpOnly, so it will be available to client-side code
                        "myCookieThing=123"
                    ]
                });
                response.end();
            } else {
                redirect(response, "/login", { message: "Invalid username or password" });
            }
        });

    } else if ( request.method === "POST" && pathname === "/logout" ) {
        
        // If the user is authenticated, we need to clear their session in order to log them out
        if ( isAuthenticated(request) ) {
            const cookies = parseCookies(request.headers.cookie);
            // Remove the session ID from the session store
            sessions.delete(cookies.sessionId);
        }

        // No matter what, clear the session ID from the client's browser 
        // by setting the session ID cookie to an empty string
        response.writeHead(302, { 
            "Location": "/login?message=You have been successfully logged out", 
            "Set-Cookie": `sessionId=; HttpOnly; Secure; SameSite=Strict`
        });
        response.end();

    } else if ( request.method === "GET" && pathname === "/register" ) {
        response.writeHead(200, { "Content-Type": "text/html" });
        response.end(fs.readFileSync('app/pages/register.html', { encoding: "utf-8" }));

    } else if ( request.method === "POST" && pathname === "/register" ) {

        parseFormData(request, (formData) => {
            // Destructure the form data into individual variables
            const { fullname, email, phone, username, password } = formData;

            const message = [];

            // Make sure required fields are present
            // We MUST do this check on the server side even though there is client-side checking
            // because a malicious user could bypass the client-side checks
            if ( !fullname || !email || !username || !password ) {
                message.push("The following fields are required: Full Name, Email, Username, Password");
            }

            if ( isUsernameTaken(username) ) {
                message.push("Username is already taken");
            }
            
            if ( isValidPassword(password) ) {
                message.push("Password must be at least 8 characters long");
            }

            // If there are messages, there was a verification problem and the user needs to fix their inputs
            if ( message.length > 0 ) {

                // Redirect back to the registration page with an error message
                // We include both the message array AND the form data so that the form can be pre-filled
                // with values the user previously entered
                // Note that the password is NOT included in the pre-fill data, for security reasons
                redirect(response, "/register", { message, fullname, email, phone, username });

            } else {

                // If we have successfully verified the form data, add the user to the system
                addUser(fullname, email, phone, username, password);
                // Then redirect to the login page
                redirect(response, "/login", { message: "Registration successful! Please log in." });

            }
        });

    } else if ( request.method == "GET" && pathname.startsWith("/auth/secret/") ) {

        if ( isAuthenticated(request)) {
            response.writeHead(200, { "Content-Type": "text/html" });
            response.end(fs.readFileSync('app/pages/auth/secret.html', { encoding: "utf-8" }));
        } else {
            redirect(response, "/login", { message: "You must be logged in to view this page" });
        }

    } else if ( request.method === "GET" && pathname.startsWith("/user/") ) {

        // Assume everything after "/user/" (the first 6 characters of the path) is a username
        const username = pathname.substring(6);  

        if ( isAuthenticated(request) ) {

            if ( isUserAuthorized(request, username) ) {
                response.writeHead(200, { "Content-Type": "text/html" });
                let html = fs.readFileSync('app/pages/auth/user.html', { encoding: "utf-8" });
                html = html.replaceAll("<!-- USERNAME -->", username);
                response.end(html);
            } else {
                sendError(403, "Hey! You can't view someone else's page!");
            }
        } else {
            redirect(response, "/login", { message: "You must be logged in to view this page" });
        }

    } else if ( request.method === "GET" && pathname === "/" ) {
        response.writeHead(200, { "Content-Type": "text/html" });
        response.end(fs.readFileSync('app/pages/index.html', { encoding: "utf-8" }));

    } else if ( request.method === "GET" && pathname === "/favicon.ico" ) {
        response.writeHead(200);
        response.end(fs.readFileSync('app/public/favicon.ico'));

    } else {
        sendError(404, "Not found");
    }
}

/**=
 * @param {*} response The HTTP response object
 * @param {*} location The URL path to redirect to
 * @param {*} params An object containing any query parameters to include in the redirect URL
 */
function redirect(response, location, params) {
    // Setting the Location header causes the client to redirect to the specified URL
    // The querystring module is being used here to convert the params object into a well-formed query string
    response.writeHead(302, { "Location": location + "?" + querystring.stringify(params) });
    response.end();
}

/**
 * @param {*} username 
 * @param {*} password 
 * @returns {boolean} True if the username and password match a valid user, false otherwise
 */
function isValidUser(username, password) {
    const users = JSON.parse(fs.readFileSync('app/data/users.json', { encoding: "utf-8" }));

    // Using plain-text passwords, simply check if the username and password match any user
    // WARNING: This is NOT secure! Passwords should NEVER be stored in plain text; they should be hashed and salted
    return users.some(user => user.username === username && user.unhashed_password === password);

}

/**
 * @param {*} request An HTTP request object
 * @returns {boolean} True if the request is made by an authenticated user, false otherwise
 */
function isAuthenticated(request) {
    const cookies = parseCookies(request.headers.cookie);

    // Check our session store to see if the session ID from the client is valid
    // If the session ID is present, then this is an authenticated user!
    return sessions.has(cookies.sessionId);
}

/**
 * @param {*} request An HTTP request object
 * @param {*} user The username of the user to check
 * @returns True if the request is made by the specified user, false otherwise
 */
function isUserAuthorized(request, user) {
    const cookies = parseCookies(request.headers.cookie);

    // Check our session store to see if the session ID from the client is valid
    // If it is, check what username is associated with that session
    // If it's the same as the user we're checking, then that user is authorized!
    return sessions.get(cookies.sessionId).username === user;
}

/**
 * @param {*} username The username to check
 * @returns {boolean} True if the username is already taken, false otherwise
 */
function isUsernameTaken(username) {
    const users = JSON.parse(fs.readFileSync('app/data/users.json', { encoding: "utf-8" }));
    return users.some(user => user.username === username);
}

function isValidPassword(password) {
    return password.length < 8;
}

/**
 * Adds a new user to app storage.
 */
function addUser(fullname, email, phone, username, password) {
    // Typically this kind of information would be stored in a database, but to keep things simple
    // we're just storing it in a JSON file
    
    // Read the current set of users
    const users = JSON.parse(fs.readFileSync('app/data/users.json', { encoding: "utf-8" }));

    // Add the new user to the list
    // WARNING: This is NOT secure! Passwords should NEVER be stored in plain text; they should be hashed and salted
    users.push({ fullname, email, phone, username, unhashed_password: password });

    // Write the updated list of users back to the file
    fs.writeFileSync('app/data/users.json', JSON.stringify(users, null, 2));
}

/**
 * @param {*} cookieHeader The value of the Cookie header from an HTTP request
 * @returns {Map} An object containing the key-value pairs of the cookies
 * 
 * E.g. A cookie like this: sessionId=abc123; myCookieThing=123
 * Would be parsed into a Map like this: { sessionId: "abc123", myCookieThing: "123" }
 */
function parseCookies (cookieHeader) {
    const cookies = {};

    cookieHeader.split(`;`).forEach( cookie => {
        const [key, value] = cookie.split(`=`);
        cookies[key.trim()] = value.trim();
    });

    return cookies;
}

/**
 * @param {*} request An HTTP request object
 * @param {*} callback A function to call with the form data once the data has been parsed
 */
function parseFormData(request, callback) {

    // Form data may come in 'chunks' (e.g. if the form is large) so Node's request object emits events
    // to indicate when new data is available, and when all data has been received

    // We will store the full form data (which comes as the body of the request) in this string
    let body = "";

    // The 'data' event is emitted whenever a new chunk of data from the HTTP request is received
    request.on("data", chunk => {
        body += chunk.toString();
    });

    // The 'end' event is emitted when the entire request body has been received
    // At this point, we can call the callback function with the form data
    // We must wrap the call to callback in a function that will be called only when the end event is emitted
    // We use querystring.parse to convert the form data string into an object because
    // the form data is formatted as a query string, e.g. "username=alice&password=1234" etc.
    request.on("end", () => callback(querystring.parse(body))); 
}