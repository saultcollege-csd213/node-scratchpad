import crypto from 'crypto';
import fs from 'fs';
import https from 'https';
import querystring from 'querystring';
import url from 'url';

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

// A session store to keep track of which session IDs are valid
// This would typically be stored in a database, but for simplicity we're using an in-memory Map here
const sessionStore = new Map();

function handleRequest(request, response) {

    // Log the request method and URL
    console.log(`Request: ${request.method} ${request.url}`);

    // Parse the URL into its components
    const { pathname, query } = url.parse(request.url, true);

    const session = establishSession(request, response, sessionStore);

    if ( request.method === "GET" && pathname === "/login" ) {

        let html = fs.readFileSync('app/pages/login.html', { encoding: "utf-8" });
        sendHtml(response, session, html);

    } else if ( request.method === "POST" && pathname === "/login" ) {
        
        parseFormData(request, (formData) => {
            // Destructure the form data obejct into its individual parts
            const { username, password, csrfToken } = formData;

            if ( ! session.isValidCSRFToken(csrfToken) ) {
                sendError(response, 403, "Forbidden: Invalid CSRF Token");
                return;
            }

            // Check if we have a valid username/password combination
            if ( isValidUser(username, password) ) {

                // Associate the current session with this user
                session.authenticate(username);

                redirect(response, "/user/" + username);
            } else {
                redirect(response, "/login", { message: "Invalid username or password" });
            }
        });

    } else if ( request.method === "POST" && pathname === "/logout" ) {
        
        // If the user is authenticated, we need to clear their session in order to log them out
        if ( session.isAuthenticated() ) {
            clearSession(response, session, sessionStore);
        }

        redirect(response, "/login", { message: "You have been successfully logged out" });

    } else if ( request.method === "GET" && pathname === "/register" ) {
        
        let html = fs.readFileSync('app/pages/register.html', { encoding: "utf-8" });
        sendHtml(response, session, html);

    } else if ( request.method === "POST" && pathname === "/register" ) {

        parseFormData(request, (formData) => {
            // Destructure the form data into individual variables
            const { fullname, email, phone, username, password, csrfToken } = formData;

            if ( ! session.isValidCSRFToken(csrfToken) ) {
                sendError(response, 403, "Forbidden: Invalid CSRF Token");
                return;
            }

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

        if ( session.isAuthenticated()) {
            const html = fs.readFileSync('app/pages/auth/secret.html', { encoding: "utf-8" });
            sendHtml(response, session, html);
        } else {
            redirect(response, "/login", { message: "You must be logged in to view this page" });
        }

    } else if ( request.method === "GET" && pathname.startsWith("/user/") ) {

        // Assume everything after "/user/" (the first 6 characters of the path) is a username
        const username = pathname.substring(6);  

        if ( session.isAuthenticated() ) {

            if ( session.isUserAuthenticated(username) ) {
                let html = fs.readFileSync('app/pages/auth/user.html', { encoding: "utf-8" });
                html = html.replaceAll("<!-- USERNAME -->", username);
                sendHtml(response, session, html);
            } else {
                sendError(response, 403, "Hey! You can't view someone else's page!");
            }
        } else {
            redirect(response, "/login", { message: "You must be logged in to view this page" });
        }

    } else if ( request.method === "GET" && pathname === "/" ) {
        sendHtml(response, session, fs.readFileSync('app/pages/index.html', { encoding: "utf-8" }));
    } else if ( request.method === "GET" && pathname === "/favicon.ico" ) {
        response.writeHead(200);
        response.end(fs.readFileSync('app/public/favicon.ico'));
    } else {
        sendError(response, 404, "Not found");
    }

}


/*===========================================================================================
 * HELPERS
 *===========================================================================================*/

function sendHtml(response, session, html) {
    response.statusCode = 200;
    response.setHeader("Content-Type", "text/html");

    // If the HTML contains the <!-- CSRF --> placeholder, inject a hidden CSRF token <input> into the HTML
    html = injectCSRFToken(html, session.csrfToken);
    response.end(html);
}

/**
 * Sends an error response according to the given statusCode and message
 * @param {object} response A Node HTTP response object
 * @param {number} statusCode HTTP status code
 * @param {string} message A message to include in the error response
 */ 
function sendError(response, statusCode, message) {
    response.statusCode = statusCode;
    response.end(message);
}
    
/**
 * @param {object} response A Node HTTP response object
 * @param {string} location The URL path to redirect to
 * @param {object} params An object containing any query parameters to include in the redirect URL
 */
function redirect(response, location, params) {
    // Setting the Location header causes the client to redirect to the specified URL
    // The querystring module is being used here to convert the params object into a well-formed query string
    response.statusCode = 302;
    response.setHeader("Location", location + "?" + querystring.stringify(params));
    response.end();
}

/**
 * @param {object} requeset A Node HTTP request object
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

/**
 * @param {*} cookieHeader The value of the Cookie header from an HTTP request
 * @returns {Map} An object containing the key-value pairs of the cookies
 * 
 * E.g. A cookie like this: sessionId=abc123; myCookieThing=123
 * Would be parsed into a Map like this: { sessionId: "abc123", myCookieThing: "123" }
 */
function parseCookies (cookieHeader) {
    const cookies = {};

    if ( cookieHeader ) {
        cookieHeader.split(`;`).forEach( cookie => {
            const [key, value] = cookie.split(`=`);
            cookies[key.trim()] = value.trim();
        });
    }

    return cookies;
}

/**
 * A Session object stores information about one user's session in a browser
 * Properties:
 * - id: A unique identifier for the session
 * - csrfToken: A unique token used to prevent CSRF attacks
 * - lastActivity: The time at which the session was last active
 * - username: The username associated with the session, undefined if the user is not authenticated
 */
class Session {
    constructor() {
        // Create a random session ID to be used in session-based authentication.
        // To maximize security, session IDs should be long, random, unique, 
        // and should not reveal any information about the user associated with the session.
        this.id = crypto.randomBytes(20).toString("hex");

        // Create a random CSRF token that will be used to prevent CSRF attacks
        // Like session ids, CSRF tokens should be long, random, unique and not reveal any information.
        // As you can see, both session and CSRF tokens are simply random sequences of hexadecimal characters.
        this.csrfToken = crypto.randomBytes(20).toString("hex");

        this.lastActivity = Date.now();

    }

    isExpired() {
        return Date.now() - this.lastActivity > 1000 * 60 * 60; // 1 hour
    }

    /**
     * Updates the last activity time to the current time
     * Used to keep the session alive if the user is active
     */
    refresh() {
        this.lastActivity = Date.now();
    }
    
    /**
     * @param {string} username The username to associate with the session
     */
    authenticate(username) {
        this.username = username;
    }

    /**
     * @returns {boolean} True if the user is authenticated, false otherwise
     */
    isAuthenticated() {
        // If the session has a username associated with it, then the user is authenticated
        // Otherwise, they are not
        return this.username !== undefined;
    }

    /**
     * @returns {boolean} True if the given username matches the username associated with the session
     */
    isUserAuthenticated(username) {
        return this.username === username;
    }

    /**
     * @returns {boolean} True if the given CSRF token matches the CSRF token associated with the session
     */
    isValidCSRFToken(csrfToken) {
        return this.csrfToken === csrfToken;
    }
}

/**
 * This function is here to encapsulate all the operations that need to be performed
 * when a new session is created. This is useful because the same operations need to be
 * performed in multiple places in the code.
 * @param {object} response A Node HTTP response object
 * @param {Map} sessionStore A Map object containing the session IDs of active sessions
 * @returns {Session} An object representing the new session
 */
function establishNewSession(response, sessionStore) {
    const session = new Session();
    // Store the session in the session store
    sessionStore.set(session.id, session);

    // New sessions will have a new session ID, so we need to set a new session ID cookie in the client's browser
    // The Set-Cookie header is used to set cookies in the client's browser
    // Cookies are key-value pairs that are stored client-side, 
    // and sent from the client to the server with each request to the server.
    // This session cookie will allows us to verify whether a given request is coming from an authenticated user or not
    // HttpOnly => The cookie is NOT available to client-side code
    // Secure => The cookie will ONLY be transmitted over HTTPS (never over HTTP)
    // SameSite => The cookie will only be sent with requests from the same SameSite
    response.setHeader("Set-Cookie", `sessionId=${session.id}; HttpOnly; Secure; SameSite=Strict; Path=/`);

    // This is just an example of setting another cookie. You can set as many as you like.
    // This cookie is not HttpOnly, so it will be available to client-side code
    response.setHeader("myCookieThing", "kjsakjfdsa");

    return session;
}

/**
 * This function is here to encapsulate all the operations that need to be performed
 * when a session is cleared.
 */
function clearSession(response, session, sessionStore) {
    // Clear the session ID cookie in the client's browser by setting it to an empty string
    response.setHeader("Set-Cookie", `sessionId=; HttpOnly; Secure; SameSite=Strict; Path=/`);
    // Clear the session ID from the session store
    sessionStore.delete(session.id);
}

/**
 * If there is no session cookie in the request, or if the session ID is not valid,
 * a new session with a new CSRF token is created.
 * @param {object} request A Node HTTP request object
 * @param {object} response A Node HTTP response object
 * @param {Map} sessionStore A Map object containing the session IDs of active sessions
 * @returns {Session} An object representing the current session
 */
function establishSession(request, response, sessionStore) {

    const cookies = parseCookies(request.headers.cookie);

    // Check if a session cookie is present in the request
    if ( cookies.sessionId && sessionStore.has(cookies.sessionId) ) {
        let session = sessionStore.get(cookies.sessionId);

        // Check if the cookie has expired
        if ( session.isExpired() ) {
            // If it has, delete the session from the session store
            sessionStore.delete(session.id);

            // And create a new session...
            return establishNewSession(response, sessionStore);

        } else {
            // If the session is still valid, update the last activity time
            session.refresh();
            return session;
        }
    } else {
        // This must be a new session, so create a new one
        return establishNewSession(response, sessionStore);
    }
}

/**
 * Inject a CSRF token into an HTML string
 * @param {string} html The HTML string to inject the CSRF token into
 * @param {string} csrfToken The CSRF token to inject
 */
function injectCSRFToken(html, csrfToken) {
    // We assume that there is a <!-- CSRF --> placeholder in the given html string.
    // We simply replace this placeholder with a hidden input field containing the CSRF token.
    // In this way, the CSRF token will be sent with the form data when the form is submitted.
    // There is no way for an attacker to know the CSRF token, so they cannot forge a POST request
    return html.replace("<!-- CSRF -->", `<input type="hidden" name="csrfToken" value="${csrfToken}">`);
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
