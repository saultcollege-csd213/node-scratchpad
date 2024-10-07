// This code takes our simple template format and converts it into valid HTML

/**
 * 
 * @param {string} pageText The content of a page to render
 * @param {string} template The template to render the page into, an HTML file with %TITLE% and %CONTENT% placeholders
 * @param {function} getPagesInFolder A function that takes a folder name and returns a list of pages in that folder
 * @returns {string} The page rendered according to the template string
 */
function toHtml(pageText, template, getPagesInFolder) {
    pageText = pageText.trim();
    const title = getTitle(pageText);
    const content = toHtmlContent(pageText, getPagesInFolder);
    return template.replace("%TITLE%", title).replace("%CONTENT%", content);
}


/**
 * @param {string} pageText The page content to extract the title from
 * @returns {string} The title of the text 
 *                   (the text after # on the first line, or "Untitled" if the first line contains no #)
 */
function getTitle(pageText) {
    if ( pageText.startsWith("#") ) {
        return pageText.slice(1, pageText.indexOf("\n")).trim();
    } else {
        return "Untitled";
    }
}

/**
 * 
 * @param {string} pageText The content of a page to render 
 * @param {function} getPagesInFolder A function that takes a folder name and returns a list of pages in that folder
 * @returns {string} The page content (minus the title) rendered as HTML
 */
function toHtmlContent(pageText, getPagesInFolder) {

    const lines = pageText.split("\n");

    let content = "";
    let inList = false;

    for (let line of lines) {
        line = line.trim();

        // If we were in a list, and the line doesn't start with a dash, close the list
        if ( inList && !line.startsWith("- ") ) {
            content += '</ul>';
            inList = false;
        }

        if ( line.startsWith("# ") ) {                  // If the line starts with a #, it's a heading
            content += `<h1>${line.slice(2)}</h1>`;
        } else if ( line.startsWith("## ") ) {          // If the line starts with ##, it's a subheading
            content += `<h2>${line.slice(3)}</h2>`;
        } else if ( line.startsWith("### ") ) {         // If the line starts with ###, it's a subsubheading
            content += `<h3>${line.slice(4)}</h3>`;
        } else if ( line.startsWith("- ") ) {           // If the line starts with a dash, it's a list item
            // If we weren't in a list before, start one
            if ( ! inList ) {
                content += '<ul>';
                inList = true;
            }
            content += `<li>${line.slice(2)}</li>`;
        } else if ( line.startsWith("@") ) {            // If the line starts with an @, it's a listing of pages in a folder
            const folder = line.slice(1);
            const pages = getPagesInFolder(folder);

            content += "<ul>";
            for (let page of pages) {
                const linkText = pageNameToLinkText(page);
                content += `<li><a href="${folder}/${page}">${linkText}</a></li>`;
            }
            content += "</ul>";
        } else if ( line !== "" ) {                  // If the line is not empty, it's a paragraph
            content += `<p>${line}</p>`;
        }

        // Now do inline elements, i.e. **bold** and *italic*
        content = content.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            .replace(/\*(.*?)\*/g, "<em>$1</em>");
        
        // Process hyperlinks, i.e. [text](url)
        content = content.replace(/\[(.*?)\]\((.*?)\)/g, "<a href='$2'>$1</a>");
    }

    return content;
}

/**
 * @param {string} pageName The name of a page
 * @returns {string} The page name converted to nicely formatted link text
 */
function pageNameToLinkText(pageName) {
    let linkText = pageName;

    // Remove the date prefix if there is one
    linkText = linkText.replace(/^\d{4}-\d{2}-\d{2}-/, "");  

    // Replace dashes with spaces
    linkText = linkText.replace(/-/g, " ");                  

    // Capitalize the first letter
    linkText = linkText.charAt(0).toUpperCase() + linkText.slice(1);

    return linkText;
}

export default { toHtml }