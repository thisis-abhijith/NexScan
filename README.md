![WhatsApp Image 2024-03-29 at 22 33 24_e939a737](https://github.com/thisis-abhijith/NexScan/assets/137030384/9c3d3b47-1dbe-40da-af7a-dfc4a9af9a32)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Website Security Scanner</h1>
    <h2>Description</h2>
    <p>This script is a security scanner for websites, designed to identify and report various security vulnerabilities and sensitive data exposures. It performs a range of analyses including scanning for sensitive data patterns, analyzing cookies and headers, testing for Cross-Site Scripting (XSS) and SQL Injection vulnerabilities, and enumerating subdomains.</p>

   <h2>Features</h2>
    <ul>
        <li>Detection of sensitive data such as emails, passwords, credit card numbers, social security numbers, and phone numbers.</li>
        <li>Security analysis of cookies including HttpOnly, Secure, and SameSite attributes.</li>
        <li>Header analysis for security-related headers.</li>
        <li>Content Security Policy (CSP) analysis.</li>
        <li>Testing for Cross-Site Scripting (XSS) vulnerabilities.</li>
        <li>Testing for SQL Injection vulnerabilities.</li>
        <li>Subdomain enumeration.</li>
    </ul>
    <h2>Requirements</h2>
    <ul>
        <li>Python 3.11</li>
        <li>Required Python packages: <code>requests</code>, <code>dnspython</code>, <code>beautifulsoup4</code></li>
    </ul>
    <h2>Usage</h2>
    <ol>
        <li>Clone the repository or download the script.</li>
        <li>Install the required Python packages using pip:
            <pre><code>pip install requests dnspython beautifulsoup4</code></pre>
        </li>
        <li>Run the script:
            <pre><code>python website_security_scanner.py</code></pre>
        </li>
        <li>Follow the prompts to enter the target URL and parameters.</li>
    </ol>
    <h2>Additional Information</h2>
    <ul>
        <li>The script uses regular expressions to identify sensitive data patterns. You can add more patterns in the <code>SENSITIVE_DATA_PATTERNS</code> dictionary if needed
        </li>
        <li>Make sure to use the script responsibly and only on websites that you have permission to test.</li>
        <li>Feel free to contribute to the development of this script by submitting pull requests or reporting issues on the GitHub repository.</li>
    </ul>
    <h2>Contact</h2>
    <p>For inquiries, you can reach me on <a href="https://www.linkedin.com/in/abhijith-soman-5b597225b//">LinkedIn</a>.</p>
</body>
</html>
