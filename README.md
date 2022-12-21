# script
This code uses Sublist3r to retrieve a list of subdomains for the inherited domain, and then uses Wfuzz and Wapiti to check each subdomain for vulnerabilities. The results of the checks are stored in a list and printed to the console at the end.

# demo

is a sample Python code that demonstrates how you might convert terminal commands to Python programs:
This code defines a terminal command as a string, and then uses the subprocess module to execute the command. The output of the command is captured and stored in a variable, which can then be printed or used in other ways in your Python program.

To convert multiple terminal commands to Python programs, you can simply define each command as a string and execute it using the subprocess module in a similar manner.


# xss ideas 

Cross-Site Scripting (XSS) is a type of web security vulnerability that allows an attacker to inject malicious code into a web page. XSS payloads are the pieces of malicious code that are injected into a web page through an XSS vulnerability.

Here is a list of some common XSS payloads:

<script>alert(1)</script>: This payload displays a pop-up alert box with the message "1" when the page is loaded.
<img src="x" onerror="alert(1)">: This payload displays an alert box when an error occurs while loading the image.

<body onload="alert(1)">: This payload displays an alert box when the page finishes loading.
<input type="text" value=""><script>alert(1)</script>: This payload displays an alert box when the user focuses on the input field.

<svg onload="alert(1)">: This payload displays an alert box when the SVG element finishes loading.

<link rel="stylesheet" href="x" onload="alert(1)">: This payload displays an alert box when the stylesheet finishes loading.
<iframe src="javascript:alert(1)">: This payload displays an alert box when the iframe finishes loading.
It's important to note that XSS payloads can be used for malicious purposes, and it is not recommended to use them on web pages that you do not own or have permission to modify. XSS vulnerabilities can be exploited to steal sensitive information, such as login credentials, and can cause serious harm to web users. It is important to properly validate and sanitize user input to prevent XSS vulnerabilities in your own web applications.



