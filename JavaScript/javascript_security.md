# JavaScript Security Vulnerabilities

## Overview
JavaScript is the language of the browser making it one of the most popular languages available and used.
Since JavaScript interacts with the DOM (Document Object Model), threat actors could potentially introduce malicious code that will run on client browsers, allowing them to exploit a large set of attacks, steal sensitive information, download malware payloads, inject key loggers for stealing sensitive information among other risks.

When writing JavaScript code, developers could mistakenly introduce vulnerabilities, allowing an adversary to run arbitrary code on the client's machine.

The most effective way to prevent vulnerabilities in JavaScript code is by understanding them in a way that proper controls can be implemented.

JavaScript Security concerns involve not only the code the programmer writes, it also involves the libraries he uses; as programming is a social art, the proliferation of libraries that are shared via popular package management tools, they pose other risks such as remote code execution and stealing credentials or even potential backdoors could be introduced.

Therefore, when adding a third-party library into the code, a proper threat modeling needs to be conducted to determine:
* Collaboration: How active is the development, what is the issues ratio, how often changes and enhancements are pushed.
* Security vulnerabilities: How is the vulnerability lifecycle management of that package? Is the maintainer aware of such vulnerabilities and diligently fixing them?
* Proper code review: Bugs hides in multiple manners, a proper security code review on open source modules/packages and libraries must be conducted before approving or using a third-party library.
* Subscribe to the repository or security advisories

## New attack vectors using JavaScript

As the current threat landscape continues to evolve, threat actors continue to enhance their tactics and techniques to compromise organizations. According to the *MITRE ATT&CK Framework*, adversaries are using JavaScript to execute various behaviors. ATT&CK Tactic number T1059.007 (Execution) called Command and Scripting Interpreter: JavaScript/JSCript, describe how criminals uses JavaScript language to perform their actions impacting users.

Such abuse of this language involves:

* JavaScript code being used by attackers for drive-by downloads and Command and Control (C2) communications.
* JavaScript code to steal payment cards from e-commerce web sites.
* Usage of JavaScript code to infect client machines.
* Code execution on victim's machines
* Some malware campaigns have used JavaScript for establishing persistence on the organization's network.
  
As JavaScript platforms proliferates (both front-end and back-end) is necessary to understand the different security risks that a threat actor can exploit. 