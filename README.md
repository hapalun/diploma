# diploma
my diploma project

Dynamic DOM-based XSS analyser

Requires:
1. Node.js
2. falafel: https://github.com/substack/node-falafel
3. Any browser (tool was tested in Google Chrome)

To instrument code:

node falafelPassVector.js input.js output.js
node falafelInstrument.js output.js instrumented.html

To perfor analysis simply open instrumented.html in browser. If alert window poped up, then program is vulnerable. Sequence of methods might be resposible for this vulnerability can be found in browser console.

