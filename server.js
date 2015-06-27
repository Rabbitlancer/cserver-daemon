var http = require('http');
const PORT = 2304;

function handleRequest(req,res) {
	res.end('Hi, I am from Node');
}

var server = http.createServer(handleRequest);

server.listen(PORT, function (){
	console.log('Server started');});