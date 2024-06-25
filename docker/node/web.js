const http = require('http');
const os = require('os');
const port = process.env.PORT || 5000;

http.createServer( (req, res) => {
  var url = req.url;

  if (url === "/foo") {
    res.writeHead(204);
    res.end();
  } else if (url === "/bar") {
    res.writeHead(304);
    res.end();
  } else if (url === "/html") {
    res.writeHead(200, undefined, {
      'Content-Type': 'text/html'
    });
    res.end('<h1>foobar</h1>');
  } else {
    res.writeHead(200);
    res.end(`Hello World from NodeJS on port ${port} from container ${os.hostname()}`);
  }
}).listen(port, () => {
  console.log("Listening on " + port);
});
