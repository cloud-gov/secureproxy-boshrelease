const http = require('http');
const os = require('os');
const port = process.env.PORT || 5000;

http.createServer( (req, res) => {
  var url = req.url;

  if (url === "/foo") {
    res.writeHead(204);
    res.end();
  } else {
    res.writeHead(200);
    res.end(`Hello World from NodeJS on port ${port} from container ${os.hostname()}`);
  }
}).listen(port, () => {
  console.log("Listening on " + port);
});
