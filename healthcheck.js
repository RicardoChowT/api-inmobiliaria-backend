// healthcheck.js - verificación de salud para Docker
const http = require("http");

const options = {
  host: "localhost",
  port: 3001,
  path: "/health",
  timeout: 5000,
};

const request = http.request(options, (res) => {
  console.log(`✅ Backend saludable - STATUS: ${res.statusCode}`);
  process.exit(0);
});

request.on("error", function (err) {
  console.log("❌ Backend no responde:", err.message);
  process.exit(1);
});

request.end();
