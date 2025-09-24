const path = require("path");
const express = require("express");
const router = require("./routes/index");
const assistantRoute = require("./routes/assistant");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use("/assistant", assistantRoute); // <= Gemini proxy
app.use("/", router);

app.listen(4000, () => console.log("Server running on http://localhost:4000"));
