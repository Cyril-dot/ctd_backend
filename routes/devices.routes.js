import express from "express";
import {
    registerDevice,
    listDevices,
    removeDevice,
    connectDevice,
    getConnection,
} from "../controllers/devices.js";
import { rateLimit } from "../middleware/rateLimit.js";
import { uuidParam } from "../utils/uuid.js";

const DevicesRouter = express.Router();
DevicesRouter.param("id", uuidParam("Device"));

// 10/min per signed-in user (falls back to IP)
const connectLimit = rateLimit({
    key: (req) => `connect:${req.authUser?.id ?? req.ip ?? "unknown"}`,
    limit: 10,
    windowSeconds: 60,
});

DevicesRouter.get("/", listDevices);
DevicesRouter.post("/", registerDevice);
DevicesRouter.post("/:id/connect", connectLimit, connectDevice);
DevicesRouter.get("/:id/connection", getConnection);
DevicesRouter.delete("/:id", removeDevice);

export default DevicesRouter;
