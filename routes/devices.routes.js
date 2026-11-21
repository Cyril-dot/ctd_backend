import express from "express";
import { registerDevice, listDevices, removeDevice } from "../controllers/devices.js";
import { uuidParam } from "../utils/uuid.js";

const DevicesRouter = express.Router();
DevicesRouter.param("id", uuidParam("Device"));

DevicesRouter.get("/", listDevices);
DevicesRouter.post("/", registerDevice);
DevicesRouter.delete("/:id", removeDevice);

export default DevicesRouter;
