import express from "express";
import { listNotifications } from "../controllers/notifications.js";

const NotificationsRouter = express.Router();
NotificationsRouter.get("/", listNotifications);

export default NotificationsRouter;
