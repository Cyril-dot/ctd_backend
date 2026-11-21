import express from "express";
import {
    listSubscriptions,
    getActiveSubscription,
    createSubscription,
    suspendSubscription,
    renewSubscription,
} from "../controllers/subscriptions.js";
import { uuidParam } from "../utils/uuid.js";

const SubscriptionsRouter = express.Router();
SubscriptionsRouter.param("id", uuidParam("Subscription"));

SubscriptionsRouter.get("/", listSubscriptions);
SubscriptionsRouter.get("/active", getActiveSubscription);
SubscriptionsRouter.post("/", createSubscription);
SubscriptionsRouter.post("/:id/suspend", suspendSubscription);
SubscriptionsRouter.post("/:id/renew", renewSubscription);

export default SubscriptionsRouter;
