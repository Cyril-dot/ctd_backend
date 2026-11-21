import express from "express";
import { listPackages, getPackage, createPackage } from "../controllers/packages.js";
import { requireAdmin } from "../middleware/requireAdmin.js";
import { uuidParam } from "../utils/uuid.js";

const PackagesRouter = express.Router();
PackagesRouter.param("id", uuidParam("Package"));

PackagesRouter.get("/", listPackages);
PackagesRouter.get("/:id", getPackage);
PackagesRouter.post("/", requireAdmin, createPackage);

export default PackagesRouter;
