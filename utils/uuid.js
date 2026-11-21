const UUID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// router.param callback: a malformed id can never match a row, so answer
// 404 instead of letting Postgres raise 22P02 (invalid uuid) -> 500.
// Usage: Router.param("id", uuidParam("Package"));
const uuidParam = (label) => (req, res, next, value) =>
    UUID_RE.test(value)
        ? next()
        : res.status(404).json({ message: `${label} not found` });

export { uuidParam };
