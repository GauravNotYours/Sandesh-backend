// Vercel catch-all wrapper for the Express app.
// Deploy this folder as your backend, and point requests to `/api/*`.
const app = require('../backend')

module.exports = (req, res) => {
  return app(req, res)
}

