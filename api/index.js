module.exports = (req, res) => {
  return res.status(200).json({
    ok: true,
    service: 'sandesh-backend',
    health: '/api/health',
    message: 'Use the /api/* routes for the backend API.',
  })
}
