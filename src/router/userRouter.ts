import { Router } from 'express';

const router = Router();

// Add your user routes here
router.get('/', (req, res) => {
    res.status(200).json({ message: 'User routes' });
});

export default router;
