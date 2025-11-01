import express from "express";
import { verifyToken } from "../middleware/auth.js";
import User from "../models/User.js";
import Transaction from "../models/Transaction.js";

const router = express.Router();

// ✅ Check Balance (Protected)
router.get("/balance", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ balance: user.balance });
});

// ✅ Transaction History (Protected)
router.get("/transactions", verifyToken, async (req, res) => {
  const history = await Transaction.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(history);
});

// ✅ Transfer Money (Protected)
router.post("/transfer", verifyToken, async (req, res) => {
  const { amount } = req.body;
  const user = await User.findById(req.user.id);

  if (user.balance < amount)
    return res.status(400).json({ message: "Insufficient Balance ❌" });

  user.balance -= amount;
  await user.save();

  const txn = new Transaction({
    userId: req.user.id,
    amount,
    type: "debit"
  });

  await txn.save();
  res.json({ message: "Transfer Successful ✅" });
});

export default router;
