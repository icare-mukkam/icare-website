const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const admin = require("firebase-admin");

admin.initializeApp();

const db = admin.firestore();

const razorpayKeyId = defineSecret("RAZORPAY_KEY_ID");
const razorpayKeySecret = defineSecret("RAZORPAY_KEY_SECRET");

exports.createRazorpayOrder = onRequest(
  {
    region: "asia-south1",
    secrets: [razorpayKeyId, razorpayKeySecret],
    cors: true,
  },
  async (req, res) => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          success: false,
          message: "POST method required",
        });
      }

      const { amount, receipt } = req.body;

      if (!amount || Number(amount) <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid amount",
        });
      }

      const razorpay = new Razorpay({
        key_id: razorpayKeyId.value(),
        key_secret: razorpayKeySecret.value(),
      });

      const order = await razorpay.orders.create({
        amount: Math.round(Number(amount) * 100),
        currency: "INR",
        receipt: receipt || `icare_${Date.now()}`,
      });

      return res.status(200).json({
        success: true,
        order,
        keyId: razorpayKeyId.value(),
      });
    } catch (error) {
      console.error("Razorpay order error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create Razorpay order",
      });
    }
  }
);

exports.verifyRazorpayPayment = onRequest(
  {
    region: "asia-south1",
    secrets: [razorpayKeySecret],
    cors: true,
  },
  async (req, res) => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          success: false,
          message: "POST method required",
        });
      }

      const {
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
        orderData,
      } = req.body;

      if (
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          success: false,
          message: "Payment information missing",
        });
      }

      const body = `${razorpay_order_id}|${razorpay_payment_id}`;

      const expectedSignature = crypto
        .createHmac("sha256", razorpayKeySecret.value())
        .update(body)
        .digest("hex");

      const isValid = crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(razorpay_signature)
      );

      if (!isValid) {
        return res.status(400).json({
          success: false,
          message: "Payment verification failed",
        });
      }

      const order = {
        ...(orderData || {}),
        razorpayOrderId: razorpay_order_id,
        razorpayPaymentId: razorpay_payment_id,
        paymentStatus: "paid",
        status: "confirmed",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      const orderRef = await db.collection("orders").add(order);

      return res.status(200).json({
        success: true,
        message: "Payment verified successfully",
        orderId: orderRef.id,
      });
    } catch (error) {
      console.error("Payment verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Payment verification failed",
      });
    }
  }
);