require('dotenv').config();
const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
const admin = require('firebase-admin');
const stripe = require('stripe')(process.env.STRIPE_SCRET_KEY);


const port = process.env.PORT || 3000;

// --------------------
// Firebase Setup
// --------------------
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// --------------------
// Express App & Middleware
// --------------------
const app = express();
app.use(cors());
app.use(express.json());

// --------------------
// MongoDB Setup
// --------------------
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

// --------------------
// JWT Middleware
// --------------------
const verifyJWT = async (req, res, next) => {
  const authHeader = req?.headers?.authorization;
  console.log("Authorization Header (Bearer <token>):", authHeader);

  if (!authHeader) return res.status(401).send({ message: "Unauthorized Access!" });

  const token = authHeader.split(" ")[1]; // extract the token

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    console.log("Decoded Token:", decoded);
    next();
  } catch (err) {
    if (err.code === "auth/id-token-expired") {
      return res.status(401).send({ message: "Token expired. Please login again." });
    }
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};


// --------------------
// Role Middleware
// --------------------
const verifyRole = (requiredRole) => async (req, res, next) => {
  try {
    if (!req.tokenEmail) return res.status(401).json({ message: "Unauthorized: No token email" });
    const user = await usersCollection.findOne({ email: req.tokenEmail });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.role.toLowerCase() !== requiredRole.toLowerCase()) return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
    next();
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err });
  }
};

// --------------------
// MongoDB Connection & Routes
// --------------------
let usersCollection, tuitionsCollection, contactCollection, paymentsCollection;

async function run() {
  try {
    await client.db('admin').command({ ping: 1 });
    console.log('Successfully connected to MongoDB!');

    const database = client.db("edumatch");
    usersCollection = database.collection("users");
    tuitionsCollection = database.collection("tuitions");
    contactCollection = database.collection("contacts");
    paymentsCollection = database.collection("payments");




    // ------------------------
    // Create Stripe Checkout Session
    // ------------------------
    app.post("/create-checkout-session", async (req, res) => {
      console.log("[create-checkout-session] Request body:", req.body);

      let { budget, tuitionTitle, studentEmail, tutorEmail, tuitionId } = req.body;

      if (!budget || !tuitionTitle || !tutorEmail || !tuitionId) {
        console.log("[create-checkout-session] Missing required fields");
        return res.status(400).json({ message: "Missing required payment fields" });
      }

      // If studentEmail isn't provided, try to resolve it from the tuition record
      if (!studentEmail && ObjectId.isValid(tuitionId)) {
        try {
          const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId) });
          if (tuition && tuition.studentEmail) {
            studentEmail = tuition.studentEmail;
          }
        } catch (err) {
          console.warn("[create-checkout-session] Failed to resolve studentEmail from tuitionId", err);
        }
      }

      if (!studentEmail) {
        console.log("[create-checkout-session] Missing studentEmail after attempt to resolve from tuitionId");
        return res.status(400).json({ message: "Missing studentEmail for payment" });
      }

      const amount = Math.round(parseFloat(budget) * 100);
      if (isNaN(amount) || !isFinite(amount)) return res.status(400).json({ message: "Invalid budget" });

      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: amount,
                product_data: { name: tuitionTitle },
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          metadata: { tuitionId, tutorEmail, studentEmail, budget, tuitionTitle },
          customer_email: studentEmail,
          success_url: `${process.env.SITE_DOMAIN}/dashboard/student/payments/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/student/payments/cancelled`,
        });

        console.log("[create-checkout-session] Stripe session created:", session.id);
        res.json({ url: session.url });
      } catch (err) {
        console.error("[create-checkout-session] Stripe error:", err);
        res.status(500).json({ message: err.message });
      }
    });

    // ------------------------
    // Verify Payment Route
    // ------------------------
    app.get("/student/payment/verify", verifyJWT, async (req, res) => {
      const { session_id } = req.query;

      if (!session_id) return res.status(400).json({ message: "Session ID is required" });

      try {
        console.log("[verify] Retrieving Stripe session:", session_id, "for user:", req.tokenEmail);
        const session = await stripe.checkout.sessions.retrieve(session_id);

        if (!session) return res.status(404).json({ message: "Stripe session not found" });

        if (session.payment_status !== "paid")
          return res.status(400).json({ message: "Payment not completed" });

        const { tuitionId, studentEmail, tutorEmail, tuitionTitle, budget } = session.metadata || {};
        if (!tuitionId || !studentEmail || !tutorEmail) {
          return res.status(400).json({ message: "Required payment metadata missing" });
        }

        // Log when metadata studentEmail doesn't match the authenticated user
        if ((req.tokenEmail || "").toLowerCase().trim() !== (studentEmail || "").toLowerCase().trim()) {
          console.warn('[verify] tokenEmail does not match metadata studentEmail', req.tokenEmail, studentEmail);
        }

        // Find the tuition by the authenticated student to ensure the user owns it
        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId), studentEmail: req.tokenEmail });
        if (!tuition) return res.status(404).json({ message: "Tuition not found" });

        // Build updated applications array with case-insensitive email match
        const normalizedTutorEmail = (tutorEmail || "").toLowerCase().trim();
        console.log('[verify] existing applications:', JSON.stringify(tuition.applications));
        const updatedApplications = (tuition.applications || []).map(app => {
          const appEmail = (app?.tutorEmail || "").toLowerCase().trim();
          const approved = appEmail === normalizedTutorEmail;
          return { ...app, status: approved ? "Approved" : "Rejected" };
        });
        console.log('[verify] updated applications:', JSON.stringify(updatedApplications));

        const updateRes = await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $set: { applications: updatedApplications } }
        );
        console.log('[verify] update result:', updateRes.result || updateRes);

        // Record payment in payments collection (avoid duplicates)
        try {
          const sessionIdStr = session.id || session_id;
          const existingPayment = await paymentsCollection.findOne({ sessionId: sessionIdStr });
          let paymentDoc = null;
          // Stripe returns amount_total in cents. Convert to dollars for storage by dividing by 100.
          const amountCents = session.amount_total || (budget ? Math.round(parseFloat(budget) * 100) : null);
          const amount = amountCents ? (amountCents / 100) : null;
          if (!existingPayment) {
            paymentDoc = {
              sessionId: sessionIdStr,
              paymentIntent: session.payment_intent || null,
              paymentIntentId: session.payment_intent || null,
              tuitionId: new ObjectId(tuitionId),
              tuitionTitle,
              studentEmail,
              tutorEmail,
              amount: amount,
              amount_cents: amountCents,
              currency: session.currency || 'usd',
              metadata: session.metadata || {},
              created_at: new Date().toISOString(),
            };
            const insertRes = await paymentsCollection.insertOne(paymentDoc);
            paymentDoc._id = insertRes.insertedId;
          } else {
            paymentDoc = existingPayment;
          }

          return res.json({
            message: "Payment verified successfully and tutor approved",
            amount: amount,
            tuitionTitle,
            tutorEmail,
            applications: updatedApplications,
            payment: paymentDoc,
          });
        } catch (err) {
          console.error("[verify] Error saving payment record:", err);
        }

        const fallbackAmountCents = session.amount_total || (budget ? Math.round(parseFloat(budget) * 100) : null);
        const fallbackAmount = fallbackAmountCents ? fallbackAmountCents / 100 : null;
        res.json({
          message: "Payment verified successfully and tutor approved",
          amount: fallbackAmount,
          tuitionTitle,
          tutorEmail,
          applications: updatedApplications
        });
      } catch (err) {
        console.error("[verify] Unexpected error:", err);
        res.status(500).json({ message: "Server error verifying payment", error: err.message });
      }
    });

    // ------------------------
    // Public debug route (optional)
    // ------------------------
    app.get("/student/payment/verify/public", async (req, res) => {
      const { session_id } = req.query;
      try {
        if (!session_id) return res.status(400).json({ message: "Session ID is required" });
        const session = await stripe.checkout.sessions.retrieve(session_id);
        return res.json({ ok: true, session });
      } catch (err) {
        console.error("[verify/public] error:", err);
        return res.status(500).json({ message: "Server error retrieving session" });
      }
    });

    // payment history route
    app.get("/student/payments", verifyJWT, async (req, res) => {
      const studentEmail = req.tokenEmail; // from JWT
      const payments = await paymentsCollection
        .find({ studentEmail })
        .toArray();
      res.json(payments);
    });





    app.post("/contact", async (req, res) => {
      const { name, email, message } = req.body;
      if (!name || !email || !message) return res.status(400).json({ error: "All fields are required" });

      const contactData = { name, email, message, created_at: new Date().toISOString() };
      const result = await contactCollection.insertOne(contactData);
      res.status(201).json({ message: "Message sent successfully", data: result });
    });

    // --------------------
    // User Routes
    // --------------------
    app.post('/user', async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      if (!userData.role) userData.role = "student";

      const query = { email: userData.email };
      const alreadyExists = await usersCollection.findOne(query);

      if (alreadyExists) {
        const result = await usersCollection.updateOne(query, { $set: { last_loggedIn: new Date().toISOString() } });
        return res.send(result);
      }

      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });

    app.get('/user/role', verifyJWT, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.tokenEmail });
      if (!user) return res.status(404).json({ success: false, message: 'User not found' });
      res.status(200).json({ success: true, role: user.role });
    });

    // --------------------
    // Admin Routes
    // --------------------
    app.get("/admin/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      try {
        const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
        res.status(200).json({ success: true, total: users.length, data: users });
      } catch (err) {
        res.status(500).json({ success: false, message: "Failed to fetch user list" });
      }
    });

    app.put("/admin/users/role/:id", verifyJWT, verifyRole("admin"), async (req, res) => {
      const { id } = req.params;
      const { role } = req.body;
      if (!["Student", "Tutor", "Admin"].includes(role)) return res.status(400).json({ message: "Invalid role" });
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid user ID" });

      const user = await usersCollection.findOne({ _id: new ObjectId(id) });
      if (!user) return res.status(404).json({ message: "User not found" });
      if (user.email === req.tokenEmail && role !== "Admin") return res.status(403).json({ message: "Cannot demote yourself" });

      const result = await usersCollection.findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: { role } },
        { returnDocument: "after", projection: { password: 0 } }
      );
      res.status(200).json({ message: "User role updated", updatedUser: result.value });
    });

    app.get("/admin/tuitions/all", verifyJWT, verifyRole("admin"), async (req, res) => {
      try {
        const tuitions = await tuitionsCollection.find({}).toArray();
        res.status(200).json(tuitions);
      } catch (err) {
        res.status(500).json({ message: "Failed to fetch all tuitions" });
      }
    });

    app.put("/admin/tuitions/status/:id", verifyJWT, verifyRole("admin"), async (req, res) => {
      const { status } = req.body;
      const { id } = req.params;
      if (!["Approved", "Rejected"].includes(status)) return res.status(400).json({ message: "Invalid status" });
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid tuition ID" });

      const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
      if (!tuition) return res.status(404).json({ message: "Tuition not found" });

      await tuitionsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
      const updatedTuition = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
      res.status(200).json({ message: `Tuition ${status}`, tuition: updatedTuition });
    });

    app.get("/admin/stats", verifyJWT, verifyRole("admin"), async (req, res) => {
      try {
        const [
          totalUsers,
          totalTuitions,
          activeTutors,
          pendingApprovals,
          totalReports,
          revenueResult,
        ] = await Promise.all([
          usersCollection.countDocuments(),
          tuitionsCollection.countDocuments(),
          usersCollection.countDocuments({ role: { $regex: /^tutor$/i } }),
          tuitionsCollection.countDocuments({ status: "Pending" }),
          contactCollection.countDocuments(),
          paymentsCollection.aggregate([
            {
              $group: {
                _id: null,
                total: { $sum: "$amount" },
              },
            },
          ]).toArray(),
        ]);

        const monthlyRevenue = revenueResult[0]?.total || 0;

        res.json({
          totalUsers,
          totalTuitions,
          activeTutors,
          pendingApprovals,
          totalReports,
          monthlyRevenue,
        });
      } catch (error) {
        console.error("Admin stats error:", error);
        res.status(500).json({ message: "Failed to load admin statistics" });
      }
    });

    // ================================
    // Admin Reports / Analytics
    // ================================
    app.get("/admin/reports/overview", verifyJWT, verifyRole("admin"), async (req, res) => {
      try {
        const [
          totalTuitions,
          pendingTuitions,
          approvedTuitions,
          totalTutors,
          totalStudents,
          totalApplicationsAgg,
          revenueAgg,
        ] = await Promise.all([
          tuitionsCollection.countDocuments(),
          tuitionsCollection.countDocuments({ status: "Pending" }),
          tuitionsCollection.countDocuments({ status: "Approved" }),
          usersCollection.countDocuments({ role: "tutor" }),
          usersCollection.countDocuments({ role: "student" }),

          // Total applications (sum of applications array length)
          tuitionsCollection.aggregate([
            {
              $project: {
                count: { $size: { $ifNull: ["$applications", []] } },
              },
            },
            { $group: { _id: null, total: { $sum: "$count" } } },
          ]).toArray(),

          // Real revenue from payments (Stripe)
          paymentsCollection.aggregate([
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ]).toArray(),
        ]);

        const totalApplications = totalApplicationsAgg[0]?.total || 0;
        const totalRevenue = revenueAgg[0]?.total || 0;

        res.json({
          totalTuitions,
          pendingTuitions,
          approvedTuitions,
          totalTutors,
          totalStudents,
          totalApplications,
          totalRevenue,
          monthlyGrowth: 15.5, // can be dynamic later
        });
      } catch (err) {
        console.error("Admin report error:", err);
        res.status(500).json({ message: "Failed to load reports" });
      }
    }
    );



    // --------------------
    // Tutor Routes
    // --------------------
    app.get("/tutors", async (req, res) => {
      const tutors = await usersCollection.find({ role: { $regex: /^tutor$/i } }).toArray();
      res.status(200).json({ success: true, total: tutors.length, data: tutors });
    });

    app.get("/tutor/revenue-history", verifyJWT, verifyRole("Tutor"), async (req, res) => {
      try {
        const tutorEmail = req.tokenEmail;

        const payments = await paymentsCollection
          .find({ tutorEmail })
          .sort({ created_at: -1 })
          .toArray();

        res.json(payments);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });


    app.get("/tutors/latest", async (req, res) => {
      const tutors = await usersCollection.find({ role: "tutor" }).sort({ _id: -1 }).limit(5).toArray();
      res.status(200).json({ success: true, data: tutors });
    });

    app.get("/tutors/:id", async (req, res) => {
      const tutor = await usersCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!tutor) return res.status(404).json({ success: false, message: "Tutor not found" });
      res.status(200).json(tutor);
    });

    app.get("/tutors/email/:email", async (req, res) => {
      const tutor = await usersCollection.findOne({ email: req.params.email, role: { $regex: /^tutor$/i } });
      if (!tutor) return res.status(404).json({ success: false, message: "Tutor not found" });
      res.status(200).json({ success: true, name: tutor.name, email: tutor.email, tutorId: tutor._id });
    });

    app.put("/tutor/apply/:tuitionId", verifyJWT, verifyRole("tutor"), async (req, res) => {
      const { tuitionId } = req.params;
      const tutorEmail = req.tokenEmail;
      const { message } = req.body;

      if (!ObjectId.isValid(tuitionId)) return res.status(400).json({ message: "Invalid tuition ID" });

      const alreadyApplied = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId), "applications.tutorEmail": tutorEmail });
      if (alreadyApplied) return res.status(400).json({ message: "Already applied" });

      const application = { tutorEmail, status: "Pending", appliedAt: new Date().toISOString() };
      if (message) application.message = message;

      await tuitionsCollection.updateOne(
        { _id: new ObjectId(tuitionId) },
        { $push: { applications: application } }
      );

      res.json({ success: true, message: "Applied successfully" });
    });

    app.get("/tutor/applications", verifyJWT, verifyRole("tutor"), async (req, res) => {
      const tutorEmail = req.tokenEmail;
      const tuitions = await tuitionsCollection.find({ "applications.tutorEmail": tutorEmail }).toArray();

      const tutorApplications = tuitions.map(tuition => {
        const myApp = tuition.applications.find(a => a.tutorEmail === tutorEmail);
        return {
          _id: tuition._id,
          title: tuition.title,
          description: tuition.description,
          budget: tuition.budget,
          location: tuition.location,
          mode: tuition.mode,
          schedule: tuition.schedule,
          applicationStatus: myApp?.status || "Pending",
          appliedAt: myApp?.appliedAt,
          message: myApp?.message || "",
        };
      });

      res.status(200).json({ success: true, data: tutorApplications });
    });

    // Withdraw an application (tutor removes their application)
    app.put("/tutor/application/withdraw/:tuitionId", verifyJWT, verifyRole("tutor"), async (req, res) => {
      try {
        const { tuitionId } = req.params;
        const tutorEmail = req.tokenEmail;

        if (!ObjectId.isValid(tuitionId)) return res.status(400).json({ message: "Invalid tuition ID" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId) });
        if (!tuition) return res.status(404).json({ message: "Tuition not found" });

        const appEntry = (tuition.applications || []).find(a => a.tutorEmail === tutorEmail);
        if (!appEntry) return res.status(404).json({ message: "Application not found" });
        if (appEntry.status && appEntry.status !== "Pending") return res.status(400).json({ message: "Cannot withdraw non-pending application" });

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $pull: { applications: { tutorEmail } } }
        );

        res.json({ success: true, message: "Application withdrawn" });
      } catch (err) {
        console.error("Withdraw application error:", err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // Edit an application (update message) - tutor only
    app.put("/tutor/application/:tuitionId", verifyJWT, verifyRole("tutor"), async (req, res) => {
      try {
        const { tuitionId } = req.params;
        const { message } = req.body;
        const tutorEmail = req.tokenEmail;

        if (!ObjectId.isValid(tuitionId)) return res.status(400).json({ message: "Invalid tuition ID" });
        if (typeof message !== 'string') return res.status(400).json({ message: "Message must be a string" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId) });
        if (!tuition) return res.status(404).json({ message: "Tuition not found" });

        const appEntry = (tuition.applications || []).find(a => a.tutorEmail === tutorEmail);
        if (!appEntry) return res.status(404).json({ message: "Application not found" });
        if (appEntry.status && appEntry.status !== "Pending") return res.status(400).json({ message: "Cannot edit non-pending application" });

        const updateRes = await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId), "applications.tutorEmail": tutorEmail },
          { $set: { "applications.$.message": message, "applications.$.updatedAt": new Date().toISOString() } }
        );

        return res.json({ success: true, message: "Application updated", updateResult: updateRes });
      } catch (err) {
        console.error("Edit application error:", err);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.get("/tutor/ongoing", verifyJWT, verifyRole("tutor"), async (req, res) => {
      const tutorEmail = req.tokenEmail;
      const ongoing = await tuitionsCollection.find({ "applications": { $elemMatch: { tutorEmail, status: "Approved" } } }).toArray();
      res.status(200).json({ success: true, data: ongoing });
    });

    // --------------------
    // Tuition Routes
    // --------------------
    app.get("/tuitions", async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;
      const sortOptions = { budget: { budget: -1 }, date: { created_at: -1 } };
      const sortBy = sortOptions[req.query.sort] || sortOptions.date;

      // Build query with optional server-side search and filters
      const search = (req.query.search || "").trim();
      let query = { status: "Approved" };
      if (search) {
        const regex = new RegExp(search, "i");
        const or = [
          { title: { $regex: regex } },
          { subject: { $regex: regex } },
          { description: { $regex: regex } },
          { location: { $regex: regex } },
        ];
        query = { ...query, $or: or };
      }

      // Optional strict filters
      const tuitionClass = (req.query.class || "").trim();
      const subjectFilter = (req.query.subject || "").trim();
      const locationFilter = (req.query.location || "").trim();

      if (tuitionClass) {
        query.class = tuitionClass;
      }
      if (subjectFilter) {
        query.subject = subjectFilter;
      }
      if (locationFilter) {
        query.location = { $regex: new RegExp(locationFilter, "i") };
      }

      const total = await tuitionsCollection.countDocuments(query);
      const tuitions = await tuitionsCollection.find(query).skip(skip).limit(limit).sort(sortBy).toArray();

      res.status(200).json({ success: true, page, limit, total, totalPages: Math.ceil(total / limit), data: tuitions });
    });

    app.get("/tuitions/latest", async (req, res) => {
      const latestTuitions = await tuitionsCollection.find({}).sort({ created_at: -1 }).limit(3).toArray();
      res.status(200).json(latestTuitions);
    });

    app.get("/tuitions/:id", async (req, res) => {
      const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!tuition) return res.status(404).json({ success: false, message: 'Tuition not found' });
      res.status(200).json(tuition);
    });

    // --------------------
    // Student Routes
    // --------------------
    app.get("/student/tuitions", verifyJWT, verifyRole("student"), async (req, res) => {
      const tuitions = await tuitionsCollection.find({ studentEmail: req.tokenEmail }).toArray();
      res.status(200).json(tuitions);
    });

    app.post("/student/tuitions", verifyJWT, verifyRole("student"), async (req, res) => {
      const newTuition = { ...req.body, studentEmail: req.tokenEmail, status: "Pending", applications: [], created_at: new Date().toISOString() };
      const result = await tuitionsCollection.insertOne(newTuition);
      res.status(201).json(result);
    });

    app.put("/student/tuitions/:id", verifyJWT, verifyRole("student"), async (req, res) => {
      const { id } = req.params;
      if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid tuition ID" });
      if (Object.keys(req.body).length === 0) return res.status(400).json({ message: "No updatable fields provided" });

      const result = await tuitionsCollection.updateOne({ _id: new ObjectId(id), studentEmail: req.tokenEmail }, { $set: req.body });
      if (result.matchedCount === 0) return res.status(404).json({ message: "Tuition not found" });

      const updated = await tuitionsCollection.findOne({ _id: new ObjectId(id) });
      res.status(200).json(updated);
    });

    app.delete("/student/tuitions/:id", verifyJWT, verifyRole("student"), async (req, res) => {
      const { id } = req.params;
      const result = await tuitionsCollection.deleteOne({ _id: new ObjectId(id), studentEmail: req.tokenEmail });
      if (!result.deletedCount) return res.status(404).json({ message: "Tuition not found" });
      res.json({ message: "Tuition deleted successfully" });
    });

    app.get("/student/applications", verifyJWT, verifyRole("student"), async (req, res) => {
      const tuitions = await tuitionsCollection
        .find({ studentEmail: req.tokenEmail })
        .toArray();

      const applications = tuitions.flatMap(t =>
        (t.applications || []).map(a => ({
          tuitionId: t._id,
          tuitionTitle: t.title,
          budget: t.budget,          // <-- REQUIRED FOR STRIPE
          class: t.class,
          subject: t.subject,

          tutorEmail: a.tutorEmail,
          studentEmail: t.studentEmail,
          status: a.status || "Pending",
          appliedAt: a.appliedAt
        }))
      );

      res.json({ applications });
    });


    app.patch("/student/applications/approve", verifyJWT, verifyRole("student"), async (req, res) => {
      try {
        const { tuitionId, tutorEmail } = req.body;

        if (!tuitionId || !tutorEmail) return res.status(400).json({ message: "Tuition ID and tutor email are required" });

        if (!ObjectId.isValid(tuitionId)) return res.status(400).json({ message: "Invalid tuition ID" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId), studentEmail: req.tokenEmail });
        if (!tuition) return res.status(404).json({ message: "Tuition not found" });

        if (!Array.isArray(tuition.applications) || tuition.applications.length === 0) {
          return res.status(400).json({ message: "No applications found for this tuition" });
        }

        const normalizedTutorEmail = (tutorEmail || "").toLowerCase().trim();
        console.log('[verify] existing applications:', JSON.stringify(tuition.applications));
        const updatedApplications = tuition.applications.map(app => {
          const appEmail = (app?.tutorEmail || "").toLowerCase().trim();
          const approved = appEmail === normalizedTutorEmail;
          return { ...app, status: approved ? "Approved" : "Rejected" };
        });
        console.log('[verify] updated applications:', JSON.stringify(updatedApplications));

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $set: { applications: updatedApplications } }
        );

        console.log('[verify] update result:', updateRes);
        res.json({ message: "Application approved", applications: updatedApplications });
      } catch (err) {
        console.error("Approve route error:", err);
        res.status(500).json({ message: "Internal server error", error: err.message });
      }
    });


    app.patch("/student/applications/reject", verifyJWT, verifyRole("student"), async (req, res) => {
      try {
        const { tuitionId, tutorEmail } = req.body;

        if (!tuitionId || !tutorEmail) return res.status(400).json({ message: "Tuition ID and tutor email are required" });

        if (!ObjectId.isValid(tuitionId)) return res.status(400).json({ message: "Invalid tuition ID" });

        const tuition = await tuitionsCollection.findOne({ _id: new ObjectId(tuitionId), studentEmail: req.tokenEmail });
        if (!tuition) return res.status(404).json({ message: "Tuition not found" });

        if (!Array.isArray(tuition.applications) || tuition.applications.length === 0) {
          return res.status(400).json({ message: "No applications found for this tuition" });
        }

        const updatedApplications = tuition.applications.map(app =>
          app.tutorEmail === tutorEmail ? { ...app, status: "Rejected" } : app
        );

        await tuitionsCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $set: { applications: updatedApplications } }
        );

        res.json({ message: "Application rejected", applications: updatedApplications });
      } catch (err) {
        console.error("Reject route error:", err);
        res.status(500).json({ message: "Internal server error", error: err.message });
      }
    });


  } finally {
    // Don't close client; keep server running
  }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server is running on port ${port}`));
