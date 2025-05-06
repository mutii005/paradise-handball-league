export default async function handler(req, res) {
  if (req.method === 'POST') {
    const { name, email, phone, college, upi } = req.body;

    if (!name || !email || !phone || !college || !upi) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    console.log("Received registration:", { name, email, phone, college, upi });

    return res.status(200).json({ success: true, message: "Registration successful." });
  } else {
    res.setHeader("Allow", ["POST"]);
    res.status(405).end(`Method ${req.method} Not Allowed`);
  }
}
