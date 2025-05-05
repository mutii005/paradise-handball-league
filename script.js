
function payNow() {
  var options = {
    key: "rzp_test_1DP5mmOlF5G5ag",
    amount: 10000, // 100 rupees
    currency: "INR",
    name: "Paradise Handball League",
    description: "Player Registration Fee",
    handler: function (response) {
      alert("Payment Successful: " + response.razorpay_payment_id);
      document.getElementById("registration-form").submit();
    },
    prefill: {
      name: "",
      email: "",
      contact: ""
    },
    theme: {
      color: "#007bff"
    }
  };
  var rzp1 = new Razorpay(options);
  rzp1.open();
}
