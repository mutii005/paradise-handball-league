
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST["email"];
    $name = $_POST["name"];
    $father = $_POST["father_name"];
    $mother = $_POST["mother_name"];
    $dob = $_POST["dob"];
    $phone = $_POST["phone"];
    $gender = $_POST["gender"];
    $district = $_POST["district"];
    $aadhaar = $_POST["aadhaar"];
    $district_achievements = $_POST["district_achievements"];
    $state_achievements = $_POST["state_achievements"];
    $national_achievements = $_POST["national_achievements"];
    $position = $_POST["position"];
    $price = $_POST["price"];

    $to = "your-email@example.com";
    $subject = "New Player Registration - Paradise Handball League";
    $message = "
      Email: $email\n
      Name: $name\n
      Father's Name: $father\n
      Mother's Name: $mother\n
      DOB: $dob\n
      Phone: $phone\n
      Gender: $gender\n
      District: $district\n
      Aadhaar: $aadhaar\n
      District Achievements: $district_achievements\n
      State Achievements: $state_achievements\n
      National Achievements: $national_achievements\n
      Position: $position\n
      Basic Price: ₹$price
    ";
    mail($to, $subject, $message);
    echo "Form submitted successfully. Please proceed to payment.";
}
?>
