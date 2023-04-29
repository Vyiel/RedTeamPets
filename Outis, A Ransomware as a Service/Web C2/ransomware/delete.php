<?php

require "conf.php";

if (isset($_POST['delete']))
{

	$id = intval($_POST['ransom_id']);
	
	$sql = "DELETE FROM victims WHERE ransomware_ID = $id";
			
	$res = $conn -> query($sql);
	
	if ($res)
	{
		echo "<script>
		alert('Record Deleted!!!');
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