<?

$using_hip = 0;
$domain = $_SERVER['REMOTE_ADDR'];
if (substr($domain, 0, 6) == "2001:7")
{
	$using_hip = 1;
}

$index = $_GET['index'];

if ($index == null)
{
	$index = 1;
}

$title = "Our Own Webmail";

echo ("
<html><head><title>$title</title></head>
<body bgColor='#9Cc4c7' link='#a0a000' text='#1A4C50' vLink='#a000a0'>
");

if ($index >= 6)
{
	echo ("
	<h3><center>$title</center></h3><hr>
	<center>
	<a href='index.php?index=6'>|Inbox|</a>
	<a href='index.php?index=7'>|Trash|</a>
	<a href='index.php?index=8'>|Compose|</a>
	<a href='index.php?index=9'>|Preferences|</a>
	<hr>");
	
	if ($index == 6) echo ("<font color='#303030'>Inbox is empty.</font>");
	if ($index == 7) echo ("<font color='#303030'>Trash is empty.</font>");
	if ($index == 8) echo ("<font color='#903030'>Failure when connecting to server!</font>");
	if ($index == 9) echo ("<font color='#903030'>Failure when connecting to server!</font>");
	
	echo ("<br />");
}
else
{
	echo ("
	<br /><br />
	<hr>
	<h2><center>$title</center></h2>
	<hr>
	
	<h4>
	<center><p>
	<form method='post' action='index.php?index=6'>
		<table>
			<tr>
				<td colspan='2'>
	");
	
	if ($index == 2)
	{
		echo ("<font color='#ff5050'><h3>Login failed, try again</h3></font><b>Enter your email account and current password:</b>");
	}
	else
	{
		echo ("<h3>Log in</h3><b>Enter your email account and current password:</b>");
	}
	
	echo ("
				</td>
			</tr>
	
			<tr>
				<td>Account:</td>
				<td><input type='text' name='form_username' /></td>
			</tr>
	
			<tr>
				<td>Password:</td>
				<td><input type='password' name='form_password' /></td>
			</tr>
	
			<tr>
				<td colspan='2' align='center'>
				<input type='submit' name='login' value='Login' />
				</td>
			</tr>
		</table>
	</form>
	</p></center>
	");
}

if ($index == 5 || $using_hip != 1)
echo ("
<br /><br /><hr>
<center><p>This connection is insecure. Please enable HIP.</p></center>
");
else
echo ("
<br /><hr>
<center><p>This connection is secure and encrypted by <font color='#ff5050'>HIP</font>.</p></center>
");


echo ("</body></html>");

?>
