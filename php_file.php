<?php
    
$server = ""; # CHANGE THIS
$username = ""; # CHANGE THIS
$password = ""; # CHANGE THIS
$database = ""; # CHANGE THIS

$conn = new mysqli($server, $username, $password, $database);

$id = $_GET['id'];

if ($id !== null) {
    $data = mysqli_query($conn, "select - from - where id = $id"); # COMPLETE QUERY
    $response = mysqli_fetch_array($data);
    if (!isset($response['user'])){
	echo "Incorrect User";
        #http_re#http_sponse_code(404); 
} else {
        echo "Correct User";
        #http_response_code(200);
    }
} 
?>

