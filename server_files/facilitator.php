<?php

///// Setup required:

$db_host = "";
$db_username = "";
$db_password = "";
$db_name = "";

/////

function set_code_exit($code)
{
    http_response_code($code);
    exit();
}

// Used to validate if the unique ID provided (UID) is valid based on a regex
// Returns 400 Bad Request if not.
function cancel_invalid_request($string)
{
    if(preg_match("/^[a-z0-9]{8}$/i", $string) == False)
    {
        set_code_exit(400);
    }
}

// Executes SQL with prepared queries & returns result.
// Bind values are supplied as an array here, which are converted to varargs with the splat (...) operator when calling bind_param
function execute_sql($sql, $type_string, $bind_vals_array, $throw_error=False)
{
    global $db_host, $db_username, $db_password, $db_name;

    $mysqli = new mysqli($db_host, $db_username, $db_password, $db_name);

    if ($mysqli->connect_errno)
    {
        set_code_exit(500);
    }

    $prepared_statement = $mysqli->prepare($sql);
    $prepared_statement->bind_param($type_string, ...$bind_vals_array);
    $prepared_statement->execute();
    $errno = $prepared_statement->errno;
    $response = $prepared_statement->get_result();
    $prepared_statement->close();
    $mysqli->close();

    // All non SELECT queries respond with False. Must determine if an error has occurred with errno. A non-zero errno is bad.
    if($response === False && $errno !== 0)
    {
        if($throw_error === False)
        {
            set_code_exit(500);
        }
        else
        {
            throw new Exception("SQL Error");
        }
    }

    return $response;
}

// A user who wants to share their file asks for a new unique ID here
// If the server cannot generate a unique ID after trying 3 times, then it gives up (this should never happen). 
// The server will create an entry with the current datetime and then associate the unique ID with the uploader's IP and port address
// This IP:Port combo is how a downloader will reach the desired NAPUFIT service
// The server returns the unique ID to the user
if (isset($_GET['new']))
{
    $MAX_TRIES = 3;
    for($i = 0; $i < $MAX_TRIES; $i++)
    {
        $unique_conn_id = bin2hex(random_bytes(4));
        $uploader_address = $_SERVER["REMOTE_ADDR"]."|".$_SERVER["REMOTE_PORT"];
        try 
        {
            // the "ss" part means "String, String" and is defining what type to expect in the wildcard ("?") fields
            execute_sql("INSERT INTO transfer_details (unique_conn_id, uploader_address, date_added) VALUES (?, ?, NOW())", "ss", [$unique_conn_id, $uploader_address], True);
            echo $unique_conn_id;
            exit();            
        }
        catch (Exception $e)
        {
            // Try again unless all attempts exhausted.
        }
    }
    set_code_exit(500);
}

// A downloader registers their interest by supplying the uploader's unique ID here.
// The server check to ensure no other downloader has already registered their interest. If so, this user is rejected.
// The server will give the downloader the uploader's IP and port address at which point the downloader will begin to communicate with the uploader independently.
// The server records the downloader's IP and Port so that the uploader knows where to do a NAT Punch-thru
if (isset($_GET['get_uploader']))
{
    $unique_conn_id = $_GET['get_uploader'];
    cancel_invalid_request($unique_conn_id);
    $response = execute_sql("SELECT downloader_address, uploader_address FROM transfer_details WHERE unique_conn_id = ? LIMIT 1", "s", [$unique_conn_id]);
    $row = $response->fetch_assoc();
    $downloader_address = $row["downloader_address"];
    if(strlen($downloader_address) === 0)
    {
        $downloader_address = $_SERVER["REMOTE_ADDR"]."|".$_SERVER["REMOTE_PORT"];
        execute_sql("UPDATE transfer_details SET downloader_address = ? WHERE unique_conn_id = ?", "ss", [$downloader_address, $unique_conn_id]);
        echo $row["uploader_address"];
        exit();
    }
    else
    {
        set_code_exit(500);
    }
}

// The uploader queries the server periodically until a downloader has registered their interest associated with the unique ID
// Once the uploader is given a downloader address, it begins the NAP Punch-thru process, which will allow the downloader to connect
if (isset($_GET['get_downloader']))
{
    $unique_conn_id = $_GET['get_downloader'];
    cancel_invalid_request($unique_conn_id);
    $response = execute_sql("SELECT downloader_address FROM transfer_details WHERE unique_conn_id = ? LIMIT 1", "s", [$unique_conn_id]);
    echo $response->fetch_assoc()["downloader_address"];
    exit();
}

// Once a connection is established, the uploader can remove their entry
if (isset($_GET['delete']))
{
    $unique_conn_id = $_GET['delete'];
    cancel_invalid_request($unique_conn_id);
    $response = execute_sql("DELETE FROM transfer_details WHERE unique_conn_id = ?", "s", [$unique_conn_id]);
    exit();
}
