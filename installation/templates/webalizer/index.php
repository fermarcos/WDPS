<html>
	<head>
		<style type="text/css">
			@import "webalizer-style.css";
		</style>
		<title>Webalizer - Indice</title>
	</head>
	<body>
		<table class="table-fill">
			<thead>
				<th class="text-center">Webalizer Logs</th>
			</thead>
			<tbody class="table-hover">
<?php
$directorio = opendir(".");
while ($archivo = readdir($directorio))
{
    if (is_dir($archivo))
    {
	if(preg_match("/webalizer\./",$archivo))
        echo "\t\t\t\t".'<tr class="consalto"><td class="text-center"><a href="'.$archivo .'">'.$archivo ."</td></tr>\n";
    }
}
?>
			</tbody>
		</table>
	</body>
</html>

