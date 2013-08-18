<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="application-name" content="WpVE - Wordpress Vuln's & Exploits">
<meta name="description" content="Analisis de Plugins vulnerables en WordPress">
<meta name="author" content="@HackeaMesta">
<!--
La Base de datos de Plugins vulnerables es una recolección de proyectos entre los que se encuentran:
[+] www.wpscan.org
[+] https://code.google.com/p/plecost
[+] www.1337day.org
[+] www.exploit-db.com
[+] www.packetstormsecurity.net

[+] www.xora.org | @xoraorg | @HackeaMesta
[+] contacto@xora.org
[+] www.github.com/HackeaMesta
-->
<title>WpVE Scan</title>

<!-- CSS Sources -->
<link rel="stylesheet" type="text/css" href="http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css">
<style type="text/css">
	body{
		color: #E6E6E6;
		background-image:  url('http://i.imgur.com/dyllFKf.png'); /* Imagen por Ashishmalik1 0 http://gnome-look.org/content/show.php/Futuristic+Conky+Terminus?content=157049 */
		background-size:100% 150%;
		background-repeat: no-repeat;
		margin-top: 5%;
	}
	.dominio{
		padding:13px;
		border:solid 3px #2E9AFE;
		border-radius: 13px;
		font-size: 20px;
	}
	a{
		color: #2ECCFA;
		font-size: 14px;
	}
	hr{
		width: 40%;
		color: #D8D8D8;
		background-color: #D8D8D8;
		height: 1px;
	}
</style>

<!-- Jquery sources -->
<script type="text/javascript" src="http://code.jquery.com/jquery-1.9.1.js"></script>
<script type="text/javascript" src="http://code.jquery.com/ui/1.10.3/jquery-ui.js"></script>

<!-- Jquery UI para botones -->
<script type="text/javascript">
	$(function() {
    $( "input[type=submit], button" )
		.button()
	});
</script>
</head>

<body>
<?php
//Obteiene la URL actual
$localhost = $_SERVER['HTTP_HOST'].":".$_SERVER['SERVER_PORT']."/";

//Formulario de dominio a analizar
echo "<div align='center'>
	<br>
	<h2>Analizar el <font color='0033FF'>dominio</font>:</h2>
	<form action='' method='POST'>
	<input type='text' class='dominio' name='protocolo' value='http://www.' size='8'>
	<input type='text' class='dominio' name='dominio' value='$localhost' size='25'>
	<br>
	<br>
	<input name='analizar' type='submit' value='Analizar'>
	</form>
	<br>
	</div>";

// Recolecta los datos
$protocolo = htmlspecialchars($_POST['protocolo'], ENT_QUOTES);
$dominio = htmlspecialchars($_POST['dominio'], ENT_QUOTES);
$path = "wp-content/plugins";

if (isset($_POST['analizar']) && !empty($dominio)) {
	echo "<div align='center' style='color: green;'>Se buscaron ".count(file('vulns.bd'))." plugins vulnerables en: <a target='_blank' href='".$dominio.$path."'>".$dominio.$path."/</a> <br> Resultados:</div>";
	$dato = file("vulns.bd") or exit("<section style='color: orange;' align='center'>Hubo un error al cargar la base de Datos, asegurese de tener los permisos correctos!</section>");
	foreach($dato as $valor){
	list($plugin, $referencia, $tipo) = explode("|", $valor);
	//construir URL: plugins
	$url = "$protocolo"."$dominio"."$path"."/"."$plugin";
	$analisis = @get_headers($url);
	if ($analisis[0] == "HTTP/1.1 200 OK") {
		echo "<table>
			<tr>
				<td>Plugin:</td>
				<td>Dominio:</td>
				<td>Referencia:</td>
				<td>Vulnerabilidad:</td>
				<td>Respuesta del Servidor</td>
			</tr>
			<tr>
				<td>$plugin</td>
				<td><a target='_blank' href='$url'>$url</td>
				<td><a target='_blank' href='$referencia'>$referencia</td>
				<td>$tipo</td>
				<td style='color: green;'>202 - OK</td>
			</tr>
		</table>";
	}
	elseif ($analisis[0] == "HTTP/1.1 301 Moved Permanently") {
		echo "<table>
			<tr>
				<td>Plugin:</td>
				<td>Dominio:</td>
				<td>Referencia:</td>
				<td>Vulnerabilidad:</td>
				<td>Respuesta del Servidor</td>
			</tr>
			<tr>
				<td>$plugin</td>
				<td><a target='_blank' href='$url'>$url</td>
				<td><a target='_blank' href='$referencia'>$referencia</td>
				<td>$tipo</td>
				<td style='color: gray;'>301 - Movido Permanentemente</td>
			</tr>
		</table>";
	}
	else{
	}
	}
}
?>
</body>
</html>
