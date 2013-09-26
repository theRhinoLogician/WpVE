<!DOCTYPE html>
<html lang="es">
<head>
<title>WpVE Scan</title>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<meta name="application-name" content="WpVE - Wordpress Vuln's & Exploits">
<meta name="description" content="Analisis de Plugins y Temas vulnerables en WordPress">
<meta name="author" content="@HackeaMesta">

<!-- Creditos
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

<!-- Fuentes CSS -->
<link rel="stylesheet" type="text/css" href="http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css">
<style type="text/css">
	body{
		color: #E6E6E6;
		background-image:  url('http://i.imgur.com/dyllFKf.png'); /* Imagen por Ashishmalik1 0 http://gnome-look.org/content/show.php/Futuristic+Conky+Terminus?content=157049 */
		background-size:100%%;
		background-repeat: no-repeat;
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
	table{
		width: 90%;
	}
</style>

<!-- Fuentes Jquery -->
<script type="text/javascript" src="http://code.jquery.com/jquery-1.9.1.js"></script>
<script type="text/javascript" src="http://code.jquery.com/ui/1.10.3/jquery-ui.js"></script>

<!-- Jquery -->
<script type="text/javascript">
	$(function() {
    $( "input[type=submit], button" )
		.button()
	});
</script>

<script type="text/javascript">
$(function() {
	$( "#msj" ).dialog({
		modal: true,
		buttons: {
			Ok: function() {
				$( this ).dialog( "close" );
			}
		}
	});
});
</script>

</head>

<body>
<?php
// Obtiene la URL actual
function obten_url(){
	$a = "http://";
	$b = $_SERVER['HTTP_HOST'];
	$c = end(explode('/',$_SERVER['PHP_SELF']));

	$path = str_replace($c,'',$_SERVER['PHP_SELF']);

	$url = $a.$b.$path;

	return $url;
}

// Formulario de dominio a analizar
echo "<div align='center'>
	<br>
	<h2>Analizar el <font color='0033FF'>dominio</font>:</h2>
	<form action='' method='POST'>
	<input type='text' class='dominio' name='dominio' value='".obten_url()."' size='30'>
	<br>
	<br>
	<input name='analizar' type='submit' value='Analizar'>
	</form>
	<br>
	</div>";

// Recolecta los datos
$dominio = htmlspecialchars($_POST['dominio'], ENT_QUOTES);
$path = "wp-content";

if (isset($_POST['analizar']) && !empty($dominio)) {
	echo "<div id='msj' title='Revisando...' align='center' style='color: green;'>Busque ".count(file('vulns.bd'))." vulnerabilidades en: <a target='_blank' href='".$dominio.$path."'>".$dominio.$path."</a> <br>:</div>";
	$dato = file("vulns.bd") or exit("<section style='color: orange;' align='center'>Hubo un error al cargar la base de Datos, asegurese de tener los permisos correctos!</section>");

	foreach($dato as $valor){
		list($vuln, $referencia, $tipo) = explode("|", $valor);

		// Construir URL: plugins
		$url = $dominio.$path."/"."$vuln";
		$analisis = @get_headers($url);

		// Array nombre de la vulnerabilidad
		list($ubicacion, $nombre) = explode("/", $vuln);

		//Imprime si el Header es = 200
		if ($analisis[0] == "HTTP/1.1 200 OK") {
			echo "<table>
				<tr style='background-color: #6E6E6E;'>
					<td width='25%'>Plugin / Tema:</td>
					<td width='25%'>Ubicación:</td>
					<td width='30%'>Referencia:</td>
					<td width='10%'>Vulnerabilidad:</td>
					<td width='10%'>Respuesta del Servidor</td>
				</tr>
				<tr>
					<td width='25%'>$nombre</td>
					<td width='25%'><a target='_blank' href='$url'>$url</td>
					<td width='30%'><a target='_blank' href='$referencia'>$referencia</td>
					<td width='10%'>$tipo</td>
					<td width='10%' style='color: green;'>202 - Ok</td>
				</tr>
			</table>
			";
		}

		//Imprime si el Header es = 301
		elseif ($analisis[0] == "HTTP/1.1 301 Moved Permanently") {
			echo "<table>
				<tr style='background-color: #6E6E6E;'>
					<td width='25%'>Plugin / Tema:</td>
					<td width='25%'>Ubicación:</td>
					<td width='30%'>Referencia:</td>
					<td width='10%'>Vulnerabilidad:</td>
					<td width='10%'>Respuesta del Servidor</td>
				</tr>
				<tr>
					<td width='25%'>$nombre</td>
					<td width='25%'><a target='_blank' href='$url'>$url</td>
					<td width='30%'><a target='_blank' href='$referencia'>$referencia</td>
					<td width='10%'>$tipo</td>
					<td width='10%' style='color: gray;'>301 - Movido Permanentemente</td>
				</tr>
			</table>
			";
		}
		else{

		}
	}
}
elseif (isset($_POST['analizar']) && empty($dominio)) {
	echo "<div id='msj' title='Error :('><p>Introduce un dominio >_<</p></div>";
}
?>

</body>
</html>
