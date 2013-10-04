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

[+] www.xora.org | @xoraorg | @HackeaMesta | contacto@xora.org | www.github.com/HackeaMesta
-->

<!-- Fuentes CSS -->
<link rel="stylesheet" type="text/css" href="http://code.jquery.com/ui/1.10.3/themes/smoothness/jquery-ui.css">
<style type="text/css">
	body{
		color: #E6E6E6;
		background-image:  url('http://i.imgur.com/dyllFKf.png'); /* Imagen por Ashishmalik1 0 http://gnome-look.org/content/show.php/Futuristic+Conky+Terminus?content=157049 */
		background-size:100%;
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
	table{
		width: 90%;
		left: 5%;
		position: absolute;
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

	$u = $a.$b.$path;

	return $u;
}

// Formulario de dominio a analizar
echo "<div align='center'>
<br>
<h2>Analizar sitio:</h2>
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

// Obtiene la versión de wp a través de meta tags
function obten_meta(){
	$sitio = htmlspecialchars($_POST['dominio'], ENT_QUOTES);
	$meta = get_meta_tags($sitio);
	$generator = $meta['generator'];

	if ($generator == "") {
		$version =	"";
	}
	else{
		$version = str_replace("WordPress", "", $generator);
	}

	return $version;
}

// Analiza si existe el archivo Readme
function archivo_readme(){
	$archivo = "readme.html";
	$site = htmlspecialchars($_POST['dominio'], ENT_QUOTES);
	$url_archivo = $site.$archivo;

	$respuesta = @get_headers($url_archivo);
	if ($respuesta[0] == "HTTP/1.1 200 OK") {
		$readme = $url_archivo;
	}
	elseif ($respuesta[0] == "HTTP/1.1 301 Moved Permanently") {
		$readme = $url_archivo;
	}
	else{
		$readme = "";
	}
	return $readme;
}

// Full Path disclosure
function fpd(){
	$p = "wp-includes/rss-functions.php";
	$s = htmlspecialchars($_POST['dominio'], ENT_QUOTES);
	$ur = $s.$p;

	$test = @get_headers($ur);
	if ($test[0] != "HTTP/1.0 500 Internal Server Error") {
		$fpd = $ur;
	}
	else{
		$fpd = "";
	}
	return $fpd;
}

if (isset($_POST['analizar']) && !empty($dominio)) {
	echo "<div id='msj' title='Revisando...' align='center' style='color: green;'>Busque ".count(file('vulns.bd'))." vulnerabilidades en: <a target='_blank' href='".$dominio.$path."'>".$dominio.$path."</a> <br>:</div>";
	$dato = file("vulns.bd") or exit("<section style='color: orange;' align='center'>No pude cargar la base de Datos :( asegurese de tener los permisos correctos!</section>");

	echo "
	<table>
	<tr style='background-color: #6E6E6E;'>
		<td colspan='1' >Versión de Wordpress</td>
		<td colspan='2' >Archivo Readme</td>
		<td colspan='2' >Full Path Disclosure</td>
	</tr>
	<tr>
		<td colspan='1' >".obten_meta()."</td>
		<td colspan='2' ><a target='_blank' href='".archivo_readme()."'>".archivo_readme()."</a></td>
		<td colspan='2' ><a target='_blank' href='".fpd()."'>".fpd()."</a></td>
	</tr>
	<tr style='background-color: #6E6E6E;'>
				<td width='25%'>Plugin / Tema:</td>
				<td width='25%'>Ubicación:</td>
				<td width='30%'>Referencia:</td>
				<td width='10%'>Vulnerabilidad:</td>
				<td width='10%'>Respuesta del Servidor</td>
	</tr>";

	foreach($dato as $valor){
		list($vuln, $referencia, $tipo) = explode("|", $valor);

		// Construir URL: plugins
		$url = $dominio.$path."/"."$vuln";
		$analisis = get_headers($url);

		// Array nombre de la vulnerabilidad
		list($ubicacion, $nombre) = explode("/", $vuln);

		//Imprime si el Header es = 200
		if ($analisis[0] == "HTTP/1.1 200 OK") {
			echo "
				<tr>
					<td width='25%'>$nombre</td>
					<td width='25%'><a target='_blank' href='$url'>$url</td>
					<td width='30%'><a target='_blank' href='$referencia'>$referencia</td>
					<td width='10%'>$tipo</td>
					<td width='10%' style='color: green;'>202 - Ok</td>
				</tr>
			";
		}

		//Imprime si el Header es = 301
		elseif ($analisis[0] == "HTTP/1.1 301 Moved Permanently") {
			echo "
				<tr>
					<td width='25%'>$nombre</td>
					<td width='25%'><a target='_blank' href='$url'>$url</td>
					<td width='30%'><a target='_blank' href='$referencia'>$referencia</td>
					<td width='10%'>$tipo</td>
					<td width='10%' style='color: gray;'>301 - Movido Permanentemente</td>
				</tr>
			";
		}
		else{

		}
	}
	echo "</table>";
}
elseif (isset($_POST['analizar']) && empty($dominio)) {
	echo "<div id='msj' title='Error :('><p>Introduce un dominio >_<</p></div>";
}
?>

</body>
</html>
