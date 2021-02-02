<?php

$scriptParts = explode('/', $_SERVER['SCRIPT_NAME']);
$pathParts = array();
if (isset($_SERVER['PHP_SELF']))
{
    $pathParts = explode('/', $_SERVER['PHP_SELF']);
}
$pathParts = array_diff($pathParts, $scriptParts);
$filePath = '/tmp/live-store/' . implode('/', $pathParts);

mkdir(dirname($filePath), 0777, true);

switch ($_SERVER['REQUEST_METHOD'])
{
case 'PUT':
    $data = file_get_contents('php://input');
    if (file_put_contents($filePath, $data) === false)
    {
        header("HTTP/1.1 500 Internal Server Error");
        die;
    }
    error_log('saved segment to '.$filePath);
    break;

case 'GET':
    header("X-Sendfile: {$filePath}");
    //readfile($filePath);
    break;
}
