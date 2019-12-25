<?php

function outputJson($params)
{
    header('Content-Type: application/json');
    $params = json_encode($params);
    $params = str_replace('\\/', '/', $params);
    echo $params;
    die;
}

function postJson($url, $fields)
{
    $ch = curl_init($url);
    $payload = json_encode($fields);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_exec($ch);
    // TODO: check curl_getinfo($ch, CURLINFO_HTTP_CODE)
    curl_close($ch);
}

function setupPackager($controlUrl, $channelId, $variantId, $trackId, $mediaType)
{
    // create the channel
    postJson("$controlUrl/channels",
        array('id' => $channelId, 'preset' => 'main'));

    // create the main timeline
    postJson("$controlUrl/channels/$channelId/timelines",
        array('id' => 'main', 'active' => true, 'max_segments' => 20, 'max_manifest_segments' => 10));

    // create the variant
    postJson("$controlUrl/channels/$channelId/variants",
        array('id' => $variantId));

    // create the track
    postJson("$controlUrl/channels/$channelId/tracks",
        array('id' => $trackId, 'media_type' => $mediaType));

    // connect the track to the variant
    postJson("$controlUrl/channels/$channelId/variants/$variantId/tracks",
        array('id' => $trackId));
}

#error_log(json_encode($_REQUEST));

// get input params (support json post)
$params = $_REQUEST;

if (isset($_SERVER['CONTENT_TYPE']) && strtolower($_SERVER['CONTENT_TYPE']) == 'application/json')
{
    $requestBody = json_decode(file_get_contents('php://input'), true);
    if (is_array($requestBody))
    {
        $params = array_merge($requestBody, $params);
    }
}

// packager params
$publishUrl = 'kmp://127.0.0.1:6543';
$controlUrl = 'http://127.0.0.1:8001/control';

switch ($params['event_type'])
{
case 'connect':
case 'unpublish':
    outputJson(array(
        'code' => 'ok',
        'message' => ''));
    break;

case 'republish':
    outputJson(array(
        'url' => $publishUrl));
    break;

case 'publish':
    break;      // handled outside the switch

default:
    outputJson(array(
        'code' => 'error',
        'message' => 'invalid event type'));
    break;
}

// parse the input params
$streamName = $params['rtmp']['name'];
$mediaType = $params['media_info']['media_type'];
$undPos = strrpos($streamName, '_');
$channelId = substr($streamName, 0, $undPos);
$variantId = substr($streamName, $undPos + 1);
$trackId = $mediaType[0] . $variantId;

// set up the packager
setupPackager($controlUrl, $channelId, $variantId, $trackId, $mediaType);

// return the publish url
$params = array(
    'channel_id' => $channelId,
    'track_id' => $trackId,
    'upstreams' => array(
        array('url' => $publishUrl),
    ),
);

outputJson($params);
