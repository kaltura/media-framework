<?php

// params
$publishUrl = 'kmp://127.0.0.1:6543';
$ccPublishUrl = 'kmp://127.0.0.1:7890';
$controlUrl = 'http://127.0.0.1:8001/control';

/* ccConf -
 * false - don't send video to cc upstream
 * null - automatically publish all cc tracks in the video
 * array - publish cc tracks according to the specified conf,
    element format is - 'cc1' => array('label' => 'English',  'lang' => 'eng')
*/
$ccConf = null;
$ccOutputAll = false;

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
    for ($i = 0; $i < 3; $i++)
    {
        $ch = curl_init($url);
        $payload = json_encode($fields);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (substr($code, 0, 1) == '2')
        {
            break;
        }

        usleep(100000);
    }
}

function setupPackager($controlUrl, $channelId, $preset, $variantId, $trackId, $mediaType)
{
    // create the channel
    postJson("$controlUrl/channels",
        array('id' => $channelId, 'preset' => $preset, 'initial_segment_index' => time()));

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

function setupPackagerCCTrack($controlUrl, $channelId, $trackId, $label=null, $lang=null)
{
    if (!$label)
    {
        $label = $trackId;
    }

    postJson("$controlUrl/channels/$channelId/tracks",
        array('id' => $trackId, 'media_type' => 'subtitle'));

    postJson("$controlUrl/channels/$channelId/variants",
        array(
            'id' => $trackId,
            'track_ids' => array('subtitle' => $trackId),
            'role' => 'alternate',
            'label' => $label,
            'lang' => $lang,
        )
    );
}

function setupPackagerCC($controlUrl, $channelId, $ccConf)
{
    foreach ($ccConf as $id => $cc)
    {
        setupPackagerCCTrack($controlUrl, $channelId, $id, $cc['label'], $cc['lang']);
    }
}

function getCCDecodeUpstream($publishUrl, $channelId, $ccConf)
{
    global $ccPublishUrl, $ccOutputAll;

    $upstream = array(
        'id' => 'cc',
        'url' => $ccPublishUrl,
    );

    if ($ccConf)
    {
        $connectData = array();
        foreach ($ccConf as $id => $cc)
        {
            $connectData[$id] = array(
                'channel_id' => $channelId,
                'track_id' => $id,
                "upstreams" => array(
                    array('url' => $publishUrl),
                )
            );
        }

        if ($ccOutputAll)
        {
            $connectData['*'] = null;
        }

        $upstream['connect_data'] = base64_encode(json_encode($connectData));
    }

    return $upstream;
}

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

switch ($params['event_type'])
{
case 'connect':
case 'unpublish':
    outputJson(array(
        'code' => 'ok',
        'message' => ''));
    break;

case 'republish':
    $upstreamId = $params['id'];
    $channelId = $params['channel_id'];

    $upstream = $upstreamId == 'cc' ?
        getCCDecodeUpstream($publishUrl, $channelId, $ccConf) :
        array('url' => $publishUrl);
    outputJson($upstream);
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
if (isset($params['rtmp']))
{
    $streamName = $params['rtmp']['name'];
}
else if (isset($params['mpegts']))
{
    $streamName = $params['mpegts']['stream_id'];
}
else
{
    $channelId = $params['cc']['channel_id'];
    $trackId = $params['cc']['service_id'];

    setupPackagerCCTrack($controlUrl, $channelId, $trackId);

    outputJson(array(
        'channel_id' => $channelId,
        'track_id' => $trackId,
        'upstreams' => array(array('url' => $publishUrl)),
    ));
}

$undPos = strrpos($streamName, '_');
$channelId = substr($streamName, 0, $undPos);
$variantId = substr($streamName, $undPos + 1);
$mediaType = $params['media_info']['media_type'];
$trackId = $mediaType[0] . $variantId;

// set up the packager
setupPackager($controlUrl, $channelId, 'main', $variantId, $trackId, $mediaType);

$upstreams = array(
    array('url' => $publishUrl),
);

if ($mediaType == 'video' && $ccConf !== false)
{
    if ($ccConf)
    {
        setupPackagerCC($controlUrl, $channelId, $ccConf);
    }

    $upstreams[] = getCCDecodeUpstream($publishUrl, $channelId, $ccConf);
}

// return the publish url
$params = array(
    'channel_id' => $channelId,
    'track_id' => $trackId,
    'upstreams' => $upstreams,
);

outputJson($params);
