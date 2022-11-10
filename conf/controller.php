<?php

// params
$segmenterApiUrl = 'http://127.0.0.1:8001/api/live';
$segmenterKmpUrl = 'kmp://127.0.0.1:8003';
$ccDecoderUrl = 'kmp://127.0.0.1:8004';

/* closed captions decoder config -
 * false - don't send video to cc decoder
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

function outputError($message)
{
    outputJson(array(
        'code' => 'error',
        'message' => $message));
}

function postJson($url, $fields)
{
    $headers = array('Content-Type:application/json');
    $payload = json_encode($fields);

    for ($i = 0; $i < 3; $i++)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (substr($code, 0, 1) == '2')
        {
            return $res;
        }

        usleep(100000);
    }
}

function postMulti($url, $requests)
{
    for ($i = 0; $i < 3; $i++)
    {
        $res = postJson($url . '/multi', $requests);

        $res = json_decode($res, true);
        if (!is_array($res))
        {
            continue;
        }

        $failed = array();
        foreach ($res as $index => $cur)
        {
            $code = $cur['code'];
            if ($code < 200 || $code > 299)
            {
                $failed[] = $requests[$index];
            }
        }

        if (!$failed)
        {
            break;
        }

        usleep(100000);
        $requests = $failed;
    }
}

function setupSegmenter($segmenterApiUrl, $channelId, $preset, $variantId, $trackId, $mediaType)
{
    postMulti($segmenterApiUrl, array(

        // create the channel
        array(
            'uri' => "/channels",
            'method' => 'POST',
            'body' => array('id' => $channelId, 'preset' => $preset, 'initial_segment_index' => time())
        ),

        // create the main timeline
        array(
            'uri' => "/channels/$channelId/timelines",
            'method' => 'POST',
            'body' => array('id' => 'main', 'active' => true, 'max_segments' => 20, 'max_manifest_segments' => 10)
        ),

        // create the variant
        array(
            'uri' => "/channels/$channelId/variants",
            'method' => 'POST',
            'body' => array('id' => $variantId)
        ),

        // create the track
        array(
            'uri' => "/channels/$channelId/tracks",
            'method' => 'POST',
            'body' => array('id' => $trackId, 'media_type' => $mediaType)
        ),

        // connect the track to the variant
        array(
            'uri' => "/channels/$channelId/variants/$variantId/tracks",
            'method' => 'POST',
            'body' => array('id' => $trackId)
        ),
    ));
}

function setupSegmenterCCTrack($segmenterApiUrl, $channelId, $trackId, $label=null, $lang=null)
{
    if (!$label)
    {
        $label = $trackId;
    }

    postMulti($segmenterApiUrl, array(
        // create the track
        array(
            'uri' => "/channels/$channelId/tracks",
            'method' => 'POST',
            'body' => array('id' => $trackId, 'media_type' => 'subtitle')
        ),

        // create the variant
        array(
            'uri' => "/channels/$channelId/variants",
            'method' => 'POST',
            'body' => array(
                'id' => $trackId,
                'track_ids' => array('subtitle' => $trackId),
                'role' => 'alternate',
                'label' => $label,
                'lang' => $lang,
            )
        ),
    ));
}

function setupSegmenterCCTracks($segmenterApiUrl, $channelId, $ccConf)
{
    foreach ($ccConf as $id => $cc)
    {
        setupSegmenterCCTrack($segmenterApiUrl, $channelId, $id, $cc['label'], $cc['lang']);
    }
}

function getCCDecodeUpstream($segmenterKmpUrl, $channelId, $ccConf)
{
    global $ccDecoderUrl, $ccOutputAll;

    $upstream = array(
        'id' => 'cc-vid',
        'url' => $ccDecoderUrl,
    );

    if ($ccConf)
    {
        $connectData = array();
        foreach ($ccConf as $id => $cc)
        {
            $connectData[$id] = array(
                'channel_id' => $channelId,
                'track_id' => $id,
                'upstreams' => array(
                    array(
                        'id' => 'cc-sub',
                        'url' => $segmenterKmpUrl
                    ),
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

if (!isset($params['event_type']))
{
    outputError('missing event type');
}

switch ($params['event_type'])
{
case 'connect': // TODO: add some authentication logic here
case 'unpublish':
    outputJson(array(
        'code' => 'ok',
        'message' => ''));
    break;

case 'republish':
    $upstreamId = $params['id'];
    $channelId = $params['channel_id'];

    $upstream = $upstreamId == 'cc' ?
        getCCDecodeUpstream($segmenterKmpUrl, $channelId, $ccConf) :
        array('url' => $segmenterKmpUrl);
    outputJson($upstream);
    break;

case 'publish':
    break;      // handled outside the switch

default:
    outputError('invalid event type');
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
else if (isset($params['cc']))
{
    $channelId = $params['cc']['channel_id'];
    $trackId = $params['cc']['service_id'];

    setupSegmenterCCTrack($segmenterApiUrl, $channelId, $trackId);

    outputJson(array(
        'channel_id' => $channelId,
        'track_id' => $trackId,
        'upstreams' => array(array(
            'id' => 'cc-sub',
            'url' => $segmenterKmpUrl
        )),
    ));
}
else
{
    outputError('unknown publish event');
}

$undPos = strrpos($streamName, '_');
$channelId = substr($streamName, 0, $undPos);
$variantId = substr($streamName, $undPos + 1);

$mediaType = $params['media_info']['media_type'];
$trackId = $mediaType[0] . $variantId;

// setup the segmenter
$preset = 'main';
if (substr($channelId, 0, 3) == 'll_')
{
    $preset = 'll';
    $channelId = substr($channelId, 3);
}

setupSegmenter($segmenterApiUrl, $channelId, $preset, $variantId, $trackId, $mediaType);

$upstreams = array(
    array(
        'id' => 'main',
        'url' => $segmenterKmpUrl
    ),
);

if ($mediaType == 'video' && $ccConf !== false)
{
    if ($ccConf)
    {
        setupSegmenterCCTracks($segmenterApiUrl, $channelId, $ccConf);
    }

    $upstreams[] = getCCDecodeUpstream($segmenterKmpUrl, $channelId, $ccConf);
}

// return the publish response
$params = array(
    'channel_id' => $channelId,
    'track_id' => $trackId,
    'upstreams' => $upstreams,
);

outputJson($params);
