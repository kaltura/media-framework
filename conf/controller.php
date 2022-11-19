<?php

// params
$segmenterKmpPort = 8003;
$segmenterKmpUrl = 'kmp://127.0.0.1:' . $segmenterKmpPort;
$segmenterApiUrl = 'http://127.0.0.1:8001/api/live';

//$transConfFile = dirname(__FILE__) . '/transcoder.json';

/* closed captions decoder config -
 * false - don't send video to cc decoder
 * null - automatically publish all cc tracks in the video
 * array - publish cc tracks according to the specified conf,
    element format is - 'cc1' => array('label' => 'English',  'lang' => 'eng')
*/
$ccConf = null;
$ccOutputAll = false;
$ccDecoderUrl = 'kmp://127.0.0.1:8004';

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

function httpGetJson($url)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $output = curl_exec($ch);
    curl_close($ch);

    return json_decode($output, true);
}

function httpPostJson($url, $fields)
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
        $res = httpPostJson($url . '/multi', $requests);

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

function segmenterChannelCreate($segmenterApiUrl, $channelId, $preset)
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
    ));
}

function segmenterTrackCreate($channelId, $trackId, $mediaType)
{
    return array(
        'uri' => "/channels/$channelId/tracks",
        'method' => 'POST',
        'body' => array('id' => $trackId, 'media_type' => $mediaType)
    );
}

function segmenterVariantCreate($channelId, $variantId, $trackIds=null, $role=null, $label=null, $lang=null)
{
    return array(
        'uri' => "/channels/$channelId/variants",
        'method' => 'POST',
        'body' => array(
            'id' => $variantId,
            'track_ids' => $trackIds,
            'role' => $role,
            'label' => $label,
            'lang' => $lang,
        )
    );
}

function segmenterVariantAddTrack($channelId, $variantId, $trackId)
{
    return array(
        'uri' => "/channels/$channelId/variants/$variantId/tracks",
        'method' => 'POST',
        'body' => array('id' => $trackId)
    );
}

function setupSegmenterTrack($segmenterApiUrl, $channelId, $variantId, $trackId, $mediaType)
{
    postMulti($segmenterApiUrl, array(
        segmenterVariantCreate($channelId, $variantId),
        segmenterTrackCreate($channelId, $trackId, $mediaType),
        segmenterVariantAddTrack($channelId, $variantId, $trackId),
    ));
}


function setupSegmenterCCTrack($segmenterApiUrl, $channelId, $trackId, $label=null, $lang=null)
{
    if (!$label)
    {
        $label = $trackId;
    }

    postMulti($segmenterApiUrl, array(
        segmenterTrackCreate($channelId, $trackId, 'subtitle'),
        segmenterVariantCreate($channelId, $trackId, array('subtitle' => $trackId), 'alternate', $label, $lang),
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


function setupSegmenterTranscodedTracks($segmenterApiUrl, $channelId, $variants, $tracks, $mediaType)
{
    $segmenterApi = array();

    foreach ($tracks as $track)
    {
        $curTrackId = $track['trackid'];

        $segmenterApi[] = segmenterTrackCreate($channelId, $curTrackId, $mediaType);
    }

    foreach ($variants as $curVariantId => $variant)
    {
        if (!isset($variant[$mediaType]))
        {
            continue;
        }

        $curTrackId = $variant[$mediaType];

        $segmenterApi = array_merge($segmenterApi, array(
            segmenterVariantCreate($channelId, $curVariantId),
            segmenterVariantAddTrack($channelId, $curVariantId, $curTrackId),
        ));
    }

    postMulti($segmenterApiUrl, $segmenterApi);
}

function getTranscoderUpstream($conf, $outputTracks, $mediaType, $segmenterKmpPort)
{
    // allocate ports
    $port = rand(0, 999);    // TODO: implement some allocation logic to prevents collisions

    $kmpPort = 16000 + $port;
    $ctrlPort = 17000 + $port;

    // build transcoder conf
    $conf = array(
        'kmp' => array(
            'listenPort' => $kmpPort,
        ),
        'control' => array(
            'listenPort' => $ctrlPort,
        ),
        'output' => array(
            'streamingUrl' => 'kmp://host.docker.internal:' . $segmenterKmpPort,
        ),
        'engine' => $conf['engine'],
        'outputtracks' => $outputTracks,
    );

    $confJson = json_encode($conf, JSON_UNESCAPED_SLASHES);

    // start transcoder
    exec("docker run -p $kmpPort:$kmpPort -p $ctrlPort:$ctrlPort --add-host=host.docker.internal:host-gateway " .
        "kaltura/transcoder-dev:latest /build/transcoder -c '$confJson'" .
        " >> /var/log/transcoder/$mediaType.log 2>> /var/log/transcoder/$mediaType.err &");

    // wait for transcoder to start
    $start = time();
    while (time() - $start < 10)
    {
        $res = httpGetJson("http://127.0.0.1:$ctrlPort/status");
        if (isset($res['result']['state']) && $res['result']['state'] == 'ready')
        {
            break;
        }

        usleep(200000);
    }

    return array(
        'id' => 'main',
        'url' => 'kmp://127.0.0.1:' . $kmpPort
    );
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

    // TODO: handle republish for transcoded streams
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

// setup the segmenter
$preset = 'main';
if (substr($channelId, 0, 3) == 'll_')
{
    $preset = 'll';
    $channelId = substr($channelId, 3);
}

segmenterChannelCreate($segmenterApiUrl, $channelId, $preset);

$upstreams = array();

if (isset($transConfFile))
{
    $transConf = json_decode(file_get_contents($transConfFile), true);
    $transOutputTracks = $transConf['outputtracks'];
}

if (isset($transOutputTracks[$mediaType]))
{
    // transcode
    $trackId = $mediaType[0] . 'src';

    $transOutputTracks = $transOutputTracks[$mediaType];

    setupSegmenterTranscodedTracks($segmenterApiUrl, $channelId, $transConf['variants'], $transOutputTracks, $mediaType);

    $upstreams[] = getTranscoderUpstream($transConf, $transOutputTracks, $mediaType, $segmenterKmpPort);
}
else
{
    // passthrough
    $trackId = $mediaType[0] . $variantId;
    setupSegmenterTrack($segmenterApiUrl, $channelId, $variantId, $trackId, $mediaType);

    $upstreams[] = array(
        'id' => 'main',
        'url' => $segmenterKmpUrl
    );
}

// decode closed captions
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
