
--[[
    maps segment ids to timestamps to enable replay of live stream
    with the original delays between segments
--]]

local io_open = io.open
local io_lines = io.lines
local os_time = os.time
local pairs = pairs
local table_insert = table.insert
local table_sort = table.sort
local ngx_re_match = ngx.re.match
local ngx_time = ngx.time

local _M = { _VERSION = '0.1' }

local function _file_exists(file)
    local f = io_open(file, "rb")
    if f then
        f:close()
    end
    return f ~= nil
end

local function _lines_from(file)
    if not _file_exists(file) then
        return {}
    end

    local lines = {}
    for line in io_lines(file) do
        lines[#lines + 1] = line
    end

    return lines
end

local function _compare_first(a, b)
  return a[1] < b[1]
end

local function _parse_file(file)
    -- get the max timestamp for each segment index
    local by_seg = {}
    local regex = [[(\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+) .*, nsi: (\d+)]]
    for _, line in pairs(_lines_from(file)) do
        -- extract timestamp and segment index from input line
        local m = ngx_re_match(line, regex)
        if m then
            local ts = os_time({year=m[1], month=m[2], day=m[3],
                                hour=m[4], min=m[5], sec=m[6]})
            local seg = m[7]

            if not by_seg[seg] or ts > by_seg[seg] then
                by_seg[seg] = ts
            end
        end
    end

    -- get the max segment index for each timestamp
    local by_ts = {}
    for seg, ts in pairs(by_seg) do
        if not by_ts[ts] or seg > by_ts[ts] then
            by_ts[ts] = seg
        end
    end

    -- sort by timestamp
    local tbl = {}
    local count = 0
    for ts, seg in pairs(by_ts) do
        table_insert(tbl, {ts, seg})
        count = count + 1
    end

    table_sort(tbl, _compare_first)
    tbl.count = count

    return tbl
end

local _cache = {}

local function _parse_file_cached(file)
    local map = _cache[file]
    if not map then
        map = _parse_file(file)
        _cache[file] = map
    end

    return map
end

local function _find_segment(map, ts)
    if ts < map[1][1] then
        return 0
    end

    -- binary search for ts in map
    local left = 1
    local right = map.count
    while left <= right do
        local mid = math.floor((left + right) / 2)
        local cur = map[mid][1]
        if cur < ts then
            left = mid + 1
        elseif cur > ts then
            right = mid - 1
        else
            return map[mid][2]
        end
    end

    return map[left - 1][2]
end

function _M.get_segment(file, start, dump_log)
    local map = _parse_file_cached(file)

    local ts = map[1][1] + ngx_time() - tonumber(start)
    local seg = _find_segment(map, ts)

    if dump_log then
        ngx.log(ngx.INFO, 'map:')
        for i = 1, map.count do
            ngx.log(ngx.INFO, i, ' ', map[i][1],' ', map[i][2])
        end

        ngx.log(ngx.INFO, 'time: ', ngx_time(), ', start: ', start)
        ngx.log(ngx.INFO, 'ts: ', ts, ', seg: ', seg)
    end

    return seg
end

function _M.get_start_time(file, ts)
    local map = _parse_file_cached(file)
    local start = ngx_time() - (tonumber(ts) - map[1][1])

    return start
end

return _M
