local ANY = -1
local MAX_FILTER_COUNT = 5

-- Взято из https://stackoverflow.com/questions/8200228/how-can-i-convert-an-ip-address-into-an-integer-with-lua
local ip2dec = function(ip) local i, dec = 3, 0; for d in string.gmatch(ip, "%d+") do dec = dec + 2 ^ (8 * i) * d; i = i - 1 end; return dec end

local filter_to_defines = function(args)
  local num = args.filter_num
  local defines = {}

  if args.enabled == 1 then
    local src_ip = ANY
    local dst_ip = ANY

    if args.src_ip ~= ANY then
      src_ip = ip2dec(args.src_ip)
    end
    if args.dst_ip ~= ANY then
      dst_ip = ip2dec(args.dst_ip)
    end

    defines["FILTER" .. num .. "_IPPROTO"]  = tonumber(args.ipproto or ANY)
    defines["FILTER" .. num .. "_SRC_IP"]   = src_ip
    defines["FILTER" .. num .. "_DST_IP"]   = dst_ip
    defines["FILTER" .. num .. "_SRC_PORT"] = tonumber(args.src_port or ANY)
    defines["FILTER" .. num .. "_DST_PORT"] = tonumber(args.dst_port or ANY)
    defines["FILTER" .. num .. "_ENABLED"]  = 1
  else
    defines["FILTER" .. num .. "_ENABLED"]  = 0
  end

  return defines
end

local filters_to_defines = function(filters)
  local defines = { }
  for idx, filter in ipairs(filters) do
    local filter_defines = filter_to_defines(filter)
    for key, value in pairs(filter_defines) do
      defines[key] = value
    end
  end
  return defines
end

local defines_to_cflags = function(filters)
  local cflags = {}
  for name, value in pairs(filters) do
    table.insert(cflags, "-D%s=%d" % {name, value})
  end

  return cflags
end

local get_ifstat_data = function(bpf, filters)
  local ifstat_data = {}

  local filter_data_columns = {
    [0] = "pkts_64",
    [1] = "pkts_65_127",
    [2] = "pkts_128_255",
    [3] = "pkts_256_511",
    [4] = "pkts_512_1023",
    [5] = "pkts_1024_1512",
    [6] = "pkts_1513",
    [7] = "pkts_bytes",
    [8] = "pkts_cnt"
  }

  for idx, filter in ipairs(filters) do
    if filter.enabled == 1 then
      local id = "filter" .. filter.filter_num
      local data = bpf:get_table(id)
      ifstat_data[id] = {}
      for idx, value in data:items(true) do
	local column = filter_data_columns[idx-1]
        ifstat_data[id][column] = tonumber(value)
      end
    end
  end

  return ifstat_data
end

local inject_ifstat_bpf = function(BPF, iface, filters)
  local defines = filters_to_defines(filters)
  defines["ANY"] = ANY

  local cflags = defines_to_cflags(defines)
  local bpf = BPF:new{src_file="ifstat_kern.c", debug=0, cflags=cflags}
  bpf:attach_xdp{device=iface, fn_name="packet_handler"}
  -- TODO: error check

  return bpf
end

local parse_config = function()
  local config = require "config"
  local filters_count = #config["filters"]
  if filters_count > MAX_FILTER_COUNT then
    error("ERROR: Max allowed amount of filters: %d" % (filters_count))
  elseif filters_count <= 0 then
    error("ERROR: Please fill config (#TODO)")
  end
  return config
end

local ubus_objects = { ifstat = {} }

return function(BPF)
  local config  = parse_config()

  local iface   = config["iface"]
  local filters = config["filters"]
  local delay   = config["delay_ms"]

  local conn = ubus.connect()
  if not conn then
    error("Failed to connect to ubus")
  end
  conn:add(ubus_objects)

  local bpf = inject_ifstat_bpf(BPF, iface, filters)

  local timer
  local publish = function()
    local data = get_ifstat_data(bpf, filters)
    conn:notify(ubus_objects.ifstat.__ubusobj, "ifstat.data", data)
    timer:set(delay)
  end

  uloop.init()
  timer = uloop.timer(publish)
  timer:set(delay)
  uloop.run()
end
