#!/usr/bin/env luajit

require "ubus"
require "uloop"

local PROGNAME = "ifstatd"
local VERSION = "2018.06.11"
local MAX_FILTER_COUNT = 5
local ANY = -1

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

local serialize_ifstat_data = function(bpf, filters)
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
      for idx, per_cpu_array in data:items(true) do
        local column = filter_data_columns[idx-1]
        local sum = 0
        for cpu_num, value in ipairs(per_cpu_array) do
          sum = sum + tonumber(value)
        end

        -- Судя по всему, по ubus не стоит передавать числа больше
        -- u32 по размеру именно в виде чисел, так что отправляем как
        -- строку
        ifstat_data[id][column] = tostring(sum)
        log.debug(id .. " | " .. column .. " = " .. sum)
      end
    end
  end

  return ifstat_data
end

local inject_ifstat_bpf = function(BPF, iface, filters)
  local defines = filters_to_defines(filters)
  defines["ANY"] = ANY
  if log.dbg then defines["DEBUG"] = 1 end

  local cflags = defines_to_cflags(defines)
  local bpf = BPF:new{src_file="ifstat_kern.c", debug=0, cflags=cflags}
  bpf:attach_xdp{device=iface, fn_name="xdp_packet_handler"}

  return bpf
end

local parse_config = function()
  local config = require "config"
  local filters_count = #config["filters"]
  if filters_count > MAX_FILTER_COUNT then
    error("Max allowed amount of filters: %d" % (filters_count))
  elseif filters_count <= 0 then
    error("Please fill config (#TODO)")
  end
  return config
end

local ubus_objects = { ifstat = {} }

local main_loop = function(BPF, config)
  local conn    = ubus.connect()

  local iface   = config["iface"]
  local filters = config["filters"]
  local delay   = config["delay_ms"]

  if not conn then
    error("Failed to connect to ubus")
  end
  log.info("Connected to ubus")
  conn:add(ubus_objects)

  local ifstat = inject_ifstat_bpf(BPF, iface, filters)
  log.info("eBPF/XDP injected to iface \"%s\"" % { iface })

  local timer
  local publish = function()
    local data = serialize_ifstat_data(ifstat, filters)
    conn:notify(ubus_objects.ifstat.__ubusobj, "ifstat.data", data)
    timer:set(delay)
  end

  uloop.init()
  timer = uloop.timer(publish)
  timer:set(1)
  log.info("Ubus data publish rate set to %d ms" % { delay })

  uloop.run()

  return 0
end

local function print_usage(file)
  file:write(string.format(
    "usage: %s [[--version|--debug|--quiet]] \n",
    PROGNAME))
end

local function print_version()
  local jit = require("jit")
  print(string.format("%s %s -- Running on %s (%s/%s)",
    PROGNAME, VERSION, jit.version, jit.os, jit.arch))
end

local function parse_cli()
  -- Включаем отображение log'а по умолчанию
  --   (см. bcc/src/lua/bcc/vendor/helpers.lua:228)
  log.enabled = true

  -- Расширяем log возможностью отправки debug-сообщений, которые
  -- могут влиять на производительность программы
  log.dbg = false
  log.debug = function() end

  while arg[1] and string.starts(arg[1], "-") do
    local k = table.remove(arg, 1)
    if k == "-q" or k == "--quiet" then
      log.enabled = false
    elseif k == "-d" or k == "--debug" then
      log.dbg = true
      log.debug = log.info
    elseif k == "-v" or k == "--version" then
      print_version()
      os.exit(0)
    elseif k == "-h" or k == "--help" then
      print_usage(io.stdout)
      os.exit(0)
    else
      print_usage(io.stderr)
      os.exit(1)
    end
  end
end

function main()
  local str = require("debug").getinfo(1, "S").source:sub(2)
  local script_path = str:match("(.*/)").."/?.lua;"
  package.path = "bcc/src/lua/"..script_path..package.path
  require("bcc.vendor.helpers")

  parse_cli()

  local BPF = require("bcc.bpf")
  local config = parse_config()

  local res, err = xpcall(main_loop, debug.traceback, BPF, config)
  if not res then
    io.stderr:write("[ERROR] "..err.."\n")
  end

  -- TODO: Код ниже выполняется при SIGINT
  BPF.cleanup()
end

main()
