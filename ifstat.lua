#!/usr/bin/env lua5.1

require "ubus"
require "uloop"

uloop.init()

local conn = ubus.connect()
if not conn then
  error("Failed to connect to ubus")
end

function print_ifstat_data(data)
  local filter_data_columns = {
    {"pkts_64", "≤ 64"},
    {"pkts_65_127", "65 .. 127"},
    {"pkts_128_255", "128 .. 255"},
    {"pkts_256_511", "256 .. 511"},
    {"pkts_512_1023", "512 .. 1023"},
    {"pkts_1024_1512", "1024 .. 1512"},
    {"pkts_1513", "≥ 1513"},
    {"pkts_bytes", "Bytes received"},
    {"pkts_cnt", "Packetes received"}
  }

  for filter_name, filter_data in pairs(data) do
    print(filter_name)
    print("=======")
    for idx, pair in ipairs(filter_data_columns) do
      local key = pair[1]
      local title = pair[2]
      print(title .. ": " .. filter_data[key])
    end
    print("")
  end
end

local sub = {
  notify = function( msg, name )
    print_ifstat_data(msg)
  end,
}

conn:subscribe("ifstat", sub)
uloop.run()
