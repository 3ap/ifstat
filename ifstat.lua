#!/usr/bin/env luajit

require "ubus"
require "uloop"

local filter_prev_value = {}
local printed_lines_count = 0

function replace_char(str, pos, r)
  return str:sub(1, pos-1) .. r .. str:sub(pos+1)
end

function print_line(line)
  io.stdout:write("\27[K")
  print(line)
  printed_lines_count = printed_lines_count + 1
end

function clear_screen()
  if printed_lines_count > 0 then
    io.stdout:write("\27[" .. tostring( printed_lines_count ) .. "A")
    printed_lines_count = 0
  end
end

function fit_value_in_column(value, width)
  local value_str = string.format("%d", value)
  if #value_str > width then
    return string.format("%." .. tostring(width-6) .."e ", value)
  else
    return string.format("%" .. tostring(width) .."s ", value_str)
  end
end

function print_ifstat_data(data)
  local filter_stat = {}
  local filter_data_columns = {
    {key="filter_num",     title="#",         width=1},
    {key="pkts_64",        title="<= 64",     width=7},
    {key="pkts_65_127",    title="65-127",    width=7},
    {key="pkts_128_255",   title="128-255",   width=7},
    {key="pkts_256_511",   title="256-511",   width=7},
    {key="pkts_512_1023",  title="512-1023",  width=8},
    {key="pkts_1024_1512", title="1024-1512", width=8},
    {key="pkts_1513",      title=">= 1513",   width=7},
    {key="pkts_bytes",     title="Bytes",     width=10},
    {key="pkts_cnt",       title="Packets",   width=8}
  }

  for filter_name, filter_data in pairs(data) do
    local filter_num = filter_name:gsub("filter","")

    -- В Lua массивы индексируются с единицы, а приходящие от демона
    -- фильтры индексируются с 0
    filter_num = tonumber(filter_num) + 1

    if filter_prev_value[filter_num] == nil then
      filter_prev_value[filter_num] = {}
    end

    -- Отображать в таблице нужно настоящие индексы фильтров, а не
    -- увеличенные на 1
    filter_data["filter_num"] = filter_num - 1
    filter_stat[filter_num] = { absolute = '', relative = '' }

    for idx, column in ipairs(filter_data_columns) do
      local value = tonumber(filter_data[column.key])
      local delta = value - (filter_prev_value[filter_num][column.key] or 0)

      filter_prev_value[filter_num][column.key] = value
      filter_stat[filter_num].absolute = filter_stat[filter_num].absolute .. fit_value_in_column(value, column.width)
      filter_stat[filter_num].relative = filter_stat[filter_num].relative .. fit_value_in_column(delta, column.width)

      if column.key == 'filter_num' then
        filter_stat[filter_num].relative = string.format("%" .. column.width+1 .. "s ", 'Δ')
      end
    end
  end

  clear_screen()

  local header = ''
  for idx, column in ipairs(filter_data_columns) do
    local title = string.format("%" .. tostring(column.width) .. "s ", column.title)
    title = replace_char(title:sub(1, column.width), column.width+1, ' ')
    header = header .. title
  end
  header = header:sub(1, #header-1)

  local frame = ''
  for i=1,#header do
    frame = frame .. '-'
  end
  print_line(frame)
  print_line(header)
  print_line(frame)

  for idx, stat in ipairs(filter_stat) do
    print_line(stat.absolute)
    print_line(stat.relative)
    print_line(frame)
  end
end

function main()
  uloop.init()

  local conn = ubus.connect(os.getenv("UBUS_SOCK"))
  if not conn then
    error("Failed to connect to ubus")
  end

  local sub = {
    notify = function( msg, name )
      print_ifstat_data(msg)
    end,
  }

  conn:subscribe("ifstat", sub)
  uloop.run()
end

main()
