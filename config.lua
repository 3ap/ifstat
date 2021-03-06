local ANY         = -1
local IPPROTO_UDP = 17
local IPPROTO_TCP = 6

local _config = {
  delay_ms = 1000,
  iface = "eth0",

  filters = {
    {
      filter_num = 0,
      enabled = 1,
      ipproto = ANY,
      src_ip = ANY,
      dst_ip = ANY,
      src_port = ANY,
      dst_port = ANY
    },
    {
      filter_num = 1,
      enabled = 1,
      ipproto = IPPROTO_TCP,
      src_ip = ANY,
      dst_ip = ANY,
      src_port = ANY,
      dst_port = ANY
    },
    {
      filter_num = 2,
      enabled = 1,
      ipproto = IPPROTO_UDP,
      src_ip = ANY,
      dst_ip = ANY,
      src_port = ANY,
      dst_port = ANY
    },
    {
      filter_num = 3,
      enabled = 0,
      ipproto = ANY,
      src_ip = ANY,
      dst_ip = ANY,
      src_port = ANY,
      dst_port = ANY
    },
    {
      filter_num = 4,
      enabled = 0,
      ipproto = ANY,
      src_ip = ANY,
      dst_ip = ANY,
      src_port = ANY,
      dst_port = ANY
    }
  }
}

return _config
