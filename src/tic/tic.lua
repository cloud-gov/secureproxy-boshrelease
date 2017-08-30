local _M = {}

local ngx = require "ngx"
local cjson = require "cjson"
local ngx_re = require "ngx.re"
local cidr = require "libcidr-ffi"

function _M.check_ingress(opts)
  local hostname = opts["headers"]["Host"]
  local port = hostname:find(":")
  if port ~= nil then
    hostname = hostname:sub(1, port-1)
  end

  local host_whitelist = opts["host_whitelist"][hostname]
  -- if host not protected, then bail
  if not host_whitelist then
    return true, {}
  end

  -- if path not protected, then bail
  for _, pattern in ipairs(host_whitelist) do
    if ngx.re.match(opts["request_uri"], pattern) then
      do return true, {} end
    end
  end

  local auth = opts["headers"]["Authorization"];
  -- if we have no auth, then bail
  if auth == nil then
    return true, {}
  end

  -- decode token, bail if we can't (malformed) or it doesn't have an email (client creds)
  local token, err = ngx_re.split(auth, "[.]")
  if err ~= nil or token[2] == nil then
    return true, {}
  end

  local decoded_token = cjson.decode(ngx.decode_base64(token[2]))
  if decoded_token.email == nil then
    return true, {}
  end

  -- extract domain from email address
  local email, err = ngx_re.split(decoded_token.email, "@")
  -- if the split failed, bail
  -- TODO: What about deployer accounts?
  if #email ~= 2 then
    ngx.log(ngx.ERR, "Skipping whitelist check. Unable to extract domain from username", cjson.encode(email))
    return true, {}
  end

  -- see if we have a whitelist registered for this domain
  if opts["whitelist"][email[2]] == nil then
    return true, email
  end

  if #source_ips then

    local parsed_ip = cidr.from_str(source_ip[1])
    -- if client IP not in domain whitelist, reject request
    if not ip_in_cidrs(parsed_ip, opts["whitelist"][email[2]]) then
      return false, email
    end

    if #source_ips > 1 then
      local parsed_ip = cidr.from_str(source_ip[2])
      -- if passed tic.secret check, ip must match global_whitelist
      if not ip_in_cidrs(parsed_ip, ops["global_whitelist"]) then
        return false, email
      end
    end
  end

  return true, email
end

function ip_in_cidrs(source_ip, cidrs)
  for _, range in ipairs(cidrs) do
    if cidr.contains(cidr.from_str(range), source_ip) then
      do return true end
    end
  end
  return false
end

return _M
