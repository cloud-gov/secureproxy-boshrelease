local _M = {}

local ngx = require "ngx"
local cjson = require "cjson"
local ngx_re = require "ngx.re"
local cidr = require "libcidr-ffi"

function _M.check_ingress(opts)
  -- where is the request coming from
  local auth = opts["headers"]["Authorization"];
  local client_ip = opts["source_ip"]
  local xff = opts["headers"]["X-Forwarded-For"]
  local proxy_ip

  -- where is the request going to
  local hostname = opts["headers"]["Host"]
  local port = hostname:find(":")

  -- strip port from hostname
  if port ~= nil then
    hostname = hostname:sub(1, port-1)
  end

  local host_whitelist = opts["host_whitelist"][hostname]
  -- if we don't have a whitelist for this host, then bail
  if not host_whitelist then
    return true, false, client_ip, {}
  end

  -- if hostname + path is whitelisted, then bail
  for _, pattern in ipairs(host_whitelist) do
    if ngx.re.match(opts["request_uri"], pattern) then
      do return true, false, client_ip, {} end
    end
  end

  -- if we have no auth, then bail
  if auth == nil then
    return true, false, client_ip, {}
  end

  -- decode token, bail if we can't (malformed) or it doesn't have an email (client creds)
  local token, err = ngx_re.split(auth, "[.]")
  if err ~= nil or token[2] == nil then
    return true, false, client_ip, {}
  end

  local decoded_token = cjson.decode(ngx.decode_base64(token[2]))
  if decoded_token.email == nil then
    return true, false, client_ip, {}
  end

  -- extract domain from email address
  local email, err = ngx_re.split(decoded_token.email, "@")
  -- if the split failed, bail
  -- TODO: What about deployer accounts?
  if #email ~= 2 then
    ngx.log(ngx.ERR, "Skipping ip_whitelist check. Unable to extract domain from username", cjson.encode(email))
    return true, false, client_ip, {}
  end

  -- see if we have an ip_whitelist registered for this domain
  if opts["ip_whitelist"][email[2]] == nil then
    return true, false, client_ip, email
  end

  -- if we have an X-Forwarded-For header then use the last one in the list instead of ngx.var.remote_addr
  -- Note: This is only safe to use behind a load balancer that appends the client IP to XFF;
  -- see http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html#x-forwarded-for
  if xff ~= nil then
    local xffl, err = ngx_re.split(xff, ", ")
    if xffl ~= nil then
      client_ip = xffl[#xffl]

      -- if we have X-Client-IP header and can check + trust X-TIC-Secret header then
      -- 1. use X-Client-IP as client_ip for domain ip_whitelist validation
      -- 2. check last value in X-Forwarded-For against proxy_whitelist
      if opts["headers"]["X-Client-IP"] ~= nil and opts["tic_secret"] ~= nil then
        if opts["headers"]["X-TIC-Secret"] == opts["tic_secret"] then
          client_ip = opts["headers"]["X-Client-IP"]
          proxy_ip = xffl[#xffl]
        end
      end

    end
  end

  -- if client_ip not in domain ip_whitelist, reject request
  if not ip_in_cidrs(client_ip, opts["ip_whitelist"][email[2]]) then
    return false, true, client_ip, email
  end

  -- if passed tic_secret check, proxy_ip must match proxy_whitelist
  if proxy_ip ~= nil and not ip_in_cidrs(proxy_ip, opts["proxy_whitelist"]) then
    return false, true, proxy_ip, email
  end

  return true, true, client_ip, email
end

function ip_in_cidrs(ip, cidrs)
  for _, range in ipairs(cidrs) do
    if cidr.contains(cidr.from_str(range), cidr.from_str(ip)) then
      do return true end
    end
  end
  return false
end

return _M
