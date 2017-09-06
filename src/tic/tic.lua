local _M = {}

local ngx = require "ngx"
local cjson = require "cjson"
local ngx_re = require "ngx.re"
local cidr = require "libcidr-ffi"

function _M.check_ingress(opts)
  -- where is the request going to
  local hostname = opts["headers"]["host"]
  local port = hostname:find(":")

  -- strip port from hostname
  if port ~= nil then
    hostname = hostname:sub(1, port-1)
  end

  local host_whitelist = opts["host_whitelist"][hostname]
  -- if we don't have a whitelist for this host, then bail
  if not host_whitelist then
    return true, false, {}, {}
  end

  -- if hostname + path is whitelisted, then bail
  for _, pattern in ipairs(host_whitelist) do
    if ngx.re.match(opts["request_uri"], pattern) then
      do return true, false, {}, {} end
    end
  end


  -- who is the request coming from
  local auth = opts["headers"]["authorization"]

  -- if we have no auth, then bail
  if auth == nil then
    return true, false, {}, {}
  end

  -- decode token, bail if we can't (malformed) or it doesn't have an email (client creds)
  local token, err = ngx_re.split(auth, "[.]")
  if err ~= nil or token[2] == nil then
    return true, false, {}, {}
  end

  local decoded_token = cjson.decode(ngx.decode_base64(token[2]))
  if decoded_token.email == nil then
    return true, false, {}, {}
  end

  -- extract domain from email address
  local email, err = ngx_re.split(decoded_token.email, "@")
  -- if the split failed, bail
  -- TODO: What about deployer accounts?
  if #email ~= 2 then
    ngx.log(ngx.ERR, "Skipping ip_whitelist check. Unable to extract domain from username", cjson.encode(email))
    return true, false, {}, {}
  end

  -- see if we have an ip_whitelist registered for this domain
  if opts["ip_whitelist"][email[2]] == nil then
    return true, false, {}, email
  end


  -- where is the request coming from
  local client_ip, proxy_ip = get_source_ips({
    source_ip=opts["source_ip"],
    tic_secret=opts["tic_secret"],
    x_tic_secret=opts["headers"]["x-tic-secret"],
    x_client_ip=opts["headers"]["x-client-ip"],
    x_forwarded_for=opts["headers"]["x-forwarded-for"]
   })

  -- if client_ip not in domain ip_whitelist, reject request
  if not ip_in_cidrs(client_ip, opts["ip_whitelist"][email[2]]) then
    return false, true, client_ip, email
  end

  -- if we don't have a proxy_whitelist, trust tic_secret alone & bail
  if opts["proxy_whitelist"] == nil then
    return true, true, client_ip, email
  end

  -- if proxy_ip not in proxy_whitelist, reject request
  if proxy_ip ~= nil and not ip_in_cidrs(proxy_ip, opts["proxy_whitelist"]) then
    return false, true, proxy_ip, email
  end

  return true, true, client_ip, email
end

function get_source_ips(opts)
  local client_ip = opts["source_ip"]
  local proxy_ip

  -- if we have an x-forwarded-for header then use the last one in the list instead of ngx.var.remote_addr
  -- Note: This is only safe to use behind a load balancer that appends the client IP to XFF;
  -- see http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html#x-forwarded-for
  if opts["x_forwarded_for"] ~= nil then
    local xffs, err = ngx_re.split(opts["x_forwarded_for"], ", ")
    if xffs ~= nil then
      client_ip = xffs[#xffs]

      -- if we have a tic_secret which matches x-tic-secret header then
      -- 1. use x-client-ip header as client_ip for domain ip_whitelist validation
      -- 2. check last value in x-forwarded-for against proxy_whitelist
      if opts["tic_secret"] ~= nil and opts["tic_secret"] == opts["x_tic_secret"] then
        if opts["x_client_ip"] ~= nil then
          client_ip = opts["x_client_ip"]
          proxy_ip = xffs[#xffs]
        end
      end

    end
  end

  return client_ip, proxy_ip
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
