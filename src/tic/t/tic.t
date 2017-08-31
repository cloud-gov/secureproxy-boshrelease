use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: no whitelist
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- config
location = /t {
  access_by_lua_block {
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist={},
      host_whitelist={localhost={}},
      source_ip=ngx.var.remote_addr,
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 2: whitelist | not restricted
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@nih.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="10.0.0.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 3: whitelist | restricted | valid
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="10.0.0.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 4: whitelist | restricted | invalid
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="10.0.7.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403

=== TEST 5: whitelist | restricted | invalid | no host whitelist
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={},
      source_ip="10.0.7.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 6: whitelist | restricted | invalid | path whitelist
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={"^/v2/info"}},
      request_uri="/v2/info",
      source_ip="10.0.7.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 7: whitelist | restricted | valid | ipv6
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"2001:db8::/60"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="2001:db8:0:0:0:0:0:1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 8: whitelist | restricted | invalid | ipv6
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}')
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"2001:db8::/60"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ip="2001:db8:1:0:0:0:0:1"
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403

=== TEST 9: whitelist | restricted | valid (XFF)
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.0.0.1"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 10: whitelist | restricted | invalid (XFF)
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r'\n" .
"X-Forwarded-For: 10.0.7.1"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403

=== TEST 11: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist valid IP | proxy_whitelist valid secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.9.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" . "\r\n" .
"X-TIC-Secret: validvalidvalid"
""
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      tic_secret="validvalidvalid",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 12: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist valid IP | proxy_whitelist invalid secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.9.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" ."\r\n" .
"X-TIC-Secret: invalidinvalidinvalid"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      tic_secret="validvalidvalid",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403
--- response_body
hi

=== TEST 13: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist invalid IP | proxy_whitelist valid secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.7.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" . "\r\n" .
"X-TIC-Secret: validvalidvalid"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      tic_secret="validvalidvalid",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403
--- response_body
hi

=== TEST 14: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist invalid IP | proxy_whitelist invalid secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.7.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" . "\r\n" .
"X-TIC-Secret: invalidinvalidinvalid"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      tic_secret="validvalidvalid",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403
--- response_body
hi

=== TEST 15: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist valid IP | proxy_whitelist no secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.9.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" . "\r\n" .
"X-TIC-Secret: nonenonenone"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 200
--- response_body
hi

=== TEST 16: whitelist | restricted | valid (X-Client-IP) | proxy_whitelist invalid IP | proxy_whitelist no secret
--- http_config
init_by_lua_block {
  tic = require "tic"
}
--- more_headers eval
use MIME::Base64;
"Authorization: Bearer header." . encode_base64('{"email":"hi@gsa.gov"}') . "\r\n" .
"X-Forwarded-For: 10.7.0.1" . "\r\n" .
"X-Client-IP: 10.0.0.1" . "\r\n" .
"X-TIC-Secret: nonenonenone"
--- config
location = /t {
  access_by_lua_block {
    ip_whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    proxy_whitelist={"10.9.0.0/24"}
    allow, filtered, source_ip, email = tic.check_ingress({
      whitelist=ip_whitelist,
      proxy_whitelist=proxy_whitelist,
      host_whitelist={localhost={}},
      source_ip="192.168.1.1",
      headers=ngx.req.get_headers()
    })
    if not allow then
      return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
  }
  echo "hi";
}
--- request
GET /t
--- error_code: 403
--- response_body
hi
