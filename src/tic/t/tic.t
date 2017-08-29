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
    allow, email = tic.check_ingress({
      whitelist={},
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={ngx.var.remote_addr},
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
    whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={"10.0.0.1"}
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
    whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={"10.0.0.1"}
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
    whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={"10.0.7.1"}
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
    whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={},
      headers=ngx.req.get_headers(),
      source_ips={"10.0.7.1"}
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
    whitelist={["gsa.gov"]={"10.0.0.0/24"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={"^/v2/info"}},
      request_uri="/v2/info",
      headers=ngx.req.get_headers(),
      source_ips={"10.0.7.1"}
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
    whitelist={["gsa.gov"]={"2001:db8::/60"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={"2001:db8:0:0:0:0:0:1"}
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
    whitelist={["gsa.gov"]={"2001:db8::/60"}}
    allow, email = tic.check_ingress({
      whitelist=whitelist,
      host_whitelist={localhost={}},
      headers=ngx.req.get_headers(),
      source_ips={"2001:db8:1:0:0:0:0:1"}
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
