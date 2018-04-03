local brute = require "brute"
local creds = require "creds"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against CMS Made Simple (version 2.2.6).

This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
stored using the credentials library.
]] 

--
-- @usage
-- nmap -sV --script http-cmsmadesimple-brute <target>
-- nmap -sV --script http-cmsmadesimple-brute
--   --script-args 'userdb=users.txt,passdb=passwds.txt,http-cmsmadesimple-brute.hostname=domain.com,
--                  http-cmsmadesimple-brute.threads=1,brute.firstonly=true' <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 22/tcp   open  ssh     syn-ack
-- 80/tcp   open  http    syn-ack
-- | http-cmsmadesimple-brute: 
-- |   Accounts: 
-- |     admin:admin123 - Valid credentials
-- |_  Statistics: Performed 6 guesses in 4 seconds, average tps: 1.5
-- 111/tcp  open  rpcbind syn-ack
-- 631/tcp  open  ipp     syn-ack
-- 3306/tcp open  mysql   syn-ack
-- Final times for host: srtt: 146 rttvar: 122  to: 100000
--
-- @args http-cmsmadesimple-brute.uri points to admin dir '/admin'. Default /admin
-- @args http-cmsmadesimple-brute.hostname sets the host header in case of virtual hosting
-- @args http-cmsmadesimple-brute.username sets the http-variable name that holds the username used to authenticate. Default: log
-- @args http-cmsmadesimple-brute.password sets the http-variable name that holds the password used to authenticate. Default: pwd
-- @args http-cmsmadesimple-brute.threads sets the number of threads. Default: 1
--
-- Other useful arguments when using this script are:
-- * http.useragent = String - User Agent used in HTTP requests
-- * brute.firstonly = Boolean - Stop attack when the first credentials are found
-- * brute.mode = user - Username password iterator
-- * passdb = String - Path to passwords list
-- * userdb = String - Path to users list
--
-- @see http-form-brute.nse

author = "Artur Kielak <kielaka@vp.pl>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

local DEFAULT_CMS_URI = "/admin"
local DEFAULT_CMS_USERVAR = "log"
local DEFAULT_CMS_PASSVAR = "pwd"
local DEFAULT_THREAD_NUM = 1

local COOKIE_SK = "_sk_"
local COOKIE_SESSID = "CMSSESSID"
local COOKIE_DBB = "dbb"

local getValue = function (cookies, key, counter)
  local counter = counter or 0
  local delim = ";"
  local first = string.find(cookies, key)

  if (counter > 0) then
    local i = 0
    while i < counter do
      first = string.find(cookies, key, first + 1)
      i = i + 1
    end
    first = string.find(cookies, key)
    first = string.find(cookies, key, first + 1)
  end

  local second = string.find(cookies, delim, first + 1)
  return string.sub(cookies, first, second - 1)
end

local getCookie = function (cookies)
  local delim = ";"
  local values = {}
  local cookie = getValue(cookies, COOKIE_SK)
  local url = (stdnse.get_script_args('http-cmsmadesimple-brute.uri') or DEFAULT_CMS_URI) .. "?" .. cookie
  cookie = cookie .. delim
  cookie = cookie .. getValue(cookies, COOKIE_SESSID) 
  cookie = cookie .. delim
  cookie = cookie .. getValue(cookies, COOKIE_DBB, 1)
  cookie = cookie .. delim
  return url, cookie 
end

---
--This class implements the Driver class from the Brute library
---
Driver = {
  new = function(self, host, port, options)
    local default = {}
    setmetatable(default, self)
    self.__index = self
    default.hostname = stdnse.get_script_args('http-cmsmadesimple-brute.hostname')
    default.http_options = {
      no_cache = true,
      header = {
        Host = stdnse.get_script_args('http-cmsmadesimple-brute.hostname'),
        ['Content-Type'] = 'application/x-www-form-urlencoded';
      }
    }
    default.host = host
    default.port = port
    default.uri = (stdnse.get_script_args('http-cmsmadesimple-brute.uri') or DEFAULT_CMS_URI) .. '/login.php'
    default.options = options
    return default
  end,

  connect = function( self )
    return true
  end,

  login = function( self, username, password )
    local post_response = http.post( self.host, self.port, self.uri, self.http_options,
    nil, { ['username'] = username, ['password'] = password, ['loginsubmit'] = ' ' } )
    if (post_response.status == 302) then
      local url, cookie = getCookie(post_response.header["set-cookie"])
      local get_response = http.get(self.host, self.port, url, {
        bypass_cache = true,
        header = { ['Cookie'] = cookie,}
      })
      if ( get_response.status == 200 and string.find(get_response.body, username) ~= nil) then
        stdnse.debug1("Initial check passed. Launching brute force attack")
        return true, creds.Account:new( username, password, creds.State.VALID)
      else
        stdnse.debug1("Initial check failed. Password field wasn't found")
      end
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return true
  end,

  check = function( self )
    return true
  end
}

action = function( host, port )
  local status, result, engine
  local username = stdnse.get_script_args('http-cmsmadesimple-brute.username') or DEFAULT_CMS_USERVAR
  local password = stdnse.get_script_args('http-cmsmadesimple-brute.password') or DEFAULT_CMS_PASSVAR
  local max_threads = tonumber(stdnse.get_script_args("http-cmsmadesimple-brute.threads")) or DEFAULT_THREAD_NUM
  engine = brute.Engine:new( Driver, host, port, { uservar = username, passvar = password } )
  engine:setMaxThreads(max_threads)
  engine.options.script_name = SCRIPT_NAME
  status, result = engine:start()
  return result
end

