local _M = { _VERSION = '0.01.05' }

local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift

local Base32_Hash = {
    [0 ] = 65, [1 ] = 66, [2 ] = 67, [3 ] = 68, [4 ] = 69, [5 ] = 70,
    [6 ] = 71, [7 ] = 72, [8 ] = 73, [9 ] = 74, [10] = 75, [11] = 76,
    [12] = 77, [13] = 78, [14] = 79, [15] = 80, [16] = 81, [17] = 82,
    [18] = 83, [19] = 84, [20] = 85, [21] = 86, [22] = 87, [23] = 88,
    [24] = 89, [25] = 90, 
    [26] = 50, [27] = 51, [28] = 52, [29] = 53, [30] = 54, [31] = 55,

    [50] = 26, [51] = 27, [52] = 28, [53] = 29, [54] = 30, [55] = 31,
    [65] = 0,  [66] = 1,  [67] = 2,  [68] = 3,  [69] = 4,  [70] = 5, 
    [71] = 6,  [72] = 7,  [73] = 8,  [74] = 9,  [75] = 10, [76] = 11, 
    [77] = 12, [78] = 13, [79] = 14, [80] = 15, [81] = 16, [82] = 17, 
    [83] = 18, [84] = 19, [85] = 20, [86] = 21, [87] = 22, [88] = 23, 
    [89] = 24, [90] = 25,
}

local function decode_base32(secret_str)
    local Secret_Token = {secret_str:byte(1, -1)}
    local Secret_Token_Base32 = {}

    local n = 0
    local bs = 0

    for i, v in ipairs(Secret_Token) do
        n = lshift(n, 5)
        n = n + Base32_Hash[v]
        bs = (bs + 5) % 8
        if (bs < 5) then
            Secret_Token_Base32[#Secret_Token_Base32+1] = rshift(band(n, lshift(0xFF, bs)), bs)
        end
    end

    return string.char(table.unpack(Secret_Token_Base32))
end

local function encode_base32(secret_str)
    local Secret_Token = {secret_str:byte(1, -1)}
    local Secret_Token_Base32 = {}
    local Tmp_cahr = 0

    local c = 0
    local n = 0
    local tmp_n = 0
    local bs =0

    for i, v in ipairs(Secret_Token) do
        n = lshift(n, 8)
        n = n + v
        c = c + 8
        bs = c % 5
        tmp_n = rshift(n, bs)

        for j = c - bs - 5, 0, -5 do
            Tmp_cahr = rshift(band(tmp_n, lshift(0x1F, j)), j)
            Secret_Token_Base32[#Secret_Token_Base32+1] = Base32_Hash[Tmp_cahr]
        end

        c = bs
        n = band(n, rshift(0xFF, 8 - bs))
    end

    return string.char(table.unpack(Secret_Token_Base32))
end

local function percent_encode_char(c)
  return string.format("%%%02X", c:byte())
end

local function url_encode(str)
  local r = str:gsub("[^a-zA-Z0-9.~_-]", percent_encode_char)
  return r
end


local function totp_time_calc(ngx_time)
    local ngx_time_str = {}

    for i = 1, 8 do
        table.insert(ngx_time_str, bit.band(ngx_time, 0xFF))
        ngx_time = bit.rshift(ngx_time, 8)
    end

    return string.reverse(string.char(table.unpack(ngx_time_str)))
end

local function totp_new_key()
    local tmp_k = ""
    math.randomseed(ngx.time())
    for i = 1, 10 do
        tmp_k = tmp_k .. string.char(math.random(0, 255))
    end
    return encode_base32(tmp_k)
end

------ TOTP functions ------

local TOTP_MT = {}

function _M.totp_init(secret_key)
    local r = {
        type = "totp",
    }
    setmetatable(r, { __index = TOTP_MT, __tostring = TOTP_MT.serialize })
    r:new_key(secret_key)
    return r
end

function TOTP_MT:new_key(secret_key)
    self.key = secret_key or totp_new_key()
    self.key_decoded = decode_base32(self.key)
end

function TOTP_MT:calc_token()
    local ngx_time = math.floor(ngx.time() / 30)
    HMAC_Result_Final = {ngx.hmac_sha1(self.key_decoded, totp_time_calc(ngx_time)):byte(1, -1)}

    local HMAC_Offset = band(HMAC_Result_Final[20], 0xF)

    -- for i, v in ipairs(HMAC_Result_Final) do
    --     ngx.say(i , " -> ", string.format("%02X", v))
    -- end

    --ngx.say("HMAC_Offset Result ->", HMAC_Offset)

    local TOTP_Token = 0

    for i = 1, 4 do
        --ngx.say(HMAC_Result_Final[HMAC_Offset + i])
        TOTP_Token = TOTP_Token + lshift(HMAC_Result_Final[HMAC_Offset + i], (4 - i) * 8 )
    end

    TOTP_Token = band(TOTP_Token, 0x7FFFFFFF)
    TOTP_Token = TOTP_Token % 1000000
    return string.format("%06d", TOTP_Token)
end

function TOTP_MT:verify_token(token)
    return (token == self:calc_token())
end

function TOTP_MT:get_url(issuer, account)
    return table.concat{
        "otpauth://totp/",
        account,
        "?secret=", self.key,
        "&issuer=", issuer,
    }
end

function TOTP_MT:get_qr_url(issuer, account)
    return table.concat{
        "https://chart.googleapis.com/chart",
        "?chs=", "200x200",
        "&cht=qr",
        "&chl=200x200",
        "&chld=M|0",
        "&chl=", url_encode(self:get_url(issuer, account)),
    }
end

function TOTP_MT:serialize()
    return table.concat{
        "type:totp\n",
        "secret:", self.key,
        "secret_decoded", self.key_decoded,
    }
end

return _M
