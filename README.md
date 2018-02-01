> Simple OTP lib for *OpenResty*

> > - [x] base32_encode
> > - [x] base32_decode
> > - [x] TOTP
> > - [ ] ~~HOTP~~

----

##  Calculate token

```lua
    local module_otp = require ("otp")
    local OTP = module_otp.totp_init("JBSWY3DPEHPK3PXP")
    ngx.say("TOTP_Token -> ", OTP:calc_token())
```

> Output
```
    TOTP_Token -> 123456
```
---

## Generate QR Code
```lua
local OTP = module_otp.totp_init("JBSWY3DPEHPK3PXP")
local url = OTP:get_qr_url('OpenResty-TOTP', 'hello@example.com')
local html = [[
<img src='%s' />
]]

html = string.format(html, url)
ngx.header['Content-Type'] = 'text/html'
ngx.say(html)

```
> Output

![QR Code](https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&chl=otpauth%3A%2F%2Ftotp%2Fhello%40example.com%3Fsecret%3DJBSWY3DPEHPK3PXP%26issuer%3DOpenResty-TOTP)


Scan the QR Code with Google Authenticator

---

## Verify OTP
```lua
local module_otp = require ("otp")
local OTP = module_otp.totp_init("JBSWY3DPEHPK3PXP")
local token = ngx.var.arg_otp
ngx.say("Verify Token : ", OTP:verify_token(token))
```

Use OTP from Google Authenticator

```bash
curl localhost/check?otp=734923
```
> Output
```
Verify Token : true
```

Thanks! [alues](https://github.com/alues/)
