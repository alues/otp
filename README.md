> Simple OTP lib for resty

> > - [x] base32_encode
> > - [x] base32_decode
> > - [x] TOTP
> > - [] HOTP

----

```lua
    local module_otp = require ("otp")
    lcoal OTP = module_otp.totp_init("JBSWY3DPEHPK3PXP")
    ngx.say("TOTP_Token -> ", OTP:totp_calc()) 
```

----
> Output
```
    TOTP_Token -> 123456
```
