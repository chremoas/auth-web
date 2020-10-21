module github.com/chremoas/auth-web

go 1.14

require (
	github.com/antihax/goesi v0.0.0-20190723215635-487b927dc566
	github.com/astaxie/beego v1.12.0
	github.com/chremoas/auth-srv v1.3.0
	github.com/chremoas/services-common v1.3.0
	github.com/elazarl/go-bindata-assetfs v1.0.0
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79
	github.com/mailru/easyjson v0.0.0-20190626092158-b2ccc519800e // indirect
	github.com/micro/go-micro v1.9.1
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
)

replace github.com/chremoas/auth-web => ../auth-web
replace github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
