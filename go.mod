module i2pgit.org/go-i2p/reseed-tools

go 1.26.3

require (
	github.com/cretz/bine v0.2.0
	github.com/eyedeekay/unembed v0.0.0-20230123014222-9916b121855b
	github.com/go-acme/lego/v4 v4.35.2
	github.com/go-i2p/checki2cp v0.0.0-20260908192038-1213c2e89cc7
	github.com/go-i2p/common v0.1.59999
	github.com/go-i2p/go-sam-bridge v0.1.59999
	github.com/go-i2p/i2pkeys v0.33.92
	github.com/go-i2p/logger v0.1.60000-0.20260701134448-2648c3b0e040
	github.com/go-i2p/onramp v0.33.92
	github.com/go-i2p/sam3 v0.33.92
	github.com/gorilla/handlers v1.5.2
	github.com/justinas/alice v1.2.0
	github.com/otiai10/copy v1.14.1
	github.com/rglonek/untar v0.0.1
	github.com/throttled/throttled/v2 v2.15.0
	github.com/urfave/cli/v3 v3.11.0
	gitlab.com/golang-commonmark/markdown v0.0.0-20211110145824-bf3e522c626a
	golang.org/x/text v0.42.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2 // indirect
	github.com/beevik/ntp v1.5.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.15 // indirect
	github.com/go-i2p/crypto v0.1.59999 // indirect
	github.com/go-i2p/elgamal v0.1.59999 // indirect
	github.com/go-i2p/go-datagrams v0.1.59999 // indirect
	github.com/go-i2p/go-i2cp v0.1.59999 // indirect
	github.com/go-i2p/go-i2p v0.1.59999 // indirect
	github.com/go-i2p/go-nat-listener v0.1.68 // indirect
	github.com/go-i2p/go-noise v0.1.59999 // indirect
	github.com/go-i2p/go-streaming v0.1.59999 // indirect
	github.com/go-i2p/go-unzip v0.0.0-20260908192035-1d47af1fc238 // indirect
	github.com/go-i2p/noise v1.1.1-0.20260327201800-8e41bb3d9f1e // indirect
	github.com/go-i2p/path v0.1.59999 // indirect
	github.com/go-i2p/pool v0.1.59999 // indirect
	github.com/go-i2p/red25519 v0.0.0-20260908192929-b906f5fda5c0 // indirect
	github.com/go-i2p/su3 v0.1.59999 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gomodule/redigo v2.0.0+incompatible // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/jackpal/go-nat-pmp v1.1.0 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/otiai10/mint v1.6.3 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/samber/oops v1.23.1 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	gitlab.com/golang-commonmark/html v0.0.0-20191124015941-a22733972181 // indirect
	gitlab.com/golang-commonmark/linkify v0.0.0-20200225224916-64bca66f6ad3 // indirect
	gitlab.com/golang-commonmark/mdurl v0.0.0-20191124015652-932350d1cb84 // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.step.sm/crypto v0.90.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/time v0.16.0 // indirect
)

//replace github.com/go-i2p/go-i2p => ../../../github.com/go-i2p/go-i2p

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)
