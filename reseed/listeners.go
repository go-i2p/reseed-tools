package reseed

import (
	"crypto/tls"
	"net"

	"github.com/cretz/bine/tor"
	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/logger"
	"github.com/go-i2p/onramp"
)

var lgr = logger.GetGoI2PLogger()

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return srv.Serve(newBlacklistListener(ln, srv.Blacklist))
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}

	if srv.TLSConfig.NextProtos == nil {
		srv.TLSConfig.NextProtos = []string{"http/1.1"}
	}

	var err error
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	srv.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(newBlacklistListener(ln, srv.Blacklist), srv.TLSConfig)
	return srv.Serve(tlsListener)
}

func (srv *Server) ListenAndServeOnionTLS(startConf *tor.StartConf, listenConf *tor.ListenConf, certFile, keyFile string) error {
	lgr.WithField("service", "onionv3-https").Debug("Starting and registering OnionV3 HTTPS service, please wait a couple of minutes...")
	var err error
	srv.Onion, err = onramp.NewOnion("reseed")
	if err != nil {
		return err
	}
	srv.OnionListener, err = srv.Onion.ListenTLS()
	if err != nil {
		return err
	}
	lgr.WithField("service", "onionv3-https").WithField("address", srv.OnionListener.Addr().String()+".onion").WithField("protocol", "https").Debug("Onionv3 server started")

	return srv.Serve(srv.OnionListener)
}

func (srv *Server) ListenAndServeOnion(startConf *tor.StartConf, listenConf *tor.ListenConf) error {
	lgr.WithField("service", "onionv3-http").Debug("Starting and registering OnionV3 HTTP service, please wait a couple of minutes...")
	var err error
	srv.Onion, err = onramp.NewOnion("reseed")
	if err != nil {
		return err
	}
	srv.OnionListener, err = srv.Onion.Listen()
	if err != nil {
		return err
	}
	lgr.WithField("service", "onionv3-http").WithField("address", srv.OnionListener.Addr().String()+".onion").WithField("protocol", "http").Debug("Onionv3 server started")

	return srv.Serve(srv.OnionListener)
}

func (srv *Server) ListenAndServeI2PTLS(samaddr string, I2PKeys i2pkeys.I2PKeys, certFile, keyFile string) error {
	lgr.WithField("service", "i2p-https").WithField("sam_address", samaddr).Debug("Starting and registering I2P HTTPS service, please wait a couple of minutes...")
	var err error
	srv.Garlic, err = onramp.NewGarlic("reseed-tls", samaddr, onramp.OPT_WIDE)
	if err != nil {
		return err
	}
	srv.I2PListener, err = srv.Garlic.ListenTLS()
	if err != nil {
		return err
	}
	lgr.WithField("service", "i2p-https").WithField("address", srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32()).WithField("protocol", "https").Debug("I2P server started")
	return srv.Serve(srv.I2PListener)
}

func (srv *Server) ListenAndServeI2P(samaddr string, I2PKeys i2pkeys.I2PKeys) error {
	lgr.WithField("service", "i2p-http").WithField("sam_address", samaddr).Debug("Starting and registering I2P service, please wait a couple of minutes...")
	var err error
	srv.Garlic, err = onramp.NewGarlic("reseed", samaddr, onramp.OPT_WIDE)
	if err != nil {
		return err
	}
	srv.I2PListener, err = srv.Garlic.Listen()
	if err != nil {
		return err
	}
	lgr.WithField("service", "i2p-http").WithField("address", srv.I2PListener.Addr().(i2pkeys.I2PAddr).Base32()+".b32.i2p").WithField("protocol", "http").Debug("I2P server started")
	return srv.Serve(srv.I2PListener)
}
