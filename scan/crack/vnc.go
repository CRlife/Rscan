package crack

import (
	"context"
	"fmt"
	"github.com/mitchellh/go-vnc"
	"net"
	"time"
)

func vnccon(cancel context.CancelFunc, ip, user, passwd string, port, timeout int) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: passwd,
			},
		},
	}
	client, err := vnc.Client(conn, config)
	if err == nil {
		defer client.Close()
		end(ip, user, passwd, port, "VNC")
		cancel()
	}

}
