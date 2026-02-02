package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
)

func handleP2PUdp(
	pCtx context.Context,
	localAddr, rAddr, md5Password, sendRole, sendMode, sendData string,
) (c net.PacketConn, remoteAddress, localAddress, role, mode, data string, err error) {
	localAddress = localAddr
	parentCtx, parentCancel := context.WithTimeout(pCtx, 30*time.Second)
	defer parentCancel()

	localConn, err := conn.NewUdpConnByAddr(localAddr)
	if err != nil {
		logs.Error("[P2P] start fail newUdpConn localWant=%s err=%v", localAddr, err)
		return
	}

	handedOff := false
	defer func() {
		if !handedOff {
			_ = localConn.Close()
		}
	}()

	port := common.GetPortStrByAddr(localAddr)
	if port == "" || port == "0" {
		port = common.GetPortStrByAddr(localConn.LocalAddr().String())
	}
	localCandidates := buildP2PLocalStr(port)

	logs.Debug("[P2P] start role=%s local=%s server=%s port=%s candidates=%s mode=%s dataLen=%d",
		sendRole, localConn.LocalAddr().String(), rAddr, port, localCandidates, sendMode, len(sendData))

	for seq := 0; seq < 3; seq++ {
		if err = getRemoteAddressFromServer(rAddr, localCandidates, localConn, md5Password, sendRole, sendMode, sendData, seq); err != nil {
			logs.Error("[P2P] getRemoteAddressFromServer seq=%d err=%v", seq, err)
			return
		}
	}

	var peerExt1, peerExt2, peerExt3 string
	var selfExt1, selfExt2, selfExt3 string
	var peerLocal string
	serverPort := common.GetPortByAddr(rAddr)

	buf := make([]byte, 1024)
	var punchedAddr net.Addr

	for {
		select {
		case <-parentCtx.Done():
			err = parentCtx.Err()
			logs.Error("[P2P] wait server reply timeout local=%s server=%s err=%v", localConn.LocalAddr().String(), rAddr, err)
			return
		default:
		}

		_ = localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, fromAddr, rerr := localConn.ReadFrom(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && (ne.Timeout() || ne.Temporary()) {
				continue
			}
			err = rerr
			logs.Error("[P2P] read server reply failed local=%s err=%v", localConn.LocalAddr().String(), err)
			return
		}

		raw := string(buf[:n])
		if raw == common.WORK_P2P_CONNECT {
			punchedAddr = fromAddr
			logs.Debug("[P2P] punched-in CONNECT from=%s local=%s", fromAddr.String(), localConn.LocalAddr().String())
			_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), fromAddr)
			break
		}

		peerExt, pLocal, m, d, selfExt := parseP2PServerReply(raw)
		if peerExt == "" {
			continue
		}

		if pLocal != "" && peerLocal == "" {
			peerLocal = pLocal
		}
		if m != "" {
			mode = m
		}
		if d != "" {
			data = d
		}

		fromPort := common.GetPortByAddr(fromAddr.String())
		switch fromPort {
		case serverPort:
			peerExt1 = peerExt
			if selfExt != "" {
				selfExt1 = selfExt
			}
		case serverPort + 1:
			peerExt2 = peerExt
			if selfExt != "" {
				selfExt2 = selfExt
			}
		case serverPort + 2:
			peerExt3 = peerExt
			if selfExt != "" {
				selfExt3 = selfExt
			}
		}

		logs.Trace("[P2P] server-reply from=%s peerExt=%s peerLocal=%s selfExt=%s mode=%s dataLen=%d",
			fromAddr.String(), peerExt, pLocal, selfExt, m, len(d))

		if peerExt1 != "" && peerExt2 != "" && peerExt3 != "" {
			break
		}
	}

	logs.Debug("[P2P] collected peerExt=[%s,%s,%s] selfExt=[%s,%s,%s] peerLocal=%s punched=%v",
		peerExt1, peerExt2, peerExt3, selfExt1, selfExt2, selfExt3, peerLocal, punchedAddr != nil)

	winConn, remoteAddress, localAddress, role, err := sendP2PTestMsg(
		parentCtx,
		localConn,
		sendRole,
		peerExt1, peerExt2, peerExt3,
		peerLocal,
		selfExt1, selfExt2, selfExt3,
		punchedAddr,
	)
	if err != nil {
		logs.Error("[P2P] sendP2PTestMsg failed local=%s err=%v", localConn.LocalAddr().String(), err)
		return
	}

	if localAddr != localAddress {
		logs.Trace("[P2P] LocalAddr changed: want=%s actual=%s", localAddr, localAddress)
	}

	network, fixedLocal, ferr := common.FixUdpListenAddrForRemote(remoteAddress, localAddress)
	if ferr != nil {
		err = ferr
		logs.Error("[P2P] fix listen addr failed remote=%s local=%s err=%v", remoteAddress, localAddress, err)
		return
	}
	if fixedLocal != localAddress {
		logs.Trace("[P2P] fix listen addr remote=%s local=%s -> %s", remoteAddress, localAddress, fixedLocal)
		localAddress = fixedLocal
	}

	needRecreate := false
	if _, ok := winConn.(*conn.SmartUdpConn); ok {
		needRecreate = true
	}
	if winConn.LocalAddr() == nil || winConn.LocalAddr().String() != localAddress {
		needRecreate = true
	}

	if needRecreate {
		_ = winConn.Close()
		c, err = net.ListenPacket("udp", localAddress)
		if err != nil {
			logs.Error("[P2P] net.ListenPacket failed network=%s local=%s err=%v", network, localAddress, err)
			return
		}
	} else {
		c = winConn
	}

	handedOff = true
	logs.Info("[P2P] connected role=%s remote=%s local=%s", role, remoteAddress, localAddress)
	logs.Debug("[P2P] handshake done role=%s remote=%s local=%s", role, remoteAddress, localAddress)
	return
}

func buildP2PLocalStr(port string) string {
	if port == "" || port == "0" {
		return ""
	}
	out := make([]string, 0, 2)

	tmpConnV4, errV4 := common.GetLocalUdp4Addr()
	if errV4 == nil && tmpConnV4 != nil {
		if la, ok := tmpConnV4.LocalAddr().(*net.UDPAddr); ok && la != nil && la.IP != nil && !common.IsZeroIP(la.IP) {
			a := net.JoinHostPort(la.IP.String(), port)
			if a != "" && !common.InStrArr(out, a) {
				out = append(out, a)
			}
		}
	}

	tmpConnV6, errV6 := common.GetLocalUdp6Addr()
	if errV6 == nil && tmpConnV6 != nil {
		if la, ok := tmpConnV6.LocalAddr().(*net.UDPAddr); ok && la != nil && la.IP != nil && !common.IsZeroIP(la.IP) {
			a := net.JoinHostPort(la.IP.String(), port)
			if a != "" && !common.InStrArr(out, a) {
				out = append(out, a)
			}
		}
	}

	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, ",")
}

func getRemoteAddressFromServer(
	rAddr, localCandidates string,
	localConn net.PacketConn,
	md5Password, role, mode, data string,
	add int,
) error {
	next, err := getNextAddr(rAddr, add)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", next)
	if err != nil {
		return err
	}
	payload := common.GetWriteStr(md5Password, role, localCandidates, mode, data)
	if _, err := localConn.WriteTo(payload, addr); err != nil {
		return err
	}
	logs.Trace("[P2P] sent req to server=%s local=%s add=%d candidates=%s", addr.String(), localConn.LocalAddr().String(), add, localCandidates)
	return nil
}

func parseP2PServerReply(raw string) (peerExt, peerLocal, mode, data, selfExt string) {
	parts := strings.Split(raw, common.CONN_DATA_SEQ)
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return
	}

	peerExt = common.ValidateAddr(parts[0])
	if peerExt == "" {
		return "", "", "", "", ""
	}

	if len(parts) >= 2 {
		peerLocal = common.ValidateAddr(parts[1])
	}
	if len(parts) >= 3 {
		mode = parts[2]
	}
	if len(parts) >= 4 {
		data = parts[3]
	}
	if len(parts) >= 5 {
		selfExt = common.ValidateAddr(parts[4])
	}
	return
}

func sendP2PTestMsg(
	pCtx context.Context,
	localConn net.PacketConn,
	sendRole string,
	peerExt1, peerExt2, peerExt3 string,
	peerLocal string,
	selfExt1, selfExt2, selfExt3 string,
	punchedAddr net.Addr,
) (winConn net.PacketConn, remoteAddr, localAddr, role string, err error) {
	parentCtx, parentCancel := context.WithCancel(pCtx)

	var closed uint32
	connList := []net.PacketConn{localConn}
	var winner net.PacketConn

	defer func() {
		atomic.StoreUint32(&closed, 1)
		parentCancel()

		if winner != nil {
			for _, c := range connList {
				if c == winner {
					continue
				}
				_ = c.Close()
			}
			return
		}

		for _, c := range connList {
			_ = c.Close()
		}
	}()

	if punchedAddr != nil {
		logs.Debug("[P2P] fast-path punched=%s", punchedAddr.String())
		rAddr, lAddr, rRole, rErr := waitP2PHandshakeSeed(parentCtx, localConn, sendRole, 10, punchedAddr)
		if rErr == nil {
			winner = localConn
			return localConn, rAddr, lAddr, rRole, nil
		}
		return nil, "", "", sendRole, rErr
	}

	if peerLocal != "" {
		logs.Debug("[P2P] peerLocal=%s", peerLocal)
		go func() {
			remoteUdpLocal, rerr := net.ResolveUDPAddr("udp", peerLocal)
			if rerr != nil {
				logs.Error("[P2P] resolve peerLocal failed peerLocal=%s err=%v", peerLocal, rerr)
				return
			}
			for i := 20; i > 0; i-- {
				select {
				case <-parentCtx.Done():
					return
				default:
				}
				if atomic.LoadUint32(&closed) != 0 {
					return
				}
				_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), remoteUdpLocal)
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}

	hasPeerExt := peerExt1 != "" && peerExt2 != "" && peerExt3 != ""
	peerInterval := 0
	if hasPeerExt {
		peerInterval, err = getAddrInterval(peerExt1, peerExt2, peerExt3)
		if err != nil {
			hasPeerExt = false
			peerInterval = 0
		}
	}

	hasSelfExt := selfExt1 != "" && selfExt2 != "" && selfExt3 != ""
	selfInterval := 0
	if hasSelfExt {
		selfInterval, err = getAddrInterval(selfExt1, selfExt2, selfExt3)
		if err != nil {
			hasSelfExt = false
			selfInterval = 0
		}
	}

	logs.Info("[P2P] nat peer=%s(%d) self=%s(%d)",
		natHintByInterval(peerInterval, hasPeerExt), peerInterval,
		natHintByInterval(selfInterval, hasSelfExt), selfInterval)

	switch {
	case hasPeerExt && hasSelfExt && peerInterval == 0 && selfInterval != 0:
		logs.Debug("[P2P] strategy=A peerExt3=%s", peerExt3)

		targetAddr, e := getNextAddr(peerExt3, peerInterval)
		if e != nil {
			return nil, "", localConn.LocalAddr().String(), sendRole, e
		}
		targetUDP, e := net.ResolveUDPAddr("udp", targetAddr)
		if e != nil {
			return nil, "", localConn.LocalAddr().String(), sendRole, e
		}

		want4 := targetUDP.IP != nil && targetUDP.IP.To4() != nil
		var network string
		var lip net.IP
		if want4 {
			network = "udp4"
			lip, e = common.GetLocalUdp4IP()
		} else {
			network = "udp6"
			lip, e = common.GetLocalUdp6IP()
		}
		if e != nil || lip == nil || common.IsZeroIP(lip) || lip.IsUnspecified() {
			logs.Error("[P2P] strategy=A get local ip failed network=%s err=%v", network, e)
			return nil, "", localConn.LocalAddr().String(), sendRole, errors.New("no usable local ip")
		}
		lip = common.NormalizeIP(lip)

		for i := 0; i < 256; i++ {
			uc, ee := net.ListenUDP(network, &net.UDPAddr{IP: lip, Port: 0})
			if ee != nil {
				continue
			}
			connList = append(connList, uc)
			time.Sleep(3 * time.Millisecond)
		}

		logs.Debug("[P2P] strategy=A target=%s connCount=%d", targetUDP.String(), len(connList))

		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
					if atomic.LoadUint32(&closed) != 0 {
						return
					}
					for _, c := range connList {
						_, _ = c.WriteTo([]byte(common.WORK_P2P_CONNECT), targetUDP)
					}
				}
			}
		}()

		type P2PResult struct {
			Conn       net.PacketConn
			RemoteAddr string
			LocalAddr  string
			Role       string
		}
		resultChan := make(chan P2PResult, 1)

		for _, c := range connList {
			go func(cc net.PacketConn) {
				rAddr, lAddr, rRole, rErr := waitP2PHandshake(parentCtx, cc, sendRole, 10)
				if rErr == nil {
					select {
					case resultChan <- P2PResult{Conn: cc, RemoteAddr: rAddr, LocalAddr: lAddr, Role: rRole}:
					default:
					}
				}
			}(c)
		}

		select {
		case res := <-resultChan:
			parentCancel()
			for _, c := range connList {
				_ = c.SetReadDeadline(time.Now())
			}
			winner = res.Conn
			return res.Conn, res.RemoteAddr, res.LocalAddr, res.Role, nil
		case <-parentCtx.Done():
			return nil, "", localConn.LocalAddr().String(), sendRole, errors.New("connect to the target failed, maybe the nat type is not support p2p")
		}

	case hasPeerExt && hasSelfExt && peerInterval != 0 && selfInterval == 0:
		logs.Debug("[P2P] strategy=B random-scan (peer symmetric-ish, self stable-ish) peerExt3=%s peerExt2=%s", peerExt3, peerExt2)

		go func() {
			addr, e := getNextAddr(peerExt3, peerInterval)
			if e != nil {
				return
			}
			remoteUDP, e := net.ResolveUDPAddr("udp", addr)
			if e != nil {
				return
			}
			logs.Trace("[P2P] strategy=B predicted target sender target=%s", remoteUDP.String())

			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
					if atomic.LoadUint32(&closed) != 0 {
						return
					}
					_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), remoteUDP)
				}
			}
		}()

		go func() {
			ip := common.RemovePortFromHost(peerExt2)
			ports := getRandomUniquePorts(1000, 1, 65535)
			logs.Debug("[P2P] strategy=B scanning ip=%s ports=%d", ip, len(ports))

			udpAddrs := make([]*net.UDPAddr, 0, len(ports))
			for _, p := range ports {
				ra, e := net.ResolveUDPAddr("udp", ip+":"+strconv.Itoa(p))
				if e == nil {
					udpAddrs = append(udpAddrs, ra)
				}
			}

			for _, ra := range udpAddrs {
				_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), ra)
			}

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
					if atomic.LoadUint32(&closed) != 0 {
						return
					}
					for _, ra := range udpAddrs {
						_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), ra)
					}
				}
			}
		}()

	default:
		logs.Debug("[P2P] strategy=Default peerInterval=%d peerExt3=%s", peerInterval, peerExt3)

		if peerExt3 != "" {
			go func() {
				addr, e := getNextAddr(peerExt3, peerInterval)
				if e != nil {
					return
				}
				remoteUDP, e := net.ResolveUDPAddr("udp", addr)
				if e != nil {
					return
				}
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-parentCtx.Done():
						return
					case <-ticker.C:
						if atomic.LoadUint32(&closed) != 0 {
							return
						}
						_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), remoteUDP)
					}
				}
			}()
		}

		if peerInterval != 0 && peerExt1 != "" && peerExt2 != "" && peerExt3 != "" {
			go func() {
				ip := common.RemovePortFromHost(peerExt2)
				p1 := common.GetPortByAddr(peerExt1)
				p2 := common.GetPortByAddr(peerExt2)
				p3 := common.GetPortByAddr(peerExt3)

				startPort := p3
				endPort := startPort + (peerInterval * 50)
				if (p1 < p3 && p3 < p2) || (p1 > p3 && p3 > p2) {
					endPort = endPort + (p2 - p3)
				}
				endPort = common.GetPort(endPort)

				ports := getRandomUniquePorts(51, startPort, endPort)
				udpAddrs := make([]*net.UDPAddr, 0, len(ports))
				for _, p := range ports {
					ra, e := net.ResolveUDPAddr("udp", ip+":"+strconv.Itoa(p))
					if e == nil {
						udpAddrs = append(udpAddrs, ra)
					}
				}

				for _, ra := range udpAddrs {
					_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), ra)
				}

				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-parentCtx.Done():
						return
					case <-ticker.C:
						if atomic.LoadUint32(&closed) != 0 {
							return
						}
						for _, ra := range udpAddrs {
							_, _ = localConn.WriteTo([]byte(common.WORK_P2P_CONNECT), ra)
						}
					}
				}
			}()
		}
	}

	rAddr, lAddr, rRole, rErr := waitP2PHandshake(parentCtx, localConn, sendRole, 10)
	if rErr == nil {
		winner = localConn
		return localConn, rAddr, lAddr, rRole, nil
	}
	return nil, "", "", sendRole, rErr
}

func waitP2PHandshakeSeed(parentCtx context.Context, localConn net.PacketConn, sendRole string, readTimeout int, seed net.Addr) (remoteAddr, localAddr, role string, err error) {
	if seed != nil {
		_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), seed)
		go func(a net.Addr) {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for i := 0; i < 20; i++ {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
				}
				_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), a)
			}
		}(seed)
	}
	return waitP2PHandshake(parentCtx, localConn, sendRole, readTimeout)
}

func waitP2PHandshake(parentCtx context.Context, localConn net.PacketConn, sendRole string, readTimeout int) (remoteAddr, localAddr, role string, err error) {
	buf := make([]byte, 10)

	var senderStarted uint32
	var lastConnectAddr atomic.Value // stores net.Addr (*net.UDPAddr)

	startSuccessSender := func() {
		if !atomic.CompareAndSwapUint32(&senderStarted, 0, 1) {
			return
		}
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for i := 0; i < 20; i++ {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
				}

				v := lastConnectAddr.Load()
				if v == nil {
					continue
				}
				a := v.(net.Addr)
				logs.Trace("[P2P] retry SUCCESS to=%s local=%s", a.String(), localConn.LocalAddr().String())
				_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), a)
			}
		}()
	}

	logs.Trace("[P2P] handshake wait role=%s local=%s timeout=%ds", sendRole, localConn.LocalAddr().String(), readTimeout)

Loop:
	for {
		select {
		case <-parentCtx.Done():
			break Loop
		default:
		}

		_ = localConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(readTimeout)))
		n, addr, rerr := localConn.ReadFrom(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if rerr != nil {
			var ne net.Error
			if errors.As(rerr, &ne) && (ne.Timeout() || ne.Temporary()) {
				continue
			}
			break
		}

		pkt := string(buf[:n])
		switch pkt {
		case common.WORK_P2P_SUCCESS:
			logs.Debug("[P2P] handshake recv SUCCESS from=%s local=%s role=%s -> send END x20", addr.String(), localConn.LocalAddr().String(), sendRole)

			for i := 20; i > 0; i-- {
				if _, werr := localConn.WriteTo([]byte(common.WORK_P2P_END), addr); werr != nil {
					return "", localConn.LocalAddr().String(), sendRole, werr
				}
			}

			if sendRole == common.WORK_P2P_VISITOR {
				for {
					select {
					case <-parentCtx.Done():
						break Loop
					default:
					}

					_ = localConn.SetReadDeadline(time.Now().Add(time.Second))
					n2, addr2, e2 := localConn.ReadFrom(buf)
					_ = localConn.SetReadDeadline(time.Time{})
					if e2 != nil {
						var ne net.Error
						if errors.As(e2, &ne) && (ne.Timeout() || ne.Temporary()) {
							continue
						}
						break Loop
					}

					if string(buf[:n2]) == common.WORK_P2P_END {
						logs.Debug("[P2P] handshake OK role=%s remote=%s local=%s", common.WORK_P2P_VISITOR, addr2.String(), localConn.LocalAddr().String())

						_, fixedLocal, ferr := common.FixUdpListenAddrForRemote(addr2.String(), localConn.LocalAddr().String())
						if ferr != nil {
							return "", "", sendRole, ferr
						}
						return addr2.String(), fixedLocal, common.WORK_P2P_VISITOR, nil
					}
				}
			}

			logs.Debug("[P2P] handshake OK role=%s remote=%s local=%s", common.WORK_P2P_PROVIDER, addr.String(), localConn.LocalAddr().String())

			_, fixedLocal, ferr := common.FixUdpListenAddrForRemote(addr.String(), localConn.LocalAddr().String())
			if ferr != nil {
				return "", "", sendRole, ferr
			}
			return addr.String(), fixedLocal, common.WORK_P2P_PROVIDER, nil

		case common.WORK_P2P_END:
			logs.Debug("[P2P] handshake OK role=%s remote=%s local=%s", common.WORK_P2P_VISITOR, addr.String(), localConn.LocalAddr().String())

			_, fixedLocal, ferr := common.FixUdpListenAddrForRemote(addr.String(), localConn.LocalAddr().String())
			if ferr != nil {
				return "", "", sendRole, ferr
			}
			return addr.String(), fixedLocal, common.WORK_P2P_VISITOR, nil

		case common.WORK_P2P_CONNECT:
			logs.Debug("[P2P] handshake recv CONNECT from=%s local=%s -> send SUCCESS + retry", addr.String(), localConn.LocalAddr().String())

			lastConnectAddr.Store(addr)
			_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), addr)
			startSuccessSender()

		default:
			logs.Trace("[P2P] handshake recv unknown pkt=%q from=%s local=%s", pkt, addr.String(), localConn.LocalAddr().String())
			continue
		}
	}

	logs.Error("[P2P] handshake fail role=%s local=%s err=timeout/canceled", sendRole, localConn.LocalAddr().String())
	return "", localConn.LocalAddr().String(), sendRole, errors.New("connect to the target failed, maybe the nat type is not support p2p")
}

func getNextAddr(addr string, n int) (string, error) {
	lastColonIndex := strings.LastIndex(addr, ":")
	if lastColonIndex == -1 {
		return "", fmt.Errorf("the format of %s is incorrect", addr)
	}
	host := addr[:lastColonIndex]
	portStr := addr[lastColonIndex+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	return host + ":" + strconv.Itoa(port+n), nil
}

func getAddrInterval(addr1, addr2, addr3 string) (int, error) {
	p1 := common.GetPortByAddr(addr1)
	if p1 == 0 {
		return 0, fmt.Errorf("the format of %s incorrect", addr1)
	}
	p2 := common.GetPortByAddr(addr2)
	if p2 == 0 {
		return 0, fmt.Errorf("the format of %s incorrect", addr2)
	}
	p3 := common.GetPortByAddr(addr3)
	if p3 == 0 {
		return 0, fmt.Errorf("the format of %s incorrect", addr3)
	}

	interVal := int(math.Floor(math.Min(math.Abs(float64(p3-p2)), math.Abs(float64(p2-p1)))))
	if p3-p1 < 0 {
		return -interVal, nil
	}
	return interVal, nil
}

func getRandomUniquePorts(count, min, max int) []int {
	if min > max {
		min, max = max, min
	}
	rng := max - min + 1
	if rng <= 0 || count <= 0 {
		return nil
	}
	if count > rng {
		count = rng
	}

	out := make([]int, 0, count)
	seen := make(map[int]struct{}, count*2)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for len(out) < count {
		p := r.Intn(rng) + min
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func natHintByInterval(interval int, has bool) string {
	if !has {
		return "unknown"
	}
	if interval == 0 {
		return "cone-ish"
	}
	return "symmetric-ish"
}
