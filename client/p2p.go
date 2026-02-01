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
		return
	}

	// Close localConn only if we exit before handing it to sendP2PTestMsg.
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

	logs.Debug("[P2P] start handleP2PUdp role=%s local=%s server=%s port=%s candidates=%s mode=%s dataLen=%d",
		sendRole, localConn.LocalAddr().String(), rAddr, port, localCandidates, sendMode, len(sendData))

	// Send three requests to server ports: rAddr, rAddr+1, rAddr+2
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

	// Enhancement: record peer addr if it already punched in.
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
			// Peer already reached us.
			punchedAddr = fromAddr
			logs.Debug("[P2P] punched-in CONNECT received from=%s local=%s -> reply SUCCESS immediately",
				fromAddr.String(), localConn.LocalAddr().String())

			// Enhancement #1: reply SUCCESS immediately once (reduce handshake latency)
			_ = writePacketWithFallback(localConn, []byte(common.WORK_P2P_SUCCESS), fromAddr)

			break
		}

		peerExt, pLocal, m, d, selfExt := parseP2PServerReply(raw)
		if peerExt == "" {
			continue
		}

		// Keep first non-empty peerLocal (server-selected)
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

	logs.Debug("[P2P] collected server info: peerExt=[%s,%s,%s] selfExt=[%s,%s,%s] peerLocal=%s punched=%v",
		peerExt1, peerExt2, peerExt3, selfExt1, selfExt2, selfExt3, peerLocal, punchedAddr != nil)

	handedOff = true
	remoteAddress, localAddress, role, err = sendP2PTestMsg(
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

	c, err = net.ListenPacket("udp", localAddress)
	if err != nil {
		logs.Error("[P2P] net.ListenPacket failed local=%s err=%v", localAddress, err)
		return
	}

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
	logs.Trace("[P2P] sent req to server=%s local=%s add=%d candidates=%s",
		addr.String(), localConn.LocalAddr().String(), add, localCandidates)
	return nil
}

// parseP2PServerReply parses server reply with backward compatibility.
// New server: peerExt | peerLocal | mode | data | selfExt
// Old server: peerExt | peerLocal | mode | data
// Older:      peerExt | peerLocal | mode
// Even older: peerExt | peerLocal
// Oldest:     peerExt
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
) (remoteAddr, localAddr, role string, err error) {
	parentCtx, parentCancel := context.WithCancel(pCtx)

	var closed uint32
	connList := []net.PacketConn{localConn}

	defer func() {
		atomic.StoreUint32(&closed, 1)
		parentCancel()
		for _, c := range connList {
			_ = c.Close()
		}
	}()

	if punchedAddr != nil {
		logs.Debug("[P2P] punchedAddr present: %s -> start SUCCESS retry sender", punchedAddr.String())
		go func(a net.Addr) {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			// send immediately once + fallback
			_ = writePacketWithFallback(localConn, []byte(common.WORK_P2P_SUCCESS), a)

			for i := 0; i < 20; i++ {
				select {
				case <-parentCtx.Done():
					return
				case <-ticker.C:
				}
				if atomic.LoadUint32(&closed) != 0 {
					return
				}
				_ = writePacketWithFallback(localConn, []byte(common.WORK_P2P_SUCCESS), a)
			}
		}(punchedAddr)
	}

	// If peerLocal exists, try LAN/public-local path as well.
	if peerLocal != "" {
		logs.Debug("[P2P] peerLocal=%s -> start LAN/public-local CONNECT sender", peerLocal)
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

	// Compute intervals only when we have enough samples.
	hasPeerExt := peerExt1 != "" && peerExt2 != "" && peerExt3 != ""
	peerInterval := 0
	if hasPeerExt {
		peerInterval, err = getAddrInterval(peerExt1, peerExt2, peerExt3)
		if err != nil {
			logs.Error("[P2P] get peerInterval failed peerExt=[%s,%s,%s] err=%v", peerExt1, peerExt2, peerExt3, err)
			hasPeerExt = false
			peerInterval = 0
		}
	}

	hasSelfExt := selfExt1 != "" && selfExt2 != "" && selfExt3 != ""
	selfInterval := 0
	if hasSelfExt {
		selfInterval, err = getAddrInterval(selfExt1, selfExt2, selfExt3)
		if err != nil {
			logs.Error("[P2P] get selfInterval failed selfExt=[%s,%s,%s] err=%v", selfExt1, selfExt2, selfExt3, err)
			hasSelfExt = false
			selfInterval = 0
		}
	}

	logs.Debug("[P2P] NAT diagnose: hasPeerExt=%v peerInterval=%d (%s) hasSelfExt=%v selfInterval=%d (%s)",
		hasPeerExt, peerInterval, natHintByInterval(peerInterval, hasPeerExt),
		hasSelfExt, selfInterval, natHintByInterval(selfInterval, hasSelfExt))

	// Decide strategy
	switch {
	// Case A:
	// peerInterval == 0 and selfInterval != 0 often indicates "we are symmetric-like".
	// Use many local sockets to increase success rate.
	case hasPeerExt && hasSelfExt && peerInterval == 0 && selfInterval != 0:
		logs.Debug("[P2P] strategy=A multi-socket (self symmetric-ish, peer stable-ish) peerExt3=%s", peerExt3)

		baseLocal := localConn.LocalAddr().String()

		for i := 0; i < 256; i++ {
			var tmpAddr string
			if strings.Contains(baseLocal, "]:") {
				tmp, e := common.GetLocalUdp6Addr()
				if e != nil {
					return "", "", "", e
				}
				tmpAddr = tmp.LocalAddr().String()
			} else {
				tmp, e := common.GetLocalUdp4Addr()
				if e != nil {
					return "", "", "", e
				}
				tmpAddr = tmp.LocalAddr().String()
			}

			tmpConn, e := conn.NewUdpConnByAddr(tmpAddr)
			if e != nil {
				return "", "", "", e
			}
			connList = append(connList, tmpConn)
			time.Sleep(10 * time.Millisecond)
		}

		targetAddr, e := getNextAddr(peerExt3, peerInterval) // peerInterval==0 means peerExt3 itself
		if e != nil {
			return "", localConn.LocalAddr().String(), sendRole, e
		}
		targetUDP, e := net.ResolveUDPAddr("udp", targetAddr)
		if e != nil {
			return "", localConn.LocalAddr().String(), sendRole, e
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
			RemoteAddr string
			LocalAddr  string
			Role       string
			Err        error
		}
		resultChan := make(chan P2PResult, 1)

		for _, c := range connList {
			go func(cc net.PacketConn) {
				rAddr, lAddr, rRole, rErr := waitP2PHandshake(parentCtx, cc, sendRole, 10)
				if rErr == nil {
					select {
					case resultChan <- P2PResult{RemoteAddr: rAddr, LocalAddr: lAddr, Role: rRole, Err: nil}:
					default:
					}
				}
			}(c)
		}

		select {
		case res := <-resultChan:
			// best effort stop other readers quickly
			parentCancel()
			for _, c := range connList {
				_ = c.SetReadDeadline(time.Now())
			}
			return res.RemoteAddr, res.LocalAddr, res.Role, nil
		case <-parentCtx.Done():
			return "", localConn.LocalAddr().String(), sendRole, errors.New("connect to the target failed, maybe the nat type is not support p2p")
		}

	// Case B:
	// peerInterval != 0 and selfInterval == 0 often indicates "peer is symmetric-like".
	// Scan random ports on peer IP.
	case hasPeerExt && hasSelfExt && peerInterval != 0 && selfInterval == 0:
		logs.Debug("[P2P] strategy=B random-scan (peer symmetric-ish, self stable-ish) peerExt3=%s peerExt2=%s", peerExt3, peerExt2)

		// Keep "predicted" target sender as well.
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

			// First burst.
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

	// Default:
	// No selfExt info (old server) or intervals missing => keep old behavior with reduced goroutine count.
	default:
		logs.Debug("[P2P] strategy=Default legacy (hasPeerExt=%v hasSelfExt=%v peerInterval=%d selfInterval=%d peerExt3=%s)",
			hasPeerExt, hasSelfExt, peerInterval, selfInterval, peerExt3)

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
				logs.Trace("[P2P] default predicted target sender target=%s", remoteUDP.String())

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

				logs.Debug("[P2P] default scan window ip=%s start=%d end=%d interval=%d", ip, startPort, endPort, peerInterval)

				ports := getRandomUniquePorts(51, startPort, endPort)
				udpAddrs := make([]*net.UDPAddr, 0, len(ports))
				for _, p := range ports {
					ra, e := net.ResolveUDPAddr("udp", ip+":"+strconv.Itoa(p))
					if e == nil {
						udpAddrs = append(udpAddrs, ra)
					}
				}

				// First burst.
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

	return waitP2PHandshake(parentCtx, localConn, sendRole, 10)
}

func waitP2PHandshake(parentCtx context.Context, localConn net.PacketConn, sendRole string, readTimeout int) (remoteAddr, localAddr, role string, err error) {
	buf := make([]byte, 10)

	var senderStarted uint32
	var lastConnectAddr atomic.Value // stores string (addr.String())

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
				addrStr := v.(string)
				udpAddr, rerr := net.ResolveUDPAddr("udp", addrStr)
				if rerr != nil || udpAddr == nil {
					continue
				}

				logs.Trace("[P2P] retry SUCCESS -> %v (local=%s)", udpAddr, localConn.LocalAddr().String())
				_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), udpAddr)
			}
		}()
	}

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
			logs.Debug("[P2P] recv SUCCESS from=%s local=%s role=%s -> send END x20",
				addr.String(), localConn.LocalAddr().String(), sendRole)

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
						logs.Debug("[P2P] visitor recv END from=%s local=%s => handshake OK",
							addr2.String(), localConn.LocalAddr().String())
						return addr2.String(), localConn.LocalAddr().String(), common.WORK_P2P_VISITOR, nil
					}
				}
			}

			logs.Debug("[P2P] provider handshake OK remote=%s local=%s", addr.String(), localConn.LocalAddr().String())
			return addr.String(), localConn.LocalAddr().String(), common.WORK_P2P_PROVIDER, nil

		case common.WORK_P2P_END:
			logs.Debug("[P2P] recv END from=%s local=%s => visitor handshake OK",
				addr.String(), localConn.LocalAddr().String())
			return addr.String(), localConn.LocalAddr().String(), common.WORK_P2P_VISITOR, nil

		case common.WORK_P2P_CONNECT:
			// Old flow effect: on CONNECT -> keep sending SUCCESS for a while
			logs.Debug("[P2P] recv CONNECT from=%s local=%s -> send SUCCESS now + start retry sender",
				addr.String(), localConn.LocalAddr().String())

			lastConnectAddr.Store(addr.String())
			_, _ = localConn.WriteTo([]byte(common.WORK_P2P_SUCCESS), addr)
			startSuccessSender()

		default:
			logs.Trace("[P2P] recv unknown pkt=%q from=%s local=%s", pkt, addr.String(), localConn.LocalAddr().String())
			continue
		}
	}

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

func writePacketWithFallback(c net.PacketConn, payload []byte, a net.Addr) error {
	if a == nil {
		return errors.New("nil addr")
	}
	if _, err := c.WriteTo(payload, a); err == nil {
		return nil
	} else {
		ua, rerr := net.ResolveUDPAddr("udp", a.String())
		if rerr != nil || ua == nil {
			return err
		}
		_, _ = c.WriteTo(payload, ua)
		return nil
	}
}

func natHintByInterval(interval int, has bool) string {
	if !has {
		return "unknown(no-samples/old-server)"
	}
	if interval == 0 {
		return "stable-mapping(cone-ish)"
	}
	return "port-varying(symmetric-ish)"
}
