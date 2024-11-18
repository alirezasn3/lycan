package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx context.Context
}

type Hop struct {
	Number    int      `json:"number"`
	Address   string   `json:"address"`
	IPEEInfo  IPEEInfo `json:"ipeeInfo"`
	RTT       int64    `json:"rtt"`
	IsPrivate bool     `json:"isPrivate"`
	TimedOut  bool     `json:"timedOut"`
	SendAt    int64
	IPID      uint16
	TCP       struct {
		RST bool `json:"rst"`
	} `json:"tcp"`
}

type IPEEInfo struct {
	OK               bool   `json:"ok"`
	Type             string `json:"type"`
	CIDR             string `json:"cidr"`
	ASNumber         int    `json:"asNumber"`
	BinarySubnetMask string `json:"binarySubnetMask"`
	SubnetMask       string `json:"subnetMask"`
	Class            string `json:"class"`
	NetworkAddress   string `json:"networkAddress"`
	NumberOfHosts    int    `json:"numberOfHosts"`
	ASName           string `json:"asName"`
	OrganizationName string `json:"organizationName"`
	Country          string `json:"country"`
	CountryCode      string `json:"countryCode"`
	QueryDuration    int    `json:"t"`
	Query            string `json:"query"`
}

type IPEEMyIP struct {
	OK        bool   `json:"ok"`
	IPAddress string `json:"ipAddress"`
	IPVersion int    `json:"ipVersion"`
}

type CustomInterface struct {
	Type         string
	Interface    pcap.Interface
	InterfaceMac net.HardwareAddr
	InterfaceIP  net.IP
	GatewayMac   net.HardwareAddr
}

var interfaces map[string]CustomInterface

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	interfaces = make(map[string]CustomInterface)
	stopTraceChannel = make(chan error, 1024)
	a.ctx = ctx
}

// stop the current trace
func (a *App) StopTrace() {
	stopTraceChannel <- nil
	a.Log("trace stopped by user")
}

// log the message in stdout and emit an event with log message to fronend
func (a *App) Log(message string) {
	log.Println(message)
	runtime.EventsEmit(a.ctx, "log", fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), message))
}

// returns the interface and gateway adresses
func (a *App) FindInterfaceIPV4Address(iface *net.Interface, linkType string) (net.IP, net.IP, error) {
	addresses, e := iface.Addrs()
	if e != nil {
		return nil, nil, e
	}
	for _, a := range addresses {
		if !strings.Contains(a.String(), ":") {
			_, n, e := net.ParseCIDR(a.String())
			if e != nil {
				return nil, nil, e
			}
			ifaceAddr := IPAddress{}
			e = ifaceAddr.Parse(n.IP.String())
			if e != nil {
				return nil, nil, e
			}
			if strings.EqualFold(linkType, "raw") {
				return net.ParseIP(strings.Split(a.String(), "/")[0]), net.ParseIP(strings.Split(a.String(), "/")[0]), nil
			} else {
				ifaceAddr.Increment()
				return net.ParseIP(strings.Split(a.String(), "/")[0]), net.ParseIP(ifaceAddr.ToString()), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no ipv4 address found for %s", iface.Name)
}

// sends an arp request and waits for a response to get the mac address
func (a *App) SendArpRequest(handle *pcap.Handle, iface *net.Interface, srcIP net.IP, dstIP net.IP) (net.HardwareAddr, error) {
	// create frame
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// create arp packet
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &arp); err != nil {
		return nil, err
	}

	// send arp request
	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	// Set a BPF filter to only capture ARP responses
	// err = handle.SetBPFFilter("arp")
	// if err != nil {
	// 	return nil, err
	// }

	// channel to signal that arp response was received
	done := make(chan net.HardwareAddr)

	// wait for the arp reply
	go func() {
		for {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue
			}
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || !net.IP(arp.SourceProtAddress).Equal(dstIP) {
				continue
			}
			done <- net.HardwareAddr(arp.SourceHwAddress)
		}
	}()

	// wait for arp response or time out after 5 seconds
	select {
	case a := <-done:
		return a, nil
	case <-time.After(time.Second * 5):
		return nil, errors.New("timed out waiting for arp reply")
	}
}

// create ipv4 ethernet frame
func (a *App) CreateIPV4EthernetFrame(srcMac, dstMac net.HardwareAddr) layers.Ethernet {
	return layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

// create ipv4 packet
func (a *App) CreateIPV4Packet(id uint16, ttl uint8, protocol layers.IPProtocol, srcIP net.IP, dstIP net.IP) layers.IPv4 {
	return layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   20,
		Id:       id,
		TTL:      ttl,
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
}

// create tcp syn packet
func (a *App) CreateTCPSYNPacket(srcPort int, dstPort int, seq int, mss int, ipv4Packet *layers.IPv4) (layers.TCP, error) {
	// create tcp syn packet
	tcpPacket := layers.TCP{
		SYN: true,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
			},
		},
	}

	if srcPort == -1 {
		tcpPacket.SrcPort = layers.TCPPort(rand.Uint32())
	} else {
		tcpPacket.SrcPort = layers.TCPPort(srcPort)
	}
	if dstPort == -1 {
		tcpPacket.DstPort = layers.TCPPort(rand.Uint32())
	} else {
		tcpPacket.DstPort = layers.TCPPort(dstPort)
	}
	if seq == -1 {
		tcpPacket.Seq = rand.Uint32()
	} else {
		tcpPacket.Seq = uint32(seq)
	}

	tcpPacket.Options[0].OptionData = []byte{byte(uint16(mss) >> 8), byte(uint16(mss) & 0xFF)}

	// calculate tcp packet checksums
	if err := tcpPacket.SetNetworkLayerForChecksum(ipv4Packet); err != nil {
		return layers.TCP{}, err
	}

	return tcpPacket, nil
}

// find the corresponding go interface from pcap interface
func (a *App) FindGoInterfaceByFromPcapInterface(pcapInterface pcap.Interface, goInterfaces []net.Interface) (*net.Interface, error) {
	for _, i := range goInterfaces {
		// get go interface addresses
		goAddresses, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		// loop over go interfaces
		for _, a := range goAddresses {
			// get go interface address from cidr
			goIP := net.ParseIP(strings.Split(a.String(), "/")[0])

			// check if go interface address is equal to pcap interface address
			for _, pcapAddress := range pcapInterface.Addresses {
				if pcapAddress.IP.Equal(goIP) {
					return &i, nil
				}
			}
		}
	}

	return nil, errors.New("no interface found")
}

// trace route
func (a *App) Trace(bindOn string, ip string, maxHops int, timeout int, protocol string, tcpDstPort int, tcpMSS int) string {
	if timeout < 1 {
		return "please enter a valid timeout"
	}
	if maxHops < 1 {
		return "please enter a valid max hops value"
	}

	// clear stop channel
	for len(stopTraceChannel) > 0 {
		<-stopTraceChannel
	}

	hopMap := make(map[uint16]*Hop)         // ipv4 id to hop map
	tcpSequenceMap := make(map[uint32]*Hop) // ipv4 sequence number to hop map
	icmpIDMap := make(map[uint16]*Hop)      // icmp id to hop map
	destinationReached := false             // whether or not the destination is reached
	shouldStop := false                     // whether or not to stop trace
	var wg sync.WaitGroup                   // waitgroup for timeouts

	// get interface
	var ok bool
	var iface CustomInterface
	if iface, ok = interfaces[bindOn]; !ok {
		return "interface not found"
	}

	// get interface pcap handle
	sourceInterfaceHandle, err := pcap.OpenLive(iface.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		a.Log(fmt.Sprintf("failed to open interface %s - %s with pcap: %s", iface.Interface.Name, iface.Interface.Description, err.Error()))
		return err.Error()
	}
	// defer sourceInterfaceHandle.Close()

	a.Log("trace started")

	// read packets
	go func() {
		// create bpf based on input
		var bpf string
		if protocol == "tcp" {
			bpf = fmt.Sprintf("(icmp[icmptype] == 11 or tcp) and dst host %s", iface.InterfaceIP.String())
		} else if protocol == "icmp" {
			bpf = fmt.Sprintf("(icmp) and dst host %s", iface.InterfaceIP.String())
		} else {
			stopTraceChannel <- errors.New("invalid protocol")
			return
		}

		// set bpf
		if err := sourceInterfaceHandle.SetBPFFilter(bpf); err != nil {
			stopTraceChannel <- fmt.Errorf("failed to set BPF filter: %v", err)
			return
		}

		// the time that packet was receieved
		var receivedAt int64

		// used to discard packets with too high ttls
		synAckReceived := false
		echoReplyRecieved := false

		// handle new packets
		for packet := range gopacket.NewPacketSource(sourceInterfaceHandle, sourceInterfaceHandle.LinkType()).Packets() {
			// set packet receive time
			receivedAt = time.Now().UnixMilli()

			// break loop on error or if destination is reached
			if shouldStop {
				break
			}

			// parse network layer
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			// check transport layer protocol
			if ipv4Layer.Protocol == layers.IPProtocolICMPv4 {
				// parse icmp packet
				icmpLayer, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				if !ok {
					a.Log("failed to parse icmp packet")
					continue
				}

				// check if the packet is icmp time exceeded or echo reply
				if icmpLayer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
					// parse origin sent ipv4 packet from payload
					originalIPV4Packet, ok := gopacket.NewPacket(icmpLayer.Payload, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if !ok {
						a.Log("failed to parse icmp time exceeded packet payload (original packet)")
						continue
					}

					// check if a packet with the found id was sent
					if h, ok := hopMap[originalIPV4Packet.Id]; ok {
						// set rtt
						h.RTT = receivedAt - h.SendAt

						// check if rtt is bigger than timeout
						if h.RTT > int64(timeout) {
							runtime.EventsEmit(a.ctx, "hop", &Hop{TimedOut: true, Number: h.Number})
						} else {
							h.Address = ipv4Layer.SrcIP.String()
							h.IsPrivate = net.ParseIP(ipv4Layer.SrcIP.String()).IsPrivate()
							runtime.EventsEmit(a.ctx, "hop", &h)

							// get IPEEInfo if ip is not private
							if !h.IsPrivate {
								// send request to api on new thread
								go func(h *Hop) {
									res, err := http.Get("https://ipee-api.alirezasn.workers.dev/v1/info/" + h.Address)
									if err != nil {
										a.Log(err.Error())
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										a.Log(err.Error())
										return
									}

									// send info to frontend
									h.IPEEInfo = info
									runtime.EventsEmit(a.ctx, "hop info", h)
									if h.Address == ip {
										stopTraceChannel <- nil
									}
									if h.Number >= maxHops {
										stopTraceChannel <- nil
									}
								}(h)
							}
						}
					}
				} else if protocol == "icmp" && icmpLayer.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
					// break the loop if echo reply packet is already received
					if echoReplyRecieved {
						break
					}

					// check if packet with the found sequnce was sent
					if h, ok := icmpIDMap[icmpLayer.Id]; ok {
						// set rtt
						h.RTT = receivedAt - h.SendAt

						// check if rtt is bigger than timeout
						if h.RTT > int64(timeout) {
							runtime.EventsEmit(a.ctx, "hop", &Hop{TimedOut: true, Number: h.Number})
						} else {
							destinationReached = true
							echoReplyRecieved = true
							h.Address = ipv4Layer.SrcIP.String()
							h.IsPrivate = net.ParseIP(ipv4Layer.SrcIP.String()).IsPrivate()
							runtime.EventsEmit(a.ctx, "hop", &h)

							// get IPEEInfo if ip is not private
							if !h.IsPrivate {
								// send request to api on new thread
								go func(h *Hop) {
									res, err := http.Get("https://ipee-api.alirezasn.workers.dev/v1/info/" + h.Address)
									if err != nil {
										a.Log(err.Error())
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										a.Log(err.Error())
										return
									}

									// send info to frontend
									h.IPEEInfo = info
									runtime.EventsEmit(a.ctx, "hop info", h)
									stopTraceChannel <- nil
								}(h)
							} else {
								stopTraceChannel <- nil
							}
						}
					}
				}
			} else if ipv4Layer.Protocol == layers.IPProtocolTCP && protocol == "tcp" {
				// break the loop if the syn/ack packet is already received
				if synAckReceived {
					break
				}

				// parse tcp packet
				tcpPacket, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if !ok {
					a.Log("failed to parse tcp packet")
				}

				// check if its tcp syn/ack packet
				if (tcpPacket.SYN && tcpPacket.ACK) || tcpPacket.RST {
					// check if packet with the found sequnce was sent
					if h, ok := tcpSequenceMap[tcpPacket.Ack-1]; ok {
						// set rtt
						h.RTT = receivedAt - h.SendAt

						// check if rtt is bigger than timeout
						if h.RTT > int64(timeout) {
							runtime.EventsEmit(a.ctx, "hop", &Hop{TimedOut: true, Number: h.Number})
						} else {
							destinationReached = true
							synAckReceived = true
							h.Address = ipv4Layer.SrcIP.String()
							h.IsPrivate = net.ParseIP(ipv4Layer.SrcIP.String()).IsPrivate()
							if tcpPacket.RST {
								h.TCP.RST = true
							}
							runtime.EventsEmit(a.ctx, "hop", &h)

							// get IPEEInfo if ip is not private
							if !h.IsPrivate {
								// send request to api on new thread
								go func(h *Hop) {
									res, err := http.Get("https://ipee-api.alirezasn.workers.dev/v1/info/" + h.Address)
									if err != nil {
										a.Log(err.Error())
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										a.Log(err.Error())
										return
									}

									// send info to frontend
									h.IPEEInfo = info
									runtime.EventsEmit(a.ctx, "hop info", h)
									stopTraceChannel <- nil
								}(h)
							} else {
								stopTraceChannel <- nil
							}
						}
					}
				}
			}
		}
	}()

	// range over 1 to max ttl and send packets
	go func() {
		for i := 1; i <= maxHops; i++ {
			// break loop on error or if destination is reached
			if shouldStop {
				break
			}

			// create ethernet frame
			ethernetFrame := a.CreateIPV4EthernetFrame(iface.InterfaceMac, iface.GatewayMac)

			// set protocol based on user input
			var ipProtocol layers.IPProtocol
			if protocol == "icmp" {
				ipProtocol = layers.IPProtocolICMPv4
			} else if protocol == "tcp" {
				ipProtocol = layers.IPProtocolTCP
			} else {
				stopTraceChannel <- errors.New("invalid protocol")
				return
			}

			// create ipv4 packet
			ipv4Packet := a.CreateIPV4Packet(uint16(rand.Uint32()), uint8(i), ipProtocol, iface.InterfaceIP, net.ParseIP(ip))

			// Create serializer buffer
			buffer := gopacket.NewSerializeBuffer()

			// create hop
			h := &Hop{IPID: ipv4Packet.Id, SendAt: time.Now().UnixMilli(), Number: i}
			hopMap[ipv4Packet.Id] = h

			// select packet layers based on link type and input and serialize them
			serializationOptions := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			if protocol == "tcp" {
				// create tcp packet
				tcpPacket, err := a.CreateTCPSYNPacket(-1, tcpDstPort, -1, tcpMSS, &ipv4Packet)
				if err != nil {
					stopTraceChannel <- err
					return
				}

				// serialize layers
				if strings.ToLower(sourceInterfaceHandle.LinkType().String()) == "ethernet" {
					if err = gopacket.SerializeLayers(buffer, serializationOptions, &ethernetFrame, &ipv4Packet, &tcpPacket); err != nil {
						stopTraceChannel <- err
						return
					}
				} else if strings.ToLower(sourceInterfaceHandle.LinkType().String()) == "raw" {
					if err = gopacket.SerializeLayers(buffer, serializationOptions, &ipv4Packet, &tcpPacket); err != nil {
						stopTraceChannel <- err
						return
					}
				}

				tcpSequenceMap[tcpPacket.Seq] = h
			} else if protocol == "icmp" {
				// create icmp packet
				icmpPacket := layers.ICMPv4{
					TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
					Id:       uint16(rand.Uint32()),
					Seq:      1,
				}

				// serialize layers
				if strings.ToLower(sourceInterfaceHandle.LinkType().String()) == "ethernet" {
					if err = gopacket.SerializeLayers(buffer, serializationOptions, &ethernetFrame, &ipv4Packet, &icmpPacket); err != nil {
						stopTraceChannel <- err
						return
					}
				} else if strings.ToLower(sourceInterfaceHandle.LinkType().String()) == "raw" {
					if err = gopacket.SerializeLayers(buffer, serializationOptions, &ipv4Packet, &icmpPacket); err != nil {
						stopTraceChannel <- err
						return
					}
				}

				icmpIDMap[icmpPacket.Id] = h
			} else {
				stopTraceChannel <- errors.New("invalid protocol")
				return
			}

			// Send the packet
			if !destinationReached {
				if err = sourceInterfaceHandle.WritePacketData(buffer.Bytes()); err != nil {
					stopTraceChannel <- err
				}
				wg.Add(1)
				go func() {
					time.Sleep(time.Millisecond * time.Duration(timeout))
					if h.Address == "" {
						h.TimedOut = true
						runtime.EventsEmit(a.ctx, "hop", &h)
					}
					if h.Number == maxHops {
						stopTraceChannel <- nil
					}
					wg.Done()
				}()
			}
			time.Sleep(time.Millisecond * time.Duration(timeout))
		}
	}()

	// wait for stop signal or for go routines to finish
	err = <-stopTraceChannel
	shouldStop = true
	time.Sleep(time.Second)
	wg.Wait()
	if err != nil {
		a.Log(err.Error())
		return err.Error()
	}
	a.Log("trace completed")
	return ""
}

// get client's public ip
func (a *App) GetPublicIP() string {
	// send request
	res, err := http.Get("https://ipee-api.alirezasn.workers.dev/v1/my-ip")
	if err != nil {
		a.Log(fmt.Sprintf("failed to get client's public ip from ipee api: %s", err.Error()))
		return fmt.Sprintf("failed to get client's public ip from ipee api: %s", err.Error())
	}

	// parse response as json
	var myIP IPEEMyIP
	err = json.NewDecoder(res.Body).Decode(&myIP)
	if err != nil {
		a.Log(fmt.Sprintf("failed to parse response from ipee api: %s", err.Error()))
		return fmt.Sprintf("failed to parse response from ipee api: %s", err.Error())
	}

	return myIP.IPAddress
}

// get app version from embeded wails.json file
func (a *App) GetVersion() string {
	var config WailsConfig
	err := json.Unmarshal(wailsConfigBytes, &config)
	if err != nil {
		a.Log(fmt.Sprintf("failed to get app version from wails.json: %s", err.Error()))
		return "unknown"
	}
	return config.Info.ProductVersion
}

// get network devices
func (a *App) GetInterfaces() ([][]string, error) {
	// get system interfaces using native go
	goInterfaces, err := net.Interfaces()
	if err != nil {
		a.Log(fmt.Sprintf("failed to get interfaces with go: %s", err.Error()))
		return nil, err
	}

	// get system interfaces using pcap
	devs, err := pcap.FindAllDevs()
	if err != nil {
		a.Log(fmt.Sprintf("failed to get interfaces with pcap: %s", err.Error()))
		return nil, err
	}

	var temp [][]string
	var wg sync.WaitGroup

	// filter interfaces that can send packets
	for _, i := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Log(fmt.Sprintf("checking device: %s - %s", i.Name, i.Description))
			// open interface
			handle, err := pcap.OpenLive(i.Name, 65536, true, pcap.BlockForever)
			if err != nil {
				a.Log(fmt.Sprintf("failed to open device with pcap: %s - %s", i.Name, i.Description))
				return
			}

			// check interface type
			if !strings.EqualFold(handle.LinkType().String(), "raw") && !strings.EqualFold(handle.LinkType().String(), "ethernet") {
				a.Log(fmt.Sprintf("skipping unsupported link type of %s for %s - %s", handle.LinkType().String(), i.Name, i.Description))
				return
			}

			// get go native interface
			goInterface, err := a.FindGoInterfaceByFromPcapInterface(i, goInterfaces)
			if err != nil {
				a.Log(fmt.Sprintf("failed to find matching interface with go for %s - %s: %s", i.Name, i.Description, err.Error()))
				return
			}

			// get interface ip and gateway
			sourceIP, gatewayIP, err := a.FindInterfaceIPV4Address(goInterface, handle.LinkType().String())
			if err != nil {
				a.Log(fmt.Sprintf("failed to find address and gateway of interface %s - %s: %s", i.Name, i.Description, err.Error()))
				return
			}

			// skip apipa range
			_, n, _ := net.ParseCIDR("169.254.1.0/16")

			if n.Contains(sourceIP) {
				a.Log(fmt.Sprintf("skipping interface with apipa: %s - %s", i.Name, i.Description))
				return
			}

			// get gateways's mac address if link type is ethernet
			if strings.EqualFold(handle.LinkType().String(), "ethernet") {
				// Get gateway's MAC address using ARP
				gatewayMac, err := a.SendArpRequest(handle, goInterface, sourceIP, gatewayIP)
				if err != nil {
					a.Log(fmt.Sprintf("failed to resolve gateway mac address for interface %s - %s: %s", i.Name, i.Description, err.Error()))
					return
				}

				a.Log(fmt.Sprintf("resolved gateway mac address for interface %s: %s, interface marked as available.", i.Name, i.Description))
				interfaces[goInterface.Name] = CustomInterface{Type: "ethernet", Interface: i, GatewayMac: gatewayMac, InterfaceMac: goInterface.HardwareAddr, InterfaceIP: sourceIP}
				temp = append(temp, []string{goInterface.Name, sourceIP.String()})
			} else if strings.EqualFold(handle.LinkType().String(), "raw") {
				// create ipv4 packet
				ipv4Packet := a.CreateIPV4Packet(uint16(rand.Uint32()), 64, layers.IPProtocolICMPv4, sourceIP, gatewayIP)

				// create icmp packet
				icmpPacket := layers.ICMPv4{
					TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
					Id:       uint16(rand.Uint32()),
					Seq:      1,
				}

				// Create serialize buffer
				buffer := gopacket.NewSerializeBuffer()

				// serialize layers
				if err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ipv4Packet, &icmpPacket); err != nil {
					a.Log(fmt.Sprintf("failed to serialize icmp packet to test interface %s - %s: %s", i.Name, i.Description, err.Error()))
					return
				}

				writeErrorChannel := make(chan error)

				// write packet
				go func() {
					err = handle.WritePacketData(buffer.Bytes())
					if err != nil {
						writeErrorChannel <- err
					} else {
						writeErrorChannel <- nil
					}
				}()

				select {
				case e := <-writeErrorChannel:
					if e != nil {
						a.Log(fmt.Sprintf("failed to write icmp packet to interface %s - %s: %s", i.Name, i.Description, e.Error()))
						return
					}
				case <-time.After(time.Second * 3):
					a.Log(fmt.Sprintf("failed to write packet to interface %s - %s: timeout", i.Name, i.Description))
					return
				}

				a.Log(fmt.Sprintf("sent icmp test packet to interface %s - %s, interface marked as available.", i.Name, i.Description))
				interfaces[goInterface.Name] = CustomInterface{Type: "raw", Interface: i, InterfaceIP: sourceIP}
				temp = append(temp, []string{goInterface.Name, sourceIP.String()})
			}

			handle.Close()
		}()
	}

	wg.Wait()

	return temp, nil
}
