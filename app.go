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

func (a *App) StopTrace() {
	stopTraceChannel <- nil
}

// returns the interface and gateway adresses
func FindInterfaceIPV4Address(iface *net.Interface, linkType string) (net.IP, net.IP, error) {
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

// ARPRequest sends an ARP request and waits for a response to get the MAC address
func ARPRequest(handle *pcap.Handle, iface *net.Interface, srcIP net.IP, dstIP net.IP) (net.HardwareAddr, error) {
	// Prepare ARP request
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

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

	// Serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts, &eth, &arp)
	if err != nil {
		return nil, err
	}

	// Send the ARP request
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	// Set a BPF filter to only capture ARP responses
	err = handle.SetBPFFilter(fmt.Sprintf("arp and src host %s", dstIP.String()))
	if err != nil {
		return nil, err
	}

	// Wait for the ARP reply
	start := time.Now()
	for {
		if time.Since(start) > 3*time.Second {
			return nil, fmt.Errorf("timeout getting ARP reply")
		}

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

		return net.HardwareAddr(arp.SourceHwAddress), nil
	}
}

func CreateEthernetFrame(srcMac, dstMac net.HardwareAddr) layers.Ethernet {
	return layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func CreateIPV4Packet(id uint16, ttl uint8, protocol layers.IPProtocol, srcIP net.IP, dstIP net.IP) layers.IPv4 {
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

func CreateTCPSYNPacketAndCalculateChecksum(srcPort int, dstPort int, seq int, mss int, ipv4Packet *layers.IPv4) (layers.TCP, error) {
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

// trace route
func (a *App) Trace(bindOn string, ip string, maxHops int, timeout int, protocol string, tcpDstPort int, tcpMSS int) string {
	// clear stop channel
	for len(stopTraceChannel) > 0 {
		<-stopTraceChannel
	}

	destinationIP := net.ParseIP(ip)
	shouldStop := false
	hopMap := make(map[uint16]*Hop)
	tcpSequenceMap := make(map[uint32]*Hop)
	icmpIDMap := make(map[uint16]*Hop)
	destinationReached := false
	var wg sync.WaitGroup // waitgroup for timeouts

	// get interface
	var ok bool
	var iface CustomInterface
	if iface, ok = interfaces[bindOn]; !ok {
		return "interface not found"
	}

	// get interface pcap handle
	sourceInterfaceHandle, err := pcap.OpenLive(iface.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err.Error()
	}
	// defer sourceInterfaceHandle.Close()

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
					fmt.Println("failed to parse icmp packet")
					continue
				}

				// check if the packet is icmp time exceeded or echo reply
				if icmpLayer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
					// parse origin sent ipv4 packet from payload
					originalIPV4Packet, ok := gopacket.NewPacket(icmpLayer.Payload, layers.LayerTypeIPv4, gopacket.Default).Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if !ok {
						fmt.Println("failed to parse icmp time exceeded packet payload (original packet)")
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
										log.Println(err)
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										log.Println(err)
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
										log.Println(err)
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										log.Println(err)
										return
									}

									// send info to frontend
									h.IPEEInfo = info
									runtime.EventsEmit(a.ctx, "hop info", h)
									// if h.Address == ip {
									// stopTraceChannel <- nil
									// }
									// if h.Number >= maxHops {
									stopTraceChannel <- nil
									// }
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
					fmt.Println("failed to parse tcp packet")
				}
				fmt.Printf("%+v\n", tcpPacket)

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
										log.Println(err)
										stopTraceChannel <- err
									}

									var info IPEEInfo
									err = json.NewDecoder(res.Body).Decode(&info)
									if err != nil {
										log.Println(err)
										return
									}

									// send info to frontend
									h.IPEEInfo = info
									runtime.EventsEmit(a.ctx, "hop info", h)
									// if h.Address == ip {
									// stopTraceChannel <- nil
									// }
									// if h.Number >= maxHops {
									stopTraceChannel <- nil
									// }
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
			ethernetFrame := CreateEthernetFrame(iface.InterfaceMac, iface.GatewayMac)

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
			ipv4Packet := CreateIPV4Packet(uint16(rand.Uint32()), uint8(i), ipProtocol, iface.InterfaceIP, destinationIP)

			// Create serializer buffer
			buffer := gopacket.NewSerializeBuffer()

			// create hop
			h := &Hop{IPID: ipv4Packet.Id, SendAt: time.Now().UnixMilli(), Number: i}
			hopMap[ipv4Packet.Id] = h

			// select packet layers based on link type and input and serialize them
			serializationOptions := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			if protocol == "tcp" {
				// create tcp packet
				tcpPacket, err := CreateTCPSYNPacketAndCalculateChecksum(-1, tcpDstPort, -1, tcpMSS, &ipv4Packet)
				if err != nil {
					stopTraceChannel <- errors.New("invalid protocol")
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
		return err.Error()
	}
	return ""
}

// get client's public IP
func (a *App) GetPublicIP() string {
	res, err := http.Get("https://ipee-api.alirezasn.workers.dev/v1/my-ip")
	if err != nil {
		log.Println(err)
		return "error" + err.Error()
	}

	var myIP IPEEMyIP
	err = json.NewDecoder(res.Body).Decode(&myIP)
	if err != nil {
		log.Println(err)
		return "error" + err.Error()
	}

	return myIP.IPAddress
}

// get app version from embeded wails.json file
func (a *App) GetVersion() string {
	var config WailsConfig
	err := json.Unmarshal(wailsConfigBytes, &config)
	if err != nil {
		log.Println(err)
		return "unknown"
	}
	return config.Info.ProductVersion
}

func FindGoInterfaceByFromPcapInterface(pcapInterface pcap.Interface, goInterfaces []net.Interface) (*net.Interface, error) {
	for _, i := range goInterfaces {
		goAddresses, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range goAddresses {
			goIP := net.ParseIP(strings.Split(a.String(), "/")[0])
			for _, pcapAddress := range pcapInterface.Addresses {
				if pcapAddress.IP.Equal(goIP) {
					return &i, nil
				}
			}
		}
	}
	return nil, errors.New("no interface found")
}

// get network devices
func (a *App) GetInterfaces() ([][]string, error) {
	// get system interfaces using native go
	goInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// get system interfaces using pcap
	devs, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	var temp [][]string

	// filter interfaces that can send packets
	for _, i := range devs {
		// open interface
		handle, err := pcap.OpenLive(i.Name, 65532, true, pcap.BlockForever)
		if err != nil {
			fmt.Printf("failed to open device: %s\n", i.Name)
			continue
		}

		// check interface type
		if !strings.EqualFold(handle.LinkType().String(), "raw") && !strings.EqualFold(handle.LinkType().String(), "ethernet") {
			fmt.Printf("link type not supported: %s\n", handle.LinkType().String())
			continue
		}

		// get go native interface
		goInterface, err := FindGoInterfaceByFromPcapInterface(i, goInterfaces)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// get interface ip and gateway
		sourceIP, gatewayIP, err := FindInterfaceIPV4Address(goInterface, handle.LinkType().String())
		if err != nil {
			fmt.Println(err)
			continue
		}

		// get gateways's mac address if link type is ethernet
		if strings.EqualFold(handle.LinkType().String(), "ethernet") {
			// Get gateway's MAC address using ARP
			gatewayMac, err := ARPRequest(handle, goInterface, sourceIP, gatewayIP)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Printf("Resolved MAC address for %s: %s\n", gatewayIP, gatewayMac)
			interfaces[i.Name] = CustomInterface{Type: "ethernet", Interface: i, GatewayMac: gatewayMac, InterfaceMac: goInterface.HardwareAddr, InterfaceIP: sourceIP}
			temp = append(temp, []string{i.Name, sourceIP.String()})
		} else if strings.EqualFold(handle.LinkType().String(), "raw") {
			// create ipv4 packet
			ipv4Packet := CreateIPV4Packet(uint16(rand.Uint32()), 64, layers.IPProtocolICMPv4, sourceIP, gatewayIP)

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
				return nil, err
			}

			// write packet
			if err = handle.WritePacketData(buffer.Bytes()); err != nil {
				return nil, err
			}

			fmt.Printf("sent icmp packet from %s to %s\n", sourceIP, gatewayIP)
			interfaces[i.Name] = CustomInterface{Type: "raw", Interface: i, InterfaceIP: sourceIP}
			temp = append(temp, []string{goInterface.Name, sourceIP.String()})
		}
	}

	return temp, nil
}
