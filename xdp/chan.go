package xdp

import (
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tikv/client-go/v2/internal/logutil"
	"go.uber.org/zap"
	"log"
	"net"
	"unsafe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf xdp.c

var XDPChan = make(chan []byte)

func init() {
	go func() {
		ifaceName := "enp34s0"
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", ifaceName, err)
		}

		// Load pre-compiled programs into the kernel.
		objs := bpfObjects{}
		if err := loadBpfObjects(&objs, nil); err != nil {
			log.Fatalf("loading objects: %s", err)
		}
		defer objs.Close()

		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpPassProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("could not attach XDP program: %s", err)
		}
		defer l.Close()

		xsk, err := NewSocket(iface.Index, 0, nil)
		if err != nil {
			log.Fatalf("could not create XDP socket: %s", err)
		}

		if err := objs.XsksMap.Put(uint32(0), uint32(xsk.FD())); err != nil {
			log.Fatalf("could not set XDP socket in map: %s", err)
		}
		go func() {
			for {
				req := <-XDPChan
				txDescs := xsk.GetDescs(1, false)

				newEther := &layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x2c, 0xf0, 0x5d, 0x2b, 0x74, 0xb9},
					DstMAC:       net.HardwareAddr{0xb4, 0x09, 0x31, 0x84, 0x80, 0x62},
					EthernetType: layers.EthernetTypeIPv4,
				}
				newIP := &layers.IPv4{
					SrcIP:    net.IPv4(192, 168, 121, 133),
					DstIP:    net.IPv4(192, 168, 125, 108),
					Version:  4,
					TTL:      64,
					Protocol: layers.IPProtocolUDP,
				}
				newUDP := &layers.UDP{
					SrcPort: 7777,
					DstPort: 7777,
				}
				newUDP.SetNetworkLayerForChecksum(newIP)

				buf := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, newEther, newIP, newUDP, gopacket.Payload(req)); err != nil {
					log.Fatalf("could not serialize packet: %s", err)
				}

				//newPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy)
				//fmt.Println(newPacket)

				copy(xsk.GetFrame(txDescs[0]), buf.Bytes())
				txDescs[0].Len = uint32(len(buf.Bytes()))

				xsk.Transmit(txDescs)
			}
		}()

		go func() {
			xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots(), true))
			for {
				numRx, _, err := xsk.Poll(-1)
				if err != nil {
					logutil.BgLogger().Error("recv", zap.Error(err))
					panic(err)
				}
				//logutil.BgLogger().Info("recv", zap.Int("numRx", numRx))
				rxDescs := xsk.Receive(numRx)
				for i := 0; i < len(rxDescs); i++ {
					frame := xsk.GetFrame(rxDescs[i])
					p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Lazy)
					//fmt.Println(p)

					//ether := p.LinkLayer().(*layers.Ethernet)
					//ip := p.NetworkLayer().(*layers.IPv4)
					udp := p.TransportLayer().(*layers.UDP)
					payload := udp.Payload
					ptr := binary.LittleEndian.Uint64(payload[:8])
					ch := (*chan []byte)(unsafe.Pointer(uintptr(ptr)))
					*ch <- payload[8:]
				}
				xsk.Fill(rxDescs)
			}
		}()
		select {}
	}()
}
