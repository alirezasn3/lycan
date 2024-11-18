export namespace layers {
	
	export class Ethernet {
	    Contents: number[];
	    Payload: number[];
	    SrcMAC: number[];
	    DstMAC: number[];
	    EthernetType: number;
	    Length: number;
	
	    static createFrom(source: any = {}) {
	        return new Ethernet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Contents = source["Contents"];
	        this.Payload = source["Payload"];
	        this.SrcMAC = source["SrcMAC"];
	        this.DstMAC = source["DstMAC"];
	        this.EthernetType = source["EthernetType"];
	        this.Length = source["Length"];
	    }
	}
	export class IPv4Option {
	    OptionType: number;
	    OptionLength: number;
	    OptionData: number[];
	
	    static createFrom(source: any = {}) {
	        return new IPv4Option(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.OptionType = source["OptionType"];
	        this.OptionLength = source["OptionLength"];
	        this.OptionData = source["OptionData"];
	    }
	}
	export class IPv4 {
	    Contents: number[];
	    Payload: number[];
	    Version: number;
	    IHL: number;
	    TOS: number;
	    Length: number;
	    Id: number;
	    Flags: number;
	    FragOffset: number;
	    TTL: number;
	    Protocol: number;
	    Checksum: number;
	    SrcIP: number[];
	    DstIP: number[];
	    Options: IPv4Option[];
	    Padding: number[];
	
	    static createFrom(source: any = {}) {
	        return new IPv4(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Contents = source["Contents"];
	        this.Payload = source["Payload"];
	        this.Version = source["Version"];
	        this.IHL = source["IHL"];
	        this.TOS = source["TOS"];
	        this.Length = source["Length"];
	        this.Id = source["Id"];
	        this.Flags = source["Flags"];
	        this.FragOffset = source["FragOffset"];
	        this.TTL = source["TTL"];
	        this.Protocol = source["Protocol"];
	        this.Checksum = source["Checksum"];
	        this.SrcIP = source["SrcIP"];
	        this.DstIP = source["DstIP"];
	        this.Options = this.convertValues(source["Options"], IPv4Option);
	        this.Padding = source["Padding"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class TCPOption {
	    OptionType: number;
	    OptionLength: number;
	    OptionData: number[];
	
	    static createFrom(source: any = {}) {
	        return new TCPOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.OptionType = source["OptionType"];
	        this.OptionLength = source["OptionLength"];
	        this.OptionData = source["OptionData"];
	    }
	}
	export class TCP {
	    Contents: number[];
	    Payload: number[];
	    SrcPort: number;
	    DstPort: number;
	    Seq: number;
	    Ack: number;
	    DataOffset: number;
	    FIN: boolean;
	    SYN: boolean;
	    RST: boolean;
	    PSH: boolean;
	    ACK: boolean;
	    URG: boolean;
	    ECE: boolean;
	    CWR: boolean;
	    NS: boolean;
	    Window: number;
	    Checksum: number;
	    Urgent: number;
	    Options: TCPOption[];
	    Padding: number[];
	
	    static createFrom(source: any = {}) {
	        return new TCP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Contents = source["Contents"];
	        this.Payload = source["Payload"];
	        this.SrcPort = source["SrcPort"];
	        this.DstPort = source["DstPort"];
	        this.Seq = source["Seq"];
	        this.Ack = source["Ack"];
	        this.DataOffset = source["DataOffset"];
	        this.FIN = source["FIN"];
	        this.SYN = source["SYN"];
	        this.RST = source["RST"];
	        this.PSH = source["PSH"];
	        this.ACK = source["ACK"];
	        this.URG = source["URG"];
	        this.ECE = source["ECE"];
	        this.CWR = source["CWR"];
	        this.NS = source["NS"];
	        this.Window = source["Window"];
	        this.Checksum = source["Checksum"];
	        this.Urgent = source["Urgent"];
	        this.Options = this.convertValues(source["Options"], TCPOption);
	        this.Padding = source["Padding"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace net {
	
	export class Interface {
	    Index: number;
	    MTU: number;
	    Name: string;
	    HardwareAddr: number[];
	    Flags: number;
	
	    static createFrom(source: any = {}) {
	        return new Interface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Index = source["Index"];
	        this.MTU = source["MTU"];
	        this.Name = source["Name"];
	        this.HardwareAddr = source["HardwareAddr"];
	        this.Flags = source["Flags"];
	    }
	}

}

export namespace pcap {
	
	export class Handle {
	
	
	    static createFrom(source: any = {}) {
	        return new Handle(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class InterfaceAddress {
	    IP: number[];
	    Netmask: number[];
	    Broadaddr: number[];
	    P2P: number[];
	
	    static createFrom(source: any = {}) {
	        return new InterfaceAddress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IP = source["IP"];
	        this.Netmask = source["Netmask"];
	        this.Broadaddr = source["Broadaddr"];
	        this.P2P = source["P2P"];
	    }
	}
	export class Interface {
	    Name: string;
	    Description: string;
	    Flags: number;
	    Addresses: InterfaceAddress[];
	
	    static createFrom(source: any = {}) {
	        return new Interface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Name = source["Name"];
	        this.Description = source["Description"];
	        this.Flags = source["Flags"];
	        this.Addresses = this.convertValues(source["Addresses"], InterfaceAddress);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

